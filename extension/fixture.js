import {documentOperation} from "./dom.js";
// Synthetic values are created in the browser and never copied through agent context.
const random = () => crypto.randomUUID().replaceAll("-","");
const expectedPassword = "Gate-" + random();
const expectedToken = "synthetic_" + random();
document.querySelector('[data-gate-kind="password"]').value = expectedPassword;
document.querySelector('[data-gate-kind="token"]').value = expectedToken;
document.querySelector('[data-gate-kind="seed"]').value = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
document.querySelector('[data-gate-kind="recovery"]').value = random() + "\n" + random();
document.querySelector('[data-gate-kind="note"]').value = "Synthetic encrypted note " + random();
document.querySelector("#status").textContent = "Ready for private synthetic operations.";
const invalidateAcceptance = () => {
  for (const field of document.querySelectorAll("input,textarea")) field.dataset.gateServiceState = "pending";
};
document.querySelector("form").addEventListener("input",invalidateAcceptance);
document.querySelector("form").addEventListener("change",invalidateAcceptance);

chrome.runtime.onMessage.addListener((message,sender,respond) => {
  if (sender.id !== chrome.runtime.id || !sender.url?.startsWith(chrome.runtime.getURL("operation.html")) ||
      message?.protocol !== 1 || !["ready","discover","check","check_capture","capture","fill","clear","verify"].includes(message.command)) return;
  if (message.command === "ready") {
    respond({ok:true,data:{ready:true}});
    return false;
  }
  // Same {command,target,lease} shape the isolated-world path passes as arguments.
  documentOperation(message.command,message.target ?? null,message.lease ?? null)
    .then(async data => {
      if (message.command === "fill" && data?.outcome === "filled") await validateAcceptance();
      respond({ok:true,data});
    }).catch(() => respond({ok:false,error:"FIXTURE_OPERATION_REJECTED"}));
  return true;
});

async function expectedOTP() {
  const counter = BigInt(Math.floor(Date.now()/30000));
  const message = new Uint8Array(8);
  new DataView(message.buffer).setBigUint64(0,counter,false);
  const key = await crypto.subtle.importKey("raw",new TextEncoder().encode("12345678901234567890"),
    {name:"HMAC",hash:"SHA-1"},false,["sign"]);
  const bytes = new Uint8Array(await crypto.subtle.sign("HMAC",key,message));
  const offset = bytes[bytes.length-1] & 15;
  const code = ((bytes[offset]&127)<<24) | (bytes[offset+1]<<16) | (bytes[offset+2]<<8) | bytes[offset+3];
  return String(code%1000000).padStart(6,"0");
}
async function validateAcceptance() {
  const accepted = new Map([
    ["password",expectedPassword],["token",expectedToken],["totp",await expectedOTP()],
    ["seed","GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"]]);
  for (const [kind,value] of accepted) {
    const input = document.querySelector('[data-gate-kind="'+kind+'"]');
    input.dataset.gateServiceState = input.value === value ? "accepted" : "rejected";
  }
  document.querySelector("#status").textContent = "Synthetic service confirmation recorded.";
}
document.querySelector("#verify-login").addEventListener("click",validateAcceptance);
