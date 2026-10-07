import test from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {webcrypto} from "node:crypto";
const source = await readFile(new URL("./dom.js",import.meta.url),"utf8");
const {documentOperation} = await import("data:text/javascript;base64,"+Buffer.from(source).toString("base64"));
Object.defineProperty(globalThis,"crypto",{value:webcrypto,writable:true,configurable:true});
class Input {
  constructor(type,name,autocomplete="") { this.type=type;this.name=name;this.id=name;
    this.autocomplete=autocomplete;this.localName="input";this.nodeType=1;this.dataset={};
    this.disabled=false;this.readOnly=false;this.isConnected=true;this._value="";this.attrs={};this.events=[]; }
  get value(){ return this._value; } set value(v){this._value=v;}
  getClientRects(){return this.hidden ? [] : [{}];}
  getAttribute(n){return this.attrs[n] ?? null;}
  dispatchEvent(e){this.events.push(e.type);this.onEvent?.(e);}
}
globalThis.HTMLInputElement=Input;
globalThis.HTMLTextAreaElement=Input;
globalThis.getComputedStyle=()=>({visibility:"visible",display:"block"});
const lease = value => ({value,expires_at:Date.now()/1000+60});
function fixture(origin="https://example.invalid") {
  globalThis.location=new URL(origin+"/login");
  globalThis.window={isSecureContext:true};
  const account=new Input("text","username","username");
  account.value="synthetic-account@example.invalid";
  const password=new Input("password","password","current-password");
  const otp=new Input("text","otp","one-time-code");
  const root={localName:"html",nodeType:1,parentElement:null,children:[]};
  const form={localName:"form",nodeType:1,parentElement:root,children:[account,password,otp],action:origin+"/login"};
  root.children=[form];
  form.querySelectorAll=()=>[account];
  form.querySelector=()=>null;
  for (const el of form.children){el.parentElement=form;el.form=form;}
  const all=[account,password,otp];
  const selector=el=>"html > form:nth-child(1) > input:nth-child("+(all.indexOf(el)+1)+")";
  globalThis.document={
    querySelectorAll(q){if(q==="input,textarea")return all;
      if(q.startsWith("input[autocomplete"))return [account];
      return all.filter(el=>selector(el)===q);},
    querySelector(){return null;}
  };
  return {account,password,otp,form};
}
test("discovery returns safe bindings and capture stays private",async()=>{
  const f=fixture(); const marker="synthetic-"+crypto.randomUUID();f.password.value=marker;
  const targets=await documentOperation("discover");
  assert.equal(targets.length,2); assert.ok(!JSON.stringify(targets).includes(marker));
  const captured=await documentOperation("capture",targets[0]);
  assert.equal(captured.captured_value,marker);
  const filled=await documentOperation("fill",targets[0],lease(marker+"-updated"));
  assert.deepEqual(filled,{outcome:"filled"});assert.deepEqual(f.password.events,["input","change"]);
  assert.ok(!JSON.stringify(filled).includes(marker));
});
test("origin, field, account, visibility, and form binding reject changes",async()=>{
  let f=fixture();let [target]=await documentOperation("discover");
  await assert.rejects(documentOperation("fill",{...target,origin:"https://attacker.invalid"},lease("synthetic")));
  await assert.rejects(documentOperation("fill",{...target,field:{...target.field,selector:"body"}},lease("synthetic")));
  f.account.value="other-account";
  await assert.rejects(documentOperation("fill",target,lease("synthetic")));
  f=fixture();[target]=await documentOperation("discover");f.password.hidden=true;
  await assert.rejects(documentOperation("capture",target));
  f=fixture();[target]=await documentOperation("discover");f.form.action="https://attacker.invalid";
  await assert.rejects(documentOperation("fill",target,lease("synthetic")));
});
test("insecure destinations and detached fields cannot receive values",async()=>{
  fixture("http://example.invalid");
  await assert.rejects(documentOperation("discover"));
  const f=fixture();const [target]=await documentOperation("discover");f.password.isConnected=false;
  await assert.rejects(documentOperation("fill",target,lease("synthetic")));
});
test("capture requires actual value and post-fill account changes are rejected",async()=>{
  const f=fixture();const [target]=await documentOperation("discover");
  await assert.rejects(documentOperation("capture",target));
  f.password.onEvent=()=>{f.account.value="changed";};
  await assert.rejects(documentOperation("fill",target,lease("synthetic")));
});
test("page mutations during asynchronous fingerprinting are rejected",async()=>{
  const f=fixture();
  const oldCrypto=globalThis.crypto;
  globalThis.crypto={subtle:{async digest(...args){f.password.name="mutated";return oldCrypto.subtle.digest(...args);}}};
  const targets=await documentOperation("discover");
  assert.equal(targets.filter(t=>t.field.kind==="password").length,0);
  globalThis.crypto=oldCrypto;
});

test("synthetic service confirmation is separate from fill and never trusts live markers",async()=>{
  let f=fixture();let [target]=await documentOperation("discover");
  f.password.dataset.gateServiceState="accepted";
  await assert.rejects(documentOperation("verify",target));
  f=fixture();
  globalThis.location={origin:"chrome-extension://abcdefghijklmnopabcdefghijklmnop",
    protocol:"chrome-extension:",pathname:"/fixture.html",href:"chrome-extension://abcdefghijklmnopabcdefghijklmnop/fixture.html"};
  f.form.action=undefined;f.password.dataset.gateKind="password";
  [target]=await documentOperation("discover");
  await documentOperation("fill",target,lease("synthetic-filled"));
  assert.equal((await documentOperation("verify",target)).confirmed,false);
  f.password.dataset.gateServiceState="accepted";
  const proof=await documentOperation("verify",target);
  assert.equal(proof.confirmed,true);assert.equal(proof.evidence_code,"synthetic_fixture_accepted");
  assert.equal(proof.private_value,"synthetic-filled");
  const publicProof={confirmed:proof.confirmed,evidence_code:proof.evidence_code,account_hash:proof.account_hash};
  assert.ok(!JSON.stringify(publicProof).includes("synthetic-filled"));
  await documentOperation("fill",target,lease("different-synthetic"));
  const replaced=await documentOperation("verify",target);
  assert.equal(replaced.confirmed,false);assert.equal(replaced.private_value,"different-synthetic");
});

test("new password and authenticator enrollment block live fill before release",async()=>{
  let f=fixture();f.password.autocomplete="new-password";
  let [target]=await documentOperation("discover");
  await assert.rejects(documentOperation("check",target),/PROTECTED_ENROLLMENT/);
  await assert.rejects(documentOperation("fill",target,lease("synthetic")),/PROTECTED_ENROLLMENT/);
  f=fixture();globalThis.location.pathname="/settings/two_factor_authentication/verify";
  target=(await documentOperation("discover")).find(t=>t.field.kind==="totp");
  await assert.rejects(documentOperation("check",target),/PROTECTED_ENROLLMENT/);
  f=fixture();f.form.querySelector=()=>({});target=(await documentOperation("discover")).find(t=>t.field.kind==="totp");
  await assert.rejects(documentOperation("fill",target,lease("synthetic")),/PROTECTED_ENROLLMENT/);
});
test("readonly tokens can be captured privately but cannot receive a value",async()=>{
  const f=fixture();f.password.type="text";f.password.name="api_key";f.password.id="api_key";
  f.password.readOnly=true;const marker="synthetic-capture-"+crypto.randomUUID();f.password.value=marker;
  const target=(await documentOperation("discover")).find(t=>t.field.kind==="token");
  assert.ok(target);assert.ok(!JSON.stringify(target).includes(marker));
  await documentOperation("check_capture",target);
  assert.equal((await documentOperation("capture",target)).captured_value,marker);
  await assert.rejects(documentOperation("check",target));
  await assert.rejects(documentOperation("fill",target,lease("synthetic")));
});
test("unrelated controls with secret-like identifiers are excluded from discovery",async()=>{
  const f=fixture();f.password.type="checkbox";f.password.name="api_key";f.password.id="api_key";
  const targets=await documentOperation("discover");assert.equal(targets.some(t=>t.field.kind==="token"),false);
});

test("expired or malformed private leases never reach the setter",async()=>{
  const f=fixture();const [target]=await documentOperation("discover");
  const original=f.password.value;
  await assert.rejects(documentOperation("fill",target,{value:"synthetic",expires_at:Date.now()/1000-1}),/LEASE_EXPIRED/);
  await assert.rejects(documentOperation("fill",target,"synthetic"),/OPERATION_REJECTED/);
  await assert.rejects(documentOperation("fill",target,{value:"synthetic"}),/OPERATION_REJECTED/);
  assert.equal(f.password.value,original);assert.deepEqual(f.password.events,[]);
});
test("lease expiring while destination fingerprint is checked withholds fill",async()=>{
  const f=fixture();const [target]=await documentOperation("discover");
  const original=f.password.value;const originalCrypto=globalThis.crypto;
  const expires_at=(Date.now()+10)/1000;
  globalThis.crypto={subtle:{async digest(...args){
    await new Promise(resolve=>setTimeout(resolve,20));return originalCrypto.subtle.digest(...args);
  }}};
  try {
    await assert.rejects(documentOperation("fill",target,{value:"synthetic",expires_at}),/LEASE_EXPIRED/);
    assert.equal(f.password.value,original);assert.deepEqual(f.password.events,[]);
  } finally {globalThis.crypto=originalCrypto;}
});
test("expiry during field events produces no successful fill receipt",async()=>{
  const f=fixture();const [target]=await documentOperation("discover");
  const originalNow=Date.now;let clock=1000;Date.now=()=>clock;
  f.password.onEvent=()=>{clock=2000;};
  try {
    await assert.rejects(documentOperation("fill",target,{value:"synthetic",expires_at:1.5}),/LEASE_EXPIRED/);
    // The released value does not stay in the page after the failure.
    assert.equal(f.password.value,"");
  } finally {Date.now=originalNow;}
});
test("every post-set failure clears the field and redispatches before throwing",async()=>{
  const marker="synthetic-"+crypto.randomUUID();
  // FILL_REJECTED: the page rewrites the value during the input event.
  let f=fixture();let [target]=await documentOperation("discover");
  f.password.onEvent=e=>{if(e.type==="input"&&f.password.value===marker)f.password._value=marker+"-mangled";};
  await assert.rejects(documentOperation("fill",target,lease(marker)),/FILL_REJECTED/);
  assert.equal(f.password.value,"");assert.deepEqual(f.password.events,["input","change","input","change"]);
  // BINDING_CHANGED: the account changes while the field holds the value.
  f=fixture();[target]=await documentOperation("discover");
  f.password.onEvent=()=>{f.account.value="other-account";};
  await assert.rejects(documentOperation("fill",target,lease(marker)),/BINDING_CHANGED/);
  assert.equal(f.password.value,"");
  // BINDING_CHANGED: the field is hidden after the events fire.
  f=fixture();[target]=await documentOperation("discover");
  f.password.onEvent=e=>{if(e.type==="change")f.password.hidden=true;};
  await assert.rejects(documentOperation("fill",target,lease(marker)),/BINDING_CHANGED/);
  assert.equal(f.password.value,"");
  // FORM_ORIGIN_REJECTED: the form target moves cross-origin after the setter.
  f=fixture();[target]=await documentOperation("discover");
  f.password.onEvent=()=>{f.form.action="https://attacker.invalid/collect";};
  await assert.rejects(documentOperation("fill",target,lease(marker)),/FORM_ORIGIN_REJECTED/);
  assert.equal(f.password.value,"");
});
test("a throwing page listener cannot stop the defensive clear",async()=>{
  const f=fixture();const [target]=await documentOperation("discover");
  f.password.onEvent=()=>{f.account.value="changed";throw Error("page listener");};
  await assert.rejects(documentOperation("fill",target,lease("synthetic-value")));
  assert.equal(f.password.value,"");
});
test("clear command empties only the bound field on the bound document",async()=>{
  let f=fixture();let [target]=await documentOperation("discover");
  f.password.value="synthetic-left-behind";f.account.value="binding-changed";
  assert.deepEqual(await documentOperation("clear",target),{outcome:"cleared"});
  assert.equal(f.password.value,"");assert.deepEqual(f.password.events,["input","change"]);
  f=fixture();[target]=await documentOperation("discover");f.password.value="synthetic-keep";
  await assert.rejects(documentOperation("clear",{...target,origin:"https://attacker.invalid"}),/DESTINATION_REJECTED/);
  await assert.rejects(documentOperation("clear",{...target,field:{...target.field,selector:"body"}}),/FIELD_REJECTED/);
  assert.equal(f.password.value,"synthetic-keep");
});
