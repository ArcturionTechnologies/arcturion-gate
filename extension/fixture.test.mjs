import test from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import vm from "node:vm";
const script=(await readFile(new URL("./fixture.js",import.meta.url),"utf8"))
  .replace('import {documentOperation} from "./dom.js";','const documentOperation = async (command,target,lease) => {pageCalls.push([command,target,lease]);return command === "fill" ? {outcome:"filled"} : {};};');
async function fixture() {
  const fields=Object.fromEntries(["password","token","seed","recovery","note","totp"].map(kind=>[kind,{value:"",dataset:{gateKind:kind}}]));
  const handlers={};const form={addEventListener(name,callback){handlers[name]=callback;}};
  const verify={addEventListener(name,callback){handlers.verify=callback;}};
  const status={textContent:""};let receiver;const pageCalls=[];
  const context={pageCalls,TextEncoder,DataView,Uint8Array,BigInt,Map,Date,crypto:globalThis.crypto,
    console:{log(){throw Error("LOG_FORBIDDEN");},error(){throw Error("LOG_FORBIDDEN");}},
    document:{querySelector(selector){
      if(selector==="form")return form;
      if(selector==="#verify-login")return verify;
      if(selector==="#status")return status;
      return fields[selector.match(/data-gate-kind="([^"]+)"/)?.[1]];
    },querySelectorAll(){return Object.values(fields);}},
    chrome:{runtime:{onMessage:{addListener(callback){receiver=callback;}},getURL:path=>"chrome-extension://bridge/"+path,id:"bridge"}}};
  await vm.runInNewContext("(async()=>{"+script+"})()",context);
  return {fields,handlers,status,receiver,pageCalls};
}
test("any fixture input/change invalidates previous service acceptance",async()=>{
  const f=await fixture();
  for(const field of Object.values(f.fields))field.dataset.gateServiceState="accepted";
  f.handlers.input();
  assert.ok(Object.values(f.fields).every(field=>field.dataset.gateServiceState==="pending"));
  for(const field of Object.values(f.fields))field.dataset.gateServiceState="accepted";
  f.handlers.change();
  assert.ok(Object.values(f.fields).every(field=>field.dataset.gateServiceState==="pending"));
});
test("fresh synthetic submit accepts original challenge and rejects replacement",async()=>{
  const f=await fixture();
  await f.handlers.verify();
  assert.equal(f.fields.password.dataset.gateServiceState,"accepted");
  assert.equal(f.fields.token.dataset.gateServiceState,"accepted");
  f.fields.password.value="different-synthetic-candidate";
  f.handlers.input();
  assert.equal(f.fields.password.dataset.gateServiceState,"pending");
  await f.handlers.verify();
  assert.equal(f.fields.password.dataset.gateServiceState,"rejected");
  assert.equal(f.fields.token.dataset.gateServiceState,"accepted");
});

test("private fixture fill invokes independent original challenge validation automatically",async()=>{
  const f=await fixture();
  const send=command=>new Promise(resolve=>f.receiver({protocol:1,command},{id:"bridge",url:"chrome-extension://bridge/operation.html"},resolve));
  let response=await send("ready");assert.equal(response.data.ready,true);
  response=await send("fill");assert.equal(response.ok,true);
  assert.equal(f.fields.password.dataset.gateServiceState,"accepted");
  f.fields.password.value="different-synthetic-record";f.handlers.input();
  response=await send("fill");assert.equal(response.ok,true);
  assert.equal(f.fields.password.dataset.gateServiceState,"rejected");
});

test("fixture receiver takes the same {command,target,lease} shape and supports clear",async()=>{
  const f=await fixture();
  const send=message=>new Promise(resolve=>f.receiver({protocol:1,...message},{id:"bridge",url:"chrome-extension://bridge/operation.html"},resolve));
  const target={field:{selector:"#p"}};const lease={value:"synthetic-lease",expires_at:1};
  assert.equal((await send({command:"fill",target,lease})).ok,true);
  assert.equal((await send({command:"clear",target,lease:null})).ok,true);
  // The retired private_value key is ignored rather than forwarded as a lease.
  await send({command:"fill",target,private_value:{value:"old-shape",expires_at:1}});
  assert.deepEqual(f.pageCalls.map(c=>c[0]),["fill","clear","fill"]);
  assert.deepEqual(f.pageCalls[0][2],lease);assert.equal(f.pageCalls[1][2],null);assert.equal(f.pageCalls[2][2],null);
});
