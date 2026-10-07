import test from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import vm from "node:vm";
const TEST_HOST="com.example.gate_test";
const script=(await readFile(new URL("./operation.js",import.meta.url),"utf8")).replace('import {documentOperation} from "./dom.js";','const documentOperation = () => {};')
  .replace('import {NATIVE_HOST as HOST} from "./config.js";','const HOST = "'+TEST_HOST+'";');
export function serialLocks() {
  let tail=Promise.resolve();const calls=[];
  return {calls,async request(name,options,callback){
    calls.push(name);const run=tail.then(()=>callback());tail=run.catch(()=>{});return run;}};
}
export function slowStorage(initial={}) {
  const data={...initial};const writes=[];
  const pause=()=>new Promise(resolve=>setTimeout(resolve,5));
  return {data,writes,async get(keys){await pause();return Object.fromEntries(keys.filter(k=>k in data).map(k=>[k,data[k]]));},
    async set(values){await pause();writes.push({...values});Object.assign(data,values);}};
}
async function run({action="fill",wrongDocument=false,expired=false,rejectFill=false,synthetic=false,confirmed=true,navigateFixture=false,service="synthetic_credential",fragment="x".repeat(40),
  storage=null,locks=serialLocks(),openTabs=null,staleFixtureTabs=[],rejectPostCheck=false}={}) {
  const marker="synthetic-private-value-"+Math.random();
  const secretAuth="synthetic-profile-auth";
  const nodes={status:{textContent:""},result:{textContent:""}};
  const nativeRequests=[];const domCommands=[];const createdTabs=[];const removedTabs=[];const scannedTabs=[];const pageMessages=[];let removed=false;let readySent=false;
  const target={tab_id:9,frame_id:0,document_id:"doc-A",
    origin:synthetic ? "chrome-extension://abcdefghijklmnopabcdefghijklmnop" : "https://example.invalid",
    document_path:synthetic ? "/fixture.html" : "/login",synthetic,
    field:{selector:"#credential",fingerprint:"f",kind:"password"},account_hash:"a"};
  const tabURL=target.origin+target.document_path;
  const context={
    console:{log(){throw Error("LOG_FORBIDDEN");},error(){throw Error("LOG_FORBIDDEN");}},
    location:{hash:"#"+fragment,pathname:"/operation.html"},
    history:{replaceState(){removed=true;}},
    document:{querySelector(selector){return nodes[selector.slice(1)];}},
    navigator:locks ? {locks} : {},
    URL,Date,JSON,Uint8Array,crypto:globalThis.crypto,
    chrome:{
      storage:{local:storage || {async get(){return {profile_id:"profile",profile_auth:secretAuth};},async set(){}}},
      runtime:{getURL:path=>"chrome-extension://abcdefghijklmnopabcdefghijklmnop/"+path,
        async sendNativeMessage(host,request){
          assert.equal(host,TEST_HOST);if(!storage)assert.equal(request.profile_auth,secretAuth);
          nativeRequests.push(JSON.parse(JSON.stringify(request)));
          if(request.action==="describe")return {ok:true,data:{action,target,service}};
          if(request.action==="publish_targets")return {ok:true,data:{targets:request.targets.map(t=>({target_id:"target-1",...t}))}};
          if(request.action==="execute")return {ok:true,data:action==="fill" ?
            {value:marker,lease_id:"lease",expires_at:(Date.now()/1000)+(expired?-1:60)}:
            {status:"captured",record_id:"record",version:1,receipt_id:"receipt",value:marker}};
          return {ok:true,data:{status:"complete"}};
        }},
      tabs:{async create(options){createdTabs.push(JSON.parse(JSON.stringify(options)));return {id:9,url:tabURL,incognito:false};},
        async get(){return {id:9,url:navigateFixture && readySent ? (typeof navigateFixture === "string" ? navigateFixture : "https://attacker.invalid/") : tabURL,incognito:false};},
        async query(query){
          if(query&&Object.keys(query).length===0&&domCommands.length===0&&createdTabs.length===0)
            return [...staleFixtureTabs.map(t=>({url:"chrome-extension://abcdefghijklmnopabcdefghijklmnop/fixture.html",...t})),
              {id:77,url:"https://unrelated-live.invalid/",incognito:false}];
          if(openTabs&&query?.lastFocusedWindow===true&&Object.keys(query).length===1)return openTabs;
          throw Error("FIXTURE_MUST_NOT_DISCOVER_LIVE_TABS");},
        async remove(tabId){removedTabs.push(tabId);},
        async sendMessage(tabId,message){domCommands.push(message.command);pageMessages.push(JSON.parse(JSON.stringify(message)));
          if(message.command==="ready"){readySent=true;return {ok:true,data:{ready:true}};}
          if(message.command==="discover")return {ok:true,data:[target]};
          return {ok:true,data:message.command==="verify" ?
            {confirmed,private_value:marker,evidence_code:"synthetic_fixture_accepted",origin:target.origin,
              document_path:target.document_path,account_hash:target.account_hash} : {outcome:"checked"}};}},
      webNavigation:{async getAllFrames({tabId}){
        const open=openTabs?.find(t=>t.id===tabId);
        return [{frameId:0,documentId:wrongDocument?"doc-B":"doc-A",url:open ? open.url : tabURL}];}},
      scripting:{async executeScript({target:scriptTarget,args}){
        domCommands.push(args[0]);scannedTabs.push(scriptTarget.tabId);
        assert.equal(args.length,3);
        if(args[0]==="discover")return [{documentId:"doc-A",result:[{...target,origin:new URL(openTabs.find(t=>t.id===scriptTarget.tabId).url).origin}]}];
        if(args[0]==="clear")return [{documentId:"doc-A",result:{outcome:"cleared"}}];
        if(args[0]==="fill"){assert.equal(args[2].value,marker);assert.ok(Number.isFinite(args[2].expires_at));if(rejectFill)throw Error("synthetic");
}
        if(args[0]==="check"&&rejectPostCheck&&domCommands.includes("fill"))throw Error("synthetic-binding-changed");
        return [{documentId:"doc-A",result:args[0]==="capture" ? {captured_value:marker,target} :
          {outcome:"filled"}}];
      }}
    }
  };
  await vm.runInNewContext("(async()=>{"+script+"})()",context);
  assert.ok(!nodes.result.textContent.includes(marker));assert.ok(!nodes.result.textContent.includes(secretAuth));
  assert.ok(!nodes.status.textContent.includes(marker));
  return {nodes,nativeRequests,domCommands,createdTabs,removedTabs,scannedTabs,pageMessages,removed};
}
test("fill keeps secret native data off page and checks target twice",async()=>{
  const r=await run();
  assert.equal(JSON.parse(r.nodes.result.textContent).status,"filled");
  assert.deepEqual(r.domCommands,["check","fill","check"]);
  assert.deepEqual(r.nativeRequests.map(x=>x.action),["describe","execute","complete"]);
  assert.equal(r.nativeRequests.at(-1).outcome,"filled");assert.equal(r.removed,true);
});
test("capture receipt strips value even if host accidentally includes it",async()=>{
  const r=await run({action:"capture"});
  assert.deepEqual(r.nativeRequests.map(x=>x.action),["describe","execute"]);
  assert.equal(JSON.parse(r.nodes.result.textContent).record_id,"record");
});
test("wrong document withholds native secret request",async()=>{
  const r=await run({wrongDocument:true});
  assert.deepEqual(r.nativeRequests.map(x=>x.action),["describe"]);
  assert.equal(JSON.parse(r.nodes.result.textContent).status,"rejected");
});
test("expired private lease and rejected fill produce rejection receipts",async()=>{
  let r=await run({expired:true});
  assert.deepEqual(r.domCommands,["check"]);assert.equal(r.nativeRequests.at(-1).outcome,"rejected");
  r=await run({rejectFill:true});assert.equal(r.nativeRequests.at(-1).outcome,"rejected");
  // A rejected fill is followed by a defensive clear of the bound field.
  assert.deepEqual(r.domCommands,["check","fill","clear"]);
});
test("bad operation fragments never contact native host",async()=>{
  const r=await run({fragment:"bad"});assert.equal(r.nativeRequests.length,0);
});

test("verification requires fixed synthetic adapter and sends only bounded proof",async()=>{
  let r=await run({action:"verify"});
  assert.deepEqual(r.nativeRequests.map(x=>x.action),["describe"]);
  r=await run({action:"verify",synthetic:true});
  assert.deepEqual(r.domCommands,["check","verify"]);
  assert.equal(r.nativeRequests.at(-1).verification.document_id,"doc-A");
  assert.equal(r.nativeRequests.at(-1).verification.confirmed,true);
  assert.ok(r.nativeRequests.at(-1).verification.private_value.startsWith("synthetic-private-value-"));
  assert.ok(!r.nodes.result.textContent.includes("private_value"));
  assert.equal(JSON.parse(r.nodes.result.textContent).status,"service_verified");
  r=await run({action:"verify",synthetic:true,confirmed:false});
  assert.equal(JSON.parse(r.nodes.result.textContent).status,"pending");
});

test("verification for a non-fixture service is refused before any DOM verify",async()=>{
  const r=await run({action:"verify",service:"some_live_service"});
  assert.deepEqual(r.domCommands,["check"]);
  assert.deepEqual(r.nativeRequests.map(x=>x.action),["describe"]);
  assert.equal(JSON.parse(r.nodes.result.textContent).status,"rejected");
});

test("fixed fixture helper opens only packaged background fixture and discovers only that tab",async()=>{
  const r=await run({fragment:"fixture",synthetic:true});
  assert.deepEqual(r.createdTabs,[{url:"chrome-extension://abcdefghijklmnopabcdefghijklmnop/fixture.html",active:false}]);
  assert.deepEqual(r.domCommands,["ready","discover"]);
  assert.deepEqual(r.nativeRequests.map(x=>x.action),["publish_targets"]);
  assert.equal(r.nativeRequests[0].targets.length,1);
  assert.equal(JSON.parse(r.nodes.result.textContent).status,"refreshed");
  const rejected=await run({fragment:"fixture=https://attacker.invalid",synthetic:true});
  assert.equal(rejected.createdTabs.length,0);assert.equal(rejected.nativeRequests.length,0);
});

test("fixture discovery rejects navigation after readiness before private scan",async()=>{
  for (const destination of ["https://attacker.invalid/","about:blank"]) {
    const r=await run({fragment:"fixture",synthetic:true,navigateFixture:destination});
    assert.deepEqual(r.domCommands,["ready"]);
    assert.equal(r.nativeRequests.length,0);
    assert.deepEqual(r.removedTabs,[9]);
    assert.equal(JSON.parse(r.nodes.result.textContent).status,"rejected");
  }
});

test("fill that throws after the setter is cleared and never reported as filled",async()=>{
  const r=await run({rejectFill:true});
  assert.equal(r.domCommands.at(-1),"clear");
  assert.ok(!r.nativeRequests.some(x=>x.action==="complete"&&x.outcome==="filled"));
  assert.equal(JSON.parse(r.nodes.result.textContent).status,"rejected");
});
test("expired lease never reaches the page, so no clear is needed",async()=>{
  const r=await run({expired:true});
  assert.ok(!r.domCommands.includes("fill"));assert.ok(!r.domCommands.includes("clear"));
});
test("successful fixture discovery keeps only the published tab and closes stale fixture tabs",async()=>{
  const r=await run({fragment:"fixture",synthetic:true,staleFixtureTabs:[{id:3},{id:4}]});
  assert.deepEqual(r.removedTabs,[3,4]);
  assert.ok(!r.scannedTabs.includes(77));assert.deepEqual(r.domCommands,["ready","discover"]);
  assert.equal(JSON.parse(r.nodes.result.textContent).status,"refreshed");
});
test("fixture tab that never becomes ready is closed",async()=>{
  const r=await run({fragment:"fixture",synthetic:true,navigateFixture:"about:blank"});
  assert.deepEqual(r.removedTabs,[9]);
});
test("concurrent first-run pages create exactly one profile",async()=>{
  const storage=slowStorage();const locks=serialLocks();
  const [a,b]=await Promise.all([run({storage,locks}),run({storage,locks})]);
  assert.equal(storage.writes.length,1);
  const ids=new Set([...a.nativeRequests,...b.nativeRequests].map(x=>x.profile_id));
  assert.equal(ids.size,1);assert.deepEqual([...ids],[storage.data.profile_id]);
  assert.ok(locks.calls.length>=2);
});
test("missing lock support fails closed without contacting the native host",async()=>{
  const r=await run({locks:null,storage:slowStorage()});
  assert.equal(r.nativeRequests.length,0);
  assert.equal(JSON.parse(r.nodes.result.textContent).status,"rejected");
});
test("discovery scans only the active HTTPS tab by default",async()=>{
  const openTabs=[
    {id:21,url:"https://background-one.invalid/login",active:false,incognito:false,lastAccessed:10},
    {id:22,url:"https://in-view.invalid/login",active:true,incognito:false,lastAccessed:5},
    {id:23,url:"https://background-two.invalid/login",active:false,incognito:false,lastAccessed:1}];
  const r=await run({fragment:"discover",openTabs});
  assert.deepEqual(r.scannedTabs,[22]);
  const published=r.nativeRequests.find(x=>x.action==="publish_targets").targets;
  // Page-side output carried tab_id 9; the browser-sourced tab ID must win.
  assert.deepEqual(published.map(t=>t.tab_id),[22]);
});
test("when the operation page holds focus, discovery uses the most recently used HTTPS tab only",async()=>{
  const openTabs=[
    {id:30,url:"chrome-extension://abcdefghijklmnopabcdefghijklmnop/operation.html",active:true,incognito:false,lastAccessed:99},
    {id:31,url:"https://older.invalid/login",active:false,incognito:false,lastAccessed:10},
    {id:32,url:"https://just-left.invalid/login",active:false,incognito:false,lastAccessed:50},
    {id:33,url:"https://private.invalid/login",active:false,incognito:true,lastAccessed:98}];
  const r=await run({fragment:"discover",openTabs});
  assert.deepEqual(r.scannedTabs,[32]);
});
test("malformed enrollment nonces never contact the native host",async()=>{
  for (const nonce of ["","short","x".repeat(129),"a".repeat(40)+"/../","a".repeat(40)+"%20"]) {
    const r=await run({fragment:"enroll="+nonce});
    assert.equal(r.nativeRequests.length,0,nonce);
    assert.equal(r.removed,true);
  }
  const ok=await run({fragment:"enroll="+"N".repeat(43)});
  assert.deepEqual(ok.nativeRequests.map(x=>x.action),["enroll"]);
  assert.equal(ok.nativeRequests[0].install_nonce,"N".repeat(43));
});
test("synthetic message and isolated-world paths share one request shape",async()=>{
  const r=await run({action:"verify",synthetic:true});
  for (const message of r.pageMessages) {
    assert.deepEqual(Object.keys(message).sort(),["command","lease","protocol","target"]);
    assert.ok(!("private_value" in message));
  }
});
test("post-fill binding check failure clears the field before reporting rejection",async()=>{
  const r=await run({rejectPostCheck:true});
  assert.deepEqual(r.domCommands,["check","fill","check","clear"]);
  assert.equal(r.nativeRequests.at(-1).outcome,"rejected");
  assert.equal(JSON.parse(r.nodes.result.textContent).status,"rejected");
});
