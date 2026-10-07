import {documentOperation} from "./dom.js";
import {NATIVE_HOST as HOST} from "./config.js";
const status = document.querySelector("#status");
const result = document.querySelector("#result");
const fixtureURL = chrome.runtime.getURL("fixture.html");
// Opaque tokens issued by the native host (operation handles, enrollment nonces).
const OPAQUE_TOKEN = /^[a-zA-Z0-9_-]{32,128}$/;
const profile = async () => {
  // First-run creation is atomic across every extension page and the service
  // worker: Web Locks are shared by all contexts of this extension origin, so two
  // concurrent operation pages cannot each generate and overwrite a profile.
  if (!navigator.locks?.request) throw new Error("PROFILE_LOCK_UNAVAILABLE");
  return navigator.locks.request("arcturion-gate-profile",{mode:"exclusive"},async () => {
    const stored = await chrome.storage.local.get(["profile_id","profile_auth"]);
    if (stored.profile_id && stored.profile_auth) return {profile_id:stored.profile_id,profile_auth:stored.profile_auth};
    const profile_id = crypto.randomUUID();
    const profile_auth = Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2,"0")).join("");
    await chrome.storage.local.set({profile_id,profile_auth});
    return {profile_id,profile_auth};
  });
};
// One request shape for both page channels: the fixture's private message
// receiver and the isolated-world documentOperation(command, target, lease).
const pageRequest = (command,target = null,lease = null) => ({protocol:1,command,target,lease});
const pageArgs = request => [request.command,request.target,request.lease];
const native = async (action,fields = {}) => {
  const response = await chrome.runtime.sendNativeMessage(HOST,{protocol:1,action,...await profile(),...fields});
  if (!response || response.ok === false || response.error) throw new Error("NATIVE_OPERATION_REJECTED");
  return response.data || response;
};
const frames = async tab => {
  if (tab.url === fixtureURL) {
    const frame = (await chrome.webNavigation.getAllFrames({tabId:tab.id}))?.find(f => f.frameId === 0);
    if (!frame?.documentId) throw new Error("DOCUMENT_REJECTED");
    return [{frameId:0,documentId:frame.documentId,url:fixtureURL}];
  }
  return (await chrome.webNavigation.getAllFrames({tabId:tab.id})) || [];
};
const invoke = async (target,command,lease = null) => {
  const tab = await chrome.tabs.get(target.tab_id);
  if (tab.incognito || !tab.url) throw new Error("PROFILE_REJECTED");
  const frame = (await frames(tab)).find(f => f.frameId === target.frame_id);
  if (!frame || frame.documentId !== target.document_id ||
      (new URL(frame.url).protocol === "chrome-extension:" ? "chrome-extension://" + new URL(frame.url).host : new URL(frame.url).origin) !== target.origin || new URL(frame.url).pathname !== target.document_path) {
    throw new Error("DOCUMENT_REJECTED");
  }
  if (target.synthetic) {
    if (tab.url !== fixtureURL || target.frame_id !== 0) throw new Error("FIXTURE_REJECTED");
    const response = await chrome.tabs.sendMessage(target.tab_id,pageRequest(command,target,lease));
    if (!response?.ok) throw new Error("FIXTURE_REJECTED");
    return response.data;
  }
  const outputs = await chrome.scripting.executeScript({target:{tabId:target.tab_id,documentIds:[target.document_id]},
    world:"ISOLATED",func:documentOperation,args:pageArgs(pageRequest(command,target,lease))});
  if (outputs.length !== 1 || outputs[0].documentId !== target.document_id) throw new Error("DOCUMENT_REJECTED");
  return outputs[0].result;
};
// Discovery is scoped to the one tab the user is looking at: the active HTTPS tab
// of the last-focused window or, when this operation page has just taken focus,
// the most recently used HTTPS tab of that window. Other open tabs are never scanned.
const activeTab = async () => {
  const tabs = (await chrome.tabs.query({lastFocusedWindow:true})) || [];
  const eligible = tabs.filter(t => Number.isInteger(t.id) && !t.incognito && typeof t.url === "string" && t.url.startsWith("https://"));
  const active = eligible.find(t => t.active);
  if (active) return [active];
  const recent = eligible.filter(t => Number.isFinite(t.lastAccessed)).sort((a,b) => b.lastAccessed - a.lastAccessed);
  return recent.length ? [recent[0]] : [];
};
const discover = async (onlyTabId = null) => {
  const targets = [];
  const tabs = onlyTabId === null ? await activeTab() : [await chrome.tabs.get(onlyTabId)];
  for (const tab of tabs) {
    if (onlyTabId !== null && (tab.url !== fixtureURL || tab.incognito)) throw new Error("FIXTURE_REJECTED");
    if (!tab.id || tab.incognito || !tab.url || (!tab.url.startsWith("https://") && tab.url !== fixtureURL)) continue;
    for (const frame of await frames(tab)) {
      if (!frame.documentId || (!frame.url.startsWith("https://") && frame.url !== fixtureURL)) continue;
      if (onlyTabId !== null) {
        // The readiness check does not authorize a tab that subsequently navigates.
        const current = await chrome.tabs.get(tab.id);
        if (current.url !== fixtureURL || current.incognito) throw new Error("FIXTURE_REJECTED");
      }
      try {
        let fields;
        if (tab.url === fixtureURL) {
          const response = await chrome.tabs.sendMessage(tab.id,pageRequest("discover"));
          if (!response?.ok) continue;
          fields = response.data;
        } else {
          const outputs = await chrome.scripting.executeScript({target:{tabId:tab.id,documentIds:[frame.documentId]},
            world:"ISOLATED",func:documentOperation,args:pageArgs(pageRequest("discover"))});
          fields = outputs[0]?.result || [];
        }
        // Browser-sourced identifiers are applied last so page-side output can never override them.
        for (const field of fields) targets.push({...field,tab_id:tab.id,frame_id:frame.frameId,document_id:frame.documentId});
      } catch { /* Restricted browser pages are excluded. */ }
    }
  }
  const receipt = await native("publish_targets",{targets});
  status.textContent = "Available destinations refreshed.";
  // Native must return only its safe target catalog, never page values.
  const safeTargets = (receipt.targets || []).map(t => ({target_id:t.target_id,origin:t.origin,
    document_path:t.document_path,field:t.field,account_hash:t.account_hash,synthetic:t.synthetic}));
  result.textContent = JSON.stringify({status:"refreshed",targets:safeTargets},null,2);
};
const closeTab = async tabId => {
  try { if (Number.isInteger(tabId)) await chrome.tabs.remove(tabId); } catch { /* Already closed. */ }
};
const openSyntheticFixture = async () => {
  // No supplied URL is accepted; this helper can open only our packaged fixture.
  // Publishing replaces this profile's targets, so fixture tabs left by an
  // earlier run are no longer destinations and are closed first.
  // Matched locally by exact URL; no other tab is touched or scanned.
  for (const stale of (await chrome.tabs.query({})) || []) if (stale.url === fixtureURL) await closeTab(stale.id);
  const tab = await chrome.tabs.create({url:fixtureURL,active:false});
  let ready = false;
  try {
    if (!Number.isInteger(tab.id) || tab.incognito) throw new Error("FIXTURE_REJECTED");
    const deadline = Date.now() + 8000;
    while (Date.now() < deadline) {
      try {
        const current = await chrome.tabs.get(tab.id);
        if (current.url === fixtureURL && !current.incognito) {
          const reply = await chrome.tabs.sendMessage(tab.id,pageRequest("ready"));
          if (reply?.ok && reply.data?.ready === true) { ready = true; return tab.id; }
        }
      } catch { /* The fixture's private receiver may still be loading. */ }
      await new Promise(resolve => setTimeout(resolve,100));
    }
    throw new Error("FIXTURE_NOT_READY");
  } finally {
    if (!ready) await closeTab(tab.id);
  }
};
// The fixture tab stays open only when it was published as a destination;
// every failure path closes it.
const discoverSyntheticFixture = async () => {
  const tabId = await openSyntheticFixture();
  let published = false;
  try {
    await discover(tabId);
    published = true;
  } finally {
    if (!published) await closeTab(tabId);
  }
};
const operate = async handle => {
  const descriptor = await native("describe",{handle});
  const target = descriptor.target;
  if (!target || !["fill","capture","verify"].includes(descriptor.action)) throw new Error("OPERATION_REJECTED");
  await invoke(target,descriptor.action === "capture" ? "check_capture" : "check");
  if (descriptor.action === "verify") {
    // Only the packaged synthetic fixture has a service verifier in this release.
    if (descriptor.service !== "synthetic_credential" || !target.synthetic) throw new Error("SERVICE_ADAPTER_UNSUPPORTED");
    const verification = await invoke(target,"verify");
    verification.document_id = target.document_id;
    try {
      await native("execute",{handle,target,verification});
    } finally {
      // Only the synthetic native verification channel may carry this field value.
      if ("private_value" in verification) verification.private_value = null;
    }
    status.textContent = verification.confirmed ? "Service status confirmed." : "Service status has not been confirmed.";
    result.textContent = JSON.stringify({status:verification.confirmed ? "service_verified" : "pending"},null,2);
    return;
  }
  if (descriptor.action === "capture") {
    const captured = await invoke(target,"capture");
    const receipt = await native("execute",{handle,target,captured_value:captured.captured_value});
    captured.captured_value = null;
    status.textContent = "Credential captured securely.";
    // Fixed safe receipt projection prevents native debug fields reaching the operation UI.
    result.textContent = JSON.stringify({status:receipt.status || "captured",record_id:receipt.record_id,
      version:receipt.version,receipt_id:receipt.receipt_id},null,2);
    return;
  }
  let privateResponse;
  let fillAttempted = false;
  try {
    privateResponse = await native("execute",{handle,target});
    if (typeof privateResponse.value !== "string" || !Number.isFinite(privateResponse.expires_at) ||
        privateResponse.expires_at * 1000 <= Date.now()) throw new Error("LEASE_REJECTED");
    // Expiry is checked again immediately before the setter inside the isolated world.
    fillAttempted = true;
    await invoke(target,"fill",{value:privateResponse.value,expires_at:privateResponse.expires_at});
    privateResponse.value = null;
    await invoke(target,"check");
    await native("complete",{handle,target,outcome:"filled",lease_id:privateResponse.lease_id});
    status.textContent = "Credential supplied privately.";
    result.textContent = JSON.stringify({status:"filled"},null,2);
  } catch {
    if (privateResponse) privateResponse.value = null;
    // A rejected fill is reported only after the field no longer holds the value.
    if (fillAttempted) { try { await invoke(target,"clear"); } catch { /* Destination is gone. */ } }
    try { await native("complete",{handle,target,outcome:"rejected",lease_id:privateResponse?.lease_id}); } catch {}
    throw new Error("PRIVATE_OPERATION_REJECTED");
  }
};
try {
  const fragment = location.hash.slice(1);
  if (fragment === "discover") await discover();
  else if (fragment === "fixture") await discoverSyntheticFixture();
  else if (fragment.startsWith("enroll=")) {
    const install_nonce = fragment.slice(7);
    history.replaceState(null,"",location.pathname);
    // Same opaque-token rule as operation handles, checked before any native contact.
    if (!OPAQUE_TOKEN.test(install_nonce)) throw new Error("INVALID_OPERATION");
    await native("enroll",{install_nonce});
    status.textContent = "This Chrome profile is enrolled.";
  } else if (OPAQUE_TOKEN.test(fragment)) {
    history.replaceState(null,"",location.pathname);
    await operate(fragment);
  } else throw new Error("INVALID_OPERATION");
} catch (error) {
  const code = error?.message === "PROTECTED_ENROLLMENT" ? "PROTECTED_ENROLLMENT" : "OPERATION_REJECTED";
  status.textContent = code === "PROTECTED_ENROLLMENT" ?
    "This is a protected enrollment step. The credential workflow remains resumable." :
    "Operation could not be completed. No credential value is displayed.";
  result.textContent = JSON.stringify({status:"rejected",code},null,2);
}
