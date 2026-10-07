// This function is self-contained because Chrome serializes it into isolated worlds.
export async function documentOperation(command, expected = null, privateLease = null) {
  const digest = async text => {
    const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, "0")).join("");
  };
  const origin = location.origin;
  const synthetic = origin.startsWith("chrome-extension:") && location.pathname === "/fixture.html";
  if (!synthetic && (location.protocol !== "https:" || !window.isSecureContext)) {
    throw new Error("DESTINATION_REJECTED");
  }
  const visible = (el, allowReadOnly = false) => {
    const s = getComputedStyle(el);
    return el.getClientRects().length > 0 && s.visibility === "visible" &&
      s.display !== "none" && !el.disabled && (allowReadOnly || !el.readOnly);
  };
  const enrollment = el => {
    if (synthetic) return false;
    if (el.autocomplete === "new-password" || classify(el) === "seed") return true;
    if (classify(el) !== "totp") return false;
    const paths = [location.pathname,el.form?.action ? new URL(el.form.action,location.href).pathname : ""];
    if (paths.some(path => /(?:setup|enroll|register|configure|enable).*(?:2fa|mfa|two.factor|authenticator)|(?:2fa|mfa|two.factor|authenticator).*(?:setup|enroll|register|configure|enable)/i.test(path) ||
        /\/settings\/.*(?:two.factor|2fa|mfa|authenticator).*\/verify(?:\/|$)/i.test(path))) return true;
    const scope = el.form || document;
    return !!scope.querySelector('input[name*="totp_secret"],input[name*="setup_key"],input[id*="setup-key"],[data-target*="two-factor-setup"],img[alt*="QR code"]');
  };
  const selectorFor = el => {
    const parts = [];
    while (el && el.nodeType === 1) {
      const index = Array.from(el.parentElement?.children || []).indexOf(el) + 1;
      parts.unshift(el.localName + (el.parentElement ? ":nth-child(" + index + ")" : ""));
      el = el.parentElement;
    }
    return parts.join(" > ");
  };
  const classify = el => {
    if (synthetic && ["password","totp","token","seed","recovery","note"].includes(el.dataset.gateKind)) return el.dataset.gateKind;
    if (el.type === "password") return "password";
    if (el.autocomplete === "one-time-code" && ["text","tel","number"].includes(el.type)) return "totp";
    if (el.localName !== "textarea" && !["text","url","search"].includes(el.type)) return null;
    // Real seed/token/recovery capture requires a recognizable dedicated field.
    const hint = (el.name + " " + el.id + " " + (el.getAttribute("aria-label") || "")).toLowerCase();
    if (/recovery.?code/.test(hint)) return "recovery";
    if (/(totp.?secret|setup.?key|authenticator.?key)/.test(hint)) return "seed";
    if (/(api.?key|access.?token|auth.?token)/.test(hint)) return "token";
    return null;
  };
  const accountFor = el => {
    const scope = el.form || document;
    const usernames = Array.from(scope.querySelectorAll('input[autocomplete="username"],input[autocomplete="email"],input[type="email"]'))
      .filter(x => x.type !== "password" && x.value.trim());
    const unique = [...new Set(usernames.map(x => x.value.trim().toLowerCase()))];
    if (unique.length === 1) return unique[0];
    return "absent";
  };
  const describe = async el => {
    const kind = classify(el);
    const selector = selectorFor(el);
    const formOrigin = el.form?.action ? new URL(el.form.action, location.href).origin : origin;
    // Cross-origin form submission never receives a credential.
    if (formOrigin !== origin) throw new Error("FORM_ORIGIN_REJECTED");
    const binding = JSON.stringify([selector,el.localName,el.type,el.name,el.id,el.autocomplete,formOrigin,el.getAttribute("aria-label") || ""]);
    const account = accountFor(el);
    const path = location.pathname;
    const fingerprint = await digest(binding);
    const account_hash = await digest(account);
    const freshFormOrigin = el.form?.action ? new URL(el.form.action, location.href).origin : location.origin;
    const freshBinding = JSON.stringify([selectorFor(el),el.localName,el.type,el.name,el.id,el.autocomplete,freshFormOrigin,el.getAttribute("aria-label") || ""]);
    if (!el.isConnected || !visible(el,true) || binding !== freshBinding || account !== accountFor(el) || kind !== classify(el) ||
        path !== location.pathname || origin !== location.origin) throw new Error("BINDING_CHANGED");
    return {origin,document_path:path,synthetic,
      field:{selector,fingerprint,kind},account_hash};
  };
  if (command === "discover") {
    const targets = [];
    for (const el of document.querySelectorAll("input,textarea")) {
      if (visible(el,true) && classify(el)) {
        try { targets.push(await describe(el)); } catch { /* Exclude unsafe destinations. */ }
      }
    }
    return targets;
  }
  if (!expected || expected.origin !== origin || expected.document_path !== location.pathname ||
      expected.synthetic !== synthetic) throw new Error("DESTINATION_REJECTED");
  const matches = document.querySelectorAll(expected.field.selector);
  const valueSetter = el => Object.getOwnPropertyDescriptor(el.localName === "textarea" ?
    HTMLTextAreaElement.prototype : HTMLInputElement.prototype,"value")?.set;
  // Removes a released value from the page. Used when any check after the
  // setter fails, so a failure receipt never leaves the secret in the DOM.
  const clearField = el => {
    try {
      const clear = valueSetter(el);
      if (clear) clear.call(el, ""); else el.value = "";
      if (synthetic) el.dataset.gateServiceState = "pending";
      el.dispatchEvent(new Event("input",{bubbles:true}));
      el.dispatchEvent(new Event("change",{bubbles:true}));
    } catch { /* Clearing is best effort and must never mask the original failure. */ }
  };
  if (command === "clear") {
    // Defensive clear after a rejected fill. The binding may be exactly what
    // changed, so only the destination document and a unique field are required.
    if (matches.length !== 1 || !["input","textarea"].includes(matches[0].localName)) throw new Error("FIELD_REJECTED");
    clearField(matches[0]);
    return {outcome:"cleared"};
  }
  const captureMode = command === "capture" || command === "check_capture";
  if (matches.length !== 1 || !visible(matches[0],captureMode)) throw new Error("FIELD_REJECTED");
  const el = matches[0];
  if (!captureMode && enrollment(el)) throw new Error("PROTECTED_ENROLLMENT");
  const current = await describe(el);
  if (current.field.fingerprint !== expected.field.fingerprint ||
      current.field.kind !== expected.field.kind || current.account_hash !== expected.account_hash) {
    throw new Error("BINDING_CHANGED");
  }
  if (command === "check" || command === "check_capture") return current;
  if (command === "verify") {
    // Only the packaged fixture has a service verifier. Its acceptance marker
    // has no authority on any live origin. Real services need their own adapter.
    if (!synthetic) throw new Error("SERVICE_ADAPTER_UNSUPPORTED");
    // Deliberate, synthetic-only exception to "never return field content":
    // private_value is the fixture's own browser-generated synthetic value. It
    // goes only to the native host, which compares it in constant time with the
    // stored candidate (proof the verifier accepted *that* candidate). It is never
    // rendered, logged or stored; operation.js nulls it after the native call.
    // Live origins throw above, so a real credential can never be returned here.
    return {confirmed:el.dataset.gateServiceState === "accepted",private_value:el.value,
      evidence_code:"synthetic_fixture_accepted",account_hash:current.account_hash,
      origin:current.origin,document_path:current.document_path};
  }
  if (command === "capture") {
    if (typeof el.value !== "string" || !el.value.length) throw new Error("EMPTY_CAPTURE");
    return {captured_value:el.value,target:current};
  }
  if (command !== "fill" || !privateLease || typeof privateLease !== "object" ||
      typeof privateLease.value !== "string" || !Number.isFinite(privateLease.expires_at)) throw new Error("OPERATION_REJECTED");
  const privateValue = privateLease.value;
  const expiry = privateLease.expires_at * 1000;
  const setter = valueSetter(el);
  if (!setter) throw new Error("FIELD_REJECTED");
  if (Date.now() >= expiry) throw new Error("LEASE_EXPIRED");
  if (synthetic) el.dataset.gateServiceState = "pending";
  setter.call(el, privateValue);
  // From here on the value is in the page: every failure clears it before throwing.
  try {
    el.dispatchEvent(new Event("input",{bubbles:true}));
    el.dispatchEvent(new Event("change",{bubbles:true}));
    // Never return the field content, even on failure.
    if (Date.now() >= expiry) throw new Error("LEASE_EXPIRED");
    if (el.value !== privateValue) throw new Error("FILL_REJECTED");
    const after = await describe(el);
    if (after.field.fingerprint !== expected.field.fingerprint || after.account_hash !== expected.account_hash ||
        !visible(el) || !el.isConnected) throw new Error("BINDING_CHANGED");
    if (Date.now() >= expiry) throw new Error("LEASE_EXPIRED");
  } catch (error) {
    clearField(el);
    throw error;
  }
  return {outcome:"filled"};
}
