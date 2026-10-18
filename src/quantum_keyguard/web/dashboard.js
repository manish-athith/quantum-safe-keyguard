"use strict";

let bearerToken = "";
let currentSnapshot = null;
let currentKemKey = "";
let toastTimer = null;

const byId = (id) => document.getElementById(id);

function setHidden(element, hidden) {
  element.hidden = hidden;
}

function text(element, value) {
  element.textContent = value == null ? "—" : String(value);
}

function make(tag, className, value) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (value != null) element.textContent = String(value);
  return element;
}

function toast(message, isError = false) {
  const node = byId("toast");
  text(node, message);
  node.className = `toast show${isError ? " error" : ""}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { node.className = "toast"; }, 4200);
}

async function api(path, options = {}, requiresAuth = true) {
  const headers = { Accept: "application/json", ...(options.headers || {}) };
  if (options.body) headers["Content-Type"] = "application/json";
  if (requiresAuth && bearerToken) headers.Authorization = `Bearer ${bearerToken}`;

  let response;
  try {
    response = await fetch(path, { ...options, headers, cache: "no-store" });
  } catch (_error) {
    throw new Error("Cannot reach LinuxONE. Keep the SSH tunnel and API terminal open.");
  }

  let body = null;
  if (response.status !== 204) {
    const contentType = response.headers.get("content-type") || "";
    body = contentType.includes("application/json")
      ? await response.json()
      : await response.text();
  }
  if (!response.ok) {
    if (response.status === 401 && requiresAuth) endBrowserSession("Session expired or was revoked.");
    const detail = body && typeof body === "object" ? body.detail : body;
    throw new Error(detail || `Request failed (${response.status})`);
  }
  return body;
}

function setBusy(button, busy, busyLabel) {
  if (!button.dataset.label) button.dataset.label = button.querySelector("span")?.textContent || button.textContent;
  button.disabled = busy;
  const label = button.querySelector("span");
  if (label) label.textContent = busy ? busyLabel : button.dataset.label;
}

function showAuthenticated(principal) {
  setHidden(byId("login-card"), true);
  setHidden(byId("identity-card"), false);
  text(byId("identity-name"), principal.display_name);
  text(byId("identity-role"), principal.role);
  text(byId("identity-device"), principal.device_id);
  text(byId("identity-session"), `${principal.session_id.slice(0, 17)}…`);
  text(byId("connection-label"), "Authenticated to LinuxONE");
  setHidden(byId("logout-button"), false);
  byId("normal-demo-button").disabled = false;
  byId("refresh-button").disabled = false;
}

function endBrowserSession(message = "Dashboard session ended.") {
  bearerToken = "";
  setHidden(byId("identity-card"), true);
  setHidden(byId("login-card"), false);
  setHidden(byId("logout-button"), true);
  byId("normal-demo-button").disabled = true;
  byId("attack-demo-button").disabled = true;
  byId("refresh-button").disabled = true;
  text(byId("connection-label"), "Re-authentication required");
  text(byId("login-status"), message);
}

async function login(event) {
  event.preventDefault();
  const form = byId("login-form");
  const submit = form.querySelector("button[type=submit]");
  submit.disabled = true;
  text(byId("login-status"), "Authenticating…");
  try {
    const result = await api("/auth/login", {
      method: "POST",
      body: JSON.stringify({
        user_id: byId("user-id").value.trim(),
        password: byId("password").value,
        device_id: byId("device-id").value.trim(),
      }),
    }, false);
    bearerToken = result.access_token;
    byId("password").value = "";
    text(byId("login-status"), "");
    showAuthenticated(result.principal);
    await refreshSnapshot();
    toast(`Welcome, ${result.principal.display_name}. Secure session active.`);
  } catch (error) {
    text(byId("login-status"), error.message);
  } finally {
    submit.disabled = false;
  }
}

async function logout() {
  try {
    if (bearerToken) await api("/auth/logout", { method: "POST" });
  } catch (_error) {
    // A contained or expired session is already unusable, which is the desired state.
  }
  endBrowserSession("Session ended safely. Sign in again when ready.");
  toast("Session token revoked.");
}

async function refreshSnapshot() {
  if (!bearerToken) return;
  try {
    currentSnapshot = await api("/dashboard/snapshot");
    renderSnapshot(currentSnapshot);
  } catch (error) {
    toast(error.message, true);
  }
}

function renderSnapshot(snapshot) {
  const { metrics, platform, principal } = snapshot;
  text(byId("metric-active"), metrics.active_keys);
  text(byId("metric-locked"), metrics.locked_keys);
  text(byId("metric-alerts"), metrics.critical_alerts);
  text(byId("metric-events"), metrics.audited_events);
  text(byId("platform-host"), platform.host);
  text(byId("platform-arch"), platform.architecture);
  text(byId("platform-crypto"), platform.crypto_backend);
  text(byId("platform-model"), platform.model);
  text(byId("platform-vault"), platform.vault_persistence);
  showAuthenticated(principal);
  renderKeys(snapshot.keys);
  renderAlerts(snapshot.alerts);
  renderEvents(snapshot.events);

  const activeKem = snapshot.keys.find((key) => key.algorithm === "ML-KEM-768" && key.status === "active");
  if (activeKem) currentKemKey = activeKem.key_id;
  byId("attack-demo-button").disabled = !currentKemKey;
}

function renderKeys(keys) {
  const list = byId("keys-list");
  list.replaceChildren();
  if (!keys.length) {
    list.append(make("p", "muted-row", "No managed keys yet. Run the normal journey."));
    return;
  }
  keys.slice().reverse().slice(0, 8).forEach((key) => {
    const item = make("article", "stack-item");
    const head = make("div", "stack-head");
    head.append(make("strong", "", key.key_id));
    head.append(make("span", `status-pill ${key.status}`, key.status.toUpperCase()));
    item.append(head, make("p", "", `${key.algorithm} · created ${formatTime(key.created_at)}`));
    list.append(item);
  });
}

function renderAlerts(alerts) {
  const list = byId("alerts-list");
  list.replaceChildren();
  if (!alerts.length) {
    list.append(make("p", "muted-row", "No critical alerts. System is monitoring."));
    return;
  }
  alerts.slice(0, 6).forEach((alert) => {
    const item = make("article", "stack-item");
    const head = make("div", "stack-head");
    head.append(make("strong", "", alert.summary));
    head.append(make("span", "status-pill contain", alert.severity.toUpperCase()));
    item.append(head, make("p", "", `${formatTime(alert.created_at)} · ${shortId(alert.correlation_id)}`));
    list.append(item);
  });
}

function renderEvents(events) {
  const body = byId("events-body");
  body.replaceChildren();
  if (!events.length) {
    const row = make("tr", "");
    const cell = make("td", "muted-row", "No evidence recorded yet.");
    cell.colSpan = 6;
    row.append(cell);
    body.append(row);
    return;
  }
  events.slice(0, 18).forEach((event) => {
    const row = make("tr", "");
    row.append(make("td", "", formatTime(event.occurred_at)));

    const action = make("td", "");
    action.append(make("span", "event-main", event.action));
    action.append(make("span", "event-sub", shortId(event.correlation_id)));
    row.append(action);

    const effectValue = event.policy_effect || event.outcome;
    const decision = make("td", "");
    decision.append(make("span", `effect ${effectValue}`, effectValue.toUpperCase()));
    row.append(decision);

    const risk = make("td", "");
    const score = event.risk_score == null ? 0 : event.risk_score;
    risk.append(make("code", "", event.risk_score == null ? "—" : `${Math.round(score * 100)}%`));
    const bar = make("div", "risk-bar");
    const fill = make("i", "");
    const riskBucket = Math.round(Math.min(1, Math.max(0, score)) * 10);
    fill.className = `risk-level-${riskBucket}`;
    bar.append(fill);
    risk.append(bar);
    row.append(risk);

    const signal = event.triggered_rules[0] || event.risk_signals[0] || event.reason_code || "—";
    row.append(make("td", "", signal));
    row.append(make("td", "", event.key_id || "—"));
    body.append(row);
  });
}

function startDemo(label) {
  const list = byId("demo-steps");
  list.replaceChildren();
  setHidden(byId("demo-placeholder"), true);
  setHidden(list, false);
  text(byId("demo-state"), label);
  byId("demo-state").className = "status-pill neutral";
}

function addDemoStep(title, detail, result, danger = false) {
  const list = byId("demo-steps");
  const item = make("li", `demo-step ${danger ? "danger" : "success"}`);
  item.append(make("span", "step-index", String(list.children.length + 1).padStart(2, "0")));
  const copy = make("div", "");
  copy.append(make("b", "", title), make("small", "", detail));
  item.append(copy);
  const score = result?.risk_score == null ? "POLICY" : `${Math.round(result.risk_score * 100)}% RISK`;
  item.append(make("span", "risk-readout", score));
  list.append(item);
}

function assertExecuted(result, label) {
  if (!result.executed || result.effect !== "allow") {
    throw new Error(`${label} stopped by ${result.effect}: ${result.explanation}`);
  }
}

async function runNormalDemo() {
  const button = byId("normal-demo-button");
  setBusy(button, true, "Running live journey…");
  byId("attack-demo-button").disabled = true;
  startDemo("RUNNING");
  const suffix = Date.now().toString(36).slice(-7);
  const signingKey = `judge-sign-${suffix}`;
  const kemKey = `judge-kem-${suffix}`;
  const message = "IBM Z Datathon approval record";

  try {
    const dsa = await api("/keys", { method: "POST", body: JSON.stringify({ key_id: signingKey, algorithm: "ML-DSA-65" }) });
    assertExecuted(dsa, "ML-DSA key creation");
    addDemoStep("ML-DSA-65 key generated", "Private material remained inside the LinuxONE vault boundary.", dsa);

    const signed = await api(`/keys/${encodeURIComponent(signingKey)}/sign`, { method: "POST", body: JSON.stringify({ message }) });
    assertExecuted(signed, "Signing");
    addDemoStep("Transaction signed", "A post-quantum signature was produced without exporting the private key.", signed);

    const verified = await api(`/keys/${encodeURIComponent(signingKey)}/verify`, {
      method: "POST",
      body: JSON.stringify({ message, signature_b64: signed.output.signature_b64 }),
    });
    assertExecuted(verified, "Verification");
    if (!verified.output.valid) throw new Error("Signature verification returned false.");
    addDemoStep("Signature verified", "The original message and signature match.", verified);

    const kem = await api("/keys", { method: "POST", body: JSON.stringify({ key_id: kemKey, algorithm: "ML-KEM-768" }) });
    assertExecuted(kem, "ML-KEM key creation");
    addDemoStep("ML-KEM-768 key generated", "Quantum-safe key establishment is ready.", kem);

    const protectedPayload = await api(`/keys/${encodeURIComponent(kemKey)}/protect`, {
      method: "POST",
      body: JSON.stringify({ plaintext: "Confidential judge demonstration payload", context: "ibm-z-datathon" }),
    });
    assertExecuted(protectedPayload, "Payload protection");
    if (!protectedPayload.output.roundtrip_verified) throw new Error("Protected payload round-trip failed.");
    addDemoStep("Payload protected end-to-end", "ML-KEM shared secret → HKDF-SHA256 → AES-256-GCM. Round-trip verified.", protectedPayload);

    currentKemKey = kemKey;
    text(byId("demo-state"), "NORMAL / ALLOW");
    byId("demo-state").className = "status-pill allow";
    await refreshSnapshot();
    byId("attack-demo-button").disabled = false;
    toast("Normal quantum-safe journey completed on the live backend.");
  } catch (error) {
    text(byId("demo-state"), "STOPPED");
    byId("demo-state").className = "status-pill challenge";
    addDemoStep("Journey stopped safely", error.message, null, true);
    toast(error.message, true);
  } finally {
    setBusy(button, false, "Run normal journey");
    button.disabled = !bearerToken;
  }
}

async function runAttackDemo() {
  if (!currentKemKey) {
    toast("Run the normal journey first to create an active target key.", true);
    return;
  }
  const button = byId("attack-demo-button");
  setBusy(button, true, "Attempting theft…");
  startDemo("ATTACK DETECTED");
  try {
    addDemoStep("Private-key export requested", `Target: ${currentKemKey}. The request enters policy and AI scoring, not the vault.`, null, true);
    const result = await api("/demo/attempt", {
      method: "POST",
      body: JSON.stringify({ action: "EXPORT_PRIVATE_KEY", key_id: currentKemKey, algorithm: "ML-KEM-768" }),
    });
    if (result.effect !== "contain" || result.executed) throw new Error("Expected containment did not occur.");
    addDemoStep("Hard rule blocked execution", `${result.triggered_rules.join(", ")} · ${result.explanation}`, result, true);
    addDemoStep("Automated containment committed", "Session revoked, token destroyed, key locked, critical alert and immutable evidence created.", result, true);
    text(byId("demo-state"), "CONTAINED");
    byId("demo-state").className = "status-pill contain";

    if (currentSnapshot) {
      const key = currentSnapshot.keys.find((item) => item.key_id === currentKemKey);
      if (key) key.status = "locked";
      currentSnapshot.metrics.locked_keys += key ? 1 : 0;
      currentSnapshot.metrics.active_keys -= key ? 1 : 0;
      currentSnapshot.metrics.critical_alerts += 1;
      renderKeys(currentSnapshot.keys);
      text(byId("metric-active"), Math.max(0, currentSnapshot.metrics.active_keys));
      text(byId("metric-locked"), currentSnapshot.metrics.locked_keys);
      text(byId("metric-alerts"), currentSnapshot.metrics.critical_alerts);
    }
    endBrowserSession("Attack contained. Your revoked session proves the response worked—sign in again to inspect evidence.");
    toast("Threat contained: key locked and session revoked.");
  } catch (error) {
    text(byId("demo-state"), "ERROR");
    byId("demo-state").className = "status-pill challenge";
    toast(error.message, true);
  } finally {
    setBusy(button, false, "Simulate key theft");
    button.disabled = !bearerToken || !currentKemKey;
  }
}

function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString([], { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function shortId(value) {
  if (!value) return "—";
  return value.length > 18 ? `${value.slice(0, 18)}…` : value;
}

byId("login-form").addEventListener("submit", login);
byId("logout-button").addEventListener("click", logout);
byId("refresh-button").addEventListener("click", refreshSnapshot);
byId("normal-demo-button").addEventListener("click", runNormalDemo);
byId("attack-demo-button").addEventListener("click", runAttackDemo);
