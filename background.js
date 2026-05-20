// VERITAS SCAN™ — background.js v8.0 © 2026 Hakim MAKMOUL
const rAPI = (typeof browser !== "undefined" ? browser : chrome);

// ▼ URL SERVEUR RENDER — correcte avec le -1
const SERVER_URL  = "https://veritas-hub-1.onrender.com";

const API_SCAN    = SERVER_URL + "/v1/scan";
const API_HEALTH  = SERVER_URL + "/v1/health";
const API_REG     = SERVER_URL + "/v1/auth/register";
const API_VER     = SERVER_URL + "/v1/auth/verify";
const API_CHECK   = SERVER_URL + "/v1/auth/check";
const API_SESSION = SERVER_URL + "/v1/payment/create-session";
const TIMEOUT_MS  = 25000;
const TRIAL_DAYS  = 5;
const FREE_DAILY  = 3;

rAPI.runtime.onInstalled.addListener(function() {
  console.log("VERITAS SCAN v8.0 — Serveur:", SERVER_URL);
  rAPI.contextMenus.create({ id:"vs-image", title:"Analyser cette image",          contexts:["image"]     });
  rAPI.contextMenus.create({ id:"vs-text",  title:"Analyser le texte selectionne", contexts:["selection"] });
  rAPI.contextMenus.create({ id:"vs-page",  title:"Scanner toute la page",         contexts:["page"]      });
  rAPI.contextMenus.create({ id:"vs-link",  title:"Verifier ce site/lien",         contexts:["link"]      });
  rAPI.storage.local.get(["installDate"], function(d) {
    if (!d.installDate) rAPI.storage.local.set({ installDate: Date.now(), scanCount: 0, fakeCount: 0, history: [] });
  });
  pingServer();
});

// Keep-alive Render — ping toutes les 10 minutes
function pingServer() {
  fetch(API_HEALTH, { signal: AbortSignal.timeout(20000) })
    .then(function(r) { return r.json(); })
    .then(function(d) { console.log("Serveur OK | users:", d.users, "| api:", d.api); })
    .catch(function() { console.log("Serveur en demarrage (Render cold start ~20s)"); });
}
pingServer();
setInterval(pingServer, 10 * 60 * 1000);

// Menus contextuels
rAPI.contextMenus.onClicked.addListener(function(info, tab) {
  if (!tab || !tab.id) return;
  if (info.menuItemId === "vs-image" && info.srcUrl)
    rAPI.tabs.sendMessage(tab.id, { action:"ctx-scan-image", imageUrl: info.srcUrl });
  if (info.menuItemId === "vs-text" && info.selectionText)
    rAPI.tabs.sendMessage(tab.id, { action:"ctx-scan-text", text: info.selectionText });
  if (info.menuItemId === "vs-page")
    rAPI.tabs.sendMessage(tab.id, { action:"scan-full-page" });
  if (info.menuItemId === "vs-link" && info.linkUrl)
    rAPI.tabs.sendMessage(tab.id, { action:"ctx-scan-site", url: info.linkUrl });
});

// Messages
rAPI.runtime.onMessage.addListener(function(req, sender, sendResponse) {

  if (req.action === "auth-register") {
    authCall(API_REG, { email: req.email })
      .then(function(r) { sendResponse(r); })
      .catch(function(e) { sendResponse({ error: e.message }); });
    return true;
  }

  if (req.action === "auth-verify") {
    authCall(API_VER, { email: req.email, code: req.code })
      .then(function(r) {
        if (r.token) rAPI.storage.local.set({ vs_token: r.token, vs_email: r.email, vs_plan: r.plan });
        sendResponse(r);
      })
      .catch(function(e) { sendResponse({ error: e.message }); });
    return true;
  }

  if (req.action === "auth-check") {
    getStore(["vs_token"]).then(function(d) {
      if (!d.vs_token) { sendResponse({ error: "Non connecte" }); return; }
      return authCallWithToken(API_CHECK, {}, d.vs_token).then(function(r) { sendResponse(r); });
    }).catch(function(e) { sendResponse({ error: e.message }); });
    return true;
  }

  if (req.action === "auth-logout") {
    rAPI.storage.local.remove(["vs_token","vs_email","vs_plan"], function() { sendResponse({ ok: true }); });
    return true;
  }

  if (req.action === "payment-session") {
    getStore(["vs_token"]).then(function(d) {
      return authCallWithToken(API_SESSION, {}, d.vs_token || "");
    }).then(function(r) { sendResponse(r); }).catch(function(e) { sendResponse({ error: e.message }); });
    return true;
  }

  if (req.action === "scan-image-url") {
    scanWithAuth({ type:"image_url", data: req.imageUrl, platform: req.platform||"web", contextText: req.contextText||"" })
      .then(function(r) { afterScan(r); sendResponse({ success:true, data:r }); })
      .catch(function(e) { sendResponse({ success:false, error:e.message }); });
    return true;
  }

  if (req.action === "scan-image-data") {
    scanWithAuth({ type:"image_data", data: req.imageData, platform: req.platform||"web", contextText: req.contextText||"" })
      .then(function(r) { afterScan(r); sendResponse({ success:true, data:r }); })
      .catch(function(e) { sendResponse({ success:false, error:e.message }); });
    return true;
  }

  if (req.action === "scan-text") {
    scanWithAuth({ type:"text", data: req.text, platform: req.platform||"web" })
      .then(function(r) { sendResponse({ success:true, data:r }); })
      .catch(function(e) { sendResponse({ success:false, error:e.message }); });
    return true;
  }

  if (req.action === "scan-site") {
    scanWithAuth({ type:"site_url", data: req.url })
      .then(function(r) { sendResponse({ success:true, data:r }); })
      .catch(function(e) { sendResponse({ success:false, error:e.message }); });
    return true;
  }

  if (req.action === "capture-tab") {
    rAPI.tabs.captureVisibleTab(null, { format:"png", quality:90 }, function(dataUrl) {
      if (rAPI.runtime.lastError) sendResponse({ success:false, error:rAPI.runtime.lastError.message });
      else sendResponse({ success:true, dataUrl: dataUrl });
    });
    return true;
  }

  if (req.action === "get-stats") {
    Promise.all([
      getStore(["installDate","plan","todayDate","todayCount","scanCount","fakeCount"]),
      getStore(["vs_plan","vs_email"])
    ]).then(function(results) {
      var d = results[0], u = results[1];
      var daysSince = Math.floor((Date.now() - (d.installDate || Date.now())) / 86400000);
      var today     = new Date().toDateString();
      sendResponse({
        success:      true,
        plan:         u.vs_plan || d.plan || "free",
        email:        u.vs_email || "",
        daysLeft:     Math.max(0, TRIAL_DAYS - daysSince),
        trialExpired: (u.vs_plan || d.plan || "free") === "free" && daysSince >= TRIAL_DAYS,
        todayCount:   d.todayDate === today ? (d.todayCount || 0) : 0,
        scanCount:    d.scanCount || 0,
        fakeCount:    d.fakeCount || 0,
        scansLeft:    Math.max(0, FREE_DAILY - (d.todayDate === today ? (d.todayCount || 0) : 0))
      });
    });
    return true;
  }

  if (req.action === "get-history") {
    rAPI.storage.local.get(["history"], function(d) { sendResponse({ success:true, history: d.history || [] }); });
    return true;
  }

  if (req.action === "clear-history") {
    rAPI.storage.local.set({ history: [] }, function() { sendResponse({ success:true }); });
    return true;
  }

  if (req.action === "toggle-bubble") {
    sendResponse({ success:true });
    return true;
  }
});

// Appel API sans token
function authCall(url, body) {
  var ctrl = new AbortController();
  var tid  = setTimeout(function() { ctrl.abort(); }, TIMEOUT_MS);
  return fetch(url, {
    method:  "POST",
    headers: { "Content-Type":"application/json", "X-Veritas-Client":"ext-v8" },
    body:    JSON.stringify(body),
    signal:  ctrl.signal
  }).then(function(r) {
    clearTimeout(tid);
    return r.json().then(function(data) {
      if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
      return data;
    });
  }).catch(function(e) {
    clearTimeout(tid);
    if (e.name === "AbortError") throw new Error("Serveur inaccessible. Attendez 20s (Render cold start) et reessayez.");
    throw e;
  });
}

// Appel API avec token JWT
function authCallWithToken(url, body, token) {
  var ctrl = new AbortController();
  var tid  = setTimeout(function() { ctrl.abort(); }, TIMEOUT_MS);
  return fetch(url, {
    method:  "POST",
    headers: { "Content-Type":"application/json", "Authorization":"Bearer " + token, "X-Veritas-Client":"ext-v8" },
    body:    JSON.stringify(body),
    signal:  ctrl.signal
  }).then(function(r) {
    clearTimeout(tid);
    return r.json();
  }).catch(function(e) {
    clearTimeout(tid);
    throw new Error(e.name === "AbortError" ? "Serveur inaccessible (cold start 20s)" : e.message);
  });
}

// Scan avec token automatique
function scanWithAuth(payload) {
  return getStore(["vs_token"]).then(function(d) {
    var token = d.vs_token || "";
    if (!token) {
      return { verdict:"NOT_LOGGED", confidence:0, message:"Connectez-vous via le popup VERITAS.", scores:{} };
    }
    return authCallWithToken(API_SCAN, payload, token).catch(function() {
      return { verdict:"SERVER_OFFLINE", confidence:0, message:"Serveur inaccessible. Attendez 20s (Render cold start).", scores:{}, source:"offline" };
    });
  });
}

function afterScan(r) {
  if (!r) return;
  var today = new Date().toDateString();
  getStore(["todayDate","todayCount","scanCount","fakeCount"]).then(function(d) {
    rAPI.storage.local.set({
      todayDate:  today,
      todayCount: d.todayDate === today ? (d.todayCount || 0) + 1 : 1,
      scanCount:  (d.scanCount || 0) + 1,
      fakeCount:  (d.fakeCount || 0) + (r.verdict === "FAKE" ? 1 : 0)
    });
  });
  getStore(["history"]).then(function(d) {
    var h = d.history || [];
    h.unshift({ type:"scan", result:r, id:Date.now(), timestamp: new Date().toISOString() });
    rAPI.storage.local.set({ history: h.slice(0, 100) });
  });
  setBadge(r.verdict);
}

function setBadge(verdict) {
  var map = { AUTHENTIC:"V", FILTERED:"!", FAKE:"X", QUOTA_EXCEEDED:"#", TRIAL_EXPIRED:"#", SERVER_OFFLINE:".", NOT_LOGGED:"?" };
  var col = { AUTHENTIC:"#00b894", FILTERED:"#e67e22", FAKE:"#c0392b", QUOTA_EXCEEDED:"#6c5ce7", TRIAL_EXPIRED:"#6c5ce7", SERVER_OFFLINE:"#636e72", NOT_LOGGED:"#636e72" };
  var txt = map[verdict] || "", bg = col[verdict] || "#636e72";
  try { rAPI.browserAction.setBadgeText({ text:txt }); rAPI.browserAction.setBadgeBackgroundColor({ color:bg }); setTimeout(function() { rAPI.browserAction.setBadgeText({ text:"" }); }, 6000); } catch(e) {}
  try { rAPI.action.setBadgeText({ text:txt }); rAPI.action.setBadgeBackgroundColor({ color:bg }); setTimeout(function() { rAPI.action.setBadgeText({ text:"" }); }, 6000); } catch(e) {}
}

function getStore(keys) {
  return new Promise(function(resolve) { rAPI.storage.local.get(keys, resolve); });
}

console.log("VERITAS SCAN v8.0 | Serveur:", SERVER_URL);
