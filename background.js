// ============================================================
// VERITAS SCAN™ — background.js v8.0
// © 2026 Hakim MAKMOUL
// ⚙️ Changez SERVER_URL si votre Render a une autre adresse
// ============================================================

const rAPI = (typeof browser !== "undefined" ? browser : chrome);

// ▼ URL DE VOTRE SERVEUR RENDER — changez si besoin
const SERVER_URL  = "https://veritas-hub-1.onrender.com";
// ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

const API_SCAN    = SERVER_URL + "/v1/scan";
const API_HEALTH  = SERVER_URL + "/v1/health";
const API_REG     = SERVER_URL + "/v1/auth/register";
const API_VER     = SERVER_URL + "/v1/auth/verify";
const API_CHECK   = SERVER_URL + "/v1/auth/check";
const API_SESSION = SERVER_URL + "/v1/payment/create-session";
const TIMEOUT_MS  = 25000;
const TRIAL_DAYS  = 5;
const FREE_DAILY  = 3;

// ─── Installation ─────────────────────────────────────────
rAPI.runtime.onInstalled.addListener(() => {
  console.log("✅ VERITAS SCAN™ v8.0 — Serveur:", SERVER_URL);
  rAPI.contextMenus.create({ id:"vs-image", title:"🔍 VERITAS — Analyser cette image",          contexts:["image"]     });
  rAPI.contextMenus.create({ id:"vs-text",  title:"🔍 VERITAS — Analyser le texte sélectionné", contexts:["selection"] });
  rAPI.contextMenus.create({ id:"vs-page",  title:"🔍 VERITAS — Scanner toute la page",         contexts:["page"]      });
  rAPI.contextMenus.create({ id:"vs-link",  title:"🔍 VERITAS — Vérifier ce site/lien",         contexts:["link"]      });
  rAPI.storage.local.get(["installDate"], d => {
    if (!d.installDate) rAPI.storage.local.set({ installDate:Date.now(), scanCount:0, fakeCount:0, history:[] });
  });
  pingServer();
});

pingServer();
setInterval(pingServer, 13 * 60 * 1000); // keep-alive Render

function pingServer() {
  fetch(API_HEALTH, { signal: AbortSignal.timeout(20000) })
    .then(r => r.json())
    .then(d => console.log("🟢 Serveur OK | users:", d.users, "| api:", d.api))
    .catch(() => console.log("🟡 Serveur en démarrage (Render cold start ~20s)"));
}

// ─── Menus contextuels ────────────────────────────────────
rAPI.contextMenus.onClicked.addListener((info, tab) => {
  if (!tab?.id) return;
  if (info.menuItemId === "vs-image" && info.srcUrl)
    rAPI.tabs.sendMessage(tab.id, { action:"ctx-scan-image", imageUrl:info.srcUrl });
  if (info.menuItemId === "vs-text" && info.selectionText)
    rAPI.tabs.sendMessage(tab.id, { action:"ctx-scan-text", text:info.selectionText });
  if (info.menuItemId === "vs-page")
    rAPI.tabs.sendMessage(tab.id, { action:"scan-full-page" });
  if (info.menuItemId === "vs-link" && info.linkUrl)
    rAPI.tabs.sendMessage(tab.id, { action:"ctx-scan-site", url:info.linkUrl });
});

// ─── Messages ─────────────────────────────────────────────
rAPI.runtime.onMessage.addListener((req, sender, sendResponse) => {

  // Auth
  if (req.action === "auth-register") {
    authCall(API_REG, { email: req.email })
      .then(r => sendResponse(r)).catch(e => sendResponse({ error: e.message }));
    return true;
  }
  if (req.action === "auth-verify") {
    authCall(API_VER, { email: req.email, code: req.code })
      .then(r => {
        if (r.token) rAPI.storage.local.set({ vs_token: r.token, vs_email: r.email, vs_plan: r.plan });
        sendResponse(r);
      }).catch(e => sendResponse({ error: e.message }));
    return true;
  }
  if (req.action === "auth-check") {
    getStore(["vs_token"]).then(d => {
      if (!d.vs_token) return sendResponse({ error: "Non connecté" });
      return authCallWithToken(API_CHECK, {}, d.vs_token);
    }).then(r => r && sendResponse(r)).catch(e => sendResponse({ error: e.message }));
    return true;
  }
  if (req.action === "auth-logout") {
    rAPI.storage.local.remove(["vs_token","vs_email","vs_plan"], () => sendResponse({ ok:true }));
    return true;
  }
  if (req.action === "payment-session") {
    getStore(["vs_token"]).then(d => authCallWithToken(API_SESSION, {}, d.vs_token||""))
      .then(r => sendResponse(r)).catch(e => sendResponse({ error: e.message }));
    return true;
  }

  // Scans
  if (req.action === "scan-image-url") {
    scanWithAuth({ type:"image_url", data:req.imageUrl, platform:req.platform||"web", contextText:req.contextText||"" })
      .then(r => { afterScan(r); sendResponse({success:true, data:r}); })
      .catch(e => sendResponse({success:false, error:e.message}));
    return true;
  }
  if (req.action === "scan-image-data") {
    scanWithAuth({ type:"image_data", data:req.imageData, platform:req.platform||"web", contextText:req.contextText||"" })
      .then(r => { afterScan(r); sendResponse({success:true, data:r}); })
      .catch(e => sendResponse({success:false, error:e.message}));
    return true;
  }
  if (req.action === "scan-text") {
    scanWithAuth({ type:"text", data:req.text, platform:req.platform||"web" })
      .then(r => sendResponse({success:true, data:r}))
      .catch(e => sendResponse({success:false, error:e.message}));
    return true;
  }
  if (req.action === "scan-site") {
    scanWithAuth({ type:"site_url", data:req.url })
      .then(r => sendResponse({success:true, data:r}))
      .catch(e => sendResponse({success:false, error:e.message}));
    return true;
  }

  // Capture
  if (req.action === "capture-tab") {
    rAPI.tabs.captureVisibleTab(null, { format:"png", quality:90 }, dataUrl => {
      if (rAPI.runtime.lastError) sendResponse({success:false, error:rAPI.runtime.lastError.message});
      else sendResponse({success:true, dataUrl});
    });
    return true;
  }

  // Storage
  if (req.action === "get-stats") {
    Promise.all([getStore(["installDate","plan","todayDate","todayCount","scanCount","fakeCount"]), getStore(["vs_plan","vs_email"])])
      .then(([d, u]) => {
        const daysSince = Math.floor((Date.now()-(d.installDate||Date.now()))/86400000);
        const today     = new Date().toDateString();
        sendResponse({
          success:true,
          plan:         u.vs_plan || d.plan || "free",
          email:        u.vs_email || "",
          daysLeft:     Math.max(0, TRIAL_DAYS-daysSince),
          trialExpired: (u.vs_plan||d.plan||"free")==="free" && daysSince>=TRIAL_DAYS,
          todayCount:   d.todayDate===today?(d.todayCount||0):0,
          scanCount:    d.scanCount||0,
          fakeCount:    d.fakeCount||0,
          scansLeft:    Math.max(0, FREE_DAILY-(d.todayDate===today?(d.todayCount||0):0))
        });
      });
    return true;
  }
  if (req.action === "get-history") {
    rAPI.storage.local.get(["history"], d => sendResponse({success:true, history:d.history||[]}));
    return true;
  }
  if (req.action === "clear-history") {
    rAPI.storage.local.set({history:[]}, () => sendResponse({success:true}));
    return true;
  }
  if (req.action === "toggle-bubble") {
    sendResponse({success:true});
    return true;
  }
});

// ─── Appel API auth (sans token) ──────────────────────────
async function authCall(url, body) {
  const ctrl = new AbortController();
  const tid  = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const r = await fetch(url, {
      method:  "POST",
      headers: { "Content-Type":"application/json", "X-Veritas-Client":"ext-v8" },
      body:    JSON.stringify(body),
      signal:  ctrl.signal
    });
    clearTimeout(tid);
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      throw new Error(err.error || `HTTP ${r.status}`);
    }
    return await r.json();
  } catch(e) {
    clearTimeout(tid);
    if (e.name === "AbortError") throw new Error("Serveur inaccessible. Attendez 20s (Render cold start) et réessayez.");
    throw e;
  }
}

// ─── Appel API avec token JWT ─────────────────────────────
async function authCallWithToken(url, body, token) {
  const ctrl = new AbortController();
  const tid  = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const r = await fetch(url, {
      method:  "POST",
      headers: { "Content-Type":"application/json", "Authorization":"Bearer "+token, "X-Veritas-Client":"ext-v8" },
      body:    JSON.stringify(body),
      signal:  ctrl.signal
    });
    clearTimeout(tid);
    return await r.json();
  } catch(e) {
    clearTimeout(tid);
    throw new Error(e.name==="AbortError" ? "Serveur inaccessible (20s cold start)" : e.message);
  }
}

// ─── Scan avec token automatique ─────────────────────────
async function scanWithAuth(payload) {
  const d     = await getStore(["vs_token"]);
  const token = d.vs_token || "";
  if (!token) {
    return { verdict:"NOT_LOGGED", confidence:0, message:"Connectez-vous d'abord via le popup VERITAS SCAN™.", scores:{} };
  }
  return authCallWithToken(API_SCAN, payload, token).catch(() => ({
    verdict:"SERVER_OFFLINE", confidence:0,
    message:`⚙️ Serveur inaccessible.\n→ Attendez 20s et réessayez (Render cold start)\n→ Vérifiez : ${API_HEALTH}`,
    scores:{}, source:"offline"
  }));
}

function afterScan(r) {
  if (!r) return;
  const today = new Date().toDateString();
  getStore(["todayDate","todayCount","scanCount","fakeCount"]).then(d => {
    rAPI.storage.local.set({
      todayDate:  today,
      todayCount: d.todayDate===today?(d.todayCount||0)+1:1,
      scanCount:  (d.scanCount||0)+1,
      fakeCount:  (d.fakeCount||0)+(r.verdict==="FAKE"?1:0)
    });
  });
  getStore(["history"]).then(d => {
    const h = d.history || [];
    h.unshift({ type:"scan", result:r, id:Date.now(), timestamp:new Date().toISOString() });
    rAPI.storage.local.set({ history: h.slice(0,100) });
  });
  setBadge(r.verdict);
}

function setBadge(verdict) {
  const map = { AUTHENTIC:"✓", FILTERED:"!", FAKE:"✗", QUOTA_EXCEEDED:"🔒", TRIAL_EXPIRED:"🔒", SERVER_OFFLINE:"…", NOT_LOGGED:"?" };
  const col = { AUTHENTIC:"#00b894", FILTERED:"#e67e22", FAKE:"#c0392b", QUOTA_EXCEEDED:"#6c5ce7", TRIAL_EXPIRED:"#6c5ce7", SERVER_OFFLINE:"#636e72", NOT_LOGGED:"#636e72" };
  const txt = map[verdict]||"", bg = col[verdict]||"#636e72";
  try { rAPI.browserAction.setBadgeText({text:txt}); rAPI.browserAction.setBadgeBackgroundColor({color:bg}); setTimeout(()=>rAPI.browserAction.setBadgeText({text:""}),6000); } catch(e) {}
  try { rAPI.action.setBadgeText({text:txt}); rAPI.action.setBadgeBackgroundColor({color:bg}); setTimeout(()=>rAPI.action.setBadgeText({text:""}),6000); } catch(e) {}
}

function getStore(keys) {
  return new Promise(resolve => rAPI.storage.local.get(keys, resolve));
}

console.log("🌐 VERITAS SCAN™ v8.0 | Serveur:", SERVER_URL);
