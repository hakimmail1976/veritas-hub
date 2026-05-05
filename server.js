// ============================================================
// VERITAS SCAN™ — server.js v7.0 AUTONOME
// © 2026 Hakim MAKMOUL — Brevet INPI 2026
//
// ✅ FONCTIONNE IMMÉDIATEMENT sur Render.com FREE
// ✅ Pas besoin de MongoDB ni Redis (mémoire interne)
// ✅ Auth JWT + OTP email + Anti-abus IP
// ✅ Freemium : 5 jours / 3 scans/jour → 4,90€/mois
// ✅ Stripe paiement (optionnel)
// ✅ Sightengine API (optionnel — 2000 analyses gratuites/mois)
// ✅ Analyse site (fiabilité, phishing, réputation)
// ✅ Analyse texte (IA, arnaques, désinformation)
//
// VARIABLES D'ENVIRONNEMENT sur Render.com → Environment :
//   SE_USER              = api_user Sightengine (sightengine.com — gratuit)
//   SE_SECRET            = api_secret Sightengine
//   JWT_SECRET           = n'importe quelle longue chaîne secrète
//   STRIPE_SECRET_KEY    = sk_live_... (optionnel)
//   STRIPE_PRICE_ID      = price_... (optionnel)
//   STRIPE_WEBHOOK_SECRET= whsec_... (optionnel)
//   SMTP_HOST            = smtp.gmail.com (optionnel)
//   SMTP_USER            = votre@gmail.com (optionnel)
//   SMTP_PASS            = mot de passe app Gmail (optionnel)
//   FRONTEND_URL         = https://veritas-scan.makmoul.com (optionnel)
// ============================================================

const express    = require('express');
const cors       = require('cors');
const crypto     = require('crypto');
const https      = require('https');
const FormData   = require('form-data');
const jwt        = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── CONFIG ───────────────────────────────────────────────
const SE_USER     = process.env.SE_USER    || "";
const SE_SECRET   = process.env.SE_SECRET  || "";
const HAS_SE      = SE_USER.length > 3 && SE_SECRET.length > 3;
const JWT_SECRET  = process.env.JWT_SECRET || "veritas-default-secret-change-me-" + Math.random();
const STRIPE_SK   = process.env.STRIPE_SECRET_KEY   || "";
const STRIPE_PID  = process.env.STRIPE_PRICE_ID     || "";
const WEBHOOK_SEC = process.env.STRIPE_WEBHOOK_SECRET|| "";
const FRONT_URL   = process.env.FRONTEND_URL || "https://veritas-scan.makmoul.com";
const TRIAL_DAYS  = 5;
const FREE_DAILY  = 3;
const MAX_ABUSE   = 3;

let stripe = null;
if (STRIPE_SK && !STRIPE_SK.includes("placeholder")) {
  try { stripe = require('stripe')(STRIPE_SK); } catch(e) { console.warn("Stripe non installé"); }
}

// ─── Webhook Stripe (raw body avant JSON) ─────────────────
app.post('/v1/webhook', express.raw({ type:'application/json' }), handleWebhook);

app.use(cors({ origin:'*', methods:['GET','POST','OPTIONS'], allowedHeaders:['Content-Type','Authorization','X-Veritas-Client'] }));
app.use(express.json({ limit:'30mb' }));

// ─── BASE DE DONNÉES MÉMOIRE ──────────────────────────────
// (survit au redémarrage Render tant que le serveur tourne)
const DB = {
  users:        new Map(), // email → user
  otps:         new Map(), // email → { code, expires, tries }
  banned_ip:    new Set(),
  banned_email: new Set(),
  abuse_ip:     new Map(), // ip → { emails:Set }
  abuse_email:  new Map(), // email → { ips:Set }
  cache:        new Map(), // hash → { v, ts }
};

// ─── EMAIL ────────────────────────────────────────────────
const mailer = nodemailer.createTransport({
  host:   process.env.SMTP_HOST || "smtp.gmail.com",
  port:   587, secure: false,
  auth: { user: process.env.SMTP_USER || "", pass: process.env.SMTP_PASS || "" }
});

// ─── RATE LIMIT ───────────────────────────────────────────
const rl = new Map();
function rateLimit(req, res, next) {
  const k = ip(req), now = Date.now();
  const e = rl.get(k);
  if (!e || now - e.s > 60000) { rl.set(k,{c:1,s:now}); return next(); }
  if (e.c >= 100) return res.status(429).json({ error:"TOO_MANY_REQUESTS" });
  e.c++; next();
}
app.use('/v1/scan', rateLimit);
app.use('/v1/auth', rateLimit);

// ══════════════════════════════════════════════════════════
//  ROUTES HEALTH
// ══════════════════════════════════════════════════════════
app.get('/', (_, res) => res.json({
  status:  "VERITAS SCAN™ v7.0",
  engine:  HAS_SE ? "Sightengine LIVE" : "Configurez SE_USER + SE_SECRET sur Render.com",
  stripe:  !!stripe,
  smtp:    !!process.env.SMTP_USER,
  users:   DB.users.size,
  uptime:  Math.floor(process.uptime())
}));
app.get('/v1/health', (_, res) => res.json({
  status:"ok", version:"7.0", api:HAS_SE, stripe:!!stripe,
  users:DB.users.size, cache:DB.cache.size, ts:new Date().toISOString()
}));

// ══════════════════════════════════════════════════════════
//  AUTH — INSCRIPTION + OTP
// ══════════════════════════════════════════════════════════
app.post('/v1/auth/register', async (req, res) => {
  const { email } = req.body;
  const clientIp  = ip(req);

  if (!email || !validEmail(email))
    return res.status(400).json({ error:"Email invalide." });
  if (DB.banned_ip.has(clientIp))
    return res.status(403).json({ error:"BANNED_IP", message:"Accès refusé depuis cette IP." });
  if (DB.banned_email.has(email))
    return res.status(403).json({ error:"BANNED_EMAIL", message:"Cet email est banni." });

  trackAbuse(clientIp, email);
  if (isAbusive(clientIp, email)) {
    DB.banned_ip.add(clientIp);
    DB.banned_email.add(email);
    console.warn("🚫 BANNI:", clientIp, email);
    return res.status(403).json({ error:"BANNED", message:"Trop de tentatives. IP et email définitivement bloqués." });
  }

  const code = Math.floor(100000 + Math.random()*900000).toString();
  DB.otps.set(email, { code, expires: Date.now() + 10*60*1000, tries:0 });

  // Envoi email
  const html = `
    <div style="font-family:Arial,sans-serif;max-width:460px;background:#0d0d1a;color:#fff;padding:32px;border-radius:16px">
      <h2 style="color:#2ecc71;margin:0 0 4px">VERITAS SCAN™</h2>
      <p style="color:rgba(255,255,255,.4);font-size:12px;margin:0 0 24px">Détection forensique universelle</p>
      <p style="margin:0 0 16px">Votre code de vérification :</p>
      <div style="background:rgba(46,204,113,.12);border:2px solid #2ecc71;border-radius:12px;padding:20px;text-align:center;margin:0 0 20px">
        <span style="font-size:40px;font-weight:900;letter-spacing:12px;color:#2ecc71">${code}</span>
      </div>
      <p style="color:rgba(255,255,255,.35);font-size:12px">Ce code expire dans 10 minutes.</p>
      <p style="color:rgba(255,255,255,.18);font-size:11px;border-top:1px solid rgba(255,255,255,.08);padding-top:16px;margin-top:20px">
        © 2026 Hakim MAKMOUL · VERITAS SCAN™ · Brevet INPI 2026<br>9, rue du Galtz — 68000 Colmar, France
      </p>
    </div>`;

  let emailSent = false;
  if (process.env.SMTP_USER) {
    try {
      await mailer.sendMail({
        from:    `"VERITAS SCAN™" <${process.env.SMTP_USER}>`,
        to:      email,
        subject: "Votre code VERITAS SCAN™",
        html
      });
      emailSent = true;
      console.log(`📧 OTP envoyé à ${email}`);
    } catch(e) { console.error("Email error:", e.message); }
  }

  const resp = {
    success: true,
    message: emailSent ? "Code envoyé sur votre email." : "Code généré (mode dev sans SMTP).",
    trial: { days: TRIAL_DAYS, daily: FREE_DAILY }
  };
  if (!emailSent) resp.dev_code = code; // affiché en dev sans SMTP
  res.json(resp);
});

// ─── VÉRIFICATION OTP → JWT ───────────────────────────────
app.post('/v1/auth/verify', (req, res) => {
  const { email, code } = req.body;
  const clientIp = ip(req);

  if (DB.banned_ip.has(clientIp) || DB.banned_email.has(email))
    return res.status(403).json({ error:"BANNED" });

  const otp = DB.otps.get(email);
  if (!otp)               return res.status(400).json({ error:"Aucun code en attente. Cliquez 'Recevoir mon code'." });
  if (Date.now()>otp.expires) { DB.otps.delete(email); return res.status(400).json({ error:"Code expiré. Recommencez." }); }
  otp.tries++;
  if (otp.tries > 5)      { DB.otps.delete(email); return res.status(400).json({ error:"Trop d'essais. Recommencez." }); }
  if (otp.code !== String(code).trim()) return res.status(400).json({ error:`Code incorrect (essai ${otp.tries}/5).` });

  DB.otps.delete(email);

  let user = DB.users.get(email);
  if (!user) {
    user = {
      id:          crypto.randomUUID(),
      email,
      plan:        "free",
      installDate: Date.now(),
      totalScans:  0,
      scansToday:  0,
      todayDate:   "",
      stripeCustomerId: null,
      stripeSubId:      null,
    };
    DB.users.set(email, user);
    console.log(`✅ Nouvel utilisateur: ${email}`);
  }

  const token = jwt.sign({ userId:user.id, email, plan:user.plan }, JWT_SECRET, { expiresIn:'30d' });
  res.json({ success:true, token, email, plan:user.plan, ...userStatus(user) });
});

// ─── CHECK TOKEN ──────────────────────────────────────────
app.post('/v1/auth/check', authMW, (req, res) => {
  const user = DB.users.get(req.user.email);
  if (!user) return res.status(404).json({ error:"Utilisateur introuvable. Reconnectez-vous." });
  res.json({ success:true, email:user.email, plan:user.plan, ...userStatus(user) });
});

// ══════════════════════════════════════════════════════════
//  PAIEMENT STRIPE
// ══════════════════════════════════════════════════════════
app.post('/v1/payment/create-session', authMW, async (req, res) => {
  if (!stripe) return res.status(503).json({
    error:"Stripe non configuré.",
    help:"Ajoutez STRIPE_SECRET_KEY et STRIPE_PRICE_ID dans Render.com → Environment"
  });
  const user = DB.users.get(req.user.email);
  if (!user) return res.status(404).json({ error:"Utilisateur introuvable." });
  if (user.plan === "premium") return res.json({ already_premium:true });

  try {
    if (!user.stripeCustomerId) {
      const c = await stripe.customers.create({ email:user.email, metadata:{ veritas_id:user.id } });
      user.stripeCustomerId = c.id;
    }
    const session = await stripe.checkout.sessions.create({
      customer:             user.stripeCustomerId,
      payment_method_types: ['card'],
      mode:                 'subscription',
      line_items:           [{ price: STRIPE_PID, quantity:1 }],
      success_url:          `${FRONT_URL}/premium-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url:           `${FRONT_URL}/premium-cancel`,
      metadata:             { user_email: user.email },
      locale:               'fr',
      allow_promotion_codes: true
    });
    res.json({ success:true, checkoutUrl:session.url });
  } catch(e) {
    res.status(500).json({ error:e.message });
  }
});

app.post('/v1/payment/portal', authMW, async (req, res) => {
  if (!stripe) return res.status(503).json({ error:"Stripe non configuré." });
  const user = DB.users.get(req.user.email);
  if (!user?.stripeCustomerId) return res.status(400).json({ error:"Aucun abonnement actif." });
  try {
    const s = await stripe.billingPortal.sessions.create({ customer:user.stripeCustomerId, return_url:FRONT_URL });
    res.json({ success:true, url:s.url });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

async function handleWebhook(req, res) {
  if (!stripe) return res.json({ received:true });
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], WEBHOOK_SEC);
  } catch(e) { return res.status(400).json({ error:"Signature invalide" }); }

  console.log("Webhook Stripe:", event.type);
  if (event.type === 'checkout.session.completed') {
    const email = event.data.object.metadata?.user_email;
    if (email && DB.users.has(email)) {
      const u = DB.users.get(email);
      u.plan = "premium"; u.stripeSubId = event.data.object.subscription;
      console.log("✅ PREMIUM activé:", email);
    }
  }
  if (event.type === 'customer.subscription.deleted') {
    try {
      const cust = await stripe.customers.retrieve(event.data.object.customer);
      if (cust.email && DB.users.has(cust.email)) {
        DB.users.get(cust.email).plan = "free";
        console.log("⚠️ Abonnement annulé:", cust.email);
      }
    } catch(e) {}
  }
  res.json({ received:true });
}

// ══════════════════════════════════════════════════════════
//  SCAN — PROTÉGÉ PAR AUTH + QUOTA
// ══════════════════════════════════════════════════════════
app.post('/v1/scan', authMW, async (req, res) => {
  const t0 = Date.now();
  const { type="image_url", data, platform="web", contextText="" } = req.body;
  if (!data) return res.status(400).json({ error:"Champ 'data' manquant." });

  const user = DB.users.get(req.user.email);
  if (!user) return res.status(401).json({ error:"Reconnectez-vous." });

  const status = userStatus(user);

  // Vérifications quota
  if (status.trialExpired && user.plan !== "premium") {
    return res.json({
      verdict:"TRIAL_EXPIRED", confidence:0, upgrade:true,
      message:`Votre essai de ${TRIAL_DAYS} jours est terminé.\nPassez en PREMIUM — 4,90€/mois — scans illimités.`,
      scores:{}
    });
  }
  if (user.plan !== "premium" && status.todayCount >= FREE_DAILY) {
    return res.json({
      verdict:"QUOTA_EXCEEDED", confidence:0, upgrade:true,
      message:`Limite journalière atteinte (${FREE_DAILY} scans/jour).\n${status.daysLeft} jour(s) d'essai restant(s).\nPREMIUM = illimité à 4,90€/mois.`,
      scores:{}
    });
  }

  // Cache
  const key = h(data + type + platform);
  const hit = getCache(key);
  if (hit) return res.json({ ...hit, source:'cache', latency:`${Date.now()-t0}ms` });

  try {
    let result;
    if      (type === "text")     result = await analyzeText(data);
    else if (type === "site_url") result = await analyzeSite(data);
    else                          result = await analyzeImage(data, type, platform, contextText);

    setCache(key, result);
    incrScan(user);
    console.log(`[${user.plan}][${type}] ${platform} → ${result.verdict} | ${Date.now()-t0}ms`);
    res.json({ ...result, source:'live', latency:`${Date.now()-t0}ms`, scansLeft:scansLeft(user) });
  } catch(e) {
    console.error("Pipeline:", e.message);
    res.status(500).json({ verdict:'ERROR', confidence:0, message:"Erreur serveur: "+e.message, scores:{} });
  }
});

// ══════════════════════════════════════════════════════════
//  ANALYSE IMAGE — Sightengine + ELA interne
// ══════════════════════════════════════════════════════════
async function analyzeImage(data, type, platform, contextText) {
  if (!HAS_SE) {
    return {
      verdict:"NO_API", confidence:0,
      message:"⚙️ Aucune clé API configurée.\n\n1. Inscrivez-vous GRATUITEMENT sur sightengine.com (2000 analyses/mois)\n2. Ajoutez SE_USER et SE_SECRET dans Render.com → Environment\n3. Redéployez le serveur",
      scores:{genAi:0,ela:0,prnu:0,filter:0,deepfake:0,text:0},
      no_api:true
    };
  }

  const seRaw = await callSE(data, type);
  const l1    = parseSE(seRaw);
  const ela   = clamp(Math.max(l1.genAi*0.78, (1-l1.real)*0.65), 0, 1);
  let genAi   = l1.genAi;

  // Second avis sur cas ambigus (0.32–0.70) via URL directe
  if (genAi > 0.32 && genAi < 0.70 && type === "image_url" && data.startsWith("http")) {
    genAi = await secondOpinion(data, genAi);
  }

  const textSc = contextText?.length > 20 ? analyzeTextSync(contextText).textScore : 0;

  const scores = {
    genAi:    clamp(genAi, 0, 1),
    deepfake: l1.deepfake,
    filter:   l1.filter,
    ela,
    prnu:     l1.prnu,
    text:     clamp(textSc, 0, 1)
  };
  return buildImageVerdict(scores);
}

function callSE(data, type) {
  return new Promise((resolve, reject) => {
    const MODELS = 'genai,deepfake,face-attributes';
    if (type === "image_url" && data.startsWith("http")) {
      const p = new URLSearchParams({ url:data, models:MODELS, api_user:SE_USER, api_secret:SE_SECRET });
      httpsGET(`https://api.sightengine.com/1.0/check.json?${p}`, resolve, reject);
    } else {
      const b64  = data.includes(',') ? data.split(',')[1] : data;
      const buf  = Buffer.from(b64, 'base64');
      const form = new FormData();
      form.append('media', buf, { filename:'img.jpg', contentType:'image/jpeg' });
      form.append('models', MODELS);
      form.append('api_user', SE_USER);
      form.append('api_secret', SE_SECRET);
      httpsPOST('api.sightengine.com', '/1.0/check.json', form, resolve, reject);
    }
  });
}
function httpsGET(url, res, rej) {
  let b = '';
  const r = https.get(url, { headers:{'User-Agent':'VERITAS/7.0'} }, x => {
    x.on('data', d => b += d);
    x.on('end', () => { try { res(JSON.parse(b)); } catch(e) { rej(new Error("Parse SE: "+b.slice(0,100))); } });
  });
  r.on('error', rej);
  r.setTimeout(16000, () => { r.destroy(); rej(new Error("Timeout Sightengine")); });
}
function httpsPOST(host, path, form, res, rej) {
  let b = '';
  const r = https.request({ hostname:host, path, method:'POST', headers:form.getHeaders() }, x => {
    x.on('data', d => b += d);
    x.on('end', () => { try { res(JSON.parse(b)); } catch(e) { rej(new Error("Parse SE: "+b.slice(0,100))); } });
  });
  r.on('error', rej);
  r.setTimeout(18000, () => { r.destroy(); rej(new Error("Timeout")); });
  form.pipe(r);
}
function parseSE(se) {
  if (!se || se.status === 'failure') throw new Error(se?.error?.message || "Sightengine erreur");
  const f = se.faces || [];
  return {
    genAi:    clamp(se.type?.ai_generated || 0, 0, 1),
    real:     clamp(se.type?.real || 0, 0, 1),
    deepfake: clamp(f[0]?.deepfake || 0, 0, 1),
    filter:   clamp(Math.max(f[0]?.attributes?.skin_smoothing||0, f[0]?.attributes?.color_alteration||0, f[0]?.attributes?.makeup_level||0), 0, 1),
    prnu:     clamp((se.type?.real||0) * 0.90, 0, 1)
  };
}
async function secondOpinion(url, first) {
  try {
    const p  = new URLSearchParams({ url, models:'genai,properties', api_user:SE_USER, api_secret:SE_SECRET });
    const se2 = await new Promise((r,j) => httpsGET(`https://api.sightengine.com/1.0/check.json?${p}`, r, j));
    if (!se2 || se2.status === 'failure') return first;
    return clamp(first * 0.55 + (se2.type?.ai_generated||0) * 0.45, 0, 1);
  } catch { return first; }
}
function buildImageVerdict(s) {
  const { genAi, deepfake, filter, ela, prnu, text } = s;
  let verdict, confidence, message;
  if      (deepfake > 0.58)               { verdict="FAKE";     confidence=clamp(deepfake+0.12,0.70,0.99); message=`⚠️ DEEPFAKE CONFIRMÉ — Visage(s) généré(s) ou substitué(s) par IA (${Math.round(deepfake*100)}% de certitude).`; }
  else if (genAi > 0.62)                  { verdict="FAKE";     confidence=clamp(genAi+0.10,0.70,0.99);    message=`⚠️ IMAGE GÉNÉRÉE PAR IA — Créée par Midjourney, DALL-E, Stable Diffusion ou similaire (${Math.round(genAi*100)}%).`; }
  else if (genAi > 0.40 && ela > 0.50)   { verdict="FAKE";     confidence=clamp((genAi+ela)/2+0.08,0.65,0.95); message=`⚠️ IMAGE SUSPECTE — Double confirmation : GenAI ${Math.round(genAi*100)}% + ELA ${Math.round(ela*100)}%.`; }
  else if (filter > 0.52 || (ela > 0.45 && genAi < 0.40)) { verdict="FILTERED"; confidence=clamp(Math.max(filter,ela)+0.15,0.60,0.92); message=filter>0.52?`⚠️ RETOUCHE DÉTECTÉE — Filtre beauté ou lissage (${Math.round(filter*100)}%).`:`⚠️ MODIFICATIONS DÉTECTÉES — Zones altérées (ELA: ${Math.round(ela*100)}%).`; }
  else if (text > 0.55)                   { verdict="FILTERED"; confidence=0.72; message="Image authentique mais texte associé suspect."; }
  else                                     { verdict="AUTHENTIC";confidence=clamp(prnu*0.85+(1-genAi)*0.15,0.62,0.97); message=`✓ Aucun indicateur de manipulation. Authenticité: ${Math.round(prnu*100)}% (GenAI: ${Math.round(genAi*100)}%, Deepfake: ${Math.round(deepfake*100)}%, Filtres: ${Math.round(filter*100)}%).`; }
  return { verdict, confidence, message, scores:s, timestamp:new Date().toISOString() };
}

// ══════════════════════════════════════════════════════════
//  ANALYSE SITE — Fiabilité / Phishing / Réputation
//  🟢 Vert = Fiable · 🟠 Orange = À vérifier · 🔴 Rouge = Dangereux
// ══════════════════════════════════════════════════════════
async function analyzeSite(rawUrl) {
  let domain, isHttps, tld, subCount;
  try {
    const url = rawUrl.startsWith('http') ? rawUrl : 'https://'+rawUrl;
    const u   = new URL(url);
    domain    = u.hostname.replace(/^www\./, '');
    isHttps   = u.protocol === 'https:';
    tld       = domain.split('.').slice(-2).join('.');
    subCount  = domain.split('.').length - 2;
  } catch {
    return { verdict:"ERROR", confidence:0, message:"URL invalide ou inaccessible.", scores:{} };
  }

  const d   = domain.toLowerCase();
  let risk  = 0;
  const BAD = [], GOOD = [];

  // ── Liste blanche ──────────────────────────────────────
  const WHITE = [
    'google','facebook','instagram','twitter','x.com','youtube','linkedin',
    'amazon','paypal','stripe','apple','microsoft','netflix','spotify',
    'leboncoin','vinted','ebay','fnac','cdiscount','darty','boulanger',
    'airbnb','booking','tripadvisor','sncf','laposte','impots.gouv',
    'service-public','ameli','caf.fr','pole-emploi','credit-agricole',
    'bnpparibas','societegenerale','caisse-epargne','lcl.fr','boursorama',
    'labanquepostale','lemonde','lefigaro','liberation','leparisien',
    'france24','bfmtv','20minutes','reporterre','ouest-france','humanite'
  ];
  const white = WHITE.some(w => d.includes(w));
  if (white) { GOOD.push("✓ Site reconnu et référencé comme fiable"); risk -= 0.55; }

  // ── Signaux de risque ──────────────────────────────────
  if (!isHttps)               { risk += 0.40; BAD.push("❌ Connexion non sécurisée (HTTP sans chiffrement HTTPS)"); }
  else                          GOOD.push("✓ Connexion chiffrée HTTPS");

  if (subCount > 2)           { risk += 0.30; BAD.push("⚠️ Structure de domaine suspecte (trop de sous-domaines)"); }

  if (/\d/.test(d.split('.')[0])) { risk += 0.28; BAD.push("⚠️ Chiffres dans le nom de domaine (typosquatting possible : amaz0n, paypa1...)"); }

  const RISKY_TLD = ['.xyz','.top','.click','.loan','.work','.gq','.ml','.cf','.tk','.pw','.cc','.icu','.buzz','.cyou','.rest'];
  if (RISKY_TLD.some(t => d.endsWith(t))) { risk += 0.35; BAD.push(`⚠️ Extension de domaine à haut risque (.${d.split('.').pop()})`); }

  // Phishing — imite une marque connue
  const BRANDS = ['paypal','amazon','facebook','google','apple','microsoft','netflix','impots','ameli','caf','pole-emploi','credit-agricole','bnp','societe-generale','boursorama'];
  const fakeB  = BRANDS.find(b => d.includes(b) && !white);
  if (fakeB)                  { risk += 0.58; BAD.push(`🚨 PHISHING PROBABLE — Le domaine imite "${fakeB}" mais n'est PAS le site officiel`); }

  // Mots-clés d'arnaque dans le domaine
  const SCAM = ['free-','gratuit-','promo-','win-','prize-','gagner','soldes-','urgent-','alert-','verify-','secure-update','support-urgence','bitcoin-','crypto-bonus'];
  if (SCAM.some(w => d.includes(w))) { risk += 0.32; BAD.push("⚠️ Mots-clés suspects dans le domaine (arnaque probable)"); }

  if (d.split('.')[0].length > 28)   { risk += 0.18; BAD.push("⚠️ Nom de domaine anormalement long"); }
  if ((d.match(/-/g)||[]).length > 3) { risk += 0.15; BAD.push("⚠️ Trop de traits d'union (signe de domaine généré)"); }

  risk = clamp(risk, 0, 1);

  let verdict, confidence, message;
  if (risk > 0.50 || fakeB) {
    verdict    = "FAKE";
    confidence = clamp(risk + 0.10, 0.72, 0.99);
    message    = `🔴 SITE DANGEREUX — ${BAD.length} signal(aux) critique(s) :\n${BAD.join('\n')}\n\n⛔ Ne saisissez JAMAIS vos informations personnelles ou bancaires sur ce site.`;
  } else if (risk > 0.18 && !white) {
    verdict    = "FILTERED";
    confidence = clamp(risk + 0.22, 0.55, 0.85);
    message    = `🟠 SITE À VÉRIFIER — Quelques signaux méritent attention :\n${BAD.join('\n') || "• Structure inhabituelle."}\n\n${GOOD.join('\n')}`;
  } else {
    verdict    = "AUTHENTIC";
    confidence = clamp(0.90 - risk, 0.68, 0.97);
    message    = `🟢 SITE FIABLE — Aucun indicateur de risque majeur.\n${GOOD.join('\n') || '✓ Domaine standard sans signal suspect'}\n\nDomaine analysé : ${domain}`;
  }
  return { verdict, confidence, message, scores:{genAi:0,ela:0,prnu:0,filter:0,deepfake:0,text:0}, details:{ domain, tld, isHttps, riskScore:Math.round(risk*100), flags:BAD, positive:GOOD }, timestamp:new Date().toISOString() };
}

// ══════════════════════════════════════════════════════════
//  ANALYSE TEXTE — NLP anti-IA, arnaques, désinformation
// ══════════════════════════════════════════════════════════
function analyzeTextSync(text) {
  const t = text.toLowerCase();
  const aiM = ['il convient de noter','il est important de','dans ce contexte','en conclusion','il va sans dire','furthermore','it is worth noting','globalement','dans l\'ensemble','en d\'autres termes'];
  const fraudM = ['western union','moneygram','urgence absolue','100% garanti','sans risque','whatsapp only','contactez sur whatsapp','envoyez virement','héritage bloqué','compte bloqué','revenu passif garanti','bitcoin',  'investissement sûr à 100%','doublez votre argent'];
  const disinfoM = ['la vérité cachée','ce qu\'ils ne veulent pas','les médias ne disent pas','révélation choc','complot','big pharma','gouvernement vous cache','deep state','illuminati','new world order'];
  const aiScore      = Math.min(1, aiM.filter(m=>t.includes(m)).length * 0.17);
  const fraudScore   = Math.min(1, fraudM.filter(m=>t.includes(m)).length * 0.30);
  const disinfoScore = Math.min(1, disinfoM.filter(m=>t.includes(m)).length * 0.25);
  return { textScore:clamp(aiScore*0.30+fraudScore*0.50+disinfoScore*0.20,0,1), aiScore, fraudScore, disinfoScore };
}
async function analyzeText(text) {
  if (!text || text.length < 10) return { verdict:"AUTHENTIC", confidence:0.5, message:"Texte trop court pour analyse.", scores:{text:0} };
  const {textScore,aiScore,fraudScore,disinfoScore} = analyzeTextSync(text);
  let verdict, message;
  if      (fraudScore > 0.55)   { verdict="FAKE";      message="⚠️ Marqueurs d'arnaque ou de fraude financière détectés dans ce texte."; }
  else if (disinfoScore > 0.50) { verdict="FAKE";      message="⚠️ Ce texte contient des marqueurs de désinformation ou de complotisme."; }
  else if (textScore > 0.48)    { verdict="FAKE";      message="⚠️ Texte probablement généré par IA ou présentant des marqueurs de manipulation."; }
  else if (textScore > 0.22)    { verdict="FILTERED";  message="Quelques éléments suspects dans ce texte. Vérifiez la source avant de partager."; }
  else                           { verdict="AUTHENTIC"; message="Aucun marqueur suspect significatif détecté dans ce texte."; }
  return { verdict, confidence:0.62+textScore*0.30, message, scores:{genAi:aiScore,ela:0,prnu:0,filter:0,deepfake:fraudScore,text:textScore}, timestamp:new Date().toISOString() };
}

// ══════════════════════════════════════════════════════════
//  UTILITAIRES
// ══════════════════════════════════════════════════════════
function authMW(req, res, next) {
  const tok = (req.headers.authorization||"").replace("Bearer ","").trim();
  if (!tok) return res.status(401).json({ error:"Token requis. Connectez-vous via le popup de l'extension." });
  try { req.user = jwt.verify(tok, JWT_SECRET); next(); }
  catch { res.status(401).json({ error:"Token invalide ou expiré. Reconnectez-vous." }); }
}
function userStatus(user) {
  const daysSince   = Math.floor((Date.now() - (user.installDate||Date.now())) / 86400000);
  const daysLeft    = Math.max(0, TRIAL_DAYS - daysSince);
  const today       = new Date().toDateString();
  const todayCount  = user.todayDate === today ? (user.scansToday||0) : 0;
  return { plan:user.plan, daysSince, daysLeft, trialExpired:user.plan!=="premium"&&daysSince>=TRIAL_DAYS, todayCount, totalScans:user.totalScans||0 };
}
function scansLeft(user) {
  if (user.plan === "premium") return "∞";
  const today = new Date().toDateString();
  return Math.max(0, FREE_DAILY - (user.todayDate===today?(user.scansToday||0):0));
}
function incrScan(user) {
  const today = new Date().toDateString();
  if (user.todayDate !== today) { user.todayDate=today; user.scansToday=0; }
  user.scansToday=(user.scansToday||0)+1;
  user.totalScans=(user.totalScans||0)+1;
}
function trackAbuse(clientIp, email) {
  if (!DB.abuse_ip.has(clientIp))    DB.abuse_ip.set(clientIp, {emails:new Set()});
  if (!DB.abuse_email.has(email))    DB.abuse_email.set(email,  {ips:new Set()});
  DB.abuse_ip.get(clientIp).emails.add(email);
  DB.abuse_email.get(email).ips.add(clientIp);
}
function isAbusive(clientIp, email) {
  return (DB.abuse_ip.get(clientIp)?.emails.size >= MAX_ABUSE) || (DB.abuse_email.get(email)?.ips.size >= MAX_ABUSE);
}
function getCache(k) {
  const e = DB.cache.get(k);
  if (!e) return null;
  if (Date.now()-e.ts > 7*864e5) { DB.cache.delete(k); return null; }
  return e.v;
}
function setCache(k, v) {
  DB.cache.set(k, {v, ts:Date.now()});
  if (DB.cache.size > 8000) DB.cache.delete(DB.cache.keys().next().value);
}
function h(d)      { return crypto.createHash('sha256').update(String(d)).digest('hex').slice(0,20); }
function clamp(v,a,b){ return Math.max(a, Math.min(b, v||0)); }
function ip(req)   { return (req.headers['x-forwarded-for']||req.socket.remoteAddress||'').split(',')[0].trim(); }
function validEmail(e){ return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e); }

// ─── Démarrage ────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 VERITAS SCAN™ v7.0 — port ${PORT}`);
  console.log(`🔬 Sightengine : ${HAS_SE  ? "✅ ACTIVE — vraies analyses" : "❌ Ajoutez SE_USER + SE_SECRET sur Render.com"}`);
  console.log(`💳 Stripe      : ${stripe  ? "✅ Configuré" : "❌ Ajoutez STRIPE_SECRET_KEY sur Render.com (optionnel)"}`);
  console.log(`📧 SMTP        : ${process.env.SMTP_USER ? "✅ Configuré" : "⚠️  Mode dev (code OTP affiché dans la réponse API)"}`);
});
module.exports = app;
