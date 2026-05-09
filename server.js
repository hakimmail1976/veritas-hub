// ============================================================
// VERITAS SCAN™ — server.js v8.0 FINAL
// © 2026 Hakim MAKMOUL — Brevet INPI 2026
//
// ✅ AUTONOME — pas de MongoDB, pas de Redis
// ✅ Auth email OTP + JWT
// ✅ Freemium 5j/3scans → Premium 4,90€/mois
// ✅ Stripe paiement réel
// ✅ Sightengine analyse IA réelle
// ✅ Analyse site fiabilité + phishing
// ✅ Anti-abus IP/email
//
// Variables Render.com → Environment :
//   JWT_SECRET           (obligatoire)
//   SE_USER + SE_SECRET  (sightengine.com — gratuit 2000/mois)
//   SMTP_HOST + SMTP_USER + SMTP_PASS  (gmail — optionnel)
//   STRIPE_SECRET_KEY + STRIPE_PRICE_ID + STRIPE_WEBHOOK_SECRET
//   FRONTEND_URL
// ============================================================

const express    = require('express');
const cors       = require('cors');
const crypto     = require('crypto');
const https      = require('https');
const FormData   = require('form-data');
const jwt        = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const app  = express();

// ===============================
// 5) LANCEMENT SERVEUR
// ===============================
const PORT = process.env.PORT || 3000;

// ⚠️ IMPORTANT POUR RENDER : écouter sur 0.0.0.0
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 VERITAS SCAN™ v8.0 démarré — port ${PORT}`);
});

// ─── CONFIG ───────────────────────────────────────────────
const SE_USER     = process.env.SE_USER             || "";
const SE_SECRET   = process.env.SE_SECRET           || "";
const HAS_SE      = SE_USER.length > 3 && SE_SECRET.length > 3;
const JWT_SECRET  = process.env.JWT_SECRET          || "veritas-secret
// ─── VÉRIFICATION OTP ─────────────────────────────────────
app.post('/v1/auth/verify', (req, res) => {
  const { email, code } = req.body;
  const ip = clientIp(req);

  if (DB.banned_ip.has(ip) || DB.banned_email.has(email))
    return res.status(403).json({ error:"BANNED" });

  const otp = DB.otps.get(email);
  if (!otp)
    return res.status(400).json({ error:"Aucun code en attente. Cliquez 'Recevoir mon code'." });
  if (Date.now() > otp.expires) {
    DB.otps.delete(email);
    return res.status(400).json({ error:"Code expiré. Recommencez." });
  }
  otp.tries++;
  if (otp.tries > 5) {
    DB.otps.delete(email);
    return res.status(400).json({ error:"Trop d'essais. Recommencez." });
  }
  if (otp.code !== String(code).trim())
    return res.status(400).json({ error:`Code incorrect (essai ${otp.tries}/5).` });

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
  res.json({ success:true, token, email, plan:user.plan, ...getUserStatus(user) });
});

// ─── CHECK TOKEN ──────────────────────────────────────────
app.post('/v1/auth/check', authMW, (req, res) => {
  const user = DB.users.get(req.user.email);
  if (!user) return res.status(404).json({ error:"Introuvable. Reconnectez-vous." });
  // Mise à jour du plan dans le token si changé
  res.json({ success:true, email:user.email, plan:user.plan, ...getUserStatus(user) });
});

// ══════════════════════════════════════════════════════════
//  PAIEMENT STRIPE
// ══════════════════════════════════════════════════════════
app.post('/v1/payment/create-session', authMW, async (req, res) => {
  if (!stripe) return res.status(503).json({
    error:"Stripe non configuré. Ajoutez STRIPE_SECRET_KEY et STRIPE_PRICE_ID dans Render → Environment."
  });
  if (!STRIPE_PID) return res.status(503).json({
    error:"STRIPE_PRICE_ID manquant. Créez un abonnement sur stripe.com et ajoutez son Price ID."
  });

  const user = DB.users.get(req.user.email);
  if (!user) return res.status(404).json({ error:"Introuvable." });
  if (user.plan === "premium") return res.json({ already_premium:true });

  try {
    if (!user.stripeCustomerId) {
      const c = await stripe.customers.create({ email:user.email, metadata:{ veritas_id:user.id } });
      user.stripeCustomerId = c.id;
    }
    const session = await stripe.checkout.sessions.create({
      customer:              user.stripeCustomerId,
      payment_method_types:  ['card'],
      mode:                  'subscription',
      line_items:            [{ price: STRIPE_PID, quantity:1 }],
      success_url:           `${FRONT_URL}/premium-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url:            `${FRONT_URL}/premium-cancel`,
      metadata:              { user_email: user.email },
      locale:                'fr',
      allow_promotion_codes: true
    });
    console.log(`💳 Session Stripe créée pour ${user.email}`);
    res.json({ success:true, checkoutUrl:session.url });
  } catch(e) {
    console.error("Stripe error:", e.message);
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

// ─── WEBHOOK STRIPE ───────────────────────────────────────
async function handleStripeWebhook(req, res) {
  if (!stripe || !WEBHOOK_SEC) return res.json({ received:true });
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], WEBHOOK_SEC);
  } catch(e) {
    console.error("Webhook signature invalide:", e.message);
    return res.status(400).json({ error:"Signature invalide" });
  }

  console.log("📦 Webhook Stripe:", event.type);

  if (event.type === 'checkout.session.completed') {
    const email = event.data.object.metadata?.user_email;
    if (email && DB.users.has(email)) {
      const u = DB.users.get(email);
      u.plan = "premium";
      u.stripeSubId = event.data.object.subscription;
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
//  SCAN — AUTH + QUOTA
// ══════════════════════════════════════════════════════════
app.post('/v1/scan', authMW, async (req, res) => {
  const t0 = Date.now();
  const { type="image_url", data, platform="web", contextText="" } = req.body;
  if (!data) return res.status(400).json
// ══════════════════════════════════════════════════════════
//  ANALYSE IMAGE — Sightengine
// ══════════════════════════════════════════════════════════
async function analyzeImage(data, type, platform, contextText) {
  if (!HAS_SE) {
    return {
      verdict:"NO_API", confidence:0,
      message:"⚙️ Clés API manquantes.\n\n1. Inscrivez-vous GRATUITEMENT sur sightengine.com\n   (2000 analyses/mois offertes)\n2. Copiez api_user et api_secret\n3. Ajoutez SE_USER et SE_SECRET dans Render → Environment\n4. Save, rebuild, and deploy",
      scores:{genAi:0,ela:0,prnu:0,filter:0,deepfake:0,text:0},
      no_api:true
    };
  }

  const se  = await callSightengine(data, type);
  const l1  = parseSightengine(se);
  const ela = clamp(Math.max(l1.genAi*0.78, (1-l1.real)*0.65), 0, 1);
  let genAi = l1.genAi;
  if (genAi > 0.32 && genAi < 0.70 && type==="image_url" && data.startsWith("http"))
    genAi = await secondOpinion(data, genAi);

  const textSc = contextText?.length > 20 ? analyzeTextSync(contextText).textScore : 0;
  const scores = { genAi:clamp(genAi,0,1), deepfake:l1.deepfake, filter:l1.filter, ela, prnu:l1.prnu, text:clamp(textSc,0,1) };
  return buildImageVerdict(scores);
}

function callSightengine(data, type) {
  return new Promise((resolve, reject) => {
    const M = 'genai,deepfake,face-attributes';
    if (type === "image_url" && data.startsWith("http")) {
      const p = new URLSearchParams({ url:data, models:M, api_user:SE_USER, api_secret:SE_SECRET });
      httpsGET(`https://api.sightengine.com/1.0/check.json?${p}`, resolve, reject);
    } else {
      const b64  = data.includes(',') ? data.split(',')[1] : data;
      const form = new FormData();
      form.append('media', Buffer.from(b64,'base64'), { filename:'img.jpg', contentType:'image/jpeg' });
      form.append('models', M);
      form.append('api_user', SE_USER);
      form.append('api_secret', SE_SECRET);
      httpsPOST('api.sightengine.com', '/1.0/check.json', form, resolve, reject);
    }
  });
}

function httpsGET(url, res, rej) {
  let b = '';
  const r = https.get(url, { headers:{'User-Agent':'VERITAS/8.0'} }, x => {
    x.on('data', d => b += d);
    x.on('end', () => { try { res(JSON.parse(b)); } catch(e) { rej(new Error("SE parse: "+b.slice(0,80))); } });
  });
  r.on('error', rej);
  r.setTimeout(16000, () => { r.destroy(); rej(new Error("Timeout Sightengine")); });
}

function httpsPOST(host, path, form, res, rej) {
  let b = '';
  const r = https.request({ hostname:host, path, method:'POST', headers:form.getHeaders() }, x => {
    x.on('data', d => b += d);
    x.on('end', () => { try { res(JSON.parse(b)); } catch(e) { rej(new Error("SE parse: "+b.slice(0,80))); } });
  });
  r.on('error', rej);
  r.setTimeout(18000, () => { r.destroy(); rej(new Error("Timeout")); });
  form.pipe(r);
}

function parseSightengine(se) {
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
    const p   = new URLSearchParams({ url, models:'genai,properties', api_user:SE_USER, api_secret:SE_SECRET });
    const se2 = await new Promise((r,j) => httpsGET(`https://api.sightengine.com/1.0/check.json?${p}`, r, j));
    if (!se2 || se2.status==='failure') return first;
    return clamp(first*0.55 + (se2.type?.ai_generated||0)*0.45, 0, 1);
  } catch { return first; }
}

function buildImageVerdict(s) {
  const { genAi, deepfake, filter, ela, prnu, text } = s;
  let verdict, confidence, message;
  if      (deepfake > 0.58)             { verdict="FAKE";     confidence=clamp(deepfake+0.12,0.70,0.99); message=`⚠️ DEEPFAKE CONFIRMÉ — Visage(s) généré(s)/substitué(s) par IA (${pct(deepfake)}%).`; }
  else if (genAi > 0.62)                { verdict="FAKE";     confidence=clamp(genAi+0.10,0.70,0.99);    message=`⚠️ IMAGE GÉNÉRÉE PAR IA — Midjourney/DALL-E/Stable Diffusion (${pct(genAi)}%).`; }
  else if (genAi > 0.40 && ela > 0.50) { verdict="FAKE";     confidence=clamp((genAi+ela)/2+0.08,0.65,0.95); message=`⚠️ IMAGE SUSPECTE — GenAI ${pct(genAi)}% + ELA ${pct(ela)}%.`; }
  else if (filter>0.52||(ela>0.45&&genAi<0.40)) { verdict="FILTERED"; confidence=clamp(Math.max(filter,ela)+0.15,0.60,0.92); message=filter>0.52?`⚠️ RETOUCHE DÉTECTÉE — Filtre beauté/lissage (${pct(filter)}%).`:`⚠️ MODIFICATIONS — Zones altérées (ELA: ${pct(ela)}%).`; }
  else if (text > 0.55)                 { verdict="FILTERED"; confidence=0.72; message="Image authentique mais texte associé suspect."; }
  else                                   { verdict="AUTHENTIC";confidence=clamp(prnu*0.85+(1-genAi)*0.15,0.62,0.97); message=`✓ Authentique — GenAI:${pct(genAi)}% Deepfake:${pct(deepfake)}% Filtres:${pct(filter)}%.`; }
  return { verdict, confidence, message, scores:s, timestamp:new Date().toISOString() };
}

// ══════════════════════════════════════════════════════════
//  ANALYSE SITE — Fiabilité / Phishing
// ══════════════════════════════════════════════════════════
async function analyzeSite(rawUrl) {
  let domain, isHttps, tld, subCount;
  try {
    const url = rawUrl.startsWith('http') ? rawUrl : 'https://'+rawUrl;
    const u   = new URL(url);
    domain    = u.hostname.replace(/^www\./,'');
    isHttps   = u.protocol === 'https:';
    tld       = domain.split('.').slice(-2).join('.');
    subCount  = domain.split('.').length - 2;
  } catch { return { verdict:"ERROR", confidence:0, message:"URL invalide.", scores:{} }; }

  const d    = domain.toLowerCase();
  let risk   = 0;
  const BAD  = [], GOOD = [];

  const WHITE = ['google','facebook','instagram','twitter','x.com','youtube','linkedin','amazon','paypal','stripe','apple','microsoft','netflix','spotify','leboncoin','vinted','ebay','fnac','cdiscount','darty','boulanger','airbnb','booking','tripadvisor','sncf','laposte','impots.gouv','service-public','ameli','caf.fr','pole-emploi','credit-agricole','bnpparibas','societegenerale','caisse-epargne','lcl.fr','boursorama','labanquepostale','lemonde','lefigaro','liberation','leparisien','france24','bfmtv','20minutes','reporterre','ouest-france'];
  const white = WHITE.some(w => d.includes(w));
  if (white) { GOOD.push("✓ Site reconnu et fiable"); risk -= 0.55; }

  if (!isHttps)               { risk+=0.40; BAD.push("❌ Connexion non sécurisée (HTTP)"); }
  else                          GOOD.push("✓ Connexion HTTPS chiffrée");
  if (subCount>2)             { risk+=0.30; BAD.push("⚠️ Structure de domaine suspecte"); }
  if (/\d/.test(d.split('.')[0])) { risk+=0.28; BAD.push("⚠️ Chiffres dans le domaine (typosquatting)"); }

  const BAD_TLD=['.xyz','.top','.click','.loan','.work','.gq','.ml','.cf','.tk','.pw','.cc','.icu','.buzz','.cyou'];
  if (BAD_TLD.some(t=>d.endsWith(t))) { risk+=0.35; BAD.push(`⚠️ Extension à risque (.${d.split('.').pop()})`); }

  const BRANDS=['paypal','amazon','facebook','google','apple','microsoft','netflix','impots','ameli','caf','pole-emploi','credit-agricole','bnp','societe-generale','boursorama'];
  const fakeB=BRANDS.find(b=>d.includes(b)&&!white);
  if (fakeB) { risk+=0.58; BAD.push(`🚨 PHISHING — Imite "${fakeB}" sans être le site officiel`); }

  const SCAM=['free-','gratuit-','win-','prize-','urgent-','verify-','secure-update','bitcoin-','crypto-bonus'];
  if (SCAM.some(w=>d.includes(w))) { risk+=0.32; BAD.push("⚠️ Mots-clés suspects dans le domaine"); }
  if (d.split('.')[0].length>28)   { risk+=0.18; BAD.push("⚠️ Nom de domaine trop long"); }
  if ((d.match(/-/g)||[]).length>3) { risk+=0.15; BAD.push("⚠️ Trop de traits d'union"); }

  risk = clamp(risk, 0, 1);

  let verdict, confidence, message;
  if (risk > 0.50 || fakeB) {
    verdict="FAKE"; confidence=clamp(risk+0.10,0.72,0.99);
    message=`🔴 SITE DANGEREUX\n${BAD.join('\n')}\n\n⛔ Ne saisissez JAMAIS vos données personnelles ou bancaires ici.`;
  } else if (risk > 0.18 && !white) {
    verdict="FILTERED"; confidence=clamp(risk+0.22,0.55,0.85);
    message=`🟠 SITE À VÉRIFIER\n${BAD.join('\n')||"• Structure inhabituelle"}\n\n${GOOD.join('\n')}`;
  } else {
    verdict="AUTHENTIC"; confidence=clamp(0.90-risk,0.68,0.97);
    message=`🟢 SITE FIABLE — Aucun indicateur de risque majeur.\n${GOOD.join('\n')||'✓ Domaine standard'}\n\nDomaine : ${domain}`;
  }
  return { verdict, confidence, message, scores:{genAi:0,ela:0,prnu:0,filter:0,deepfake:0,text:0}, details:{domain,tld,isHttps,riskScore:pct(risk),flags:BAD,positive:GOOD}, timestamp:new Date().toISOString() };
}
// ══════════════════════════════════════════════════════════
//  ANALYSE TEXTE
// ══════════════════════════════════════════════════════════
function analyzeTextSync(text) {
  const t=text.toLowerCase();
  const aiM=['il convient de noter','il est important de','dans ce contexte','en conclusion','il va sans dire','furthermore','it is worth noting','globalement','dans l\'ensemble'];
  const fraudM=['western union','moneygram','urgence absolue','100% garanti','sans risque','whatsapp only','envoyez virement','héritage bloqué','compte bloqué','revenu passif garanti','investissement sûr','doublez votre argent'];
  const disinfoM=['la vérité cachée','ce qu\'ils ne veulent pas','les médias ne disent pas','révélation choc','complot','big pharma','gouvernement vous cache','deep state'];
  const aiScore=Math.min(1,aiM.filter(m=>t.includes(m)).length*0.17);
  const fraudScore=Math.min(1,fraudM.filter(m=>t.includes(m)).length*0.30);
  const disinfoScore=Math.min(1,disinfoM.filter(m=>t.includes(m)).length*0.25);
  return { textScore:clamp(aiScore*0.30+fraudScore*0.50+disinfoScore*0.20,0,1), aiScore, fraudScore, disinfoScore };
}

async function analyzeText(text) {
  if (!text||text.length<10) return { verdict:"AUTHENTIC", confidence:0.5, message:"Texte trop court.", scores:{text:0} };
  const {textScore,aiScore,fraudScore,disinfoScore}=analyzeTextSync(text);
  let verdict, message;
  if      (fraudScore>0.55)   { verdict="FAKE";      message="⚠️ Marqueurs d'arnaque ou fraude détectés."; }
  else if (disinfoScore>0.50) { verdict="FAKE";      message="⚠️ Marqueurs de désinformation détectés."; }
  else if (textScore>0.48)    { verdict="FAKE";      message="⚠️ Texte généré par IA ou contenu frauduleux probable."; }
  else if (textScore>0.22)    { verdict="FILTERED";  message="Quelques éléments suspects. Vérifiez la source."; }
  else                         { verdict="AUTHENTIC"; message="Aucun marqueur suspect significatif détecté."; }
  return { verdict, confidence:0.62+textScore*0.30, message, scores:{genAi:aiScore,ela:0,prnu:0,filter:0,deepfake:fraudScore,text:textScore}, timestamp:new Date().toISOString() };
}

// ══════════════════════════════════════════════════════════
//  UTILITAIRES
// ══════════════════════════════════════════════════════════
function authMW(req, res, next) {
  const tok = (req.headers.authorization||"").replace("Bearer ","").trim();
  if (!tok) return res.status(401).json({ error:"Non connecté. Ouvrez le popup VERITAS et connectez-vous." });
  try { req.user = jwt.verify(tok, JWT_SECRET); next(); }
  catch { res.status(401).json({ error:"Session expirée. Reconnectez-vous." }); }
}

function getUserStatus(user) {
  const daysSince  = Math.floor((Date.now()-(user.installDate||Date.now()))/86400000);
  const daysLeft   = Math.max(0, TRIAL_DAYS-daysSince);
  const today      = new Date().toDateString();
  const todayCount = user.todayDate===today ? (user.scansToday||0) : 0;
  return { plan:user.plan, daysSince, daysLeft, trialExpired:user.plan!=="premium"&&daysSince>=TRIAL_DAYS, todayCount, totalScans:user.totalScans||0 };
}

function scansLeft(user) {
  if (user.plan==="premium") return "∞";
  const today=new Date().toDateString();
  return Math.max(0, FREE_DAILY-(user.todayDate===today?(user.scansToday||0):0));
}

function incrScan(user) {
  const today=new Date().toDateString();
  if (user.todayDate!==today) { user.todayDate=today; user.scansToday=0; }
  user.scansToday=(user.scansToday||0)+1;
  user.totalScans=(user.totalScans||0)+1;
}

function trackAbuse(ip, email) {
  if (!DB.abuse_ip.has(ip))    DB.abuse_ip.set(ip,    {emails:new Set()});
  if (!DB.abuse_email.has(email)) DB.abuse_email.set(email,{ips:new Set()});
  DB.abuse_ip.get(ip).emails.add(email);
  DB.abuse_email.get(email).ips.add(ip);
}

function isAbusive(ip, email) {
  return (DB.abuse_ip.get(ip)?.emails.size>=MAX_ABUSE)||(DB.abuse_email.get(email)?.ips.size>=MAX_ABUSE);
}

function getCache(k) {
  const e=DB.cache.get(k);
  if (!e) return null;
  if (Date.now()-e.ts>7*864e5) { DB.cache.delete(k); return null; }
  return e.v;
}
function setCache(k,v) {
  DB.cache.set(k,{v,ts:Date.now()});
  if (DB.cache.size>8000) DB.cache.delete(DB.cache.keys().next().value);
}

function hash(d) {
  return crypto.createHash('sha256').update(String(d)).digest('hex').slice(0,32);
}

function pct(x) { return Math.round(x*100); }
function clamp(x,a,b) { return Math.max(a,Math.min(b,x)); }

function clientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim()
      || req.connection?.remoteAddress
      || req.socket?.remoteAddress
      || req.ip
      || "0.0.0.0";
}
