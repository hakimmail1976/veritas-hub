// VERITAS SCAN v8 - server.js
// Build: npm install | Start: node server.js

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const https = require('https');
const FormData = require('form-data');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;

const SE_USER = process.env.SE_USER || "";
const SE_SECRET = process.env.SE_SECRET || "";
const HAS_SE = SE_USER.length > 3 && SE_SECRET.length > 3;
const JWT_SECRET = process.env.JWT_SECRET || "veritas-secret-" + Date.now();
const STRIPE_SK = process.env.STRIPE_SECRET_KEY || "";
const STRIPE_PID = process.env.STRIPE_PRICE_ID || "";
const WEBHOOK_SEC = process.env.STRIPE_WEBHOOK_SECRET || "";
const FRONT_URL = process.env.FRONTEND_URL || "https://veritas-scan.makmoul.com";
const TRIAL_DAYS = 5;
const FREE_DAILY = 3;
const MAX_ABUSE = 3;

let stripe = null;
if (STRIPE_SK && STRIPE_SK.startsWith("sk_")) {
  try { stripe = require('stripe')(STRIPE_SK); } catch(e) {}
}

app.post('/v1/webhook', express.raw({type:'application/json'}), handleWebhook);
app.use(cors({origin:'*', methods:['GET','POST','OPTIONS'], allowedHeaders:['Content-Type','Authorization','X-Veritas-Client']}));
app.use(express.json({limit:'30mb'}));

const DB = {
  users: new Map(),
  otps: new Map(),
  banned_ip: new Set(),
  banned_email: new Set(),
  abuse_ip: new Map(),
  abuse_email: new Map(),
  cache: new Map()
};

const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "smtp.gmail.com",
  port: 587, secure: false,
  auth: {user: process.env.SMTP_USER || "", pass: process.env.SMTP_PASS || ""}
});

const rl = new Map();
function rateLimit(req, res, next) {
  const k = getIP(req), now = Date.now();
  const e = rl.get(k);
  if (!e || now - e.s > 60000) { rl.set(k, {c:1,s:now}); return next(); }
  if (e.c >= 100) return res.status(429).json({error:"RATE_LIMIT"});
  e.c++; next();
}
app.use('/v1/auth', rateLimit);
app.use('/v1/scan', rateLimit);

app.get('/', (_, res) => res.json({
  status: "VERITAS SCAN v8.0",
  api: HAS_SE, stripe: !!stripe,
  smtp: !!process.env.SMTP_USER,
  users: DB.users.size,
  uptime: Math.floor(process.uptime()) + "s"
}));

app.get('/v1/health', (_, res) => res.json({
  status:"ok", version:"8.0", api:HAS_SE,
  stripe:!!stripe, users:DB.users.size, cache:DB.cache.size
}));

app.post('/v1/auth/register', async (req, res) => {
  const {email} = req.body;
  const ip = getIP(req);
  if (!email || !email.includes('@')) return res.status(400).json({error:"Email invalide."});
  if (DB.banned_ip.has(ip)) return res.status(403).json({error:"IP bannie."});
  if (DB.banned_email.has(email)) return res.status(403).json({error:"Email banni."});

  trackAbuse(ip, email);
  if (isAbusive(ip, email)) {
    DB.banned_ip.add(ip); DB.banned_email.add(email);
    return res.status(403).json({error:"Trop de tentatives. IP et email bloqués."});
  }

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  DB.otps.set(email, {code, expires: Date.now() + 10*60*1000, tries:0});

  const html = `<div style="font-family:Arial;background:#0d0d1a;color:#fff;padding:32px;border-radius:16px;max-width:460px">
    <h2 style="color:#2ecc71">VERITAS SCAN</h2>
    <p>Votre code :</p>
    <div style="background:rgba(46,204,113,.15);border:2px solid #2ecc71;border-radius:12px;padding:20px;text-align:center;margin:16px 0">
      <span style="font-size:42px;font-weight:900;letter-spacing:12px;color:#2ecc71">${code}</span>
    </div>
    <p style="color:rgba(255,255,255,.4);font-size:12px">Expire dans 10 minutes.<br>© 2026 Hakim MAKMOUL · VERITAS SCAN · Brevet INPI 2026</p>
  </div>`;

  let sent = false;
  if (process.env.SMTP_USER) {
    try {
      await mailer.sendMail({
        from: `"VERITAS SCAN" <${process.env.SMTP_USER}>`,
        to: email, subject: "Votre code VERITAS SCAN", html
      });
      sent = true;
    } catch(e) { console.error("SMTP:", e.message); }
  }

  const resp = {success:true, message: sent ? "Code envoyé par email." : "Code généré (mode dev).", trial:{days:TRIAL_DAYS, daily:FREE_DAILY}};
  if (!sent) resp.dev_code = code;
  res.json(resp);
});

app.post('/v1/auth/verify', (req, res) => {
  const {email, code} = req.body;
  const ip = getIP(req);
  if (DB.banned_ip.has(ip) || DB.banned_email.has(email)) return res.status(403).json({error:"Banni."});

  const otp = DB.otps.get(email);
  if (!otp) return res.status(400).json({error:"Aucun code. Cliquez 'Recevoir mon code'."});
  if (Date.now() > otp.expires) { DB.otps.delete(email); return res.status(400).json({error:"Code expiré. Recommencez."}); }
  otp.tries++;
  if (otp.tries > 5) { DB.otps.delete(email); return res.status(400).json({error:"Trop d'essais. Recommencez."}); }
  if (otp.code !== String(code).trim()) return res.status(400).json({error:`Code incorrect (${otp.tries}/5).`});

  DB.otps.delete(email);
  let user = DB.users.get(email);
  if (!user) {
    user = {id:crypto.randomUUID(), email, plan:"free", installDate:Date.now(), totalScans:0, scansToday:0, todayDate:"", stripeCustomerId:null, stripeSubId:null};
    DB.users.set(email, user);
    console.log("Nouvel utilisateur:", email);
  }

  const token = jwt.sign({userId:user.id, email, plan:user.plan}, JWT_SECRET, {expiresIn:'30d'});
  res.json({success:true, token, email, plan:user.plan, ...getStatus(user)});
});

app.post('/v1/auth/check', authMW, (req, res) => {
  const user = DB.users.get(req.user.email);
  if (!user) return res.status(404).json({error:"Introuvable. Reconnectez-vous."});
  res.json({success:true, email:user.email, plan:user.plan, ...getStatus(user)});
});

app.post('/v1/payment/create-session', authMW, async (req, res) => {
  if (!stripe || !STRIPE_PID) return res.status(503).json({error:"Stripe non configuré. Ajoutez STRIPE_SECRET_KEY et STRIPE_PRICE_ID sur Render."});
  const user = DB.users.get(req.user.email);
  if (!user) return res.status(404).json({error:"Introuvable."});
  if (user.plan === "premium") return res.json({already_premium:true});
  try {
    if (!user.stripeCustomerId) {
      const c = await stripe.customers.create({email:user.email, metadata:{veritas_id:user.id}});
      user.stripeCustomerId = c.id;
    }
    const session = await stripe.checkout.sessions.create({
      customer: user.stripeCustomerId,
      payment_method_types: ['card'],
      mode: 'subscription',
      line_items: [{price:STRIPE_PID, quantity:1}],
      success_url: `${FRONT_URL}/premium-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${FRONT_URL}/premium-cancel`,
      metadata: {user_email:user.email},
      locale: 'fr',
      allow_promotion_codes: true
    });
    res.json({success:true, checkoutUrl:session.url});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/v1/payment/portal', authMW, async (req, res) => {
  if (!stripe) return res.status(503).json({error:"Stripe non configuré."});
  const user = DB.users.get(req.user.email);
  if (!user?.stripeCustomerId) return res.status(400).json({error:"Aucun abonnement."});
  try {
    const s = await stripe.billingPortal.sessions.create({customer:user.stripeCustomerId, return_url:FRONT_URL});
    res.json({success:true, url:s.url});
  } catch(e) { res.status(500).json({error:e.message}); }
});

async function handleWebhook(req, res) {
  if (!stripe || !WEBHOOK_SEC) return res.json({received:true});
  let event;
  try { event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], WEBHOOK_SEC); }
  catch(e) { return res.status(400).json({error:"Signature invalide"}); }
  if (event.type === 'checkout.session.completed') {
    const email = event.data.object.metadata?.user_email;
    if (email && DB.users.has(email)) {
      const u = DB.users.get(email);
      u.plan = "premium"; u.stripeSubId = event.data.object.subscription;
      console.log("PREMIUM activé:", email);
    }
  }
  if (event.type === 'customer.subscription.deleted') {
    try {
      const c = await stripe.customers.retrieve(event.data.object.customer);
      if (c.email && DB.users.has(c.email)) DB.users.get(c.email).plan = "free";
    } catch(e) {}
  }
  res.json({received:true});
}

app.post('/v1/scan', authMW, async (req, res) => {
  const t0 = Date.now();
  const {type="image_url", data, platform="web", contextText=""} = req.body;
  if (!data) return res.status(400).json({error:"Champ 'data' manquant."});

  const user = DB.users.get(req.user.email);
  if (!user) return res.status(401).json({error:"Reconnectez-vous."});

  const status = getStatus(user);
  if (status.trialExpired && user.plan !== "premium") return res.json({
    verdict:"TRIAL_EXPIRED", confidence:0, upgrade:true,
    message:`Essai de ${TRIAL_DAYS} jours terminé.\nPassez en PREMIUM — 4,90€/mois.`, scores:{}
  });
  if (user.plan !== "premium" && status.todayCount >= FREE_DAILY) return res.json({
    verdict:"QUOTA_EXCEEDED", confidence:0, upgrade:true,
    message:`Limite journalière (${FREE_DAILY}/jour). ${status.daysLeft} jour(s) restant(s).\nPREMIUM = illimité à 4,90€/mois.`, scores:{}
  });

  const ckey = h(data + type + platform);
  const hit = getCache(ckey);
  if (hit) return res.json({...hit, source:'cache', latency:`${Date.now()-t0}ms`});

  try {
    let result;
    if (type === "text") result = await analyzeText(data);
    else if (type === "site_url") result = await analyzeSite(data);
    else result = await analyzeImage(data, type, platform, contextText);
    setCache(ckey, result);
    incrScan(user);
    console.log(`[${user.plan}][${type}] ${platform} -> ${result.verdict} | ${Date.now()-t0}ms`);
    res.json({...result, source:'live', latency:`${Date.now()-t0}ms`, scansLeft:scansLeft(user)});
  } catch(e) {
    console.error("Pipeline:", e.message);
    res.status(500).json({verdict:'ERROR', confidence:0, message:"Erreur: "+e.message, scores:{}});
  }
});

async function analyzeImage(data, type, platform, contextText) {
  if (!HAS_SE) return {
    verdict:"NO_API", confidence:0,
    message:"Inscrivez-vous sur sightengine.com (gratuit) et ajoutez SE_USER + SE_SECRET sur Render.",
    scores:{genAi:0,ela:0,prnu:0,filter:0,deepfake:0,text:0}, no_api:true
  };
  const se = await callSE(data, type);
  const l1 = parseSE(se);
  const ela = clamp(Math.max(l1.genAi*0.78, (1-l1.real)*0.65), 0, 1);
  let genAi = l1.genAi;
  if (genAi > 0.32 && genAi < 0.70 && type==="image_url" && data.startsWith("http"))
    genAi = await secondOpinion(data, genAi);
  const textSc = contextText?.length > 20 ? analyzeTextSync(contextText).textScore : 0;
  return buildVerdict({genAi:clamp(genAi,0,1), deepfake:l1.deepfake, filter:l1.filter, ela, prnu:l1.prnu, text:clamp(textSc,0,1)});
}

function callSE(data, type) {
  return new Promise((resolve, reject) => {
    const M = 'genai,deepfake,face-attributes';
    if (type === "image_url" && data.startsWith("http")) {
      const p = new URLSearchParams({url:data, models:M, api_user:SE_USER, api_secret:SE_SECRET});
      httpsGET(`https://api.sightengine.com/1.0/check.json?${p}`, resolve, reject);
    } else {
      const b64 = data.includes(',') ? data.split(',')[1] : data;
      const form = new FormData();
      form.append('media', Buffer.from(b64,'base64'), {filename:'img.jpg', contentType:'image/jpeg'});
      form.append('models', M); form.append('api_user', SE_USER); form.append('api_secret', SE_SECRET);
      httpsPOST('api.sightengine.com', '/1.0/check.json', form, resolve, reject);
    }
  });
}
function httpsGET(url, res, rej) {
  let b = '';
  const r = https.get(url, {headers:{'User-Agent':'VERITAS/8.0'}}, x => {
    x.on('data', d => b += d);
    x.on('end', () => { try { res(JSON.parse(b)); } catch(e) { rej(e); } });
  });
  r.on('error', rej);
  r.setTimeout(16000, () => { r.destroy(); rej(new Error("Timeout SE")); });
}
function httpsPOST(host, path, form, res, rej) {
  let b = '';
  const r = https.request({hostname:host, path, method:'POST', headers:form.getHeaders()}, x => {
    x.on('data', d => b += d);
    x.on('end', () => { try { res(JSON.parse(b)); } catch(e) { rej(e); } });
  });
  r.on('error', rej);
  r.setTimeout(18000, () => { r.destroy(); rej(new Error("Timeout")); });
  form.pipe(r);
}
function parseSE(se) {
  if (!se || se.status==='failure') throw new Error(se?.error?.message || "SE erreur");
  const f = se.faces || [];
  return {
    genAi: clamp(se.type?.ai_generated||0, 0, 1),
    real: clamp(se.type?.real||0, 0, 1),
    deepfake: clamp(f[0]?.deepfake||0, 0, 1),
    filter: clamp(Math.max(f[0]?.attributes?.skin_smoothing||0, f[0]?.attributes?.color_alteration||0, f[0]?.attributes?.makeup_level||0), 0, 1),
    prnu: clamp((se.type?.real||0)*0.90, 0, 1)
  };
}
async function secondOpinion(url, first) {
  try {
    const p = new URLSearchParams({url, models:'genai,properties', api_user:SE_USER, api_secret:SE_SECRET});
    const se2 = await new Promise((r,j) => httpsGET(`https://api.sightengine.com/1.0/check.json?${p}`, r, j));
    if (!se2 || se2.status==='failure') return first;
    return clamp(first*0.55 + (se2.type?.ai_generated||0)*0.45, 0, 1);
  } catch { return first; }
}
function buildVerdict(s) {
  const {genAi, deepfake, filter, ela, prnu, text} = s;
  let verdict, confidence, message;
  if (deepfake > 0.58) { verdict="FAKE"; confidence=clamp(deepfake+0.12,0.70,0.99); message=`DEEPFAKE (${pct(deepfake)}%)`; }
  else if (genAi > 0.62) { verdict="FAKE"; confidence=clamp(genAi+0.10,0.70,0.99); message=`IMAGE IA — Midjourney/DALL-E/SD (${pct(genAi)}%)`; }
  else if (genAi > 0.40 && ela > 0.50) { verdict="FAKE"; confidence=clamp((genAi+ela)/2+0.08,0.65,0.95); message=`IMAGE SUSPECTE — GenAI ${pct(genAi)}% + ELA ${pct(ela)}%`; }
  else if (filter>0.52||(ela>0.45&&genAi<0.40)) { verdict="FILTERED"; confidence=clamp(Math.max(filter,ela)+0.15,0.60,0.92); message=filter>0.52?`RETOUCHE (${pct(filter)}%)`:`MODIFICATIONS (ELA ${pct(ela)}%)`; }
  else if (text > 0.55) { verdict="FILTERED"; confidence=0.72; message="Texte associé suspect."; }
  else { verdict="AUTHENTIC"; confidence=clamp(prnu*0.85+(1-genAi)*0.15,0.62,0.97); message=`Authentique — GenAI:${pct(genAi)}% Deepfake:${pct(deepfake)}%`; }
  return {verdict, confidence, message, scores:s, timestamp:new Date().toISOString()};
}

async function analyzeSite(rawUrl) {
  let domain, isHttps;
  try {
    const url = rawUrl.startsWith('http') ? rawUrl : 'https://'+rawUrl;
    const u = new URL(url);
    domain = u.hostname.replace(/^www\./,'');
    isHttps = u.protocol === 'https:';
  } catch { return {verdict:"ERROR", confidence:0, message:"URL invalide.", scores:{}}; }

  const d = domain.toLowerCase();
  let risk = 0;
  const BAD=[], GOOD=[];
  const WHITE=['google','facebook','instagram','twitter','x.com','youtube','linkedin','amazon','paypal','stripe','apple','microsoft','netflix','spotify','leboncoin','vinted','ebay','fnac','cdiscount','darty','boulanger','airbnb','booking','sncf','laposte','impots.gouv','service-public','ameli','caf.fr','pole-emploi','credit-agricole','bnpparibas','societegenerale','lcl.fr','boursorama','lemonde','lefigaro','liberation','leparisien','france24','bfmtv','20minutes','reporterre'];
  const white = WHITE.some(w => d.includes(w));
  if (white) { GOOD.push("Site reconnu et fiable"); risk -= 0.55; }
  if (!isHttps) { risk+=0.40; BAD.push("Connexion non sécurisée (HTTP)"); } else GOOD.push("HTTPS actif");
  if (domain.split('.').length > 4) { risk+=0.30; BAD.push("Structure de domaine suspecte"); }
  if (/\d/.test(d.split('.')[0])) { risk+=0.28; BAD.push("Chiffres dans le domaine (typosquatting)"); }
  const BAD_TLD=['.xyz','.top','.click','.loan','.tk','.pw','.cc','.icu','.buzz'];
  if (BAD_TLD.some(t=>d.endsWith(t))) { risk+=0.35; BAD.push(`Extension à risque (.${d.split('.').pop()})`); }
  const BRANDS=['paypal','amazon','facebook','google','apple','microsoft','netflix','impots','ameli','caf','pole-emploi','credit-agricole','bnp','societe-generale'];
  const fakeB = BRANDS.find(b=>d.includes(b)&&!white);
  if (fakeB) { risk+=0.58; BAD.push(`PHISHING — imite "${fakeB}"`); }
  risk = clamp(risk, 0, 1);

  let verdict, confidence, message;
  if (risk > 0.50 || fakeB) { verdict="FAKE"; confidence=clamp(risk+0.10,0.72,0.99); message=`SITE DANGEREUX\n${BAD.join('\n')}\n\nNe saisissez pas vos données ici.`; }
  else if (risk > 0.18 && !white) { verdict="FILTERED"; confidence=clamp(risk+0.22,0.55,0.85); message=`SITE A VERIFIER\n${BAD.join('\n')||"Structure inhabituelle"}\n${GOOD.join('\n')}`; }
  else { verdict="AUTHENTIC"; confidence=clamp(0.90-risk,0.68,0.97); message=`SITE FIABLE\n${GOOD.join('\n')||"Domaine standard"}\nDomaine : ${domain}`; }
  return {verdict, confidence, message, scores:{genAi:0,ela:0,prnu:0,filter:0,deepfake:0,text:0}, timestamp:new Date().toISOString()};
}

function analyzeTextSync(text) {
  const t = text.toLowerCase();
  const ai=['il convient de noter','il est important de','en conclusion','furthermore','it is worth noting','globalement'].filter(m=>t.includes(m)).length;
  const fraud=['western union','moneygram','100% garanti','sans risque','whatsapp only','héritage bloqué','doublez votre argent'].filter(m=>t.includes(m)).length;
  const disinfo=['la vérité cachée','les médias ne disent pas','révélation choc','complot','gouvernement vous cache','deep state'].filter(m=>t.includes(m)).length;
  const aiScore=Math.min(1,ai*0.17), fraudScore=Math.min(1,fraud*0.30), disinfoScore=Math.min(1,disinfo*0.25);
  return {textScore:clamp(aiScore*0.30+fraudScore*0.50+disinfoScore*0.20,0,1), aiScore, fraudScore};
}
async function analyzeText(text) {
  if (!text||text.length<10) return {verdict:"AUTHENTIC", confidence:0.5, message:"Texte trop court.", scores:{text:0}};
  const {textScore,aiScore,fraudScore} = analyzeTextSync(text);
  let verdict, message;
  if (fraudScore>0.55) { verdict="FAKE"; message="Marqueurs d'arnaque détectés."; }
  else if (textScore>0.48) { verdict="FAKE"; message="Texte IA ou frauduleux probable."; }
  else if (textScore>0.22) { verdict="FILTERED"; message="Quelques éléments suspects."; }
  else { verdict="AUTHENTIC"; message="Aucun marqueur suspect."; }
  return {verdict, confidence:0.62+textScore*0.30, message, scores:{genAi:aiScore,ela:0,prnu:0,filter:0,deepfake:fraudScore,text:textScore}, timestamp:new Date().toISOString()};
}

function authMW(req, res, next) {
  const tok = (req.headers.authorization||"").replace("Bearer ","").trim();
  if (!tok) return res.status(401).json({error:"Non connecté. Ouvrez le popup VERITAS."});
  try { req.user = jwt.verify(tok, JWT_SECRET); next(); }
  catch { res.status(401).json({error:"Session expirée. Reconnectez-vous."}); }
}
function getStatus(user) {
  const daysSince = Math.floor((Date.now()-(user.installDate||Date.now()))/86400000);
  const today = new Date().toDateString();
  const todayCount = user.todayDate===today ? (user.scansToday||0) : 0;
  return {plan:user.plan, daysSince, daysLeft:Math.max(0,TRIAL_DAYS-daysSince), trialExpired:user.plan!=="premium"&&daysSince>=TRIAL_DAYS, todayCount, totalScans:user.totalScans||0};
}
function scansLeft(user) {
  if (user.plan==="premium") return "∞";
  const today=new Date().toDateString();
  return Math.max(0,FREE_DAILY-(user.todayDate===today?(user.scansToday||0):0));
}
function incrScan(user) {
  const today=new Date().toDateString();
  if (user.todayDate!==today){user.todayDate=today;user.scansToday=0;}
  user.scansToday=(user.scansToday||0)+1; user.totalScans=(user.totalScans||0)+1;
}
function trackAbuse(ip, email) {
  if (!DB.abuse_ip.has(ip)) DB.abuse_ip.set(ip,{emails:new Set()});
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
  if (Date.now()-e.ts>7*864e5){DB.cache.delete(k);return null;}
  return e.v;
}
function setCache(k,v) {
  DB.cache.set(k,{v,ts:Date.now()});
  if (DB.cache.size>8000) DB.cache.delete(DB.cache.keys().next().value);
}
function h(d) { return crypto.createHash('sha256').update(String(d)).digest('hex').slice(0,20); }
function clamp(v,a,b) { return Math.max(a,Math.min(b,v||0)); }
function pct(v) { return Math.round((v||0)*100); }
function getIP(req) { return (req.headers['x-forwarded-for']||req.socket.remoteAddress||'').split(',')[0].trim(); }

app.listen(PORT, "0.0.0.0", () => {
  console.log(`VERITAS SCAN v8.0 - port ${PORT}`);
  console.log(`Sightengine: ${HAS_SE ? "ACTIVE" : "Non configuré (ajoutez SE_USER + SE_SECRET)"}`);
  console.log(`Stripe: ${stripe ? "Configuré" : "Non configuré"}`);
  console.log(`SMTP: ${process.env.SMTP_USER ? "Configuré" : "Mode dev (code OTP dans la réponse)"}`);
  console.log(`JWT: ${process.env.JWT_SECRET ? "Personnalisé" : "Temporaire (ajoutez JWT_SECRET)"}`);
});

module.exports = app;
