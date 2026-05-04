// VERITAS SCAN™ — index.js — Serveur Principal
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');

const { connectDB } = require('./utils/db');
const { connectRedis } = require('./cache/redis');
const { startTrialCron } = require('./cron/trial_cron');

const authRouter = require('./auth/routes');
const scanRouter = require('./analysis/routes');
const webhookRouter = require('./webhooks/stripe_webhook');
const checkoutRouter = require('./auth/checkout');

const app = express();

// ─── Sécurité ─────────────────────────────────────────────────────────────
app.use(helmet());
app.use(morgan('combined'));

// Le webhook Stripe doit recevoir le body brut (avant JSON parsing)
app.use('/webhook/stripe', express.raw({ type: 'application/json' }));
app.use(express.json({ limit: '20mb' }));

// ─── CORS ─────────────────────────────────────────────────────────────────
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',');
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.some(o => origin.startsWith(o.trim()))) {
      callback(null, true);
    } else {
      callback(new Error('CORS bloqué'));
    }
  },
  credentials: true
}));

// ─── Rate limiting global ─────────────────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'RATE_LIMIT_EXCEEDED' }
});
app.use('/v1/', globalLimiter);

// ─── Routes ───────────────────────────────────────────────────────────────
app.use('/v1/auth', authRouter);
app.use('/v1/scan', scanRouter);
app.use('/v1/trial', require('./auth/trial'));
app.use('/webhook/stripe', webhookRouter);
app.use('/checkout', checkoutRouter);

// Health check
app.get('/health', (req, res) => res.json({ status: 'ok', version: '1.0.0' }));

// ─── Démarrage ────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;

async function start() {
  try {
    await connectDB();
    await connectRedis();
    startTrialCron();

    app.listen(PORT, () => {
      console.log(`✅ VERITAS SCAN Server démarré sur le port ${PORT}`);
      console.log(`   Environnement: ${process.env.NODE_ENV}`);
    });
  } catch (err) {
    console.error('❌ Erreur démarrage:', err);
    process.exit(1);
  }
}

start();

module.exports = app;
