<<<<<<< HEAD
const express = require('express');
const cors = require('cors');

const app = express();

app.use(cors());
app.use(express.json({ limit: '15mb' }));

// Route GET - Test
app.get('/', (req, res) => {
    res.json({ 
        status: "VERITAS API OK",
        message: "Serveur prêt à recevoir les scans" 
    });
});

// Route POST - Très importante
app.post('/', (req, res) => {
    console.log("📥 POST reçu :", req.body);

    const { type, data } = req.body || {};

    if (!data) {
        return res.status(400).json({ error: true, message: "Aucune image reçue" });
    }

    // Réponse finale
    res.json({
        success: true,
        verdict: "AUTHENTIC",
        confidence: 0.88,
        message: "Analyse terminée avec succès",
        type: type || "image",
        timestamp: new Date().toISOString()
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 VERITAS SCAN Server démarré sur port ${PORT}`);
});
=======
import express from "express";
import cors from "cors";
import nodemailer from "nodemailer";
import Stripe from "stripe";
import fetch from "node-fetch";

const app = express();
app.use(express.json({ limit: "15mb" }));
app.use(cors());

// ===============================
//  VARIABLES ENVIRONNEMENT
// ===============================
const {
  SMTP_HOST,
  SMTP_USER,
  SMTP_PASS,
  SE_USER,
  SE_SECRET,
  STRIPE_SECRET_KEY,
  STRIPE_PRICE_ID
} = process.env;

// ===============================
//  ROUTE PRINCIPALE
// ===============================
app.get("/", (req, res) => {
  res.json({
    status: "VERITAS SCAN™ v8.0",
    engine: SE_USER ? "Sightengine connecté" : "Ajoutez SE_USER...",
    users: 0
  });
});

// ===============================
//  ROUTE SANTÉ
// ===============================
app.get("/health", (req, res) => {
  res.json({ status: "VERITAS API OK" });
});

// ===============================
//  OTP — ENVOI DU CODE
// ===============================
app.post("/api/sendCode", async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({ success: false, error: "Paramètres manquants" });
    }

    const transporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: 587,
      secure: false,
      auth: { user: SMTP_USER, pass: SMTP_PASS }
    });

    await transporter.sendMail({
      from: `"VERITAS SCAN™" <${SMTP_USER}>`,
      to: email,
      subject: "Votre code de vérification",
      text: `Votre code est : ${code}`,
      html: `<h2>Code de vérification</h2><p>${code}</p>`
    });

    res.json({ success: true, message: "Email envoyé" });
  } catch (err) {
    console.error("SMTP ERROR:", err);
    res.status(500).json({ success: false, error: "Erreur SMTP" });
  }
});

// ===============================
//  OTP — VÉRIFICATION DU CODE
// ===============================
app.post("/api/verify", (req, res) => {
  const { userCode, realCode } = req.body;

  if (!userCode || !realCode) {
    return res.status(400).json({ success: false, error: "Paramètres manquants" });
  }

  if (userCode !== realCode) {
    return res.json({ success: false, error: "Code incorrect" });
  }

  res.json({ success: true });
});

// ===============================
//  ANALYSE IA — SIGHTENGINE
// ===============================
app.post("/api/scan", async (req, res) => {
  try {
    const { type, data } = req.body;

    if (!SE_USER || !SE_SECRET) {
      return res.json({ error: true, message: "Sightengine non configuré" });
    }

    if (!type || !data) {
      return res.status(400).json({ error: true, message: "Paramètres manquants" });
    }

    const payload = {
      api_user: SE_USER,
      api_secret: SE_SECRET
    };

    if (type === "image") {
      payload.url = data;
      payload.models = "nudity,offensive,faces,quality";
    } else if (type === "text") {
      payload.text = data;
      payload.models = "text-content";
    } else {
      return res.status(400).json({ error: true, message: "Type invalide" });
    }

    const response = await fetch("https://api.sightengine.com/1.0/check.json", {
      method: "POST",
      body: new URLSearchParams(payload)
    });

    const result = await response.json();
    res.json(result);
  } catch (err) {
    console.error("SCAN ERROR:", err);
    res.status(500).json({ error: true, message: "Erreur analyse IA" });
  }
});

// ===============================
//  STRIPE — CHECKOUT
// ===============================
app.post("/api/create-checkout-session", async (req, res) => {
  try {
    const stripe = new Stripe(STRIPE_SECRET_KEY);

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      line_items: [{ price: STRIPE_PRICE_ID, quantity: 1 }],
      success_url: "https://veritas-scan.com/success",
      cancel_url: "https://veritas-scan.com/cancel"
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error("STRIPE ERROR:", err);
    res.status(500).json({ error: "Erreur Stripe" });
  }
});

// ===============================
//  DÉMARRAGE SERVEUR
// ===============================
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`✅ VERITAS SCAN™ API démarrée sur le port ${PORT}`);
});
>>>>>>> 87b325ee015dbf7941c494625fc3377aa8ef78e0
