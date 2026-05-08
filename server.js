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
  const { user
