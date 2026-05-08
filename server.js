import express from "express";
import cors from "cors";
import nodemailer from "nodemailer";
import Stripe from "stripe";

const app = express();
app.use(express.json());
app.use(cors());

// --- Variables d'environnement ---
const {
  JWT_SECRET,
  SE_USER,
  SE_SECRET,
  SMTP_HOST,
  SMTP_USER,
  SMTP_PASS,
  STRIPE_SECRET_KEY,
  STRIPE_PRICE_ID,
  STRIPE_WEBHOOK_SECRET
} = process.env;

// --- Route principale ---
app.get("/", (req, res) => {
  res.json({
    status: "VERITAS SCAN™ v8.0",
    engine: SE_USER ? "Sightengine connecté" : "Ajoutez SE_USER...",
    users: 0
  });
});

// --- Route test santé ---
app.get("/health", (req, res) => {
  res.json({ status: "VERITAS API OK" });
});

// --- Route OTP email ---
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
    console.error(err);
    res.status(500).json({ success: false, error: "Erreur SMTP" });
  }
});

// --- Route Stripe ---
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
    console.error(err);
    res.status(500).json({ error: "Erreur Stripe" });
  }
});

// --- Démarrage serveur ---
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`✅ VERITAS SCAN™ API démarrée sur le port ${PORT}`));
