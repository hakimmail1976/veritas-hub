import express from "express";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.json({ limit: "10mb" }));

// Endpoint principal utilisé par ton extension
app.post("/v1/scan", (req, res) => {
  return res.json({
    verdict: "AUTHENTIC",
    score: 0.92,
    detail: "Analyse test OK."
  });
});

// Page d'accueil pour vérifier que le serveur tourne
app.get("/", (req, res) => {
  res.json({ status: "VERITAS API OK" });
});

// Port Render
app.listen(3000, () => console.log("VERITAS API OK"));
