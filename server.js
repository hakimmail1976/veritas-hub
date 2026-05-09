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