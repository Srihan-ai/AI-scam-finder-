const express = require('express');
const cors = require('cors');
const { scanContent } = require('./analyzers/mainScanner');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', service: 'AI Scam Checker API', version: '2.4.0', timestamp: new Date().toISOString() });
});

// Primary scan endpoint
app.post('/api/scan', (req, res) => {
  try {
    const { input, scanType } = req.body;
    if (!input || typeof input !== 'string' || input.trim().length === 0) {
      return res.status(400).json({ error: 'Please provide a valid link, message, or UPI payment request to scan.' });
    }

    const result = scanContent(input.trim(), scanType);
    res.json(result);
  } catch (error) {
    console.error('Scan error:', error);
    res.status(500).json({ error: 'Failed to complete scam analysis: ' + error.message });
  }
});

app.listen(PORT, () => {
  console.log(`🛡️ AI Scam Checker backend listening at http://localhost:${PORT}`);
});
