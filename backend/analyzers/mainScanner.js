const { analyzeUrl } = require('./urlAnalyzer');
const { analyzeUpi } = require('./upiAnalyzer');
const { analyzeMessage } = require('./messageAnalyzer');
const { generateAiExplanation } = require('./aiExplainer');
const { normalizeAdversarialText } = require('./adversarialNormalizer');

/**
 * Intelligent Multi-Modal Scanner
 * Integrates adversarial text normalization (homoglyphs, zero-width spaces, leetspeak, spaced keywords),
 * evaluates URL, UPI, and SMS/WhatsApp attack vectors, and computes comprehensive risk assessment.
 */
function scanContent(rawInput, userForcedType = null) {
  if (!rawInput || typeof rawInput !== 'string') {
    return {
      scanId: 'SCAM-' + Math.random().toString(36).substring(2, 9).toUpperCase(),
      timestamp: new Date().toISOString(),
      inputPreview: '',
      detectedType: 'UNKNOWN',
      riskScore: 0,
      riskLevel: 'SAFE',
      flags: [],
      aiExplanation: generateAiExplanation({ inputType: 'UNKNOWN', riskScore: 0, riskLevel: 'SAFE', flags: [] })
    };
  }

  // 1. Adversarial Evasion Normalization
  const { normalizedText, evasionFlags } = normalizeAdversarialText(rawInput.trim());
  const input = normalizedText;

  let detectedType = 'MESSAGE';
  let primaryAnalysis = null;
  let secondaryAnalyses = [];

  // Determine Type if not forced
  const isExplicitUrl = /^(https?:\/\/|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\/|$))/i.test(input) && !input.includes(' ') && input.length < 512;
  const isUpiUri = input.toLowerCase().startsWith('upi://') || /^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$/.test(input);
  const mentionsUpiPin = /(?:enter\s+(?:upi\s+)?pin|approve\s+collect|scan\s+qr.*receive|vpa|@ok|@paytm|@ybl|daalein.*pin)/i.test(input);

  if (userForcedType === 'URL' || (userForcedType !== 'UPI' && userForcedType !== 'MESSAGE' && isExplicitUrl)) {
    detectedType = 'URL';
    primaryAnalysis = analyzeUrl(input);
  } else if (userForcedType === 'UPI' || (userForcedType !== 'URL' && userForcedType !== 'MESSAGE' && (isUpiUri || (mentionsUpiPin && input.length < 180)))) {
    detectedType = 'UPI';
    primaryAnalysis = analyzeUpi(input);
  } else {
    detectedType = 'MESSAGE';
    primaryAnalysis = analyzeMessage(input);

    // Cross-scan embedded URLs in message
    if (primaryAnalysis.extractedUrls && primaryAnalysis.extractedUrls.length > 0) {
      for (const extractedUrl of primaryAnalysis.extractedUrls) {
        const urlRes = analyzeUrl(extractedUrl);
        if (urlRes) {
          secondaryAnalyses.push(urlRes);
        }
      }
    }

    // Cross-scan embedded UPI references in message
    if (mentionsUpiPin || /@(?:okaxis|okhdfcbank|okicici|oksbi|paytm|ybl|ibl|axl)/i.test(input)) {
      const upiRes = analyzeUpi(input);
      if (upiRes && upiRes.flags.length > 0) {
        secondaryAnalyses.push(upiRes);
      }
    }
  }

  // Aggregate results and flags, including adversarial evasion flags
  let combinedFlags = [...evasionFlags, ...(primaryAnalysis.flags || [])];
  let finalRiskScore = primaryAnalysis.riskScore || 10;

  // Add weight if adversarial evasion was detected
  if (evasionFlags.length > 0) {
    finalRiskScore = Math.max(finalRiskScore, 85);
  }

  for (const sub of secondaryAnalyses) {
    if (sub.flags && sub.flags.length > 0) {
      combinedFlags.push(...sub.flags);
    }
    if (sub.riskScore && sub.riskScore > finalRiskScore) {
      finalRiskScore = sub.riskScore;
    }
  }

  // Deduplicate flags by title
  const seenTitles = new Set();
  const uniqueFlags = [];
  for (const flag of combinedFlags) {
    if (!seenTitles.has(flag.title)) {
      seenTitles.add(flag.title);
      uniqueFlags.push(flag);
    }
  }

  // Determine final risk level
  finalRiskScore = Math.min(Math.max(finalRiskScore, 5), 99);
  let finalRiskLevel = 'LOW';
  if (finalRiskScore >= 85) finalRiskLevel = 'CRITICAL';
  else if (finalRiskScore >= 65) finalRiskLevel = 'HIGH';
  else if (finalRiskScore >= 40) finalRiskLevel = 'MEDIUM';
  else if (finalRiskScore <= 20) finalRiskLevel = 'SAFE';

  // Generate deep AI explanation
  const aiExplanation = generateAiExplanation({
    inputType: detectedType,
    riskScore: finalRiskScore,
    riskLevel: finalRiskLevel,
    flags: uniqueFlags,
    metadata: {
      category: primaryAnalysis.category || null,
      domain: primaryAnalysis.domain || null,
      vpa: primaryAnalysis.vpa || null
    }
  });

  return {
    scanId: 'SCAM-' + Math.random().toString(36).substring(2, 9).toUpperCase(),
    timestamp: new Date().toISOString(),
    inputPreview: rawInput.length > 180 ? rawInput.substring(0, 180) + '...' : rawInput,
    detectedType,
    riskScore: finalRiskScore,
    riskLevel: finalRiskLevel,
    flags: uniqueFlags,
    details: primaryAnalysis,
    secondaryDetections: secondaryAnalyses,
    aiExplanation
  };
}

module.exports = { scanContent };
