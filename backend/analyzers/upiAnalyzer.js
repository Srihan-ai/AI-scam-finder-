/**
 * UPI & Payment Request Pattern Analyzer
 * Detects reverse-charge traps, collect request exploits, spoofed support handles, and malicious UPI URIs.
 */

const RECOGNIZED_UPI_HANDLES = [
  'okaxis', 'okhdfcbank', 'okicici', 'oksbi', 'paytm', 'ybl', 'ibl', 'axl',
  'apl', 'barodampay', 'federal', 'indus', 'kotak', 'upi', 'idfcbank', 'aubank'
];

const SUSPICIOUS_VPA_PREFIXES = [
  'support', 'care', 'customercare', 'helpline', 'officer', 'refund',
  'desk', 'nodal', 'fraud', 'reversal', 'manager', 'kyc', 'verification',
  'police', 'rbi', 'army', 'defence', 'olx', 'cbi', 'security'
];

const CORPORATE_BRANDS = [
  'sbi', 'hdfc', 'icici', 'axis', 'paytm', 'phonepe', 'gpay', 'amazon',
  'flipkart', 'zomato', 'swiggy', 'airtel', 'jio', 'electricity', 'bescom'
];

function analyzeUpi(rawInput) {
  const flags = [];
  let riskScore = 10;
  const text = rawInput.trim();
  const lowerText = text.toLowerCase();

  let isUpiScheme = false;
  let vpa = null;
  let payeeName = null;
  let amount = null;
  let transactionNote = null;

  // Pattern A: Detect upi://pay URI
  if (lowerText.startsWith('upi://pay') || lowerText.includes('upi://pay?')) {
    isUpiScheme = true;
    try {
      const urlObj = new URL(text.includes('://') ? text : 'upi://' + text);
      const params = urlObj.searchParams;
      vpa = params.get('pa') || '';
      payeeName = params.get('pn') || '';
      amount = params.get('am') || '';
      transactionNote = params.get('tn') || '';
    } catch (e) {
      const paMatch = text.match(/[?&]pa=([^&]+)/i);
      const pnMatch = text.match(/[?&]pn=([^&]+)/i);
      const amMatch = text.match(/[?&]am=([^&]+)/i);
      const tnMatch = text.match(/[?&]tn=([^&]+)/i);
      if (paMatch) vpa = decodeURIComponent(paMatch[1]);
      if (pnMatch) payeeName = decodeURIComponent(pnMatch[1]);
      if (amMatch) amount = decodeURIComponent(amMatch[1]);
      if (tnMatch) transactionNote = decodeURIComponent(tnMatch[1]);
    }
  } else {
    // Pattern B: Raw UPI VPA address like username@bank
    const vpaRegex = /([a-zA-Z0-9.\-_]{2,256})@([a-zA-Z]{2,64})/g;
    const match = vpaRegex.exec(text);
    if (match) {
      vpa = match[0];
    }
  }

  // 🚨 CRITICAL RULE #1: REVERSE CHARGE FRAUD ("ENTER PIN TO RECEIVE MONEY")
  // Extremely flexible regex handling intervening app names or phrases
  const reverseChargeIndicators = [
    /(?:enter|type|give|submit)\s+(?:your\s+)?(?:upi\s+)?(?:m?pin|code|password)[\s\w,]{0,45}(?:receive|get|claim|credit|accept|collect)/i,
    /(?:receive|claim|get|credit|collect)\s+[\w\s,]{0,35}(?:enter|type|submit)\s+(?:your\s+)?(?:upi\s+)?(?:m?pin|pin)/i,
    /(?:scan|scan\s+this)\s+(?:qr|code)[\s\w,]{0,35}(?:receive|get\s+money|claim|credit)/i,
    /approve\s+(?:collect\s+request|request)[\s\w,]{0,35}(?:receive|get|claim)/i,
    /enter\s+pin\s+for\s+(?:refund|cashback|bonus)/i,
    /type\s+(?:your\s+)?(?:mpin|pin)\s+to\s+get/i,
    /(?:pin|mpin).*required.*(?:to\s+receive|for\s+credit)/i
  ];

  for (const pattern of reverseChargeIndicators) {
    if (pattern.test(lowerText)) {
      riskScore = 99;
      flags.push({
        severity: 'CRITICAL',
        title: 'Reverse Charge PIN Trap (Financial Theft Alert)',
        detail: 'The message instructs you to enter your UPI PIN or scan a QR code to "receive" or "claim" money. IN UPI ARCHITECTURE, YOU NEVER ENTER YOUR PIN TO RECEIVE MONEY. Entering your PIN will immediately DEDUCT money from your account!'
      });
      break;
    }
  }

  // 🚨 RULE #2: Collect Request Misdirection
  if (lowerText.includes('collect request') || lowerText.includes('requested money') || lowerText.includes('pay request')) {
    if (lowerText.includes('refund') || lowerText.includes('prize') || lowerText.includes('cashback') || lowerText.includes('bonus')) {
      riskScore = Math.max(riskScore, 95);
      flags.push({
        severity: 'CRITICAL',
        title: 'Deceptive UPI Collect Request Exploitation',
        detail: 'The sender has dispatched a payment "Collect Request" disguised as a refund or prize claim. If you accept or enter your PIN in your UPI app, money will be transferred TO the scammer.'
      });
    } else {
      riskScore = Math.max(riskScore, 70);
      flags.push({
        severity: 'HIGH',
        title: 'Unsolicited UPI Collect Request',
        detail: 'Be cautious of unsolicited collect requests from unknown parties. Never approve requests without independently verifying the sender.'
      });
    }
  }

  // 🚨 RULE #3: UPI Link with deceptive transaction note
  if (transactionNote) {
    const noteLower = transactionNote.toLowerCase();
    if (noteLower.includes('refund') || noteLower.includes('cashback') || noteLower.includes('credit') || noteLower.includes('lottery') || noteLower.includes('prize')) {
      riskScore = Math.max(riskScore, 96);
      flags.push({
        severity: 'CRITICAL',
        title: `Deceptive Transaction Note: "${transactionNote}"`,
        detail: `The payment link is coded with note "${transactionNote}", but the payment action is a DEBIT from your bank account. Scammers use misleading notes to trick victims into thinking they are receiving funds.`
      });
    }
  }

  // 🚨 RULE #4: VPA Impersonation / Spoofed Support Handle
  if (vpa) {
    const [handlePrefix, handleProvider] = vpa.toLowerCase().split('@');

    const hasBrand = CORPORATE_BRANDS.some(b => handlePrefix.includes(b));
    const hasSupportKeyword = SUSPICIOUS_VPA_PREFIXES.some(s => handlePrefix.includes(s));

    if (hasBrand && hasSupportKeyword) {
      riskScore = Math.max(riskScore, 92);
      flags.push({
        severity: 'CRITICAL',
        title: `Spoofed Support VPA Handle: "${vpa}"`,
        detail: `This UPI address combines brand name ("${handlePrefix}") with support keywords on a consumer PSP handle (@${handleProvider}). Legitimate banks and corporations NEVER use consumer VPAs (like @okaxis or @paytm) to resolve customer disputes or send refunds.`
      });
    } else if (hasSupportKeyword) {
      riskScore = Math.max(riskScore, 75);
      flags.push({
        severity: 'HIGH',
        title: `Deceptive Customer Support Keyword in VPA ("${vpa}")`,
        detail: `The handle uses support/officer keywords. Scammers frequently register these custom personal handles on Google Pay / PhonePe to impersonate official authorities.`
      });
    }

    if (handleProvider && !RECOGNIZED_UPI_HANDLES.includes(handleProvider)) {
      flags.push({
        severity: 'MEDIUM',
        title: `Uncommon UPI Handle Provider: @${handleProvider}`,
        detail: `The PSP handle @${handleProvider} is non-standard. Verify the merchant before proceeding with any transfer.`
      });
      riskScore += 15;
    }
  }

  // 🚨 RULE #5: Micro-deposit verification trap
  if (lowerText.includes('send 1 rupee') || lowerText.includes('pay 1 rs') || lowerText.includes('pay ₹1') || lowerText.includes('send ₹10')) {
    if (lowerText.includes('verify') || lowerText.includes('activate') || lowerText.includes('unblock')) {
      riskScore = Math.max(riskScore, 85);
      flags.push({
        severity: 'HIGH',
        title: 'Micro-Transaction Verification Bait',
        detail: 'Scammers ask victims to send ₹1 or ₹5 to "verify account", then exploit the authenticated channel or substitute higher amounts in subsequent prompts.'
      });
    }
  }

  // Determine overall risk
  riskScore = Math.min(Math.max(riskScore, 5), 99);

  let riskLevel = 'LOW';
  if (riskScore >= 85) riskLevel = 'CRITICAL';
  else if (riskScore >= 65) riskLevel = 'HIGH';
  else if (riskScore >= 40) riskLevel = 'MEDIUM';

  return {
    type: 'UPI',
    vpa: vpa || 'Extracted Payment Request',
    payeeName: payeeName || null,
    amount: amount || null,
    transactionNote: transactionNote || null,
    riskScore,
    riskLevel,
    flags
  };
}

module.exports = { analyzeUpi, RECOGNIZED_UPI_HANDLES };
