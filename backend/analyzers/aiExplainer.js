/**
 * AI Explanation Engine
 * Synthesizes deep psychological, behavioral, and technical analysis
 * explaining in clear language why an input is unsafe and how to protect oneself.
 */

function generateAiExplanation({ inputType, riskScore, riskLevel, flags, metadata }) {
  let whyUnsafe = '';
  let attackVector = 'Standard Inspection';
  let psychologicalTactics = [];
  let technicalImpact = '';
  let safetyRatingGrade = 'A';
  let checklist = [];

  // Determine Verdict
  let verdict = 'REAL';
  let verdictDescription = '';
  if (riskScore >= 60) {
    verdict = 'FAKE';
    verdictDescription = 'This content shows strong indicators of fraud. Do not interact with it.';
  } else if (riskScore >= 35) {
    verdict = 'SUSPICIOUS';
    verdictDescription = 'This content has warning signs. Proceed with caution and verify through official channels.';
  } else {
    verdict = 'REAL';
    verdictDescription = 'No significant threat patterns were detected. This content appears legitimate.';
  }

  // Determine Letter Grade
  if (riskScore >= 90) {
    safetyRatingGrade = 'F (Confirmed Severe Threat)';
  } else if (riskScore >= 75) {
    safetyRatingGrade = 'D (High Risk / Deceptive)';
  } else if (riskScore >= 50) {
    safetyRatingGrade = 'C (Suspicious / Caution Required)';
  } else if (riskScore >= 25) {
    safetyRatingGrade = 'B (Low Risk / Minor Warnings)';
  } else {
    safetyRatingGrade = 'A+ (Safe / Verified)';
  }

  if (riskScore <= 20) {
    whyUnsafe = 'Our multi-layer threat analysis did not detect any known fraud signatures, deceptive domains, or malicious payment traps. The content appears legitimate or matches trusted official registers.';
    attackVector = 'No Active Threat Detected';
    psychologicalTactics = ['Normal communication', 'No coercive language'];
    technicalImpact = 'Safe to browse or interact with normal caution.';
    checklist = [
      'Ensure the browser address bar shows the correct lock icon (HTTPS).',
      'Verify you initiated the interaction yourself rather than following unexpected links.',
      'Remember never to disclose your passwords or OTP to anyone.'
    ];

    return {
      whyUnsafe,
      attackVector,
      psychologicalTactics,
      technicalImpact,
      safetyRatingGrade,
      checklist,
      verdict,
      verdictDescription
    };
  }

  // UPI Scam Explanation
  if (inputType === 'UPI' || (flags && flags.some(f => f.title.includes('PIN Trap') || f.title.includes('Collect Request')))) {
    attackVector = 'UPI Reverse Charge / Social Engineering Financial Theft';
    psychologicalTactics = [
      'Inversion of Financial Mechanics (Telling the victim to enter PIN to "receive" funds)',
      'Artificial Authority (Using support/refund handles to manufacture trust)',
      'Time Urgency (Demanding rapid approval before collect request expires)'
    ];
    technicalImpact = 'Direct debit from your primary linked bank account. Once an authenticated UPI PIN is submitted, the transaction is instant and practically irreversible.';
    whyUnsafe = `This payment request presents an immediate financial risk. Scammers exploit the widespread misconception that a UPI PIN or QR scan is required to receive money. Under NPCI UPI specifications, YOUR UPI PIN IS ONLY REQUIRED TO SEND OR DEBIT MONEY. Any request or message prompting you to enter your PIN, scan a QR code, or approve a collect request to claim a refund or prize will instantly drain that amount from your bank account.`;
    checklist = [
      'DO NOT enter your UPI PIN under any circumstance.',
      'DO NOT approve or click "Pay" on any collect request in your UPI apps (GPay, PhonePe, Paytm, BHIM).',
      'Decline and report the collect request as "Spam / Fraud" directly inside your UPI app.',
      'If you already entered your PIN, immediately contact your bank to freeze your UPI ID and report within 2 hours to 1930 (National Cyber Crime Helpline).'
    ];
  }
  // URL Phishing Explanation
  else if (inputType === 'URL') {
    attackVector = 'Credential Harvesting / Typosquatting / Malicious Payload Delivery';
    psychologicalTactics = [
      'Brand Impersonation (Mimicking reputable banks or government services)',
      'Visual Misdirection (Using subdomains to hide the true untrusted apex domain)',
      'Shortened Link Concealment (Hiding malicious domains behind shorteners)'
    ];
    technicalImpact = 'Phishing forms designed to intercept your NetBanking user ID, password, debit card CVV, and SMS OTP in real-time, or triggering automatic download of Android spyware APKs.';
    whyUnsafe = `The link leads to an unverified or deceptive destination that mimics legitimate institutions. Attackers frequently register lookalike domains using disposable TLDs (like .xyz, .top) and insert trusted brand names into the prefix. Once opened, these sites display cloned login portals that record your credentials as you type and prompt for OTPs to initiate unauthorized fund transfers.`;
    checklist = [
      'DO NOT click the link, and do not input passwords, PAN, or debit card numbers.',
      'Never download or install any ".apk" file sent through SMS or messaging platforms.',
      'Always access official banking services by manually typing their verified web address (e.g., onlinesbi.sbi or hdfcbank.com) into your browser.',
      'Report the phishing URL to the National Cyber Crime Reporting Portal at cybercrime.gov.in.'
    ];
  }
  // Message / SMS / WhatsApp Scam Explanation
  else {
    const categoryTitle = metadata && metadata.category ? metadata.category : 'Social Engineering Fraud';
    attackVector = `${categoryTitle} (Phishing / Smishing)`;

    psychologicalTactics = [
      'Fear & Intimidation (Threats of power disconnection, police arrest, or account freezing)',
      'Extreme Urgency (Creating artificial deadlines like "within 2 hours" or "tonight at 9:30 PM")',
      'Authority Impersonation (Falsely claiming to be Electricity Officers, CBI, Police, or Bank Managers)',
      'Greed / Euphoria Bait (Promising effortless part-time income or multi-lakh lottery prizes)'
    ];

    technicalImpact = 'Compromise of bank accounts through credential harvesting, unauthorized UPI collect traps, or installation of remote-access trojans (RATs).';

    whyUnsafe = `This message is engineered using classic social engineering tactics to manipulate your emotions. Whether it uses fear (such as power disconnection or fake legal notices) or greed (such as easy online tasks or lottery prizes), the goal is identical: to rush you into making an unverified payment, clicking a phishing link, or calling an unauthorized scammer's phone number. Legitimate government entities, utility providers, and banks do not send sudden threats over personal mobile numbers.`;

    checklist = [
      'DO NOT call the phone number provided in the message.',
      'DO NOT click any links or download attached files or APKs.',
      'Verify your actual account status through the official provider app or official customer care helpline.',
      'Block the sender and report the number on the Government of India Chakshu Portal (sancharsaathi.gov.in) and Cyber Crime Portal (1930).'
    ];
  }

  return {
    whyUnsafe,
    attackVector,
    psychologicalTactics,
    technicalImpact,
    safetyRatingGrade,
    checklist,
    verdict,
    verdictDescription
  };
}

module.exports = { generateAiExplanation };
