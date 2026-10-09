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

  // Determine Verdict with specific, content-aware description
  let verdict = 'REAL';
  let verdictDescription = '';

  // Build a specific description using the top flag if available
  const topFlag = flags && flags.length > 0 ? flags[0] : null;
  const topFlagTitle = topFlag ? topFlag.title.replace('Scam Pattern Detected: ', '') : null;

  if (riskScore >= 60) {
    verdict = 'FAKE';
    if (topFlagTitle) {
      verdictDescription = `This content is likely a scam. It matches a known fraud pattern: "${topFlagTitle}". Do not click links, share OTPs, or make any payments.`;
    } else if (inputType === 'URL') {
      verdictDescription = 'This link leads to a deceptive or malicious destination. It uses fake branding, suspicious domains, or hidden redirects to steal your credentials or money.';
    } else if (inputType === 'UPI') {
      verdictDescription = 'This UPI request is fraudulent. Scammers trick you into entering your PIN claiming you will receive money — but it will deduct money from your account instead.';
    } else {
      verdictDescription = 'This message uses psychological manipulation — urgency, fear, or false authority — to push you into a harmful action. Do not respond or follow any instructions in it.';
    }
  } else if (riskScore >= 35) {
    verdict = 'SUSPICIOUS';
    if (topFlagTitle) {
      verdictDescription = `This content has warning signs related to "${topFlagTitle}". It may not be a confirmed scam, but proceed with extreme caution and verify through official channels before taking any action.`;
    } else if (inputType === 'URL') {
      verdictDescription = 'This link has some suspicious characteristics — an unusual domain, a URL shortener, or unverified hosting. Do not enter any personal information.';
    } else {
      verdictDescription = 'This message contains some pressure tactics or unverified claims. Do not act immediately — verify the source through official contact numbers first.';
    }
  } else {
    verdict = 'REAL';
    if (inputType === 'URL') {
      verdictDescription = 'This link appears to be from a legitimate, verified source. No phishing domains, deceptive patterns, or malicious indicators were found.';
    } else if (inputType === 'UPI') {
      verdictDescription = 'This UPI ID appears normal. No known fraud patterns were detected, but always confirm the recipient\'s identity before sending money.';
    } else {
      verdictDescription = 'This message does not contain known scam patterns, urgency tactics, or deceptive content. It appears to be a genuine communication.';
    }
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
    const safeDetail = inputType === 'URL'
      ? 'The domain matches a verified, trusted source and no phishing indicators, suspicious TLDs, or deceptive redirects were found.'
      : inputType === 'UPI'
      ? 'The UPI ID follows standard formatting and no known reverse-charge or PIN-trap patterns were detected.'
      : 'The message does not contain known fraud keywords, urgency triggers, OTP requests, or suspicious links.';

    whyUnsafe = `Our multi-layer threat analysis did not detect any known fraud signatures, deceptive domains, or malicious patterns. ${safeDetail}`;
    attackVector = 'No Active Threat Detected';
    psychologicalTactics = ['Normal communication', 'No coercive language detected'];
    technicalImpact = 'Safe to interact with normal caution.';
    checklist = [
      'Ensure the browser address bar shows the correct lock icon (HTTPS) before entering any information.',
      'Verify you initiated this interaction yourself rather than following an unexpected link.',
      'Never disclose your passwords, UPI PIN, or OTP to anyone — not even bank staff.'
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

    // Pick specific psychological tactics based on category
    if (categoryTitle.includes('Electricity') || categoryTitle.includes('Utility')) {
      psychologicalTactics = [
        'Fear & Intimidation (Threat of immediate power disconnection)',
        'Artificial Urgency (Specific deadline like "tonight at 9:30 PM")',
        'Authority Impersonation (Fake electricity officer or DISCOM helpline)'
      ];
      whyUnsafe = `This message is a classic Electricity Disconnection Scam. The scammer poses as a utility officer and creates panic with a fake disconnection deadline to make you call their number or download a screen-sharing app. No real electricity board sends threats over personal mobile numbers or WhatsApp. They also NEVER ask you to pay through unofficial UPI IDs or phone call instructions.`;
    } else if (categoryTitle.includes('KYC') || categoryTitle.includes('Bank') || categoryTitle.includes('Suspension')) {
      psychologicalTactics = [
        'Fear of Account Loss (Claiming your bank account is blocked)',
        'Urgency to Comply (Immediate verification required)',
        'Brand Impersonation (Mimicking SBI, HDFC, ICICI, or RBI)'
      ];
      whyUnsafe = `This is a Bank KYC / Account Suspension scam. The message impersonates your bank and claims your account is blocked unless you click a link or call a number. Legitimate banks NEVER send links to update KYC, PAN, or Aadhaar via SMS or WhatsApp. If you click the link, a fake bank login page steals your NetBanking credentials and live OTP in real time.`;
    } else if (categoryTitle.includes('Task') || categoryTitle.includes('Job') || categoryTitle.includes('YouTube')) {
      psychologicalTactics = [
        'Greed / Easy Income Bait (₹500–₹5000 per day for simple tasks)',
        'Initial Trust Building (First few payments are real to build confidence)',
        'Investment Trap (Later demands for deposits to "unlock" bigger commissions)'
      ];
      whyUnsafe = `This is the notorious Task / Part-Time Job scam (also called "Pig Butchering"). Victims are paid small amounts initially for liking YouTube videos or rating hotels. Once trust is established, they're pressured to deposit large sums into crypto wallets or dummy merchant accounts to "unlock higher paying tasks" — and then the scammer vanishes with all the money.`;
    } else if (categoryTitle.includes('Digital Arrest') || categoryTitle.includes('CBI') || categoryTitle.includes('Police')) {
      psychologicalTactics = [
        'Extreme Fear (Fake CBI/Narcotics arrest warrant)',
        'Isolation Tactic ("Do not tell anyone, stay on video call")',
        'Authority Impersonation (Police, CBI, Customs Officer uniforms on video)'
      ];
      whyUnsafe = `CRITICAL: This is a "Digital Arrest" scam. Fraudsters pose as CBI, Narcotics, or Customs officers on video calls and claim your Aadhaar/phone is linked to illegal activity. The Supreme Court and Ministry of Home Affairs have confirmed: DIGITAL ARREST DOES NOT EXIST in Indian law. No real law enforcement agency interrogates citizens via Skype, WhatsApp, or demands "verification payments."`;
    } else if (categoryTitle.includes('Lottery') || categoryTitle.includes('KBC')) {
      psychologicalTactics = [
        'Greed / Euphoria Bait (Fake multi-lakh prize announcement)',
        'Processing Fee Trap (Pay small fee to claim large prize)',
        'Fake Authority (KBC, Tata, Government lottery branding)'
      ];
      whyUnsafe = `This is an advance-fee lottery scam. You are told you won a prize you never entered. Before "receiving" it, you're asked to pay processing fees, GST, or custom clearance charges. Once you pay, the scammers demand more fees or disappear. No legitimate lottery announces winners via personal SMS or WhatsApp.`;
    } else {
      psychologicalTactics = [
        'Fear & Intimidation (Threats of legal action, account freezing, or disconnection)',
        'Extreme Urgency (Artificial deadlines like "within 2 hours" or "tonight")',
        'Authority Impersonation (Falsely claiming to be bank, police, or government officer)',
        'Greed / Euphoria Bait (Promising effortless income or prizes)'
      ];
      whyUnsafe = `This message is engineered using social engineering tactics to manipulate your emotions. Whether it uses fear (legal notices, disconnection threats) or greed (easy jobs, lottery prizes), the goal is identical: rush you into making an unverified payment, clicking a phishing link, or calling a scammer's number. Legitimate institutions never send threats or prize announcements over personal mobile numbers.`;
    }

    technicalImpact = 'Compromise of bank accounts through credential harvesting, unauthorized UPI collect traps, or installation of remote-access trojans (RATs).';

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
