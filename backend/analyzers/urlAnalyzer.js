/**
 * URL and Link Pattern Analyzer
 * Detects deceptive domains, typosquatting, suspicious TLDs, IP hosts, and phishing keywords.
 */

// Well-known high-risk TLDs heavily abused in disposable phishing campaigns
const SUSPICIOUS_TLDS = [
  '.xyz', '.top', '.club', '.work', '.click', '.icu', '.loan', '.cam',
  '.rip', '.live', '.cc', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz',
  '.online', '.site', '.monster', '.website', '.rest', '.quest', '.skin'
];

// Official verified brand apex domains
const OFFICIAL_BRAND_DOMAINS = {
  sbi: ['sbi.co.in', 'onlinesbi.sbi', 'sbi.bank', 'statebankofindia.com'],
  hdfc: ['hdfcbank.com', 'hdfc.com'],
  icici: ['icicibank.com'],
  axis: ['axisbank.com'],
  kotak: ['kotak.com'],
  pnb: ['pnbindia.in'],
  paytm: ['paytm.com'],
  phonepe: ['phonepe.com'],
  amazon: ['amazon.in', 'amazon.com'],
  flipkart: ['flipkart.com'],
  google: ['google.com', 'google.co.in'],
  apple: ['apple.com'],
  netflix: ['netflix.com'],
  uidai: ['uidai.gov.in'],
  incometax: ['incometax.gov.in'],
  cybercrime: ['cybercrime.gov.in'],
  npci: ['npci.org.in']
};

// Verified authentic domains (whitelist)
const VERIFIED_AUTHENTIC_DOMAINS = [
  'google.com', 'google.co.in', 'youtube.com', 'microsoft.com', 'apple.com',
  'amazon.in', 'amazon.com', 'flipkart.com', 'sbi.co.in', 'onlinesbi.sbi',
  'hdfcbank.com', 'icicibank.com', 'axisbank.com', 'kotak.com',
  'npci.org.in', 'cybercrime.gov.in', 'uidai.gov.in', 'incometax.gov.in',
  'rbi.org.in', 'gov.in', 'nic.in', 'github.com', 'wikipedia.org',
  'paytm.com', 'phonepe.com'
];

// URL shorteners that mask final destination
const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly', 'rb.gy', 'shorturl.at',
  'ow.ly', 'buff.ly', 'rebrand.ly', 'tiny.cc', 'bl.ink'
];

// High-risk keywords in URL path or parameters
const SENSITIVE_KEYWORDS = [
  { term: 'kyc', label: 'KYC Verification Trap', weight: 30 },
  { term: 'pan-update', label: 'Fake PAN Card Update', weight: 32 },
  { term: 'aadhaar', label: 'Aadhaar Harvesting', weight: 28 },
  { term: 'refund', label: 'Fake Refund Gateway', weight: 28 },
  { term: 'lottery', label: 'Lottery Bait', weight: 32 },
  { term: 'claim-reward', label: 'Deceptive Reward Claim', weight: 30 },
  { term: 'reward-points', label: 'Bank Points Expiry Trap', weight: 28 },
  { term: 'gift-voucher', label: 'Gift Scam Bait', weight: 22 },
  { term: 'electric-bill', label: 'Electricity Bill Extortion', weight: 30 },
  { term: 'login-verify', label: 'Phishing Credential Harvester', weight: 40 },
  { term: 'secure-login', label: 'Fake Secure Login Page', weight: 40 },
  { term: 'verify-account', label: 'Account Verification Phishing', weight: 38 },
  { term: 'account-verify', label: 'Account Verification Phishing', weight: 38 },
  { term: 'signin-verify', label: 'Fake Sign-in Verification', weight: 38 },
  { term: 'update-kyc', label: 'KYC Update Phishing', weight: 35 },
  { term: 'confirm-identity', label: 'Identity Confirmation Trap', weight: 35 },
  { term: 'otp-verify', label: 'OTP Harvesting Page', weight: 40 },
  { term: 'redelivery', label: 'Fake Redelivery Fee Trap', weight: 35 },
  { term: 'tracking-fix', label: 'Fake Parcel Tracking Scam', weight: 35 },
  { term: 'apk', label: 'Malicious Android APK Link', weight: 40 },
  { term: 'login-verify', label: 'Phishing Credential Harvester', weight: 35 },
  { term: 'secure-banking', label: 'Spoofed Banking Portal', weight: 35 },
  { term: 'urgent', label: 'Fabricated Urgency Parameter', weight: 20 },
  { term: 'unblock', label: 'Fake Account Unblock Tool', weight: 30 },
  { term: 'cashback', label: 'Cashback Lure', weight: 25 },
  { term: 'rewards', label: 'Deceptive Reward Lure', weight: 25 }
];

function analyzeUrl(rawInput) {
  const flags = [];
  let riskScore = 5;
  let parsedUrl = null;
  let originalUrl = rawInput.trim();

  // Ensure protocol exists for URL parsing
  let normalizedUrl = originalUrl;
  if (!/^https?:\/\//i.test(normalizedUrl)) {
    normalizedUrl = 'http://' + normalizedUrl;
  }

  try {
    parsedUrl = new URL(normalizedUrl);
  } catch (err) {
    const urlMatch = rawInput.match(/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\/[^\s]*)?/);
    if (urlMatch) {
      try {
        parsedUrl = new URL('http://' + urlMatch[0]);
      } catch (e) {
        flags.push({
          severity: 'HIGH',
          title: 'Malformed or Obfuscated Link Structure',
          detail: 'The link contains irregular formatting used by phishing kits to evade security gateways.'
        });
        return {
          type: 'URL',
          riskScore: 78,
          riskLevel: 'HIGH',
          flags,
          extractedTarget: originalUrl
        };
      }
    } else {
      return null;
    }
  }

  const hostname = parsedUrl.hostname.toLowerCase();
  const pathname = parsedUrl.pathname.toLowerCase();
  const search = parsedUrl.search.toLowerCase();
  const fullHref = parsedUrl.href.toLowerCase();

  // Check 1: Whitelist check
  const isWhitelisted = VERIFIED_AUTHENTIC_DOMAINS.some(trusted => 
    hostname === trusted || hostname.endsWith('.' + trusted)
  );

  if (isWhitelisted && !search.includes('redirect') && !search.includes('url=')) {
    return {
      type: 'URL',
      isLegitimate: true,
      riskScore: 4,
      riskLevel: 'SAFE',
      domain: hostname,
      flags: [{
        severity: 'SAFE',
        title: 'Verified Official Domain',
        detail: `"${hostname}" is verified against known authentic, officially registered digital portals.`
      }],
      summary: 'Legitimate and verified domain. No deceptive markers identified.'
    };
  }

  // Check 2: IP Address as host
  const isIpAddress = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  if (isIpAddress) {
    riskScore += 50;
    flags.push({
      severity: 'CRITICAL',
      title: 'Direct IP Address Used As Hostname',
      detail: `The link directs to raw IP address "${hostname}" instead of a registered domain. Legitimate companies never send banking or account links with raw IP addresses.`
    });
  }

  // Check 3: Homograph / Punycode Attacks
  if (hostname.startsWith('xn--') || /[^\u0000-\u007F]/.test(hostname)) {
    riskScore += 55;
    flags.push({
      severity: 'CRITICAL',
      title: 'Internationalized Punycode / Homograph Attack',
      detail: 'The domain uses deceptive Unicode lookalike characters (IDN homograph attack) to visually imitate a genuine company.'
    });
  }

  // Check 4: Suspicious TLD
  const matchedTld = SUSPICIOUS_TLDS.find(tld => hostname.endsWith(tld));
  if (matchedTld) {
    riskScore += 35;
    flags.push({
      severity: 'HIGH',
      title: `High-Risk Disposable TLD (${matchedTld})`,
      detail: `The domain uses an inexpensive top-level domain (${matchedTld}) frequently used in short-lived phishing attacks to avoid domain registrar vetting.`
    });
  }

  // Check 5: Brand Impersonation & Typosquatting
  for (const [brand, officialDomains] of Object.entries(OFFICIAL_BRAND_DOMAINS)) {
    if (hostname.includes(brand)) {
      const isOfficial = officialDomains.some(off => hostname === off || hostname.endsWith('.' + off));
      if (!isOfficial) {
        riskScore += 55;
        flags.push({
          severity: 'CRITICAL',
          title: `Brand Impersonation / Fake ${brand.toUpperCase()} Domain`,
          detail: `The domain "${hostname}" incorporates the brand name "${brand.toUpperCase()}", but is NOT the official domain (${officialDomains.join(', ')}). This is an active phishing trap.`
        });
        break;
      }
    }
  }

  // Check 6: Free Hosting Platforms Abused for Phishing
  const freeHostingServices = ['web.app', 'firebaseapp.com', 'pages.dev', 'github.io', 'vercel.app', 'glitch.me', '000webhostapp.com'];
  const isFreeHost = freeHostingServices.some(service => hostname.endsWith(service));
  if (isFreeHost) {
    const hasSensitiveKeyword = SENSITIVE_KEYWORDS.some(k => fullHref.includes(k.term));
    if (hasSensitiveKeyword) {
      riskScore += 45;
      flags.push({
        severity: 'CRITICAL',
        title: 'Abuse of Free Hosting Service for Phishing Portal',
        detail: `The link is hosted on a free app cloud platform (${hostname}) while asking for sensitive credentials, a common tactic to bypass domain reputation filters.`
      });
    } else {
      riskScore += 20;
      flags.push({
        severity: 'MEDIUM',
        title: 'Free / Unverified Web Hosting Provider',
        detail: `The link is hosted on a free developer platform (${hostname}). Be cautious before entering private information.`
      });
    }
  }

  // Check 7: URL Shorteners masking destination
  const isShortener = URL_SHORTENERS.some(short => hostname === short || hostname.endsWith('.' + short));
  if (isShortener) {
    riskScore += 25;
    flags.push({
      severity: 'MEDIUM',
      title: 'Obfuscated Destination via URL Shortener',
      detail: `The link uses a URL masking service (${hostname}) to hide where you will actually be redirected. Scammers use this to conceal malicious targets from SMS filters.`
    });
  }

  // Check 8: Sensitive Keywords in path or parameters
  for (const keyword of SENSITIVE_KEYWORDS) {
    if (pathname.includes(keyword.term) || search.includes(keyword.term)) {
      riskScore += keyword.weight;
      flags.push({
        severity: keyword.weight >= 30 ? 'CRITICAL' : 'HIGH',
        title: `Phishing Lure Keyword Detected: "${keyword.term}"`,
        detail: `${keyword.label} found in path. Attackers construct fake endpoints using these terms to trick users into submitting OTPs or credentials.`
      });
    }
  }

  // Check 9: Suspicious file extensions (Malicious APK, executable)
  if (pathname.endsWith('.apk') || pathname.endsWith('.exe') || pathname.endsWith('.scr') || pathname.endsWith('.bat')) {
    riskScore += 55;
    flags.push({
      severity: 'CRITICAL',
      title: 'Direct Android APK / Executable Malware Download',
      detail: 'The link prompts an automatic or direct file download (.apk / .exe). Trojans disguised as "Bank Update" or "Rewards APK" steal SMS OTPs and control devices.'
    });
  }

  // Check 10: Excessive hyphens
  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    riskScore += 18;
    flags.push({
      severity: 'HIGH',
      title: 'High Domain Hyphen Entropy',
      detail: `The domain contains ${hyphenCount} hyphens (${hostname}), a common indicator of algorithmically generated phishing links.`
    });
  }

  // Check 11: Suspicious action words in hostname itself
  const suspiciousHostnamePatterns = [
    { pattern: /secure.*login|login.*secure/i, label: 'Fake Secure Login Domain', weight: 45 },
    { pattern: /verify.*account|account.*verify/i, label: 'Account Verification Phishing Domain', weight: 45 },
    { pattern: /update.*kyc|kyc.*update/i, label: 'KYC Update Phishing Domain', weight: 45 },
    { pattern: /signin.*verify|verify.*signin/i, label: 'Fake Sign-in Domain', weight: 45 },
    { pattern: /otp.*verify|verify.*otp/i, label: 'OTP Harvesting Domain', weight: 50 },
    { pattern: /dhl.*track|fedex.*track|indiapost.*track/i, label: 'Fake Courier Tracking Domain', weight: 40 },
    { pattern: /redelivery|redeliver/i, label: 'Fake Redelivery Domain', weight: 40 },
    { pattern: /bank.*login|login.*bank/i, label: 'Fake Bank Login Domain', weight: 50 },
    { pattern: /refund.*claim|claim.*refund/i, label: 'Fake Refund Claim Domain', weight: 45 },
  ];

  for (const { pattern, label, weight } of suspiciousHostnamePatterns) {
    if (pattern.test(hostname)) {
      riskScore += weight;
      flags.push({
        severity: 'CRITICAL',
        title: `Deceptive Domain Pattern: ${label}`,
        detail: `The domain "${hostname}" contains action words (login, verify, secure, track) designed to impersonate official services and harvest credentials.`
      });
      break;
    }
  }

  // Clamp risk score to 0-100
  riskScore = Math.min(Math.max(riskScore, 5), 99);

  let riskLevel = 'LOW';
  if (riskScore >= 85) riskLevel = 'CRITICAL';
  else if (riskScore >= 65) riskLevel = 'HIGH';
  else if (riskScore >= 40) riskLevel = 'MEDIUM';

  return {
    type: 'URL',
    domain: hostname,
    fullUrl: parsedUrl.href,
    riskScore,
    riskLevel,
    flags
  };
}

module.exports = { analyzeUrl, VERIFIED_AUTHENTIC_DOMAINS };
