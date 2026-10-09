/**
 * Message and Text Pattern Analyzer
 * Detects SMS, WhatsApp, and Telegram fraud patterns across banking, utility, job, lottery, UPI, and digital arrest vectors.
 */

const SCAM_CATEGORIES = [
  {
    id: 'UPI_REVERSE_CHARGE',
    name: 'UPI Reverse Charge / PIN Receive Trap',
    patterns: [
      /(?:enter|type|give|submit)\s+(?:your\s+)?(?:upi\s+)?(?:m?pin|pin|code)[\s\w,]{0,45}(?:receive|get|claim|credit|accept|collect)/i,
      /(?:receive|claim|get|credit|collect)\s+[\w\s,]{0,35}(?:enter|type|submit)\s+(?:your\s+)?(?:upi\s+)?(?:m?pin|pin)/i,
      /(?:scan|scan\s+this)\s+(?:qr|code)[\s\w,]{0,35}(?:receive|get\s+money|claim|credit)/i,
      /approve\s+(?:collect\s+request|request)[\s\w,]{0,35}(?:receive|get|claim)/i,
      /enter\s+pin\s+for\s+(?:refund|cashback|bonus)/i
    ],
    requiredMatches: 1,
    baseScore: 99,
    explanation: 'DANGER: The message claims you must enter your UPI PIN or scan a QR code to receive money. Under UPI specifications, a PIN is NEVER required to receive money. Entering your PIN will instantly deduct money from your bank account.'
  },
  {
    id: 'ELECTRICITY_SCAM',
    name: 'Electricity / Utility Disconnection Threat',
    patterns: [
      /(?:electricity|power)\s+(?:will\s+be\s+)?(?:disconnected|cut|terminated|shut\s+off)/i,
      /(?:previous|last)\s+month\s+bill\s+not\s+(?:updated|paid)/i,
      /(?:tonight\s+at\s+)?(?:9:?30|8:?30|10:?00)\s*(?:pm|hours)/i,
      /contact\s+(?:electricity\s+)?officer/i,
      /(?:bescom|mahadiscom|tneb|uppcl|dhbvn|bses)\s+(?:helpline|bill|payment)/i
    ],
    requiredMatches: 2,
    baseScore: 94,
    explanation: 'Scammers send fake power disconnection warnings with urgent deadlines (often "tonight at 9:30 PM") and ask victims to call a personal mobile number or download a screen-sharing app to settle an alleged pending bill.'
  },
  {
    id: 'KYC_BANK_SUSPENSION',
    name: 'Bank Account / KYC / PAN Card Suspension',
    patterns: [
      /(?:account|card|sim|netbanking)\s+(?:has\s+been\s+)?(?:blocked|suspended|deactivated|frozen|hold)/i,
      /(?:update|link|verify)\s+(?:your\s+)?(?:kyc|pan|aadhaar|pan\s+card)/i,
      /(?:sbi|hdfc|icici|axis|pnb|bob|kotak|canara)\s+(?:customer|account|user)/i,
      /(?:mandatory|immediately)\s+(?:update|click|verify)/i,
      /click\s+(?:here|link)\s+to\s+(?:avoid|unblock|activate|update)/i
    ],
    requiredMatches: 2,
    baseScore: 95,
    explanation: 'Indian banks never send SMS or WhatsApp messages containing external links to update KYC or PAN. This is a classic credential harvesting tactic designed to steal your NetBanking ID, password, and OTP.'
  },
  {
    id: 'TASK_JOB_SCAM',
    name: 'Task-Based Part-Time Job / YouTube Like Scam',
    patterns: [
      /(?:part\s*time\s*job|work\s*from\s*home|freelance\s*job)/i,
      /(?:earn|salary|daily\s*income)\s*(?:rs\.?|inr|₹)?\s*(?:[1-9][0-9]{2,4})\s*(?:to|-)\s*(?:[1-9][0-9]{3,5})?/i,
      /(?:like|subscribe)\s+(?:youtube\s+videos|channels)/i,
      /(?:rate|review)\s+(?:hotels|products|google\s+maps)/i,
      /(?:contact|telegram|whatsapp)\s+(?:hr|manager|receptionist|mentor)/i,
      /(?:daily\s+payment|instant\s+withdrawal|prepaid\s+task)/i
    ],
    requiredMatches: 2,
    baseScore: 90,
    explanation: 'This is the notorious "Task/Telegram" or "Pig Butchering" scam. Victims are initially paid ₹150-₹500 for trivial tasks, and are then coerced into depositing thousands into crypto or dummy merchant wallets under the promise of high commissions.'
  },
  {
    id: 'DIGITAL_ARREST_SCAM',
    name: 'Digital Arrest / Cyber Police & CBI Impersonation',
    patterns: [
      /(?:digital\s+arrest|cbi|narcotics\s+control|customs\s+department|delhi\s+police|mumbai\s+police)/i,
      /(?:fir\s+registered|arrest\s+warrant|court\s+notice|money\s+laundering)/i,
      /(?:illegal\s+parcel|drugs|passports|taiwan|cambodia)/i,
      /(?:stay\s+on\s+video\s+call|skype\s+verification|do\s+not\s+disconnect)/i,
      /(?:seize\s+assets|verification\s+of\s+funds)/i
    ],
    requiredMatches: 2,
    baseScore: 98,
    explanation: 'CRITICAL WARNING: The Supreme Court, Ministry of Home Affairs, and Indian Police have made it clear: THERE IS NO SUCH THING AS "DIGITAL ARREST" in Indian law. Law enforcement NEVER interrogates citizens or issues court bail through Skype or WhatsApp video calls.'
  },
  {
    id: 'PARCEL_CUSTOMS_SCAM',
    name: 'Courier Delivery / Customs Smishing Scam',
    patterns: [
      /(?:india\s*post|fedex|dhl|blue\s*dart|ekart|bluedart)/i,
      /(?:package|parcel|shipment|delivery)\s+(?:failed|held|detained|stuck|stopped)/i,
      /(?:incorrect\s+address|update\s+address|street\s+number)/i,
      /(?:within\s+24\s+hours|otherwise\s+returned)/i,
      /(?:customs\s+fee|redelivery\s+charge|pay\s+(?:rs\.?|₹|inr)\s*[0-9]+)/i
    ],
    requiredMatches: 2,
    baseScore: 88,
    explanation: 'Scammers blast automated SMS messages claiming an undelivered parcel with an incorrect address. Clicking the link takes you to a cloned postal site asking for a trivial ₹20-₹49 fee, which then steals full credit/debit card numbers and CVV.'
  },
  {
    id: 'LOTTERY_KBC_SCAM',
    name: 'Lottery / KBC All-India Lucky Draw Fraud',
    patterns: [
      /(?:congratulations|lucky\s*draw|winner|lottery)/i,
      /(?:kbc|kaun\s+banega\s+crorepati|tata\s+safari|25\s+lakh|cheque)/i,
      /(?:call\s+rana\s+pratap|contact\s+manager|claim\s+number)/i,
      /(?:deposit\s+gst|processing\s+fee|clearance\s+charge)/i
    ],
    requiredMatches: 2,
    baseScore: 92,
    explanation: 'Advance-fee fraud. You are told you won a non-existent multi-lakh lottery, but must pay "processing fees", "GST", or "custom clearance" upfront. Once sent, the scammers disappear.'
  },
  {
    id: 'REWARD_POINTS_SCAM',
    name: 'Credit Card / Telecom Reward Points Expiry Scam',
    patterns: [
      /(?:reward\s+points|bonus\s+points)\s+(?:expiring|expired|accumulated)/i,
      /(?:worth|value)\s+(?:rs\.?|₹)?\s*[0-9]{3,5}/i,
      /(?:redeem|convert\s+to\s+cash|claim\s+cashback)/i,
      /(?:sbi\s+card|hdfc\s+reward|icici\s+points|axis\s+edge)/i
    ],
    requiredMatches: 2,
    baseScore: 86,
    explanation: 'Banks do not send SMS messages urging you to "convert expiring points to direct cash" by logging into unknown third-party URLs. Doing so exposes your bank login credentials.'
  },
  {
    id: 'REMOTE_APP_MALWARE',
    name: 'Remote Access Tool / Malicious APK Trap',
    patterns: [
      /(?:download|install)\s+(?:apk|app|application)/i,
      /(?:anydesk|teamviewer|quicksupport|rustdesk|screen\s+share)/i,
      /(?:sbi_yono\.apk|kyc_update\.apk|electric_bill\.apk)/i,
      /(?:grant\s+permission|accessibility\s+service)/i
    ],
    requiredMatches: 1,
    baseScore: 96,
    explanation: 'Scammers trick users into installing remote-access tools (AnyDesk/RustDesk) or custom malicious APKs that bypass 2-Factor Authentication by reading SMS OTPs silently in the background.'
  }
];

const PSYCHOLOGICAL_PRESSURE_WORDS = [
  { phrase: 'immediately', weight: 8 },
  { phrase: 'urgent', weight: 10 },
  { phrase: 'within 24 hours', weight: 12 },
  { phrase: 'tonight', weight: 10 },
  { phrase: 'last warning', weight: 15 },
  { phrase: 'final notice', weight: 15 },
  { phrase: 'account will be closed', weight: 15 },
  { phrase: 'legal action', weight: 15 },
  { phrase: 'police complaint', weight: 15 },
  { phrase: 'do not disclose', weight: 12 },
  { phrase: 'share otp', weight: 25 },
  { phrase: 'tell otp', weight: 25 }
];

function analyzeMessage(text) {
  const flags = [];
  let detectedCategory = null;
  let highestScore = 5;
  const lowerText = text.toLowerCase();

  for (const category of SCAM_CATEGORIES) {
    let matchCount = 0;

    for (const pattern of category.patterns) {
      if (pattern.test(lowerText)) {
        matchCount++;
      }
    }

    if (matchCount >= category.requiredMatches) {
      detectedCategory = category;
      highestScore = Math.max(highestScore, category.baseScore);
      flags.push({
        severity: category.baseScore >= 90 ? 'CRITICAL' : 'HIGH',
        title: `Scam Pattern Detected: ${category.name}`,
        detail: category.explanation
      });
      break;
    }
  }

  let pressureScore = 0;
  const foundPressureTerms = [];
  for (const item of PSYCHOLOGICAL_PRESSURE_WORDS) {
    if (lowerText.includes(item.phrase)) {
      pressureScore += item.weight;
      foundPressureTerms.push(item.phrase);
    }
  }

  if (foundPressureTerms.length > 0) {
    const isHighPressure = pressureScore >= 20;
    highestScore = Math.min(99, highestScore + pressureScore);
    flags.push({
      severity: isHighPressure ? 'HIGH' : 'MEDIUM',
      title: 'High Psychological Coercion & Pressure Tactics',
      detail: `Contains urgency and fear-inducing triggers: "${foundPressureTerms.join('", "')}". Fraudsters use artificial urgency so victims act impulsively without verifying.`
    });
  }

  if (/share\s+(?:your\s+)?otp|send\s+(?:me\s+)?(?:the\s+)?otp|verify\s+(?:with\s+)?otp/i.test(lowerText)) {
    highestScore = 99;
    flags.push({
      severity: 'CRITICAL',
      title: 'Direct OTP Solicitation (Zero Tolerance Indicator)',
      detail: 'The message requests or instructs sharing an OTP. NO BANK, E-COMMERCE FIRM, OR GOVERNMENT BODY EVER ASKS FOR AN OTP OVER CHAT, PHONE, OR FORM.'
    });
  }

  const urlRegex = /(https?:\/\/[^\s]+|[a-zA-Z0-9-]+\.(?:xyz|top|site|online|club|click|apk|link|cc|app|work)[^\s]*)/gi;
  const extractedUrls = text.match(urlRegex) || [];

  const phoneRegex = /(?:\+?91[\-\s]?)?[6-9]\d{9}/g;
  const extractedPhones = text.match(phoneRegex) || [];

  let riskLevel = 'LOW';
  if (highestScore >= 85) riskLevel = 'CRITICAL';
  else if (highestScore >= 65) riskLevel = 'HIGH';
  else if (highestScore >= 40) riskLevel = 'MEDIUM';

  return {
    type: 'MESSAGE',
    category: detectedCategory ? detectedCategory.name : 'General Unverified Message',
    categoryId: detectedCategory ? detectedCategory.id : 'GENERAL',
    riskScore: Math.min(Math.max(highestScore, 5), 99),
    riskLevel,
    extractedUrls,
    extractedPhones,
    flags
  };
}

module.exports = { analyzeMessage, SCAM_CATEGORIES };
