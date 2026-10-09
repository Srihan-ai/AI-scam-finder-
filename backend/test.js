const { scanContent } = require('./analyzers/mainScanner');

const testCases = [
  {
    name: 'Phishing URL test',
    input: 'http://sbi-rewards-gift.xyz/kyc-update/login.php?user=test'
  },
  {
    name: 'UPI Reverse Charge test',
    input: 'Congratulations! You won ₹15,000 refund. Enter your UPI PIN in PhonePe to receive money immediately.'
  },
  {
    name: 'Electricity Disconnection test',
    input: 'Dear Customer, your electricity power will be disconnected tonight at 9:30 PM because previous month bill was not updated. Please contact electricity officer at 9876543210 immediately.'
  },
  {
    name: 'Legitimate URL test',
    input: 'https://www.hdfcbank.com'
  }
];

console.log('--- TESTING AI SCAM SCANNER ENGINE ---');
for (const tc of testCases) {
  const result = scanContent(tc.input);
  console.log(`\nTest: ${tc.name}`);
  console.log(`Type: ${result.detectedType} | Score: ${result.riskScore}/100 | Risk: ${result.riskLevel}`);
  console.log(`Flags Count: ${result.flags.length}`);
  console.log(`AI Explanation Summary: ${result.aiExplanation.whyUnsafe.substring(0, 100)}...`);
}
console.log('\nAll scanner tests completed successfully!');
