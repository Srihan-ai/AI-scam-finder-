/**
 * Adversarial Normalizer & Evasion Detection Module
 * Strips zero-width characters, maps homoglyphs, decodes leetspeak,
 * detects keyword spacing evasion, and normalizes Hinglish scam phrasing.
 */

// Common Cyrillic / Greek lookalike homoglyphs mapping to ASCII Latin
const HOMOGLYPH_MAP = {
  '\u0430': 'a', // Cyrillic small a
  '\u0410': 'A', // Cyrillic capital A
  '\u0435': 'e', // Cyrillic small e
  '\u0415': 'E', // Cyrillic capital E
  '\u043E': 'o', // Cyrillic small o
  '\u041E': 'O', // Cyrillic capital O
  '\u0440': 'p', // Cyrillic small er
  '\u0420': 'P', // Cyrillic capital Er
  '\u0441': 'c', // Cyrillic small es
  '\u0421': 'C', // Cyrillic capital Es
  '\u0443': 'y', // Cyrillic small u
  '\u0423': 'Y', // Cyrillic capital U
  '\u0445': 'x', // Cyrillic small ha
  '\u0425': 'X', // Cyrillic capital Ha
  '\u0456': 'i', // Cyrillic small Byelorussian-Ukrainian i
  '\u0406': 'I', // Cyrillic capital I
  '\u0458': 'j', // Cyrillic small je
  '\u0408': 'J', // Cyrillic capital Je
  '\u03BF': 'o', // Greek small omicron
  '\u039F': 'O', // Greek capital Omicron
  '\u03B1': 'a', // Greek small alpha
  '\u0391': 'A', // Greek capital Alpha
  '\u03C1': 'p', // Greek small rho
  '\u03A1': 'P'  // Greek capital Rho
};

function normalizeAdversarialText(rawText) {
  if (!rawText || typeof rawText !== 'string') return { normalizedText: '', evasionFlags: [] };

  const evasionFlags = [];
  let text = rawText;

  // 1. Detect and strip Zero-Width and Hidden Unicode Characters
  const zeroWidthRegex = /[\u200B-\u200D\uFEFF\u202A-\u202E\u2060-\u206F]/g;
  if (zeroWidthRegex.test(text)) {
    evasionFlags.push({
      severity: 'CRITICAL',
      title: 'Adversarial Zero-Width Unicode Evasion Detected',
      detail: 'The input contains hidden zero-width or directional override characters inserted by scammers to evade automated regex and NLP security filters.'
    });
    text = text.replace(zeroWidthRegex, '');
  }

  // 2. Detect and normalize Homoglyphs / Lookalikes
  let hasHomoglyphs = false;
  let normalizedHomoglyphs = '';
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (HOMOGLYPH_MAP[char]) {
      hasHomoglyphs = true;
      normalizedHomoglyphs += HOMOGLYPH_MAP[char];
    } else {
      normalizedHomoglyphs += char;
    }
  }

  if (hasHomoglyphs) {
    evasionFlags.push({
      severity: 'CRITICAL',
      title: 'Homoglyph / Punycode Deception Detected',
      detail: 'Non-Latin Cyrillic or Greek characters were detected imitating standard Latin characters (e.g. Cyrillic "а" or "р" used to spoof brands or words).'
    });
    text = normalizedHomoglyphs;
  }

  // 3. Detect spaced-out evasive words (e.g. "e n t e r   p i n", "u p i   p i n", "k y c")
  const spacedKeywordPatterns = [
    { pattern: /\bu\s+p\s+i\b/gi, replacement: 'upi' },
    { pattern: /\bp\s+i\s+n\b/gi, replacement: 'pin' },
    { pattern: /\bm\s*p\s*i\s*n\b/gi, replacement: 'mpin' },
    { pattern: /\bk\s+y\s+c\b/gi, replacement: 'kyc' },
    { pattern: /\be\s+n\s+t\s+e\s+r\b/gi, replacement: 'enter' },
    { pattern: /\bo\s+t\s+p\b/gi, replacement: 'otp' },
    { pattern: /\bs\s+b\s+i\b/gi, replacement: 'sbi' },
    { pattern: /\bh\s+d\s+f\s+c\b/gi, replacement: 'hdfc' }
  ];

  let hasSpacedEvasion = false;
  for (const { pattern, replacement } of spacedKeywordPatterns) {
    if (pattern.test(text)) {
      hasSpacedEvasion = true;
      text = text.replace(pattern, replacement);
    }
  }

  if (hasSpacedEvasion) {
    evasionFlags.push({
      severity: 'HIGH',
      title: 'Keyword Character Spacing Evasion Detected',
      detail: 'Keywords were deliberately spaced out (e.g. "p i n" or "u p i") to circumvent security pattern scanners.'
    });
  }

  // 4. Normalize common leetspeak substitutions in high-risk phrases
  // e.g. "3nt3r" -> "enter", "p1n" -> "pin", "cl1ck" -> "click"
  const leetPatterns = [
    { pattern: /\b3nt3r\b/gi, replacement: 'enter' },
    { pattern: /\bp1n\b/gi, replacement: 'pin' },
    { pattern: /\bcl1ck\b/gi, replacement: 'click' },
    { pattern: /\br3c31v3\b/gi, replacement: 'receive' },
    { pattern: /\bl0tt3ry\b/gi, replacement: 'lottery' },
    { pattern: /\bk¥c\b/gi, replacement: 'kyc' }
  ];

  let hasLeetEvasion = false;
  for (const { pattern, replacement } of leetPatterns) {
    if (pattern.test(text)) {
      hasLeetEvasion = true;
      text = text.replace(pattern, replacement);
    }
  }

  if (hasLeetEvasion) {
    evasionFlags.push({
      severity: 'HIGH',
      title: 'Obfuscated Leetspeak Evasion Detected',
      detail: 'Numbers and symbols were used to mask sensitive trigger keywords (e.g. "3nt3r p1n").'
    });
  }

  return {
    normalizedText: text,
    evasionFlags
  };
}

module.exports = { normalizeAdversarialText };
