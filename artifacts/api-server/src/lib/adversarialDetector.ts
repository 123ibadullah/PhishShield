/**
 * Adversarial attack detection for phishing emails
 * Detects various evasion techniques used by attackers to bypass detection
 */

import { logger } from './logger.js';

export interface AdversarialDetectionResult {
    /** Whether any adversarial techniques were detected */
    detected: boolean;
    /** List of detected adversarial techniques */
    techniques: string[];
    /** Confidence score (0-100) */
    confidence: number;
    /** Normalized text after removing adversarial artifacts */
    normalizedText: string;
    /** Explanation of detected techniques */
    explanation: string;
}

/**
 * Detects homoglyph attacks where attackers use similar-looking characters
 * from different Unicode scripts to mimic legitimate domains or keywords
 */
function detectHomoglyphs(text: string): { detected: boolean; techniques: string[]; normalizedText: string } {
    const techniques: string[] = [];
    let normalizedText = text;

    // Common homoglyph substitutions
    const homoglyphMap: Record<string, string> = {
        // Latin 'a' lookalikes
        'а': 'a', // Cyrillic 'а'
        'α': 'a', // Greek alpha
        // Latin 'c' lookalikes
        'с': 'c', // Cyrillic 'с'
        // Latin 'e' lookalikes
        'е': 'e', // Cyrillic 'е'
        'ё': 'e', // Cyrillic 'ё'
        'ε': 'e', // Greek epsilon
        // Latin 'o' lookalikes
        'о': 'o', // Cyrillic 'о'
        'ο': 'o', // Greek omicron
        'θ': 'o', // Greek theta (sometimes used)
        // Latin 'p' lookalikes
        'р': 'p', // Cyrillic 'р'
        // Latin 'x' lookalikes
        'х': 'x', // Cyrillic 'х'
        'χ': 'x', // Greek chi
        // Latin 'y' lookalikes
        'у': 'y', // Cyrillic 'у'
        'γ': 'y', // Greek gamma
        // Digit '0' lookalikes
        'Ο': '0', // Greek capital omicron
        'О': '0', // Cyrillic capital O
        // Digit '1' lookalikes
        'Ӏ': '1', // Cyrillic palochka
        'Ⅰ': '1', // Roman numeral I
        'l': '1', // lowercase L
        '|': '1', // pipe
        // Digit '2' lookalikes
        'ƻ': '2', // Latin letter
        // Digit '3' lookalikes
        'Ʒ': '3', // Latin letter
        // Digit '4' lookalikes
        'Ꮞ': '4', // Cherokee letter
        // Digit '5' lookalikes
        'Ƽ': '5', // Latin letter
        // Digit '6' lookalikes
        'б': '6', // Cyrillic be
        // Digit '8' lookalikes
        'Ȣ': '8', // Latin letter
        '∞': '8', // infinity symbol
        // Digit '9' lookalikes
        'գ': '9', // Armenian letter
    };

    let detected = false;
    let normalized = text;

    // Check for homoglyphs
    for (const [homoglyph, replacement] of Object.entries(homoglyphMap)) {
        if (text.includes(homoglyph)) {
            detected = true;
            techniques.push(`homoglyph-${replacement}`);
            normalized = normalized.split(homoglyph).join(replacement);
        }
    }

    // Also check for mixed script (e.g., Latin + Cyrillic in same word)
    const mixedScriptPattern = /[a-zA-Z].*[\u0400-\u04FF]|[\u0400-\u04FF].*[a-zA-Z]/;
    if (mixedScriptPattern.test(text)) {
        detected = true;
        techniques.push('mixed-script');
    }

    return { detected, techniques, normalizedText: normalized };
}

/**
 * Detects URL obfuscation techniques
 */
function detectUrlObfuscation(text: string): { detected: boolean; techniques: string[] } {
    const techniques: string[] = [];

    // Check for URL encoding
    const urlEncodedPattern = /%[0-9a-fA-F]{2}/g;
    const urlEncodedMatches = text.match(urlEncodedPattern);
    if (urlEncodedMatches && urlEncodedMatches.length > 3) {
        techniques.push('url-encoding');
    }

    // Check for hex encoding
    const hexEncodedPattern = /\\x[0-9a-fA-F]{2}/g;
    const hexMatches = text.match(hexEncodedPattern);
    if (hexMatches && hexMatches.length > 3) {
        techniques.push('hex-encoding');
    }

    // Check for double encoding
    const doubleEncodedPattern = /%25[0-9a-fA-F]{2}/g;
    const doubleMatches = text.match(doubleEncodedPattern);
    if (doubleMatches && doubleMatches.length > 0) {
        techniques.push('double-encoding');
    }

    // Check for punycode (starts with xn--)
    const punycodePattern = /xn--[a-zA-Z0-9-]+/g;
    const punycodeMatches = text.match(punycodePattern);
    if (punycodeMatches && punycodeMatches.length > 0) {
        techniques.push('punycode');
    }

    return { detected: techniques.length > 0, techniques };
}

/**
 * Detects HTML entity encoding
 */
function detectHtmlEncoding(text: string): { detected: boolean; techniques: string[]; normalizedText: string } {
    const techniques: string[] = [];
    let normalizedText = text;

    // Common HTML entities (encoded -> decoded)
    const htmlEntities: Record<string, string> = {
        '<': '<',
        '>': '>',
        '&': '&',
        '"': '"',
        ''': "'",
        '&#x27;': "'",
        '&#x2F;': '/',
        '&#x60;': '`',
        '&#x3D;': '=',
        '&#x25;': '%',
        '&#x40;': '@',
        '&#x24;': '$',
        '&#x23;': '#',
    };

    let detected = false;
    let normalized = text;

    for (const [entity, replacement] of Object.entries(htmlEntities)) {
        if (text.includes(entity)) {
            detected = true;
            techniques.push(`html-entity-${replacement}`);
            normalized = normalized.split(entity).join(replacement);
        }
    }

    // Also check for numeric HTML entities (&#65; or &#x41;)
    const numericEntityPattern = /&#([0-9]+);|&#x([0-9a-fA-F]+);/g;
    const numericMatches = text.match(numericEntityPattern);
    if (numericMatches && numericMatches.length > 3) {
        detected = true;
        techniques.push('numeric-html-entities');
    }

    return { detected, techniques, normalizedText: normalized };
}

/**
 * Detects zero-width and invisible characters
 */
function detectInvisibleChars(text: string): { detected: boolean; techniques: string[]; normalizedText: string } {
    const techniques: string[] = [];

    // Zero-width characters
    const zeroWidthPattern = /[\u200B-\u200D\uFEFF\u2060\u180E]/g;
    const zeroWidthMatches = text.match(zeroWidthPattern);
    if (zeroWidthMatches && zeroWidthMatches.length > 0) {
        techniques.push('zero-width-chars');
    }

    // Remove zero-width characters
    const normalizedText = text.replace(zeroWidthPattern, '');

    // Invisible separator characters
    const invisibleSeparators = /[\u2063\u2064\u2062]/g;
    const invisibleMatches = text.match(invisibleSeparators);
    if (invisibleMatches && invisibleMatches.length > 0) {
        techniques.push('invisible-separators');
    }

    // Bidirectional control characters (used for text direction attacks)
    const bidiPattern = /[\u202A-\u202E\u200E\u200F\u061C]/g;
    const bidiMatches = text.match(bidiPattern);
    if (bidiMatches && bidiMatches.length > 0) {
        techniques.push('bidi-control-chars');
    }

    return {
        detected: techniques.length > 0,
        techniques,
        normalizedText: normalizedText.replace(invisibleSeparators, '').replace(bidiPattern, '')
    };
}

/**
 * Detects base64 encoded content in text
 */
function detectBase64(text: string): { detected: boolean; techniques: string[] } {
    const techniques: string[] = [];

    // Base64 pattern (rough detection)
    const base64Pattern = /[A-Za-z0-9+/]{20,}={0,2}/g;
    const base64Matches = text.match(base64Pattern);

    if (base64Matches && base64Matches.length > 0) {
        // Check if any match looks like actual base64 (has proper length and character distribution)
        for (const match of base64Matches) {
            if (match.length >= 20) {
                techniques.push('base64-encoded');
                break;
            }
        }
    }

    return { detected: techniques.length > 0, techniques };
}

/**
 * Detects noise injection (adding benign text to dilute phishing signals)
 */
function detectNoiseInjection(text: string): { detected: boolean; techniques: string[]; normalizedText: string } {
    const techniques: string[] = [];

    // Common noise patterns
    const noisePatterns = [
        // Repeated benign phrases
        /(thank you|regards|sincerely|best regards|kind regards|yours truly)\s*(,\s*)?[a-zA-Z\s]*(\n\s*){2,}/gi,
        // Long disclaimers
        /(this email is confidential|this message is intended only|if you received this email in error).{50,}/gi,
        // Legal boilerplate
        /(copyright|all rights reserved|confidentiality notice|privileged communication).{30,}/gi,
    ];

    let noiseDetected = false;
    let normalizedText = text;

    for (const pattern of noisePatterns) {
        if (pattern.test(text)) {
            noiseDetected = true;
            techniques.push('noise-injection');
            // Remove the noise (simplified - in reality we'd be more careful)
            normalizedText = normalizedText.replace(pattern, ' ');
            break;
        }
    }

    // Check for excessive benign words ratio
    const words = text.toLowerCase().split(/\s+/).filter(w => w.length > 0);
    const benignWords = ['thanks', 'regards', 'hello', 'hi', 'dear', 'sincerely', 'best', 'kind', 'yours', 'truly'];
    const benignCount = words.filter(w => benignWords.includes(w)).length;
    const totalWords = words.length;

    if (totalWords > 50 && benignCount > totalWords * 0.3) {
        // More than 30% of words are benign greetings/closings
        noiseDetected = true;
        techniques.push('excessive-benign-content');
    }

    return { detected: noiseDetected, techniques, normalizedText };
}

/**
 * Main function to detect adversarial attacks in text
 */
export function detectAdversarialAttacks(text: string): AdversarialDetectionResult {
    if (!text || text.trim().length === 0) {
        return {
            detected: false,
            techniques: [],
            confidence: 0,
            normalizedText: text,
            explanation: 'Empty text'
        };
    }

    const allTechniques: string[] = [];
    let normalizedText = text;

    // Run all detectors
    const homoglyphResult = detectHomoglyphs(normalizedText);
    if (homoglyphResult.detected) {
        allTechniques.push(...homoglyphResult.techniques);
        normalizedText = homoglyphResult.normalizedText;
    }

    const urlObfuscationResult = detectUrlObfuscation(normalizedText);
    if (urlObfuscationResult.detected) {
        allTechniques.push(...urlObfuscationResult.techniques);
    }

    const htmlEncodingResult = detectHtmlEncoding(normalizedText);
    if (htmlEncodingResult.detected) {
        allTechniques.push(...htmlEncodingResult.techniques);
        normalizedText = htmlEncodingResult.normalizedText;
    }

    const invisibleCharsResult = detectInvisibleChars(normalizedText);
    if (invisibleCharsResult.detected) {
        allTechniques.push(...invisibleCharsResult.techniques);
        normalizedText = invisibleCharsResult.normalizedText;
    }

    const base64Result = detectBase64(normalizedText);
    if (base64Result.detected) {
        allTechniques.push(...base64Result.techniques);
    }

    const noiseResult = detectNoiseInjection(normalizedText);
    if (noiseResult.detected) {
        allTechniques.push(...noiseResult.techniques);
        normalizedText = noiseResult.normalizedText;
    }

    // Calculate confidence based on number and severity of techniques
    const confidence = Math.min(100, allTechniques.length * 15);

    // Generate explanation
    let explanation = 'No adversarial techniques detected.';
    if (allTechniques.length > 0) {
        const uniqueTechniques = [...new Set(allTechniques)];
        explanation = `Detected ${uniqueTechniques.length} adversarial technique(s): ${uniqueTechniques.join(', ')}.`;
    }

    logger.debug('Adversarial attack detection completed', {
        techniques: allTechniques,
        confidence,
        originalLength: text.length,
        normalizedLength: normalizedText.length
    });

    return {
        detected: allTechniques.length > 0,
        techniques: allTechniques,
        confidence,
        normalizedText,
        explanation
    };
}

/**
 * Preprocess text by removing adversarial artifacts before analysis
 * This should be called before running phishing detection
 */
export function preprocessAdversarialText(text: string): string {
    const result = detectAdversarialAttacks(text);
    return result.normalizedText;
}