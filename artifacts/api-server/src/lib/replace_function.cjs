const fs = require('fs');
const path = require('path');

const filePath = path.join(__dirname, 'adversarialDetector.ts');
let content = fs.readFileSync(filePath, 'utf8');

// Replace the entire detectHtmlEncoding function
const correctedFunction = `/**
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
        techniques.push(\`html-entity-\${replacement}\`);
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
}`;

        // Find the start and end of the function
        const startMarker = '/**\n * Detects HTML entity encoding\n */';
        const endMarker = 'function detectHtmlEncoding(text: string): { detected: boolean; techniques: string[]; normalizedText: string } {';

        // Since the function is large, we'll use a regex to replace the entire function
        const functionRegex = /\/\*\*\s*\n \* Detects HTML entity encoding\s*\n \*\/\s*\nfunction detectHtmlEncoding\(text: string\): \{ detected: boolean; techniques: string\[\]; normalizedText: string \} \{[\s\S]*?\n\}/;

        if (functionRegex.test(content)) {
            content = content.replace(functionRegex, correctedFunction);
            console.log('Function replaced successfully.');
        } else {
            console.log('Function not found with regex, trying manual replacement...');
            // Fallback: split by lines and replace lines 139-180
            const lines = content.split('\n');
            const startIndex = lines.findIndex(line => line.includes('Detects HTML entity encoding'));
            if (startIndex >= 0) {
                // Find the end of the function (look for closing brace at same indentation)
                let endIndex = startIndex;
                let braceCount = 0;
                for (let i = startIndex; i < lines.length; i++) {
                    if (lines[i].includes('{')) braceCount++;
                    if (lines[i].includes('}')) braceCount--;
                    if (braceCount === 0 && i > startIndex) {
                        endIndex = i;
                        break;
                    }
                }
                if (endIndex > startIndex) {
                    const newLines = [...lines.slice(0, startIndex), correctedFunction, ...lines.slice(endIndex + 1)];
                    content = newLines.join('\n');
                    console.log('Manual replacement done.');
                }
            }
        }

        fs.writeFileSync(filePath, content, 'utf8');
        console.log('File updated.');