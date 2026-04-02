const fs = require('fs');
const path = require('path');

const filePath = path.join(__dirname, 'adversarialDetector.ts');
let content = fs.readFileSync(filePath, 'utf8');

// Split lines
const lines = content.split('\n');
console.log('Original line 149:', JSON.stringify(lines[148]));

// Replace line 149 (0-indexed 148) with correct line
lines[148] = "        ''': \"'\",";

// Write back
fs.writeFileSync(filePath, lines.join('\n'));
console.log('Line replaced');

// Verify
const newContent = fs.readFileSync(filePath, 'utf8');
const newLines = newContent.split('\n');
console.log('New line 149:', JSON.stringify(newLines[148]));