const fs = require('fs');
const path = require('path');

const filePath = path.join(__dirname, 'adversarialDetector.ts');
let content = fs.readFileSync(filePath, 'utf8');

// Replace the malformed line
const lines = content.split('\n');
if (lines[148].includes("'''")) {
    lines[148] = "        ''': \"'\",";
    console.log('Fixed line 149');
} else {
    console.log('Line 149 already fixed:', lines[148]);
}

fs.writeFileSync(filePath, lines.join('\n'));
console.log('File updated successfully');