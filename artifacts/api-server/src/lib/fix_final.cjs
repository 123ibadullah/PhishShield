const fs = require('fs');
const path = require('path');

const filePath = path.join(__dirname, 'adversarialDetector.ts');
let content = fs.readFileSync(filePath, 'utf8');

// Replace the malformed line - using regex to find the exact pattern
const lines = content.split('\n');
let changed = false;
for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes("'''")) {
        console.log('Found malformed line at', i + 1, ':', lines[i]);
        lines[i] = lines[i].replace("'''", "'''");
        console.log('Changed to:', lines[i]);
        changed = true;
    }
}

if (!changed) {
    console.log('No malformed line found');
} else {
    fs.writeFileSync(filePath, lines.join('\n'));
    console.log('File updated successfully');
}

// Verify
const newContent = fs.readFileSync(filePath, 'utf8');
const newLines = newContent.split('\n');
console.log('Verification line 149:', JSON.stringify(newLines[148]));