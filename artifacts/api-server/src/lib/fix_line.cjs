const fs = require('fs');
const path = require('path');

const filePath = path.join(__dirname, 'adversarialDetector.ts');
let content = fs.readFileSync(filePath, 'utf8');

console.log('File length:', content.length);

// Find the problematic line
const lines = content.split('\n');
for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes("'''")) {
        console.log(`Found at line ${i + 1}:`, JSON.stringify(lines[i]));
        console.log('Char codes:', [...lines[i]].map(c => c.charCodeAt(0)));
        // Replace the line
        lines[i] = lines[i].replace("'''", "'''");
        console.log('New line:', JSON.stringify(lines[i]));
        break;
    }
}

const newContent = lines.join('\n');
fs.writeFileSync(filePath, newContent, 'utf8');
console.log('File updated.');