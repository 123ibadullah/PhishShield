const fs = require('fs');
const path = require('path');

const filePath = path.join(__dirname, 'adversarialDetector.ts');
let content = fs.readFileSync(filePath, 'utf8');

console.log('Fixing adversarialDetector.ts...');

// Replace the malformed line ''' with '''
const fixedContent = content.replace(/''': "'",/g, "''': \"'\",");

// Also check for any other occurrences of triple quotes
const lines = fixedContent.split('\n');
let changed = false;
for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes("'''")) {
        console.log(`Found triple quotes at line ${i + 1}: ${JSON.stringify(lines[i])}`);
        lines[i] = lines[i].replace(/'''/g, "'''");
        changed = true;
    }
}

if (changed) {
    fs.writeFileSync(filePath, lines.join('\n'), 'utf8');
    console.log('File fixed successfully.');

    // Verify the fix
    const newContent = fs.readFileSync(filePath, 'utf8');
    const newLines = newContent.split('\n');
    for (let i = 0; i < newLines.length; i++) {
        if (newLines[i].includes("'''")) {
            console.error(`ERROR: Still found triple quotes at line ${i + 1}: ${JSON.stringify(newLines[i])}`);
        }
    }

    // Check line 149 specifically
    if (newLines.length >= 149) {
        console.log(`Line 149 after fix: ${JSON.stringify(newLines[148])}`);
    }
} else {
    console.log('No triple quotes found. File may already be fixed.');
}