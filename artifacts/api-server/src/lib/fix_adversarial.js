const fs = require('fs');
const path = require('path');

const filePath = path.join(__dirname, 'adversarialDetector.ts');
let content = fs.readFileSync(filePath, 'utf8');

// Replace the malformed line
content = content.replace(/''': "'",/g, "''': \"'\",");

// Also fix the HTML entities to be proper encoded entities
// Replace '<': '<' with '<': '<' etc.
content = content.replace(/'<': '<',/g, "'<': '<',");
content = content.replace(/>': '>',/g, ">': '>',");
content = content.replace(/&': '&',/g, "&': '&',");
content = content.replace(/\"': '\"',/g, ""': '\"',");

fs.writeFileSync(filePath, content, 'utf8');
console.log('File fixed successfully');