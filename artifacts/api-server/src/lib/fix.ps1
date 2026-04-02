$content = Get-Content -Path "adversarialDetector.ts" -Raw
$content = $content -replace "''': ""'"",", "''': ""'"","
$content = $content -replace "'<': '<',", "'<': '<',"
$content = $content -replace "'>': '>',", "'>': '>',"
$content = $content -replace "'&': '&',", "'&': '&',"
$content = $content -replace "'""': '""',", "'"': '""',"
Set-Content -Path "adversarialDetector.ts" -Value $content -NoNewline
Write-Host "File fixed"