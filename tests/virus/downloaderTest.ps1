$apiUrl = "127.0.0.1:5000/api/virusdownload"
$apiKey = "superSecretApiKey"
$outputFile = "testvirus.zip"

# Prepare the JSON payload
$jsonPayload = @{
    api_key = $apiKey
} | ConvertTo-Json -Depth 1

# Send the request
Invoke-WebRequest -Uri $apiUrl -Method Get -Body $jsonPayload -ContentType "application/json" -OutFile $outputFile