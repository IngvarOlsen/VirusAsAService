$apiUrl = "127.0.0.1:5000/api/virusdownload"
$apiKey = "4f300d801d8a81426755f5d09d2e0db613580d88dbbe6d6359e2f98f49c97019"
$outputFile = "testvirus.zip"

# Prepare the JSON payload
$jsonPayload = @{
    api_key = $apiKey
} | ConvertTo-Json -Depth 1

# Send the request
Invoke-WebRequest -Uri $apiUrl -Method Get -Body $jsonPayload -ContentType "application/json" -OutFile $outputFile