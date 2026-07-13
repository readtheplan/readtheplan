$api_token = $env:RTP_FIXTURE_EXTERNAL_FACT_POWERSHELL_SECRET_DO_NOT_LEAK
$response = Invoke-RestMethod -SkipCertificateCheck https://powershell-facts.example.invalid/v1
Write-Output "windows_inventory=$response"
