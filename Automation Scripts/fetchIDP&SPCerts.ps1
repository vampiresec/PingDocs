# Genrate SP and IDP cert details report from PingFederate

# Usage: .\fetchIDP&SPCerts.ps1 -Environment [prod|nonprod]

# Prerequisite: Install-Module -Name ImportExcel

# Generate ApiCreds.xml using below script and save in present working directory
# $apiCreds = @{
#     "prod" = @{
#        "client_id" = "<client_id>"
#        "client_secret" = "<client_secret>"
#        "token_url" = "https://auth.pingfederate.com"
#        "api_url" = "https://<pingfederate-admin-prod-api-url>"
#     }
#     "nonprod" = @{
#        "client_id" = "<client_id>"
#       "client_secret" = "<client_secret>"
#        "token_url" = "https://auth.pingfederate.com"
#        "api_url" = "https://<pingfederate-admin-nonprod-api-url>"
#     }
# }
# $secureString = ConvertTo-SecureString (ConvertTo-Json $apiCreds) -AsPlainText -Force
# $secureString | Export-Clixml -Path ".\ApiCreds.xml"
# End of Prerequisite

param(
    [string]$Environment
)
if(!$(Test-Path -Path ".\ApiCreds.xml" -PathType Leaf)){
    Write-Host "ApiCreds.xml not found`nPlease save correct ApiCreds.xml in present working directory "
    exit
}
$apicreds = Import-Clixml -Path ".\ApiCreds.xml"

$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($apicreds)
$env = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR) | ConvertFrom-Json 

function Get-AccessToken { 
    param ( 
        [PSCustomObject]$Env
        ) 
    $body = @{ 
        grant_type = "client_credentials" 
        client_id = $Env.client_id 
        client_secret = $Env.client_secret
        scope="pf-admin" 
    } 
    $response = Invoke-RestMethod -Method Post -Uri "$($Env.token_url)/as/token.oauth2" -ContentType "application/x-www-form-urlencoded" -Body $body 

    return $response.access_token 
}

function GetSPConnectionsByID {
    param (
        [PSCustomObject]$Env,
        [String]$Token,
        [String]$id
    )
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("X-XSRF-Header", "PingFederate")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "bearer $Token")

    $response = Invoke-RestMethod -Method Get -Uri "$($Env.api_url)/pf-admin-api/v1/idp/spConnections/$id" -Headers $headers 

    return $response

}

function GetSPConnections {
    param (
        [PSCustomObject]$Env,
        [String]$Token
    )
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("X-XSRF-Header", "PingFederate")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "bearer $Token")

    $response = Invoke-RestMethod -Method Get -Uri "$($Env.api_url)/pf-admin-api/v1/idp/spConnections" -Headers $headers 

    return $response

}

if($Environment){
    $Environment = $Environment.ToString().ToLower() 
    if($Environment -eq "prod"){
        $e = $env.prod
    }
    elseif($Environment -eq "nonprod"){
        $e = $env.nonprod
    }
    else{
        Write-Output "Example :`n-Envrionment [prod|nonprod]"
        exit
    }

    $token = Get-AccessToken -Env $e
    if($token){
        $json = GetSPConnections -Token $token -Env $e
        $json_updated = $json -replace "(?-i)email", "_email"
        $IdpSpCertCsv = New-Object 'System.Collections.Generic.List[System.Object]'

        $fileName = ".\idpsp.json"
        Set-Content $fileName $json_updated
        foreach($conn in $(Get-Content $fileName | ConvertFrom-Json).items){

            $headers = New-Object 'System.Collections.Generic.Dictionary[[String],[String]]'
            $headers.Add("Accept", "application/json")
            $headers.Add("X-XSRF-Header", "PingFederate")
            $headers.Add("Content-Type", "application/json")
            $headers.Add("Authorization", "bearer $token")
            Write-Host "Fetching certs for $($conn.entityId)"
            $IDPCert = Invoke-RestMethod -Method Get -Uri $conn.credentials.signingSettings.signingKeyPairRef.location -Headers $headers
            $IdpSpCertCsv.Add([PSCustomObject]@{
                "entityId" = $conn.entityId
                "name" = $conn.name
                "active" = $conn.active
                "Cert Type" = "IDP"
                "activeVerificationCert" = ""
                "serialNumber"= (([System.Numerics.BigInteger]::Parse("$($IDPCert.serialNumber)")).ToString("x12") -split '(.{2})' | Where-Object {$_ -ne ""}) -join ":"
                "subjectDN" = $IDPCert.subjectDN
                "expires" = $IDPCert.expires
                "Environment" = $Environment
                "CMDB Details" = "$($conn.contactInfo.company) || $($conn.applicationName)"
            })

            foreach($spcert in $conn.credentials.certs){
                $IdpSpCertCsv.add([PSCustomObject]@{
                    "entityId" = $conn.entityId
                    "name" = $conn.name
                    "active" = $conn.active
                    "Cert Type" = "SP"
                    "activeVerificationCert" = $spcert.activeVerificationCert
                    "serialNumber"= (([System.Numerics.BigInteger]::Parse("$($spcert.serialNumber)")).ToString("x12") -split '(.{2})' | Where-Object {$_ -ne ""}) -join ":"
                    "subjectDN" = $spcert.certView.subjectDN
                    "expires" = $spcert.certView.expires
                    "Environment" = $Environment
                    "CMDB Details" = "$($conn.contactInfo.company) || $($conn.applicationName)"
                })
            }
        }
        $IdpSpCertCsv | Export-Csv ".\SPIdpCert-$Environment-details.csv" -NoTypeInformation
        Import-Csv ".\SPIdpCert-$Environment-details.csv" | Export-Excel -Path ".\SPIdpCert-$Environment-details.xlsx"
        Write-Host ".\SPIdpCert-$Environment-details.xlsx Created ..."
        # Remove-Item ".\SPIdpCert-$Environment-details.csv"
    }
    else{
        Write-Output "Unable to get access-token."
        exit
    }
}
else {
    Write-Output "-Envrionment [prod|nonprod] is mandotory parameter. "
    exit
}