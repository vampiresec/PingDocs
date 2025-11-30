<#
.SYNOPSIS
    A Script to send cert expiry email notifications application/ business owners
.EXAMPLE
    .\CertExpiryNotification.ps1 -Environment [nonprod|prod]
.NOTES
    Author: Chaitanya Chavan <chaitanyachavan118@gmail.com>
#>

param(
    [string]$Environment
)

$env = @{
    "prod" = @{
        "token_url"=""
        "client_id"=""
        "client_secret"=""
        "api_url"=""
    }
    "nonprod" = @{
        "token_url"=""
        "client_id"=""
        "client_secret"=""
        "api_url"=""
    }
}


function Send-Notification{
    param(
        [switch]$Tdays,
        [switch]$Fdays,
        [switch]$Sdays,
        [switch]$Twodays,
        [PSCustomObject]$CertObj
    )
    $days= 0
    if($Tdays.IsPresent){$days=30}
    if($Fdays.IsPresent){$days=15}
    if($Sdays.IsPresent){$days=7}
    if($Twodays.IsPresent){$days=2}

    Write-Log "Sending Email"
    $From = "<NoReply@yourdomaim>"
    $To = "$($CertObj.Email)"
    $cc = "your DL"
    $SMTPServer = "<SMTP Domain>"
    $SMTPPort = "25"
    $Subject = "A PingFederate Certificate Is About to Expire in $(($CertObj.expires).toString("MMMM")) - $($CertObj.name)"
    $Body = @"
<!DOCTYPE html>
<html>
<head>
    <style>
        body {
            font-family: Arial, sans-serif;
            color: #333333;
        }
        .container {
            width: 100%;
            margin: 0 auto;
        }
        h2 {
            color: #2c3e50;
        }
        table {
            width: auto; /* Let table size adjust to content */
            border-collapse: collapse;
            margin-top: 15px;
            table-layout: auto; /* Key property for auto-fit */
        }
        th, td {
            border: 1px solid #dddddd;
            text-align: left;
            padding: 8px;
            font-size: 14px;
            white-space: nowrap; /* Prevent wrapping for better fit */
        }
        th {
            background-color: #f4f4f4;
            color: #2c3e50;
        }
        tr:nth-child(even) {
            background-color: #fafafa;
        }
        .expiry-warning {
            color: #e74c3c;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <p>Hi @$($CertObj.Email),</p><br>
        <p>The following certificate is getting expired in $($days) days. Please take necessary action:</p>
        <table>
            <tbody>
                <tr>
                    <th>Application Name</th>
                    <td>$($CertObj.name)</td>
                    
                </tr>
                <tr>
                    <th>EntityId</th>
                    <td>$($CertObj.entityId)</td>
                </tr>
                <tr>
                    <th>subjectDN</th>
                    <td>$($CertObj.subjectDN)</td>
                </tr>
                <tr>
                    <th>Serial Number</th>
                    <td>$($CertObj.serialNumber)</td>
                </tr>
                <tr>
                    <th>Environment</th>
                    <td>$($CertObj.Environment)</td>
                </tr>
                <tr>
                    <th>Expiry Date</th>
                    <td $(if($Sdays -or $Twodays){'class="expiry-warning"'})>$($CertObj.expires)</td>
                </tr>
            </tbody>
        </table>
        <p>Please ensure renewal before the expiry date to avoid service disruption. Ignore if already renewed.</p>
        <br>
        <p>Thanks,<br>SSO Team</p>
    </div>
</body>
</html>
"@
    Start-Sleep -Second 10
    Send-MailMessage -From $From -to $To -Cc $cc -Subject $Subject -Body $Body -BodyAsHtml -SmtpServer $SMTPServer -Port $SMTPPort
    Write-log "$($CertObj.name)Email Sent to $($CertObj.Email)"
}
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

# Script Loggin functionality
$logFile = ".\ScriptLog.txt"
function Write-Log {
    param (
        [string]$message,
        [string]$level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "$timestamp [$level] $message"
    Add-Content -Path $logFile -Value $entry
}

$30days = New-Object "System.Collections.Generic.List[System.Object]"
$15days = New-Object "System.Collections.Generic.List[System.Object]"
$7days = New-Object "System.Collections.Generic.List[System.Object]"
$2days = New-Object "System.Collections.Generic.List[System.Object]"


if($Environment){
    $Environment = $Environment.ToString().ToLower() 
    $e = $env.prod
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
    Write-log "Script execution started"
    Write-log "Generating access_token"
    try {
        $token = Get-AccessToken -Env $e
        Write-log "Generated access_token"
    }
    catch {
        Write-Log "Unable to generate access_token" -level "ERROR"
        Write-Log "Error occurred: $_" -level "ERROR"
        exit
    }
    
    if($token){
        $json = GetSPConnections -Token $token -Env $e
        $json_updated = $json -replace "(?-i)email", "_email"
     
        $fileName = ".\SP.json"
        Set-Content $fileName $json_updated
        foreach($conn in $(Get-Content $fileName | ConvertFrom-Json).items){

            $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $headers.Add("Accept", "application/json")
            $headers.Add("X-XSRF-Header", "PingFederate")
            $headers.Add("Content-Type", "application/json")
            $headers.Add("Authorization", "bearer $token")
            Write-Host "Fetching certs for $($conn.entityId)"
            $IDPCert = Invoke-RestMethod -Method Get -Uri $conn.credentials.signingSettings.signingKeyPairRef.location -Headers $headers
            $CertObj = [PSCustomObject]@{
                "entityId" = $conn.entityId
                "name" = $conn.name
                "Cert Type" = "IDP"
                "serialNumber"= (([System.Numerics.BigInteger]::Parse("$($IDPCert.serialNumber)")).ToString("x12") -split '(.{2})' | Where-Object {$_ -ne ""}) -join ":"
                "subjectDN" = $IDPCert.subjectDN
                "expires" = Get-Date $IDPCert.expires
                "Environment" = $Environment
                "Email" = "$($conn.contactInfo.email)"
            }
            if([int]([datetime]$IDPCert.expires).Subtract((Get-Date).ToUniversalTime()).TotalDays -eq 30){
                $30days.Add($CertObj)
                Send-Notification -Tdays -CertObj $CertObj
            }
            if([int]([datetime]$IDPCert.expires).Subtract((Get-Date).ToUniversalTime()).TotalDays -eq 15){
                $15days.Add($CertObj)
                Send-Notification -Fdays -CertObj $CertObj
            }
            if([int]([datetime]$IDPCert.expires).Subtract((Get-Date).ToUniversalTime()).TotalDays -eq 7){
                $7days.Add($CertObj)
                Send-Notification -Sdays -CertObj $CertObj
            }
            if([int]([datetime]$IDPCert.expires).Subtract((Get-Date).ToUniversalTime()).TotalDays -eq 2){
                $2days.Add($CertObj)
                Send-Notification -Twodays -CertObj $CertObj
            }
        }
        Write-Log "Generating CSVs...."
        $30days | Export-Csv ".\30Days.csv" -NoTypeInformation
        $15days | Export-Csv ".\15Days.csv" -NoTypeInformation
        $7days | Export-Csv ".\7Days.csv" -NoTypeInformation
        $2days | Export-Csv ".\2Days.csv" -NoTypeInformation
        Write-Log "Generated CSVs"

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
