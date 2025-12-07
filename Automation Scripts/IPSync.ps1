#Requires -Module MSOnline
#Requires -Module ExchangeOnlineManagement


# Prerequisite: Create encrypted ApiCreds.enc and PingOneEnv.enc using below script and save in present working directory



if(!$(Test-Path -Path ".\ApiCreds.enc" -PathType Leaf)){
    Write-Host "ApiCreds.enc not found`nPlease save correct ApiCreds.xml in present working directory "
    exit
}

if(!$(Test-Path -Path ".\PingOneEnv.enc" -PathType Leaf)){
    Write-Host "ApiCreds.enc not found`nPlease save correct ApiCreds.xml in present working directory "
    exit
}

Add-Type -AssemblyName System.Security
$decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($(Get-Content .\ApiCreds.enc), $null, 'LocalMachine')
$PingFedEnv = [System.Text.Encoding]::UTF8.GetString($decrypted) | ConvertFrom-Json

$decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($(Get-Content .\PingOneEnv.enc), $null, 'LocalMachine')

$PingOneENV = [System.Text.Encoding]::UTF8.GetString($decrypted) | ConvertFrom-Json

Set-Content .\IPSycScriptLog.txt ""
# Define log file path
$logFile = ".\IPSycScriptLog.txt"

# Function to write log entries
function Write-Log {
    param (
        [string]$message,
        [string]$level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "$timestamp [$level] $message"
    Add-Content -Path $logFile -Value $entry
}

function fetchIpsZscaler{
    $ipjson = Invoke-RestMethod -Uri "https://config.zscaler.com/api/zscaler.net/future/json" 
    return $ipjson
}

function Get-PingFedAccessToken { 
    param ( 
        [PSCustomObject]$Env
        ) 
    $body = @{ 
        grant_type = "client_credentials" 
        client_id = $Env.client_id 
        client_secret = $Env.client_secret
        scope="pf-admin" 
    } 

    Write-Log "Generating PingFed access_token"
    try{
            $response = Invoke-RestMethod -Method Post -Uri "$($env.token_url)/as/token.oauth2" -ContentType "application/x-www-form-urlencoded" -Body $body
    }
    catch{
        Write-Log "Error occurred: $_" -level "ERROR"
        exit
    }
    finally{
        Write-log "Genereated PignFed access_token"
    }

    return $response.access_token 
}

function GetSelectorsByID{
    param(
        [PSCustomObject]$Env,
        [string]$Token,
        [string]$Id
    )
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("X-XSRF-Header", "PingFederate")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "bearer $Token")

    $response = Invoke-RestMethod -Method Get -Uri "$($Env.api_url)/pf-admin-api/v1/authenticationSelectors/$Id" -Headers $headers 

    $response 
}

function UpdateSelectors{
    param(
        [PSCustomObject]$Env,
        [string]$Token,
        [String]$body,
        [String]$id
    )
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("X-XSRF-Header", "PingFederate")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "bearer $Token")
    Write-log "Updating IPs for selector: $id"
    try {
        $response = Invoke-RestMethod -Method Put -Uri "$($Env.api_url)/pf-admin-api/v1/authenticationSelectors/$id" -Headers $headers -Body $body   
    }
    catch {
        Write-log "Failed to update selector: $id"
        Write-Log "Error occurred: $_" -level "ERROR"
    }
    finally {
        Write-Log "Updated IPs for selector: $id"
    }


    $response   
}
function Get-PingOneAccessToken{
    param(
        [PSCustomObject]$Env
    )
    $toke = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Env.client_id + ":" + $Env.client_secret ))
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/x-www-form-urlencoded")
    $headers.Add("Authorization", "basic $toke")

    $body = @{ 
        grant_type = "client_credentials"  
    } 
    Write-Log "Generating PingOne access_token"
    try{
        $response = Invoke-RestMethod "https://auth.pingone.com/$($Env.env)/as/token" -Method 'POST' -Headers $headers -Body $body
    }
    catch{
        Write-Log "Error occurred: $_" -level "ERROR"
        exit
    }
    finally{
        Write-log "Genereated PignOne access_token"
    }

    return $response.access_token
}

function GetPredictor{
    param(
        [PSCustomObject]$Env,
        [String]$Token
    )
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Bearer $Token")
    Write-Log "Loading Predictor"
    try{
        $url = "https://api.pingone.com/v1/environments/$($Env.env)/riskPredictors/$($Env.predictor_id)"
        $response = Invoke-RestMethod -Uri $url -Method 'GET' -Headers $headers
    }
    catch{
        Write-Log "Failed to load Predictor" -level "ERROR"
        Write-Log "Error occurred: $_" -level "ERROR"
        exit
    }
    finally{
        Write-log "Predictor loaded"
    }
    return $response

}
function updatePredictor{
    param(
        [PSCustomObject]$Env,
        [String]$Token,
        [String]$body
    )
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Bearer $Token")
    Write-Log "Updating Predictor"
    try {
        $url = "https://api.pingone.com/v1/environments/$($Env.env)/riskPredictors/$($Env.predictor_id)"
        $response = Invoke-RestMethod -Uri $url -Method 'PUT' -Headers $headers -Body $body -ContentType "application/json"
    }
    catch {
        Write-Log "Failed to update Predictor" -level "ERROR"
        Write-Log "Error occurred: $_" -level "ERROR"
    }
    finally {
        Write-log "Predictor updated"
    }

    return $response
}

function FormatSelectorJson{
    param(
        [PSCustomObject]$selectorhashtable,
        [array]$ips
    )
    $list =  [System.Collections.ArrayList]::new()
    foreach($ip in $ips){
        $row =@{
            "fields" = @(@{
                "value" = $ip
                "name" = "Network Range (CIDR notation)"
            })
            "defaultRow" = $false
        }
        [void]$list.Add($row)
    }
    $table = @{
        "name" = "Networks"
        "rows" = $list
    }
    $selectorhashtable.configuration.tables = @($table)

    return $selectorhashtable
}


$envx = @("nonprod","prod")

$Zips = fetchIpsZscaler 
# filtering ipv6 ip addresses
$ipv4 = $Zips.prefixes | Where-Object { $_ -notmatch ":" }

$u = [System.Collections.Generic.HashSet[string]]::new()
$udpateflag = $false

foreach($e in $envx){
    Write-log "$($e.ToUpper()) opreations loading"
    $PingOneToken = Get-PingOneAccessToken -Env $PingOneENV.$e
    $PingFedToken = Get-PingFedAccessToken -Env $PingFedEnv.$e
    $res = GetPredictor -Env $PingOneENV.$e -Token $PingOneToken
    Set-Content "Backup-$e-Predictor-$(Get-Date -Format "yyyy-MM-ddTHH-mm-ss").json" $($res | ConvertTo-Json -Depth 5)
    $Predictor = @{}
    $res.PSObject.Properties | ForEach-Object {
        $Predictor[$_.Name] = $_.Value
    }
    $Predictor.Remove("_links")
    $Predictor.Remove("createdAt")
    $Predictor.Remove("createdBy")
    $Predictor.Remove("updatedAt")


    $updatedIp = [System.Collections.ArrayList]@($Predictor.whiteList)

    Set-Content "IPs-$e-Before-update.csv" "IPs"
    Add-Content "IPs-$e-Before-update.csv" $updatedIp


    $updateflag = $false
    # Checking whether IPV4 ips exists in the predictor
    foreach($ip in $ipv4){
            if(!($Predictor.whiteList -match $ip)){
                $updateflag = $true
                $updatedIp.Add("$ip")
                $u.Add("$ip")
            }    
    }


    $Predictor.whiteList = $updatedIp



    $SIDs = @("<selectorID0>","<selectorID1>","<selectorID2>")
    if($updateflag){
    updatePredictor -Env $PingOneENV.$e -T $PingOneToken -body $($Predictor | ConvertTo-Json -Depth 8)
    foreach($sid in $SIDs){
        $backup = GetSelectorsByID -Env $PingFedEnv.$e -Token $PingFedToken -Id $sid
        Set-Content "Backup-$e-selector-$sid-$(Get-Date -Format "yyyy-MM-ddTHH-mm-ss").json" $($backup | ConvertTo-Json -Depth 8)
        $selectorhashtable = FormatSelectorJson -selectorhashtable $backup -ips $updateIp
        UpdateSelectors -Env $PingFedENV.$e -Token $PingFedToken -id $sid -body $($selectorhashtable | ConvertTo-Json -Depth 8)
        }
        Set-Content "IPs-$e-After-update.csv" "IPs"
        Add-Content "IPs-$e-After-update.csv" $updatedIp
    }
    else{
        Write-Log "NO new IPs found - Nothing to update"
    }
    Write-log "$($e.ToUpper()) opreations done"
}

Get-ChildItem -Path . -File -Filter 'Backup-*' |
  Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } |
  Remove-Item -Force


Write-Log "Sending Email"
$From = "<FromEmailAddress>"
$To = "<ToEmailAddress>" 
$SMTPServer = "<SMTPServerAddress>"
$SMTPPort = "25"
$date = Get-Date -Format "yyyy-MM-dd"

$Subject = "ZScaler IP Sync $date"

if($updateflag){
    $Body = "Hi Team,

Below IPs has been synced with all selectos and predictors:
"+ $($u.toArray() -join "
") +".

Thanks,
PingCronScheduler"
    $Attachment1 = @(".\IPs-prod-After-update.csv",".\IPs-nonprod-After-update.csv",".\IPs-nonprod-Before-update.csv",".\IPs-prod-Before-update.csv", ".\IPSycScriptLog.txt")
}
else{
    $Body = "Hi Team,

 No New ip found to sync.

Thanks,
PingCronScheduler"
    $Attachment1 = @(".\IPSycScriptLog.txt")
} 


Start-Sleep -Second 10
Send-MailMessage -From $From -to $To -Subject $Subject -Body $Body -BodyAsHtml -SmtpServer $SMTPServer -Port $SMTPPort -Attachments $Attachment1









 