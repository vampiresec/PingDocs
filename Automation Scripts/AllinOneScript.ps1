<#
.SYNOPSIS
    A Script to automate some pingfed tasks
.EXAMPLE
    .\AllinOneScript.ps1 -Environment [prod|nonprod]
    .\AllinOneScript.ps1 -Environment [prod|nonprod] -DumpSPConnections
    .\AllinOneScript.ps1 -Environment [prod|nonprod] -DonwloadIDPCert <certid>
    .\AllinOneScript.ps1 -Environment [prod|nonprod] -DumpOAuthClients
    .\AllinOneScript.ps1 -Environment [prod|nonprod] -DumpOIDCPolicies
    .\AllinOneScript.ps1 -Environment [prod|nonprod] -DumpATMs
    .\AllinOneScript.ps1 -Environment [prod|nonprod] -DeleteInActiveSPConnections
    .\AllinOneScript.ps1 -Environment [prod|nonprod] -DeleteAllExpiredIDPCert
.NOTES
    Author: Chaitanya Chavan <chaitanyachavan118@gmail.com>
    Date: 13-Apr-2025
#>

param(
    [string]$Environment,
    [switch]$DumpSPConnections,
    [switch]$DumpOAuthClients,
    [switch]$DumpOIDCPolicies,
    [switch]$DumpATMs,
    [switch]$DeleteInActiveSPConnections,
    [switch]$DeleteInactiveOAuthClients,
    [String]$DownloadIDPCert,
    [switch]$DeleteAllExpiredIDPCert
)

if(!$(Test-Path -Path ".\ApiCreds.xml" -PathType Leaf)){
    Write-Host "ApiCreds.xml not found`nPlease save correct ApiCreds.xml in present working directory "
    exit
}
$apicreds = Import-Clixml -Path ".\ApiCreds.xml"

$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($apicreds)
$env = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR) | ConvertFrom-Json 


function printHelp {
    Write-Output ""
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

function Get-OAuthClients {
    param (
        [PSCustomObject]$Env,
        [String]$Token
    )
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("X-XSRF-Header", "PingFederate")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "bearer $Token")

    $response = Invoke-RestMethod -Method Get -Uri "$($Env.api_url)/pf-admin-api/v1/oauth/clients" -Headers $headers 
    
    return $response

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

function DeleteSPConnection{
    param(
        [String]$id,
        [PSCustomObject]$Env,
        [string]$Token
    )
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("X-XSRF-Header", "PingFederate")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "bearer $Token")

    $response = Invoke-RestMethod -Method Delete -Uri "$($Env.api_url)/pf-admin-api/v1/idp/spConnections/$id" -Headers $headers 
    
    return $response
}

function GetCerts {
    param (
        [PSCustomObject]$Env,
        [String]$Token
    )
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("X-XSRF-Header", "PingFederate")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "bearer $Token")

    $response = Invoke-RestMethod -Method Get -Uri "$($Env.api_url)/pf-admin-api/v1/keyPairs/signing" -Headers $headers 
    
    return $response
}

function delCert {
    param (
        [PSCustomObject]$Env,
        [String]$Token,
        [String]$Id
    )
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("X-XSRF-Header", "PingFederate")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "bearer $Token")

    $response = Invoke-RestMethod -Method Delete -Uri "$($Env.api_url)/pf-admin-api/v1/keyPairs/signing/$Id" -Headers $headers 
    
    return $response
}

function DownloadIDPCert {
    param(
        [String]$Id,
        [PSCustomObject]$Env,
        [string]$Token
    )
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("X-XSRF-Header", "PingFederate")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "bearer $Token")

    $response = Invoke-RestMethod -Method Get -Uri "$($Env.api_url)/pf-admin-api/v1/keyPairs/signing/$Id/certificate" -Headers $headers 

    $response
}

function GetATMs{
    param (
        [PSCustomObject]$Env,
        [String]$Token
    )
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("X-XSRF-Header", "PingFederate")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "bearer $Token")

    $response = Invoke-RestMethod -Method Get -Uri "$($Env.api_url)/pf-admin-api/v1/oauth/accessTokenManagers" -Headers $headers 
    
    return $response
}

function GetOIDCPolicies{
    param (
        [PSCustomObject]$Env,
        [String]$Token
    )
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("X-XSRF-Header", "PingFederate")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "bearer $Token")

    $response = Invoke-RestMethod -Method Get -Uri "$($Env.api_url)/pf-admin-api/v1/oauth/openIdConnect/policies" -Headers $headers 
    
    return $response
}

function GetPCVs{
    param (
        [PSCustomObject]$Env,
        [String]$Token
    )
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("X-XSRF-Header", "PingFederate")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "bearer $Token")

    $response = Invoke-RestMethod -Method Get -Uri "https://pfadmin.ping.nonprod.aws.mdlz.com/pf-admin-api/v1/passwordCredentialValidators" -Headers $headers

    return $response
}

function GetSelectors{
    param(
        [PSCustomObject]$Env,
        [string]$Token
    )
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("X-XSRF-Header", "PingFederate")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "bearer $Token")

    $response = Invoke-RestMethod -Method Get -Uri "$($Env.api_url)/pf-admin-api/v1/authenticationSelectors" -Headers $headers 

    $response 
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

function CreateSelectors{
    param(
        [PSCustomObject]$Env,
        [string]$Token,
        [String]$body
    )
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("X-XSRF-Header", "PingFederate")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "bearer $Token")

    $response = Invoke-RestMethod -Method POST -Uri "$($Env.api_url)/pf-admin-api/v1/authenticationSelectors" -Headers $headers -Body $body

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

    $response = Invoke-RestMethod -Method PUT -Uri "$($Env.api_url)/pf-admin-api/v1/authenticationSelectors/$id" -Headers $headers -Body $body

    $response   
}


# Script Controller
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
        if($DumpSPConnections){
            Write-Output "Dumping SP Connections json....."
            $json = GetSPConnections -Env $e -Token $token
            Set-Content ".\SPConnections-$Environment-$(Get-Date -Format "yyyy-MM-ddTHH-mm-ss").json" $json
            Write-Output "SPConnections-$Environment-$(Get-Date -Format "yyyy-MM-ddTHH-mm-ss").json created..."
            
        }
        if($DumpOAuthClients){
            Write-Output "Dumping OAuth Clients json....."
            $json = Get-OAuthClients -Env $e -Token $token
            Set-Content ".\OAuthClients-$Environment-$(Get-Date -Format "yyyy-MM-ddTHH-mm-ss").json" $($json | ConvertTo-Json -Depth 5)
            Write-Output "OAuthClients-$Environment-$(Get-Date -Format "yyyy-MM-ddTHH-mm-ss").json created..."
            
        }
        if($DeleteInActiveSPConnections){
            
            # Backup
            Write-Output "Generating $Environment backup...."
            $json = GetSPConnections -Token $token -Env $e
            Set-Content ".\Backup-SPConnections-$Environment-$(Get-Date -Format "yyyy-MM-ddTHH-mm-ss").json" $json
            Write-Output "Backup-SPConnections-$Environment-$(Get-Date -Format "yyyy-MM-ddTHH-mm-ss").json created..."
            
            # Generating csv
            $json_updated = $json -replace "(?-i)email", "_email"
            Set-Content ".\tmp.json" $json_updated
            $ecsv = New-Object 'System.Collections.Generic.List[System.Object]'
            $dcsv = New-Object 'System.Collections.Generic.List[System.Object]' 
            foreach($conn in $(Get-Content .\tmp.json | ConvertFrom-Json).items){
                if($conn.active -eq $true){
                    $ecsv.add([PSCustomObject]@{
                        "id" = $conn.id
                        "entityId" = $conn.entityId
                        "name" = $conn.name
                        "type" = $conn.type
                        "active" = $conn.active
                        
                    })
                }
                if($conn.active -eq $false){
                    $dcsv.add([PSCustomObject]@{
                        "id" = $conn.id
                        "entityId" = $conn.entityId
                        "name" = $conn.name
                        "type" = $conn.type
                        "active" = $conn.active
                    })
               }
            }
            Remove-Item ".\tmp.json"
            Write-Output "Generating Enabled and Disabled connections csv"
            $ecsv | Export-Csv ".\EnabledConnections-$Environment-$(Get-Date -Format "yyyy-MM-ddTHH-mm-ss").csv" -NoTypeInformation
            $dcsv | Export-Csv ".\DisabledConnections-$Environment-$(Get-Date -Format "yyyy-MM-ddTHH-mm-ss").csv" -NoTypeInformation

            $dcsv
            $confirm = Read-Host "Do you want to delete above Connections [Y|N]"
            $confirm = $confirm.ToString().ToLower()
            if($confirm -eq "y"){
                foreach($d in $dcsv){
                    DeleteSPConnection -id $d.id -Env $e -Token $token
                    Write-Output "Deleted SP connenctions : $($d.EntityId) "
                }
            }
            else{
                Write-Output "Exiting script....."
                exit
            }
        }
        if($DownloadIDPCert){
            Write-Output "Saved as $DownloadIDPCert.crt"
            Set-Content "$DownloadIDPCert.crt" $(DownloadIDPCert -Id $DownloadIDPCert -Env $e -Token $token)
        }
        if($DumpATMs){
            Write-Output "Dumping ATMs json....."
            $atms = GetATMs -Env $e -Token $token
            $filename = "ATMs-$Environment-$(Get-Date -Format "yyyy-MM-ddTHH-mm-ss").json"
            Set-Content $filename $($atms | Convertto-json -Depth 7)
            Write-Output "$filename saved"
        }
        if($DumpOIDCPolicies){
            Write-Output "Dumping OIDCPolicies json....."
            $atms = GetOIDCPolicies -Env $e -Token $token
            $filename = "OIDCPolicies-$Environment-$(Get-Date -Format "yyyy-MM-ddTHH-mm-ss").json"
            Set-Content $filename $($atms | Convertto-json -Depth 7)
            Write-Output "$filename saved"
        }
        if($DeleteAllExpiredIDPCert){
            $certs = GetCerts -Env $e -Token $token
            
            $expired_certs = New-Object 'System.Collections.Generic.List[System.Object]'
            $active_certs = New-Object 'System.Collections.Generic.List[System.Object]'

            # Creating JSON for backup
            Write-Output "Generating $Environment certs backup...."
            Set-Content ".\Backup-IDPCerts-$Environment-$(Get-Date -Format "yyyy-MM-ddTHH-mm-ss").json" $($certs | ConvertTo-Json)
            Write-Output ".\Backup-IDPCerts-$Environment-$(Get-Date -Format "yyyy-MM-ddTHH-mm-ss").json created..."
            
            # Downloading Expired certs
            $directory = ".\ExpiredCerts"

            if (!(Test-Path -Path $directory)) {
                New-Item -ItemType Directory -Path $directory
            }

            foreach($crt in $certs.items){
                if($crt.status -eq "EXPIRED" ){
                    if ($crt.subjectDN -match "CN=([^,]+)") { 
                        $cnValue = $matches[1]
                        $expired_certs.add([PSCustomObject]@{
                            "id" = $crt.id
                            "Subject DN" = $crt.subjectDN
                            "CN" = $cnValue
                            "Serial Number" = $crt.serialNumber
                            "Expiry" = $crt.expires
                            "Status" = $crt.status
                        })

                        Write-Output "Downloading cert $cnValue "
                        $(DownloadIDPCert -Id $crt.id -Env $e -Token $token) | Out-File ".\ExpiredCerts\$($cnValue  -replace '[\\/:*?"<>|]', '_')-$($crt.expires -replace ':','-').crt" 
                        Write-Output "Downloaded cert $cnValue"
                    }
                    
                    
                }
                if($crt.status -eq "VALID" ){

                    if ($crt.subjectDN -match "CN=([^,]+)") { 
                        $cnValue = $matches[1]
                        $active_certs.add([PSCustomObject]@{
                            "id" = $crt.id
                            "Subject DN" = $crt.subjectDN
                            "CN" = $cnValue
                            "Serial Number" = $crt.serialNumber
                            "Expiry" = $crt.expires
                            "Status" = $crt.status
                        })
                    }
                }
            }

            $active_certs | Export-Csv ".\Active-IDPCerts-$Environment-$(Get-Date -Format "yyyy-MM-ddTHH-mm-ss").csv" -NoTypeInformation
            $expired_certs | Export-Csv ".\Expired-IDPCerts-$Environment-$(Get-Date -Format "yyyy-MM-ddTHH-mm-ss").csv" -NoTypeInformation

            $expired_certs

            $confirm = Read-Host "Do you want to delete above IDP Certs [Y|N]"
            $confirm = $confirm.ToString().ToLower()
            if($confirm -eq "y"){
                foreach($c in $expired_certs){
                    Write-Output "Deleting cert $($c.CN) "
                    Try{
                        delCert -Id $c.id -Env $e -Token $token
                    }
                    catch{
                        Write-Output "Unable to delete cert $($c.CN)"
                        continue
                    }
                    Write-Output "Deleted cert $($c.CN)"
                }    
            }
            else{
                Write-Output "Exiting script....."
                exit
            }
        }
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
