
# Make sure to update the below lines
# 1. <base64-encoded-clientid-and-secret> with your base64 encoded client id and secret
# 2. <environmentID> wiht the environment id in the URLs
# 3. <populationID> with the population id you want to update from and to

function Get-AccessToken{
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/x-www-form-urlencoded")
    $headers.Add("Authorization", "Basic <base64-encoded-clientid-and-secret>")

    $body = @{ 
        grant_type = "client_credentials"  
    } 
    $response = Invoke-RestMethod 'https://auth.pingone.com/<environmentID>/as/token' -Method 'POST' -Headers $headers -Body $body

    return $response.access_token
}


function Get-UsersByPopulation{
    param(
        [String]$Population,
        [String]$Token,
        [switch]$ExportExcel
    )
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "bearer $Token")
    $headers.Add("Content-Type","application/json") 

    $flag = $true
    
    $nextUrl = "https://api.pingone.com/v1/environments/<environmentID>/users?filter=population.id eq `"$Population`""
    
    $users = New-Object 'System.Collections.Generic.List[System.Object]'

    while($flag){
        $res = Invoke-RestMethod -Uri $nextUrl -Method 'GET' -Headers $headers
        
        $nextUrl = $res._links.next.href

        foreach($user in $res._embedded.users){
            $users.Add([PSCustomObject]@{
                id = $user.id
                username = $user.username
                enabled = $user.enabled
                mfaEnabled = $user.mfaEnabled
                OldPopulationId = $user.population.id
            })
        }
        if($res._links.next.href -eq $null){
            $flag = $false
        }
    }
    if($ExportExcel){
        $users | Export-Csv ".\PingOne-$Population-population-users.csv" -NoTypeInformation
        Import-Csv ".\PingOne-$Population-population-users.csv" | Export-Excel -Path ".\PingOne-$Population-population-users-$(Get-Date -Format "yyyy-MM-ddTHH-mm-ss").xlsx"
        Remove-Item ".\PingOne-$Population-population-users.csv"   
    }

    return $users
    
}

function updatePopulation {
    param (
        [String]$Population,
        [String]$Id,
        [String]$Token
    )
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "bearer $Token")
    $headers.Add("Content-Type","application/json") 
    $url = "https://api.pingone.com/v1/environments/<environmentID>/users/$id/population"
    $response = Invoke-RestMethod -Method Put -Uri $url  -Headers $headers -Body "{`"id`" : `"$Population`"}"
    
}

$token = Get-AccessToken

$userDetails = Get-UsersByPopulation -Population "<populationID>" -Token $token -ExportExcel

foreach($u in $userDetails){
    Write-Host "[ ] Updating population for $($u.username)"
    try {
        updatePopulation -Token $token -Id $u.id -Population "<populationID>"
    }
    catch {
        Write-Host "[X] Unable to update population for $($u.username) "
        continue
    }
    Write-Host "[#] Updated population for $($u.username)"
}

