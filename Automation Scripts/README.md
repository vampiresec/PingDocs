# PingFederate Automation Scripts

A collection of PowerShell scripts to automate PingFederate and PingOne administration tasks.

## Scripts Overview

### 1. AllinOneScript.ps1
**Description**: Multi-purpose script for managing PingFederate SP connections, OAuth clients, certificates, and policies.

**Usage**:
```powershell
.\AllinOneScript.ps1 -Environment [prod|nonprod] -DumpSPConnections
.\AllinOneScript.ps1 -Environment [prod|nonprod] -DumpOAuthClients
.\AllinOneScript.ps1 -Environment [prod|nonprod] -DumpOIDCPolicies
.\AllinOneScript.ps1 -Environment [prod|nonprod] -DumpATMs
.\AllinOneScript.ps1 -Environment [prod|nonprod] -DownloadIDPCert <certid>
.\AllinOneScript.ps1 -Environment [prod|nonprod] -DeleteInActiveSPConnections
.\AllinOneScript.ps1 -Environment [prod|nonprod] -DeleteAllExpiredIDPCert
```

**Features**:
- Export SP connections, OAuth clients, OIDC policies, and access token managers
- Download IDP certificates
- Delete inactive SP connections with backup
- Remove expired certificates automatically

---

### 2. CertExpiryNotifications.ps1
**Description**: Sends automated email notifications to application owners about expiring certificates.

**Usage**:
```powershell
.\CertExpiryNotification.ps1 -Environment [prod|nonprod]
```

**Features**:
- Monitors certificates expiring in 30, 15, 7, and 2 days
- Sends HTML-formatted email notifications
- Generates CSV reports for each expiry timeframe
- Includes certificate details (serial number, subject DN, expiry date)

---

### 3. fetchIDP&SPCerts.ps1
**Description**: Generates comprehensive reports of IDP and SP certificate details from PingFederate.

**Usage**:
```powershell
.\fetchIDP&SPCerts.ps1 -Environment [prod|nonprod]
```

**Prerequisites**:
- Install ImportExcel module: `Install-Module -Name ImportExcel`

**Features**:
- Fetches both IDP and SP certificates
- Exports data to Excel format
- Includes certificate status, serial numbers, expiry dates
- Maps certificates to applications and CMDB details

---

### 4. IPSync.ps1
**Description**: Synchronizes ZScaler IP addresses with PingFederate authentication selectors and PingOne risk predictors.

**Usage**:
```powershell
.\IPSync.ps1
```

**Requirements**:
- MSOnline module
- ExchangeOnlineManagement module

**Features**:
- Fetches current ZScaler IP ranges
- Updates PingFederate authentication selectors
- Updates PingOne risk predictors
- Sends email notifications with changes
- Creates automatic backups (30-day retention)

---

### 5. PingOnePopulationsUpdate.ps1
**Description**: Migrates users between PingOne populations in bulk.

**Usage**:
```powershell
.\PingOnePopulationsUpdate.ps1
```

**Note**: Update the following before running:
- Base64-encoded client credentials
- Environment IDs
- Source and target population IDs

**Features**:
- Exports current population user list to Excel
- Updates user populations in bulk
- Error handling for individual user updates

---

## Prerequisites

### Common Requirements
All scripts require `ApiCreds.xml` file in the working directory with the following structure:

```powershell
$apiCreds = @{
    "prod" = @{
        "client_id" = "<client_id>"
        "client_secret" = "<client_secret>"
        "token_url" = "https://auth.pingfederate.com"
        "api_url" = "https://<pingfederate-admin-prod-api-url>"
    }
    "nonprod" = @{
        "client_id" = "<client_id>"
        "client_secret" = "<client_secret>"
        "token_url" = "https://auth.pingfederate.com"
        "api_url" = "https://<pingfederate-admin-nonprod-api-url>"
    }
}
$secureString = ConvertTo-SecureString (ConvertTo-Json $apiCreds) -AsPlainText -Force
$secureString | Export-Clixml -Path ".\ApiCreds.xml"
```

### Additional Requirements
- **IPSync.ps1**: Requires `ApiCreds.enc` and `PingOneEnv.enc` encrypted files
- **fetchIDP&SPCerts.ps1**: Requires ImportExcel PowerShell module

---

## Author
Chaitanya Chavan <chaitanyachavan118@gmail.com>

## Notes
- Always test scripts in non-production environment first
- Scripts create automatic backups before making changes
- Review generated CSV/Excel reports before confirming deletions
- Ensure proper API credentials and permissions are configuredad