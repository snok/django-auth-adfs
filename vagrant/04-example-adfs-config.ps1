# ########## SETTINGS #########
$webIP = "10.10.10.10"
$webName = "web"
$appName = "Django Application"
$clientId = "487d8ff7-80a8-4f62-b926-c2852ab06e94"
$relyingPartyId = "web.example.com"
# #############################

Write-Host "Waiting for domain controller to become reachable."
$isUp = $false
while($isUp -eq $false) {
    Try {
        $domain = Get-ADDomain
        $isUp = $true
    } Catch {
        Write-Host "Retrying in 15 seconds"
        $isUp = $false
        Start-Sleep 15
    }
}

# Add webserver DNS record
# ------------------------
Write-Host "Adding DNS record..."
Add-DnsServerResourceRecordA -Name $webName -IPv4Address $webIP -ZoneName (Get-ADDomain).Forest

# Add example users and groups
# ----------------------------
Write-Host "Creating Django Admins group"
$staffGroup = New-ADGroup `
-Name "Django Admins" `
-SamAccountName django_admins `
-GroupCategory Security `
-GroupScope Global `
-Passthru

Write-Host "Creating user Alice..."
New-ADUser `
-Name "Alice" `
-GivenName Alice `
-SurName Wonder `
-SamAccountName alice `
-EmailAddress ("alice@"+(Get-ADDomain).Forest) `
-UserPrincipalName ("alice@"+(Get-ADDomain).Forest) `
-AccountPassword (convertto-securestring "Password123" -asplaintext -force) `
-Enabled $true

Write-Host "Creating user Bob..."
$bob = New-ADUser `
-Name "Bob" `
-GivenName Bob `
-SurName Builder `
-SamAccountName bob `
-EmailAddress ("bob@"+(Get-ADDomain).Forest) `
-UserPrincipalName ("bob@"+(Get-ADDomain).Forest) `
-AccountPassword (convertto-securestring "Password123" -asplaintext -force) `
-Enabled $true `
-Passthru

Add-ADGroupMember -Identity django_admins -Members $bob

Write-Host "Disabling Internet Explorer Enhanced Security Configuration"
$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0

# Add ADFS config
# ---------------

Write-Host "Waiting for Federation Server to become reachable."
$isUp = $false
while($isUp -eq $false) {
    Try {
        $domain = Get-AdfsProperties
        $isUp = $true
    } Catch {
        Write-Host "Retrying in 15 seconds"
        $isUp = $false
        Start-Sleep 15
    }
}

Write-Host "Adding application group $appName"
New-AdfsApplicationGroup -Name $appName -ApplicationGroupIdentifier $appName

Write-Host "Adding native application"
Add-AdfsNativeClientApplication `
-name "$appName - Native application" `
-Identifier $clientId `
-ApplicationGroupIdentifier $appName `
-RedirectUri ("http://$webName."+(Get-ADDomain).Forest+":8000/oauth2/callback")

Write-Host "Adding web application"
Add-AdfsWebApiApplication `
-Name "$appName - Web application" `
-Identifier $relyingPartyId `
-AccessControlPolicyName "Permit everyone" `
-ApplicationGroupIdentifier $appName `
-IssuanceTransformRules (
    '@RuleTemplate = "LdapClaims"
     @RuleName = "User attribute claims"
     c:[
        Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname",
        Issuer == "AD AUTHORITY"
     ]
     => issue(
        store = "Active Directory",
        types = (
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
            "http://schemas.xmlsoap.org/claims/Group",
            "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"
        ),
        query = ";mail,givenName,sn,tokenGroups,sAMAccountName;{0}",
        param = c.Value
     );'
)

Write-Host "Adding native application"
Grant-AdfsApplicationPermission `
-ClientRoleIdentifier $clientId `
-ServerRoleIdentifier $relyingPartyId `
-ScopeNames "openid"
