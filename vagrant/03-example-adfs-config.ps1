# ########## SETTINGS #########
$webIP = "10.0.0.10"
$webName = "web"
$appName = "Django Application"
$clientId = "django_website.adfs.client_id"
$resourceId = "django_website.adfs.relying_party_id"
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
Write-Host "Creating Django Staff group"
$staffGroup = New-ADGroup `
-Name "Django Staff" `
-SamAccountName djangostaff `
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
$user = New-ADUser `
-Name "Bob" `
-GivenName Bob `
-SurName Builder `
-SamAccountName bob `
-EmailAddress ("bob@"+(Get-ADDomain).Forest) `
-UserPrincipalName ("bob@"+(Get-ADDomain).Forest) `
-AccountPassword (convertto-securestring "Password123" -asplaintext -force) `
-Enabled $true `
-Passthru

Add-ADGroupMember -Identity djangostaff -Members $user

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

If ([Environment]::OSVersion.version.major -ge 10) {
    # Windows 2016 config
    Write-Host "Adding application group $appName"
    New-AdfsApplicationGroup -Name $appName -ApplicationGroupIdentifier $appName

    Write-Host "Adding native application"
    Add-AdfsNativeClientApplication `
    -name "$appName - Native application" `
    -Identifier $clientId `
    -ApplicationGroupIdentifier $appName `
    -RedirectUri ("http://$webName."+(Get-ADDomain).Forest+":8000/oauth2/login")

    Write-Host "Adding web application"
    Add-AdfsWebApiApplication `
    -Name "$appName - Web application" `
    -Identifier $resourceId `
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
         );

         @RuleTemplate = "EmitGroupClaims"
         @RuleName = "Django staff"
         c:[
            Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid",
            Value == "'+$staffGroup.SID+'",
            Issuer == "AD AUTHORITY"
         ]
         => issue(
            Type = "is_staff",
            Value = "true",
            Issuer = c.Issuer,
            OriginalIssuer = c.OriginalIssuer,
            ValueType = c.ValueType
         );'
    )

    Write-Host "Adding native application"
    Grant-AdfsApplicationPermission `
    -ClientRoleIdentifier $clientId `
    -ServerRoleIdentifier $resourceId `
    -ScopeNames "openid"

} Else {
    # Windows 2012 config
    Write-Host "Adding ADFS client"
    Add-ADFSClient `
    -Name "$appName OAuth2 Client" `
    -ClientId $resourceId `
    -RedirectUri ("http://$webName."+(Get-ADDomain).Forest+":8000/oauth2/login")

    Write-Host "Adding Relying Party Trust"
    Add-AdfsRelyingPartyTrust `
    -Name $appName `
    -Identifier $guid `
    -IssuanceAuthorizationRules (
        '@RuleTemplate = "AllowAllAuthzRule"
         => issue(
            Type = "http://schemas.microsoft.com/authorization/claims/permit",
            Value = "true"
         );'
    ) `
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
         );

         @RuleTemplate = "EmitGroupClaims"
         @RuleName = "Django staff"
         c:[
            Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid",
            Value == "'+$staffGroup.SID+'",
            Issuer == "AD AUTHORITY"
         ]
         => issue(
            Type = "is_staff",
            Value = "true",
            Issuer = c.Issuer,
            OriginalIssuer = c.OriginalIssuer,
            ValueType = c.ValueType
         );'
    )
}
