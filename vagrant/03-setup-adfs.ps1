# ########## SETTINGS #########
$adfsHost = "adfs"
# #############################

Write-Host "Waiting for domain controller to become reachable."
$isUp = $false
while($isUp -eq $false) {
    Try {
        $domain = Get-ADDomain
        $isUp = $true
    } Catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
        Write-Host "Retrying in 30 seconds"
        $isUp = $false
        Start-Sleep 30
    }
}

# Install the ADFS role
# ---------------------
Write-Host "Installing ADFS role..."
Install-WindowsFeature -Name ADFS-Federation -IncludeManagementTools

# Add ADFS DNS record
# -------------------
Write-Host "Adding DNS record..."
$ip = Get-NetIPAddress -InterfaceAlias "Ethernet 2" -AddressFamily ipv4
Add-DnsServerResourceRecordA -Name $adfsHost -IPv4Address $ip.IPAddress -ZoneName (Get-ADDomain).Forest


# Generate ADFS certificate
# -------------------------
Write-Host "Generating self signed certificate for ADFS..."

Import-Module \\vboxsrv\vagrant\vagrant\New-SelfSignedCertificateEx.ps1
$cert = New-SelfSignedCertificateEx `
-Subject ("CN="+$adfsHost+"."+(Get-ADDomain).Forest) `
-SubjectAlternativeName ($adfsHost+"."+(Get-ADDomain).Forest) `
-AlgorithmName RSA `
-KeyLength 2048 `
-SignatureAlgorithm SHA256 `
-StoreLocation LocalMachine

# Configure ADFS
# --------------
Write-Host "Configure ADFS..."
#  Needed to be able to create a group Managed Service Account
# set-service kdssvc -StartupType Automatic
Add-KdsRootKey -EffectiveTime (Get-Date).AddHours(-10)

Write-Host "Creating Group Managed Service Account..."
$Name = 'FsGmsa'
$DNS_Name = $adfsHost+"."+(Get-ADDomain).Forest
New-ADServiceAccount -Name $Name -DNSHostName $DNS_Name -PrincipalsAllowedToRetrieveManagedPassword "$env:computername`$"

Import-Module ADFS
Install-AdfsFarm `
-CertificateThumbprint $cert.Thumbprint `
-FederationServiceDisplayName "Example Corp" `
-FederationServiceName ($adfsHost+"."+(Get-ADDomain).Forest) `
-GroupServiceAccountIdentifier ((Get-ADDomain).NetBIOSName + "\FsGmsa`$") `
-OverwriteConfiguration

# https://social.technet.microsoft.com/Forums/office/en-US/a290c5c0-3112-409f-8cb0-ff23e083e5d1/ad-fs-windows-2012-r2-adfssrv-hangs-in-starting-mode?forum=winserverDS
sc.exe triggerinfo kdssvc start/networkon
