# ########## SETTINGS #########
$domainName = "example.com"
$netbiosName = "EXAMPLE"
$safeModePwd = "Password123"
# #############################

# Install and configure domain controller role
# --------------------------------------------
Write-Host "Installing domain features..."
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

Write-Host "Promoting DC..."
If ([Environment]::OSVersion.version.major -ge 10) {
    $mode = "WinThreshold"
} Else {
    $mode = "Win2012R2"
}
Import-Module ADDSDeployment
Install-ADDSForest `
-CreateDnsDelegation:$false `
-DatabasePath "C:\Windows\NTDS" `
-DomainMode $mode `
-DomainName $domainName `
-DomainNetbiosName $netbiosName `
-ForestMode $mode `
-InstallDns:$true `
-LogPath "C:\Windows\NTDS" `
-SysvolPath "C:\Windows\SYSVOL" `
-Force:$true `
-SafeModeAdministratorPassword (Convertto-SecureString -AsPlainText $safeModePwd -Force) `
-NoRebootOnCompletion
