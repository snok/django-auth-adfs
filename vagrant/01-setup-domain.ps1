# ########## SETTINGS #########
$domainName = "example.com"
$netbiosName = "EXAMPLE"
$safeModePwd = "Password123"
# #############################
Set-LocalUser `
    -name "administrator" `
    -AccountNeverExpires `
    -Password (Convertto-SecureString -AsPlainText "Vagrant123" -Force) `
    -PasswordNeverExpires $true
# Install and configure domain controller role
# --------------------------------------------
Write-Host "Installing domain features..."
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
Write-Host "Promoting DC..."
Import-Module ADDSDeployment
Install-ADDSForest `
  -CreateDnsDelegation:$false `
  -DatabasePath "C:\Windows\NTDS" `
  -DomainMode "WinThreshold" `
  -DomainName $domainName `
  -DomainNetbiosName $netbiosName `
  -ForestMode "WinThreshold" `
  -InstallDns:$true `
  -LogPath "C:\Windows\NTDS" `
  -SysvolPath "C:\Windows\SYSVOL" `
  -Force:$true `
  -SafeModeAdministratorPassword (Convertto-SecureString -AsPlainText $safeModePwd -Force) `
  -NoRebootOnCompletion
