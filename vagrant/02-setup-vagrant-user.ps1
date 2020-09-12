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

Add-ADGroupMember -Identity "Domain Admins" -Members vagrant
Add-ADGroupMember -Identity "Enterprise Admins" -Members vagrant
Add-ADGroupMember -Identity "Schema Admins" -Members vagrant
