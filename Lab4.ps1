#1.1.5 (L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled' (Automated)Powershell Script

# Import the Group Policy module
Import-Module GroupPolicy

# Get the local Group Policy object
$localGPO = Get-WmiObject -Namespace "root\rsop\computer" -Class RSOP_GPO -Filter "GPOType='Local'"

# Get the security policy section of the local GPO
$securityPolicy = Get-WmiObject -Namespace "root\rsop\computer" -Class RSOP_SecuritySettingBoolean -Filter "GPOID='$($localGPO.id)' AND keyname='PasswordComplexity'"

# Check if the setting is already configured correctly
if ($securityPolicy.Value -eq 4) {
    Write-Host "The 'Password must meet complexity requirements' setting is already set to 'Enabled: Automated'."
}
else {
    # Configure the setting to 'Enabled: Automated'
    $securityPolicy.Value = 4
    $securityPolicy.Put() | Out-Null
    Write-Host "Successfully configured the 'Password must meet complexity requirements' setting to 'Enabled: Automated'."
}


#18.4.3 (L1) Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)' (Automated)Powershell script

$GPOName = "YourGPOName"  # Replace with the name of your Group Policy Object

# Enable SMBv1 Disable Driver policy setting
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableInsecureGuestAuth" -Value 0 -Force

# Apply Group Policy update
Invoke-GPUpdate -Force

# Get the GPO
$gpo = Get-GPO -Name $GPOName

# Configure the SMBv1 Disable Driver policy setting in the GPO
$policyPath = "Computer Configuration\Policies\Administrative Templates\Network\Lanman Workstation"
$policyName = "Enable insecure guest logons"
$policyValue = "Enabled: Disable driver"

Set-GPRegistryValue -Name $GPOName -Key "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "EnableInsecureGuestAuth" -Type DWORD -Value 0
Set-GPRegistryValue -Name $GPOName -Key "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "RequireSecuritySignature" -Type DWORD -Value 1
Set-GPRegistryValue -Name $GPOName -Key "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "EnableSecuritySignature" -Type DWORD -Value 1

# Link the GPO to the appropriate Organizational Units (OUs) or domain
# Replace "OU=YourOU,DC=YourDomain,DC=com" with the desired OU or domain
New-GPLink -Name $GPOName -Target "OU=YourOU,DC=YourDomain,DC=com"

# Force Group Policy update on the targeted machines
Invoke-GPUpdate -Computer "YourServerName" -Force
