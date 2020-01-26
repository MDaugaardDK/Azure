$ADGroupMembers = Get-ADGroupMember -identity "ADGroup" -Recursive | Get-ADUser -Properties UserPrincipalName | Select UserPrincipalName

$username = "user@domain.com"
$pwdTxt = Get-Content "C:\Path\Encrypted.txt"
$securePwd = $pwdTxt | ConvertTo-SecureString -Key (1..16)
$credObject = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $securePwd
Connect-AzureAD -Credential $credObject

ForEach ($Member in $ADGroupMembers) {
$member.UserPrincipalName
Get-AzureADUserLicenseDetail -ObjectId "$($Member.UserPrincipalName)" | select SkuPartNumber | fl *
}
