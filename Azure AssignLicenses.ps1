# Prerequisites - Connect to Azure
$username = "user@domain.com"
$pwdTxt = Get-Content "C:\path\Encrypted.txt"
$securePwd = $pwdTxt | ConvertTo-SecureString -Key (1..16)
$credObject = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $securePwd

Install-Module AzureAD
Install-Module MSOnline
Import-Module ActiveDirectory
Connect-MsolService -Credential $credObject
Connect-AzureAD -Credential $credObject

# ArrayLists 
$ArrayListGroup1 =              Get-ADGroupMember -identity "Group1" -Recursive | Get-ADUser -Properties UserPrincipalName | Select UserPrincipalName 
$ArrayListGroup2 =              Get-ADGroupMember -identity "Group2" -Recursive | Get-ADUser -Properties UserPrincipalName | Select UserPrincipalName
$ArrayLists = $ArrayListGroup1 + $ArrayListGroup2

# Create the objects we'll need to add and remove licenses
$license = New-Object -TypeName  Microsoft.Open.AzureAD.Model.AssignedLicense
$licenses = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses

# Find the SkuID of the license we want to add - in this example we'll use the Power_BI_PRO license
$license.SkuId = (Get-AzureADSubscribedSku | Where-Object -Property SkuPartNumber -Value "Power_BI_PRO" -EQ).SkuID

# Set the Power BI Pro license as the license we want to add in the $licenses object
$licenses.AddLicenses = $license

#Measure all users with PowerBI licenses
$PowerBILicens = Get-MsolUser -All | Where-Object {($_.licenses).AccountSkuId -match "Power_BI_PRO"} | select UserPrincipalName

$CompareBefore = Compare-Object  -ReferenceObject $ArrayLists -DifferenceObject $PowerBILicens -Property UserPrincipalName

# Compare both arraylists and remove licenses which is not in the arraylists
(Compare-Object  -ReferenceObject $ArrayLists -DifferenceObject $PowerBILicens -Property UserPrincipalName |
ForEach-Object {
      if ($_.SideIndicator -eq '=>') {
    $Licenses.AddLicenses = @()
    $Licenses.RemoveLicenses = (Get-AzureADSubscribedSku | Where-Object -Property SkuPartNumber -Value "Power_BI_PRO" -EQ).SkuID
    Set-AzureADUserLicense -ObjectId $_.UserPrincipalName -AssignedLicenses $licenses
} elseif ($_.SideIndicator -eq '<=') {
    $licenses.AddLicenses = $license
    $licenses.RemoveLicenses = @()
    Set-AzureADUserLicense -ObjectId $_.UserPrincipalName -AssignedLicenses $licenses
}
$_ 
})