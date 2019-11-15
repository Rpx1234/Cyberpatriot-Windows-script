 Get-Wmiobject Win32_UserAccount -filter 'LocalAccount=TRUE' | select-object  Name | Export-Csv -Path ".\users.csv"  -NoTypeInformation 

 $userslist = import-csv -Path ".\users.csv"
$authorizedusers = import-csv -Path ".\authusers.csv" 


Compare-Object -ReferenceObject $userslist -DifferenceObject $authorizedusers -Property 'Name' | Select * -ExcludeProperty SideIndicator |export-csv '.\badaccounts.csv' -notypeinformation


Read-Host -Prompt 'Ready to continue'


$guest = Read-Host -Prompt 'Disable Guest account?(y or n)'
 if($guest -eq "y") {

  net user guest /active:no
 }
 else {break}
 
$admin = Read-Host -Prompt 'Disable Administrator account?(y or n)'
if($admin -eq "y") 
{
  net user "Administrator" /active:no
}
else {break}

$media = Read-Host -Prompt 'look for media files?(y or n)'
if($media -eq "y")
{
Get-ChildItem -Path C:\Users -Include *.jpg,*.png,*.jpeg,*.avi,*.mp4,*.mp3,*.wav -File -Recurse -ErrorAction SilentlyContinue | Out-File -filepath .\Mediafiles.txt
}
else{break}

$firewall = Read-Host -Prompt 'enable firewall?(y or n)'
if($firewall -eq "y")
{
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
}

else{break}

$checkusrmanually = Read-Host -prompt 'would you like to check users manually?(y or n)'
if($checkusrmanually -eq "y")
{
start C:\Windows\System32\lusrmgr.msc /wait
}
else{break}

 
