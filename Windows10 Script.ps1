         # This will check if script is running as admin, if not it will elevate itself
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Write-Host "Script was not run as Admin, changing to admin now"
    Start-Sleep 1
    Write-Host "                                               3"
    Start-Sleep 1
    Write-Host "                                               2"
    Start-Sleep 1
    Write-Host "                                               1"
    Start-Sleep 1
    Start-Process powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit
}

 
 
 Get-Wmiobject Win32_UserAccount -filter 'LocalAccount=TRUE' | select-object  Name | Export-Csv -Path ".\users.csv"  -NoTypeInformation 

 $userslist = import-csv -Path ".\users.csv"
$authorizedusers = import-csv -Path ".\authusers.csv" 


Compare-Object -ReferenceObject $userslist -DifferenceObject $authorizedusers -Property 'Name' | Select * -ExcludeProperty SideIndicator |export-csv '.\badaccounts.csv' -notypeinformation


# in testing phase
     #Creates array of users
        #$users = Get-ChildItem -Path 'C:\Users' -directory
      #imports list of allowed users
         #$allowedusers = Import-Csv -Path ".\authusers.csv"
        # Compare-Object -ReferenceObject $users -DifferenceObject $allowedusers -Property 'Name' | export-csv '.\badaccounts.csv' -NoTypeInformation













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
  
   # enables firewall
Write-Host Enabling firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
  #set max password age
Write-Host setting max password age to 90
 net accounts /maxpwage:90
  # set min password age
Write-Host Setting min password age to 10
 net accounts /minpwage:10
  # set password history 
Write-Host setting password history setting to 5
 net accounts /uniquepw:5
  #set min password length
Write-Host setting min password length
 net accounts /minpwlen:10
 #not able to force password must meet complexity requirements
  # https://www.tenforums.com/tutorials/87386-change-maximum-minimum-password-age-local-accounts-windows-10-a.html
  # https://www.tenforums.com/tutorials/87545-change-minimum-password-length-local-accounts-windows-10-a.html
  # https://www.tenforums.com/tutorials/87379-enable-disable-password-expiration-local-accounts-windows-10-a.html
  # https://www.top-password.com/blog/change-account-lockout-password-complexity-policy-in-windows/

 # setting account lockout policy
 Write-Host Setting account lockout policy
    net accounts /lockoutduration:30
    net accounts /lockoutthreshold:5
    net accounts /lockoutwindow:30












$checkusrmanually = Read-Host -prompt 'would you like to check users manually?(y or n)'
if($checkusrmanually -eq "y")
{
start C:\Windows\System32\lusrmgr.msc /wait
}
else{break}

 
