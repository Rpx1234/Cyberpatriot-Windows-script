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

 
#changes all users passwords
$password = Read-Host -Prompt "Enter password for all users" -AsSecureString 
$exclude = "Administrator","Guest","DefaultAccount"
Get-LocalUser |
  Where {$exclude -notcontains $_.Name} |
    Set-Localuser -Password $password

#auditing????
    auditpol /set /category:"Account Logon" /success:enable 
    auditpol /set /category:"Account Logon" /failure:enable
    auditpol /set /category:"DS Access" /success:enable
    auditpol /set /category:"DS Access" /failure:enable
    auditpol /set /category:"Policy Change" /success:enable
    auditpol /set /category:"Policy Change" /failure:enable
    auditpol /set /category:"Logon/Logoff" /success:enable
    auditpol /set /category:"Logon/Logoff" /failure:enable
    auditpol /set /category:"Object Access" /success:enable
    auditpol /set /category:"Object Access" /failure:enable
    auditpol /set /category:"Privilege Use" /success:enable
    auditpol /set /category:"Privilege Use" /failure:enable
    auditpol /set /category:"Account Management" /success:enable
    auditpol /set /category:"Account Management" /failure:enable
    auditpol /set /category:"Detailed Tracking" /success:enable
    auditpol /set /category:"Detailed Tracking" /failure:enable
    auditpol /set /category:"System" /success:enable 
    auditpol /set /category:"System" /failure:enable


# firewall rules
    New-NetFirewallRule -DisplayName "ssh" -Direction Inbound -LocalPort 22 -Protocol TCP -Action Block 
    New-NetFirewallRule -DisplayName "ftp" -Direction Inbound -LocalPort 21 -Protocol TCP -Action Block 
    New-NetFirewallRule -DisplayName "telnet" -Direction Inbound -LocalPort 23 -Protocol TCP -Action Block 
    New-NetFirewallRule -DisplayName "SMTP" -Direction Inbound -LocalPort 25 -Protocol TCP -Action Block 
    New-NetFirewallRule -DisplayName "SNMP" -Direction Inbound -LocalPort 161 -Protocol TCP -Action Block 
    New-NetFirewallRule -DisplayName "RDP" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Block 


# disable Internet explorer password caching
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f

# don't display last user username
  reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f
# enable ctrl+alt +del
   reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f

#boring internet stuff
	reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f
	reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonBadCertRecving /t REG_DWORD /d 1 /f
	reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
	reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV8 /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
#audit
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v auditbaseobjects /t REG_DWORD /d 1 /f
#prevent print driver installs
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f
#enable installer detection
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
# clear DNS cache
ipconfig /flushdns
# don't allow remote access to floppie disks
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f