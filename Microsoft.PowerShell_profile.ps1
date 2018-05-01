### Init
Write-Host "Hello Jon!"
Set-Location $HOME

### Imports
Import-Module $HOME\workspace\psregistry\psregistry.psm1

### Variables
$CplTools = @{
	'System Properties'= 'sysdm.cpl'
	'Computer Management'= 'compmgmt'
	'Add New Hardware'= 'sysdm.cpl add new hardware'
	'Add/Remove Programs'= 'appwiz.cpl'
	'Date/Time Properties'= 'timedate.cpl'
	'FindFast'= 'findfast.cpl'
	'Joystick Properties'= 'joy.cpl'
	'Mouse Properties'= 'main.cpl'
	'Keyboard Properties'= 'main.cpl keyboard'
	'Power Properties'= 'main.cpl power'
	'Sound Properties'= 'mmsys.cpl'
	'Network Properties'= 'ncpa.cpl'
	'Password Properties'= 'password.cpl'
	'Regional Settings'= 'intl.cpl'
	}

### Functions
Function Start-Posh {
	Start-Process -FilePath powershell.exe -Verb RunAs
}

Function Show-CplTools {
	Write-Output $CplTools
}

Function Show-WifiProfiles {
	# Add RegEx to turn results into hastable/powershell object
	netsh wlan show profiles
}

Function Show-Wifi {
	param (
		[switch]$All=$false
	)
	$Bssid = (netsh wlan show network mode=bssid | Select-Object -Skip 3).Trim() | Out-String
	$RegEx = @"
(?x)
SSID\s\d+\s:\s(?<SSID>[a-z0-9\-\*\.&_]+)\r\n
Network\stype\s+:\s(?<NetworkType>\w+)\r\n
Authentication\s+:\s(?<Authentication>[a-z0-9\-_]+)\r\n
Encryption\s+:\s(?<Encryption>\w+)\r\n
BSSID\s1\s+:\s(?<BSSID>(?:\w+:){5}\w+)\r\n
Signal\s+:\s(?<Signal>\d{1,2})%\r\n
Radio\stype\s+:\s(?<Radio>[a-z0-9\.]+)\r\n
Channel\s+:\s(?<Channel>\w+)\r\n
"@
	$Networks = $Bssid -Split "\r\s+\n"
	if ($All) {
		$WiFiNetworks = $Networks | ForEach-Object {
			if ($PSItem -match $RegEx) {
				[PSCustomObject]@{
					SSID=$Matches.SSID
					NetworkType=$Matches.NetworkType
					AuthenticationType=$Matches.Autentication
					Encryption=$Matches.Encryption
					BSSID=$Matches.BSSID
					SignalPercentage=[int]$Matches.Signal
					RadioType=$Matches.Radio
					Channel=$Matches.Channel
				}
			}
		}
	}
	elseif (!$All) {
		$WiFiNetworks = $Networks | ForEach-Object {
			if ($PSItem -match $RegEx) {
				[PSCustomObject]@{
					SSID=$Matches.SSID
					SignalPercentage=[int]$Matches.Signal
				}
			}
		}
	}
	
	Write-Output ($WiFiNetworks | Sort-Object SignalPercentage -Descending)
}

Function Connect-WiFi {
	param (
		$Network
	)

	netsh wlan connect ssid="$Network" name="$Network"
}

Function Set-Shell {
	param (
		[Switch]$ToExplorer,
		[Switch]$ToPowershell,
		[Switch]$Logoff
	)

	$Shell = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name Shell | Select-Object -ExpandProperty Shell
	Write-Host @"
The shell is currently set to $Shell
For powershell, run : Set-Shell -ToPowershell
For explorer, run : Set-Shell -ToExplorer
"@

	if ($ToPowershell) {
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name Shell -Value "powershell.exe"
	}

	elseif ($ToExplorer) {
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name Shell -Value "explorer.exe"
	}

	if ($LogOff) {
		Write-Host "Logging off, log back in to see new settings reflected"
		Invoke-Expression logoff
	}
}

Function Set-RDP {
	param (
		$Hostname="localhost",
		$Credential,
		[Switch]$Enabled,
		[Switch]$Disabled
	)

	$KeyPath = "HKLM:\SYSTEM\CurRentControlSet\Control\Terminal Server"
	$KeyName = "fDenyTSConnections"
	$Session = if ($Credential) {New-PSSession -Computer $Hostname -Credential $Credential} else {New-PSSession -Computer $Hostname}

	if ($Enabled) {
		Invoke-Command -Session $Session -ScriptBlock {
			Set-ItemProperty -Path $using:KeyPath -Name $using:KeyName -Value 0
			Enable-NetFirewallRule -Name "RemoteDesktop-UserMode-In-TCP"
			Enable-NetFirewallRule -Name "RemoteDesktop-UserMode-In-UDP"
		}
	}

	elseif ($Disabled) {
		Set-ItemProperty -Path $KeyPath -Name $KeyName -Value 1
		Disable-NetFirewallRule -Name "RemoteDesktop-UserMode-In-TCP"
		Disable-NetFirewallRule -Name "RemoteDesktop-UserMode-In-UDP"
	}
}

Function Connect-VPN {
	param (
		[Switch]$US,
		[Switch]$CA
	)

	Get-Process | Where-Object ProcessName -EQ "openvpn-gui" | Stop-Process
	Set-Location 'C:\Program Files\OpenVPN\config\'

	if ($US) {
		Write-Host "Conneting to US vpn..."
		Start-Process -FilePath 'C:\Program Files\OpenVPN\bin\openvpn-gui.exe' -ArgumentList @("--connect","us01rt01-udp-443-config.ovpn")
	}

	elseif ($CA) {
		Write-Host "Conneting to CA vpn..."
		Start-Process -FilePath 'C:\Program Files\OpenVPN\bin\openvpn-gui.exe' -ArgumentList @("--connect","ca01rt01-TCP-443-config.ovpn")
	}

	Set-Location ~
}

Function Set-TrustedHosts {
	Set-Item wsman:\localhost\Client\TrustedHosts -value * -Force
}

function Invoke-PowerShell {
    powershell -nologo
    Invoke-PowerShell
}

function Restart-PowerShell {
    if ($host.Name -eq 'ConsoleHost') {
        exit
    }
    Write-Warning 'Only usable while in the PowerShell console host'
}

$parentProcessId = (Get-WmiObject Win32_Process -Filter "ProcessId=$PID").ParentProcessId
$parentProcessName = (Get-WmiObject Win32_Process -Filter "ProcessId=$parentProcessId").ProcessName

if ($host.Name -eq 'ConsoleHost') {
    if (-not($parentProcessName -eq 'powershell.exe')) {
        Invoke-PowerShell
    }
}

### Aliases
Set-Alias -Name 'reload' -Value 'Restart-PowerShell'
Set-Alias Chrome 'C:\Program Files (x86)\Google\Chrome\Application\Chrome.exe'
Set-Alias G 'findstr'
Set-Alias C 'clip'
Set-Alias HV 'virtmgmt.msc'