#Requires -RunAsAdministrator
<#
.SYNOPSIS
	Windows Server 2019 / Windows 10 Hardening Script
.DESCRIPTION
	Applies DISA STIG-aligned registry, Defender, firewall, SCHANNEL, and auditing configurations.
	Note: Review aggressive settings (e.g., NTLM restrictions, Public Firewall block-all) before running in production.
#>





#
# Environment Setup
#
# Helper function to mimic 'reg add'
function Set-RegistryValue {
	param (
		[Parameter(Mandatory = $true)][string]$Path,
		[Parameter(Mandatory = $true)][string]$Name,
		[Parameter(Mandatory = $true)][object]$Value,
		[Microsoft.Win32.RegistryValueKind]$Type = 'DWord'
	)
	if (-not (Test-Path $Path)) {
		New-Item -Path $Path -Force | Out-Null
	}
	Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
}





#
# File Associations & Shell Mitigations
#
Write-Host "[*] Configuring file associations..." -ForegroundColor Cyan
.\assocs.bat
#
# Mitigate SettingContent-ms and Device Metadata exploits
Set-RegistryValue -Path "HKLM:\SOFTlARE\Classes\SettingContent\Shell\Open\Command" -Name "DelegateExecute" -Value "" -Type String
Remove-Item -Path "HKLM:\SOFTWARE\Classes\.devicemetadata-ms" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Classes\.devicemanifest-ms" -Recurse -Force -ErrorAction SilentlyContinue





#
# Windows Defender, ASR Rules & Exploit Guard
#
Write-Host "[*] Configuring Windows Defender & Exploit Guard..." -ForegroundColor Cyan
[System.Environment]::SetEnvironmentVariable("MP_FORCE_USE_SANDBOX", "1", "Machine")
if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
	Update-MpSignature -ErrorAction SilentlyContinue
	Set-MpPreference `
		-PUAProtection Enabled `
		-DisableRealtimeMonitoring $false `
		-EnableControlledFolderAccess Enabled `
		-MAPSReporting Advanced `
		-SubmitSamplesConsent SendAllSamples `
		-EnableNetworkProtection Enabled `
		-ErrorAction SilentlyContinue
	#
	# Attack Surface Reduction (ASR) Rules
	$asrRules = @(
		"D1E49AAC-8F56-4280-B9BA-993A6D77406B", # Block process creations originating from PSExec and WMI
		"D4F940AB-401B-4EFC-AADC-AD5F3C50688A", # Block Office apps from creating child processes
		"75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84", # Block Office apps from injecting code into other processes
		"92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B", # Block Win32 API calls from Office macros
		"3B576869-A4EC-4529-8536-B80A7769E899", # Block Office apps from creating executable content
		"5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", # Block execution of potentially obfuscated scripts
		"BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", # Block executable content from email client and webmail
		"D3E037E1-3EB8-44C8-A917-57927947596D", # Block JS or VBS from launching downloaded executable content
		"01443614-cd74-433a-b99e-2ecdc07bfc25", # Block executable files unless they meet prevalence/age/trusted criteria
		"C1DB55AB-C21A-4637-BB3F-A12568109D35", # Use advanced protection against ransomware
		"9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2", # Block credential stealing from lsass.exe
		"B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4"  # Block untrusted and unsigned processes that run from USB
	)
	$asrActions = @("Enabled") * $asrRules.Count
	Add-MpPreference -AttackSurfaceReductionRules_Ids $asrRules -AttackSurfaceReductionRules_Actions $asrActions -ErrorAction SilentlyContinue
}
#
# Process Mitigation & Microsoft Baseline XML
Set-ProcessMitigation -System -Enable DEP, EmulateAtlThunks, BottomUp, HighEntropy, SEHOP, SEHOPTelemetry, TerminateOnError -ErrorAction SilentlyContinue
$tempXml = [System.IO.Path]::GetTempFileName() + ".xml"
try {
	Invoke-WebRequest -Uri "https://demo.wd.microsoft.com/Content/ProcessMitigation.xml" -OutFile $tempXml -UseBasicParsing
	Set-ProcessMitigation -PolicyFilePath $tempXml
} catch {
	Write-Warning "Could not download or apply ProcessMitigation.xml: $_"
} finally {
	Remove-Item $tempXml -Force -ErrorAction SilentlyContinue
}
#
# Optional Features (Application Guard, SMBv1, PowerShell v2)
$featuresToEnable = @("Windows-Defender-ApplicationGuard")
foreach ($feat in $featuresToEnable) {
	Enable-WindowsOptionalFeature -Online -FeatureName $feat -NoRestart -ErrorAction SilentlyContinue | Out-Null
}
$featuresToDisable = @("SMB1Protocol", "MicrosoftWindowsPowerShellV2", "MicrosoftWindowsPowerShellV2Root")
foreach ($feat in $featuresToDisable) {
	Disable-WindowsOptionalFeature -Online -FeatureName $feat -NoRestart -ErrorAction SilentlyContinue | Out-Null
}





#
# Network, Services & Filesystem Hardening
#
Write-Host "[*] Hardening Network, WinRM, NetBIOS, and Filesystem..." -ForegroundColor Cyan
#
# Disable NetBIOS over TCP/IP across all adapters (Replaces deprecated WMIC)
Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "TcpipNetbiosOptions = 0 OR TcpipNetbiosOptions = 1" |
	Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 } | Out-Null
#
# Disable TCP timestamps
netsh int tcp set global timestamps=disabled | Out-Null
#
# Disable 8.3 names and enable Last Access timestamp
fsutil behavior set disable8dot3 1 | Out-Null
fsutil behavior set disablelastaccess 0 | Out-Null





#
# Windows Firewall & LOLBin Outbound Blocks
#
Write-Host "[*] Configuring Windows Firewall and blocking LOLBins..." -ForegroundColor Cyan
netsh advfirewall reset | Out-Null
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True
#
# Configure Firewall Logging
Set-NetFirewallProfile -All -LogFileName "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" -LogMaxSizeKilobytes 4096 -LogBlocked True
#
# Uncomment the line below ONLY if you have physical access and want to block ALL inbound traffic on Public networks:
Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block -DefaultOutboundAction Allow -AllowInboundRules False
#
# Setup rules
$sysExes = @(
	"calc.exe", "certutil.exe", "cmstp.exe", "cscript.exe", "esentutl.exe",
	"expand.exe", "extrac32.exe", "findstr.exe", "hh.exe", "makecab.exe",
	"mshta.exe", "msiexec.exe", "nltest.exe", "notepad.exe", "odbcconf.exe",
	"pcalua.exe", "print.exe", "regasm.exe", "regsvr32.exe", "replace.exe",
	"rpcping.exe", "rundll32.exe", "runscripthelper.exe", "scriptrunner.exe",
	"SyncAppvPublishingServer.exe", "wbem\wmic.exe", "wscript.exe"
)
$lolbinTargets = @(
	"C:\Program Files (x86)\Microsoft Office\root\client\AppVLP.exe",
	"C:\Program Files\Microsoft Office\root\client\AppVLP.exe"
)
foreach ($exe in $sysExes) {
	$lolbinTargets += "$env:SystemRoot\System32\$exe"
	$lolbinTargets += "$env:SystemRoot\SysWOW64\$exe"
}
foreach ($path in $lolbinTargets) {
	if (Test-Path $path) {
		$fileName = Split-Path $path -Leaf
		New-NetFirewallRule `
			-DisplayName "Block $fileName netconns" `
			-Direction Outbound `
			-Program $path `
			-Protocol TCP `
			-Action Block `
			-Profile Any `
			-Enabled True | Out-Null
	}
}





#
# Registry Hardening (OS, LSA, SMB, DLL Hijacking, Edge, PowerShell)
#
Write-Host "[*] Applying Registry hardening settings..." -ForegroundColor Cyan
$regSettings = @(
	# Defender & Device Guard
	@{ Path = "HKCU:\SOFTWARE\Microsoft\Windows Defender"; Name = "PassiveMode"; Value = 2 }
	@{ Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableRealtimeMonitoring"; Value = 0 }
	@{ Path = "HKCU:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"; Name = "DriverLoadPolicy"; Value = 3 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; Name = "EnableVirtualizationBasedSecurity"; Value = 1 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; Name = "RequirePlatformSecurityFeatures"; Value = 3 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; Name = "LsaCfgFlags"; Value = 1 }
	#
	# SMBv1, SMBv3 Compression & Signing
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name = "DisableCompression"; Value = 1 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name = "SMB1"; Value = 0 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name = "RestrictNullSessAccess"; Value = 1 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"; Name = "Start"; Value = 4 }
	@{ Path = "HKLM:\System\CurrentControlSet\Services\LanmanWorkStation\Parameters"; Name = "RequireSecuritySignature"; Value = 1 }
	@{ Path = "HKLM:\System\CurrentControlSet\Services\LanmanWorkStation\Parameters"; Name = "EnableSecuritySignature"; Value = 1 }
	@{ Path = "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"; Name = "RequireSecuritySignature"; Value = 1 }
	@{ Path = "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"; Name = "EnableSecuritySignature"; Value = 1 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name = "EnablePlainTextPassword"; Value = 0 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"; Name = "AllowInsecureGuestAuth"; Value = 0 }
	#
	# LDAP & Netlogon Secure Channel
	@{ Path = "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters"; Name = "LDAPServerIntegrity"; Value = 2 }
	@{ Path = "HKLM:\System\CurrentControlSet\Services\ldap"; Name = "LDAPClientIntegrity"; Value = 1 }
	@{ Path = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"; Name = "RequireSignOrSeal"; Value = 1 }
	@{ Path = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"; Name = "SealSecureChannel"; Value = 1 }
	@{ Path = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"; Name = "SignSecureChannel"; Value = 1 }
	#
	# LSA, NTLM, WDigest & Credential Guard (Warning: RestrictSendingNTLMTraffic=2 breaks outgoing RDP & shares)
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"; Name = "UseLogonCredential"; Value = 0 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"; Name = "Negotiate"; Value = 0 }
	@{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"; Name = "SupportedEncryptionTypes"; Value = 2147483640 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name = "RestrictReceivingNTLMTraffic"; Value = 2 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name = "RestrictSendingNTLMTraffic"; Value = 2 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name = "NTLMMinServerSec"; Value = 537395200 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name = "NTLMMinClientSec"; Value = 537395200 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name = "allownullsessionfallback"; Value = 0 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "LMCompatibilityLevel"; Value = 5 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "RestrictAnonymousSAM"; Value = 1 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "RestrictAnonymous"; Value = 1 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "EveryoneIncludesAnonymous"; Value = 0 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "RestrictRemoteSAM"; Value = "O:BAG:BAD:(A;;RC;;;BA)"; Type = "String" }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "UseMachineId"; Value = 1 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "LimitBlankPasswordUse"; Value = 1 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "RunAsPPL"; Value = 1 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "DisableRestrictedAdmin"; Value = 0 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "DisableRestrictedAdminOutboundCreds"; Value = 1 }
	@{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe"; Name = "AuditLevel"; Value = 8 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"; Name = "AllowProtectedCreds"; Value = 1 }
	#
	# DNS, TCP/IP & IPv6
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Name = "EnableMulticast"; Value = 1 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Name = "DisableSmartNameResolution"; Value = 1 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"; Name = "DisableParallelAandAAAA"; Value = 1 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "IGMPLevel"; Value = 0 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "DisableIPSourceRouting"; Value = 2 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "EnableICMPRedirect"; Value = 0 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"; Name = "DisableIPSourceRouting"; Value = 2 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"; Name = "DisabledComponents"; Value = 0xFF }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters"; Name = "NoNameReleaseOnDemand"; Value = 1 }
	@{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad"; Name = "WpadOverride"; Value = 1 }
	#
	# UAC, WinRM, RPC, RDP & Printers
	@{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "EnableLUA"; Value = 1 }
	@{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "EnableVirtualization"; Value = 1 }
	@{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "ConsentPromptBehaviorAdmin"; Value = 2 }
	@{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "LocalAccountTokenFilterPolicy"; Value = 0 }
	@{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "FilterAdministratorToken"; Value = 1 }
	@{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "InactivityTimeoutSecs"; Value = 900 }
	@{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"; Name = "SaveZoneInformation"; Value = 2 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name = "NoDataExecutionPrevention"; Value = 0 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name = "NoHeapTerminationOnCorruption"; Value = 0 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"; Name = "DisableWebPnPDownload"; Value = 1 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"; Name = "DisableHTTPPrinting"; Value = 1 }
	@{ Path = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"; Name = "AutoConnectAllowedOEM"; Value = 0 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"; Name = "fMinimizeConnections"; Value = 1 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"; Name = "NoGPOListChanges"; Value = 0 }
	@{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name = "SCRemoveOption"; Value = 2 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"; Name = "RestrictRemoteClients"; Value = 1 }
	@{ Path = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Schedule"; Name = "DisableRpcOverTcp"; Value = 1 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control"; Name = "DisableRemoteScmEndpoints"; Value = 1 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"; Name = "NC_ShowSharedAccessUI"; Value = 0 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; Name = "AllowUnencryptedTraffic"; Value = 0 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"; Name = "AllowDigest"; Value = 0 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name = "fAllowToGetHelp"; Value = 0 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name = "fEncryptRPCTraffic"; Value = 1 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name = "fDisableCdm"; Value = 1 }
	#
	# DLL Hijacking, WSH, AutoRun, Power & Windows Update
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"; Name = "CWDIllegalInDllSearch"; Value = 2 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"; Name = "SafeDLLSearchMode"; Value = 1 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"; Name = "ProtectionMode"; Value = 1 }
	@{ Path = "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings"; Name = "Enabled"; Value = 0 }
	@{ Path = "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings"; Name = "ActiveDebugging"; Value = "1"; Type = "String" }
	@{ Path = "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings"; Name = "DisplayLogo"; Value = "1"; Type = "String" }
	@{ Path = "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings"; Name = "SilentTerminate"; Value = "0"; Type = "String" }
	@{ Path = "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings"; Name = "UseWINSAFER"; Value = "1"; Type = "String" }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"; Name = "DODownloadMode"; Value = 0 }
	@{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"; Name = "DODownloadMode"; Value = 0 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"; Name = "ACSettingIndex"; Value = 1 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"; Name = "DCSettingIndex"; Value = 1 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name = "NoAutoplayfornonVolume"; Value = 1 }
	@{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoDriveTypeAutoRun"; Value = 0xFF }
	@{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoDriveTypeAutoRun"; Value = 0xFF }
	@{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoAutorun"; Value = 1 }
	#
	# Explorer File Visibility & SmartScreen
	@{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "HideFileExt"; Value = 0 }
	@{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "HideFileExt"; Value = 0 }
	@{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "Hidden"; Value = 1 }
	@{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "Hidden"; Value = 1 }
	@{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "ShowSuperHidden"; Value = 1 }
	@{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "ShowSuperHidden"; Value = 1 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "EnableSmartScreen"; Value = 1 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "ShellSmartScreenLevel"; Value = "Block"; Type = "String" }
	#
	# Biometrics & App Privacy
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures"; Name = "EnhancedAntiSpoofing"; Value = 1 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"; Name = "NoLockScreenCamera"; Value = 1 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsActivateWithVoiceAboveLock"; Value = 2 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsActivateWithVoice"; Value = 2 }
	#
	# .NET Framework Strong Crypto & ClickOnce Trust Manager
	@{ Path = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727"; Name = "SchUseStrongCrypto"; Value = 1 }
	@{ Path = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727"; Name = "SystemDefaultTlsVersions"; Value = 1 }
	@{ Path = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727"; Name = "SchUseStrongCrypto"; Value = 1 }
	@{ Path = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727"; Name = "SystemDefaultTlsVersions"; Value = 1 }
	@{ Path = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"; Name = "SchUseStrongCrypto"; Value = 1 }
	@{ Path = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"; Name = "SystemDefaultTlsVersions"; Value = 1 }
	@{ Path = "HKLM:\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel"; Name = "MyComputer"; Value = "Disabled"; Type = "String" }
	@{ Path = "HKLM:\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel"; Name = "LocalIntranet"; Value = "Disabled"; Type = "String" }
	@{ Path = "HKLM:\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel"; Name = "Internet"; Value = "Disabled"; Type = "String" }
	@{ Path = "HKLM:\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel"; Name = "TrustedSites"; Value = "Disabled"; Type = "String" }
	@{ Path = "HKLM:\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel"; Name = "UntrustedSites"; Value = "Disabled"; Type = "String" }
	#
	# Legacy Edge & IE Settings
	@{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter"; Name = "EnabledV9"; Value = 1 }
	@{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name = "SafeForScripting"; Value = 0 }
	@{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main"; Name = "FormSuggest Passwords"; Value = "no"; Type = "String" }
	#
	# Auditing & PowerShell Logging
	@{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"; Name = "ProcessCreationIncludeCmdLine_Enabled"; Value = 1 }
	@{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "SCENoApplyLegacyAuditPolicy"; Value = 1 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"; Name = "EnableModuleLogging"; Value = 1 }
	@{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Name = "EnableScriptBlockLogging"; Value = 1 }
)
foreach ($item in $regSettings) {
	$type = if ($item.ContainsKey('Type')) { $item.Type } else { 'DWord' }
	Set-RegistryValue -Path $item.Path -Name $item.Name -Value $item.Value -Type $type
}
#
# Restart WinRM to apply registry changes
Restart-Service -Name WinRM -Force -ErrorAction SilentlyContinue





#
# SCHANNEL Ciphers, Hashes, Key Exchanges & TLS Protocols
#
Write-Host "[*] Configuring SCHANNEL TLS/SSL settings..." -ForegroundColor Cyan
$schannelBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
#
# Ciphers
$enabledCiphers  = @("AES 128/128", "AES 256/256")
$disabledCiphers = @("DES 56/56", "NULL", "RC2 128/128", "RC2 40/128", "RC2 56/128", "RC4 128/128", "RC4 40/128", "RC4 56/128", "RC4 64/128", "Triple DES 168")
foreach ($c in $enabledCiphers)  { Set-RegistryValue -Path "$schannelBase\Ciphers\$c" -Name "Enabled" -Value 0xffffffff }
foreach ($c in $disabledCiphers) { Set-RegistryValue -Path "$schannelBase\Ciphers\$c" -Name "Enabled" -Value 0 }
#
# Hashes
foreach ($h in @("MD5", "SHA", "SHA256", "SHA384", "SHA512")) {
	Set-RegistryValue -Path "$schannelBase\Hashes\$h" -Name "Enabled" -Value 0xffffffff
}
#
# Key Exchanges
foreach ($k in @("Diffie-Hellman", "ECDH", "PKCS")) {
	Set-RegistryValue -Path "$schannelBase\KeyExchangeAlgorithms\$k" -Name "Enabled" -Value 0xffffffff
}
Set-RegistryValue -Path "$schannelBase\KeyExchangeAlgorithms\Diffie-Hellman" -Name "ServerMinKeyBitLength" -Value 0x00001000
#
# Protocols
$disabledProtocols = @("Multi-Protocol Unified Hello", "PCT 1.0", "SSL 2.0", "SSL 3.0")
$enabledProtocols  = @("TLS 1.0", "TLS 1.1", "TLS 1.2")
foreach ($proto in $disabledProtocols) {
	foreach ($side in @("Client", "Server")) {
		Set-RegistryValue -Path "$schannelBase\Protocols\$proto\$side" -Name "Enabled" -Value 0
		Set-RegistryValue -Path "$schannelBase\Protocols\$proto\$side" -Name "DisabledByDefault" -Value 1
	}
}
foreach ($proto in $enabledProtocols) {
	foreach ($side in @("Client", "Server")) {
		Set-RegistryValue -Path "$schannelBase\Protocols\$proto\$side" -Name "Enabled" -Value 0xffffffff
		Set-RegistryValue -Path "$schannelBase\Protocols\$proto\$side" -Name "DisabledByDefault" -Value 0
	}
}
#
# Cipher Suite Order
$cipherSuites = @(
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	"TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_128_GCM_SHA256",
	"TLS_RSA_WITH_AES_256_CBC_SHA256", "TLS_RSA_WITH_AES_128_CBC_SHA256",
	"TLS_RSA_WITH_AES_256_CBC_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA",
	"TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256",
	"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_WITH_NULL_SHA256", "TLS_RSA_WITH_NULL_SHA",
	"TLS_PSK_WITH_AES_256_GCM_SHA384", "TLS_PSK_WITH_AES_128_GCM_SHA256",
	"TLS_PSK_WITH_AES_256_CBC_SHA384", "TLS_PSK_WITH_AES_128_CBC_SHA256",
	"TLS_PSK_WITH_NULL_SHA384", "TLS_PSK_WITH_NULL_SHA256"
) -join ","

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "Functions" -Value $cipherSuites -Type String

#
# Event Logs & Advanced Audit Policy
#
Write-Host "[*] Configuring Event Log sizes and Auditpol..." -ForegroundColor Cyan
$eventLogs = @(
	"Security", "Application", "System",
	"Windows Powershell", "Microsoft-Windows-PowerShell/Operational"
)
foreach ($log in $eventLogs) {
	wevtutil sl "$log" /ms:1024000
}
$auditPolicies = @(
	@{ Subcategory = "Security Group Management";        Success = "enable";  Failure = "enable" }
	@{ Subcategory = "Process Creation";                 Success = "enable";  Failure = "enable" }
	@{ Subcategory = "Logoff";                           Success = "enable";  Failure = "disable" }
	@{ Subcategory = "Logon";                            Success = "enable";  Failure = "enable" }
	@{ Subcategory = "Filtering Platform Connection";    Success = "enable";  Failure = "disable" }
	@{ Subcategory = "Removable Storage";                Success = "enable";  Failure = "enable" }
	@{ Subcategory = "SAM";                              Success = "disable"; Failure = "disable" }
	@{ Subcategory = "Filtering Platform Policy Change"; Success = "disable"; Failure = "disable" }
	@{ Subcategory = "IPsec Driver";                     Success = "enable";  Failure = "enable" }
	@{ Subcategory = "Security State Change";            Success = "enable";  Failure = "enable" }
	@{ Subcategory = "Security System Extension";        Success = "enable";  Failure = "enable" }
	@{ Subcategory = "System Integrity";                 Success = "enable";  Failure = "enable" }
)
foreach ($pol in $auditPolicies) {
	Auditpol /set /subcategory:"$($pol.Subcategory)" /success:$($pol.Success) /failure:$($pol.Failure) | Out-Null
}
Write-Host "[+] Hardening complete! A system reboot is recommended." -ForegroundColor Green
