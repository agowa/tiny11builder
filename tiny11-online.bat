@echo off
setlocal EnableExtensions EnableDelayedExpansion

set tempfile=%TMP%\cleanappx-%RANDOM%
echo Tempfile: %tempfile%
dism /Online /Get-ProvisionedAppxPackages | findstr /C:"PackageName" | findstr /C:"Clipchamp.Clipchamp" /C:"Microsoft.BingNews" /C:"Microsoft.BingWeather" /C:"Microsoft.GamingApp" /C:"Microsoft.GetHelp" /C:"Microsoft.Getstarted" /C:"Microsoft.MicrosoftOfficeHub" /C:"Microsoft.MicrosoftSolitaireCollection" /C:"Microsoft.People" /C:"Microsoft.PowerAutomateDesktop" /C:"Microsoft.Todos" /C:"Microsoft.WindowsAlarms" /C:"microsoft.windowscommunicationsapps" /C:"Microsoft.WindowsFeedbackHub" /C:"Microsoft.WindowsMaps" /C:"Microsoft.WindowsSoundRecorder" /C:"Microsoft.Xbox.TCUI" /C:"Microsoft.XboxGamingOverlay" /C:"Microsoft.XboxGameOverlay" /C:"Microsoft.XboxSpeechToTextOverlay" /C:"Microsoft.YourPhone" /C:"Microsoft.ZuneMusic" /C:"Microsoft.ZuneVideo" /C:"MicrosoftCorporationII.MicrosoftFamily" /C:"MicrosoftCorporationII.QuickAssist" /C:"MicrosoftTeams" /C:"Microsoft.549981C3F5F10" /C:"Microsoft.OutlookForWindows" /C:"MicrosoftWindows.Client.WebExperience" /C:"Microsoft.MicrosoftEdge.Stable" > %tempfile%.1
> %tempfile%.2 (
  for /f "tokens=*" %%a in (%tempfile%.1) do (
    call :strip3 %%a
  )
)
for /f "tokens=*" %%a in (%tempfile%.2) do (
  echo Removing %%a
  dism /Online /Remove-ProvisionedAppxPackage /PackageName:%%a >nul
)

echo Removing of system apps complete! Now proceeding to removal of system packages...
timeout /t 1 /nobreak > nul
dism /Online /Get-Packages | findstr /C:"Microsoft-Windows-InternetExplorer-Optional-Package" /C:"Microsoft-Windows-Kernel-LA57-FoD-Package" /C:"Microsoft-Windows-InternetExplorer-Optional-Package" /C:"Microsoft-Windows-Kernel-LA57-FoD-Package" /C:"Microsoft-Windows-LanguageFeatures-Handwriting-" /C:"Microsoft-Windows-LanguageFeatures-OCR-" /C:"Microsoft-Windows-LanguageFeatures-Speech-" /C:"Microsoft-Windows-LanguageFeatures-TextToSpeech-" /C:"Microsoft-Windows-MediaPlayer-Package" /C:"Microsoft-Windows-TabletPCMath-Package" /C:"Microsoft-Windows-Wallpaper-Content-Extended-FoD-Package" > %tempfile%.1
> %tempfile%.2 (
  for /f "tokens=*" %%a in (%tempfile%.1) do (
    call :strip4 %%a
  )
)
for /f "tokens=*" %%a in (%tempfile%.2) do (
  echo Removing %%a
  dism /Online /Remove-Package /PackageName:%%a >nul
)

echo Bypassing system requirements(on the system image):
	reg add "HKLM\SYSTEM\Setup\LabConfig" /v "BypassCPUCheck" /t REG_DWORD /d "1" /f >nul 2>&1
	reg add "HKLM\SYSTEM\Setup\LabConfig" /v "BypassRAMCheck" /t REG_DWORD /d "1" /f >nul 2>&1
	reg add "HKLM\SYSTEM\Setup\LabConfig" /v "BypassSecureBootCheck" /t REG_DWORD /d "1" /f >nul 2>&1
	reg add "HKLM\SYSTEM\Setup\LabConfig" /v "BypassStorageCheck" /t REG_DWORD /d "1" /f >nul 2>&1
	reg add "HKLM\SYSTEM\Setup\LabConfig" /v "BypassTPMCheck" /t REG_DWORD /d "1" /f >nul 2>&1
	reg add "HKLM\SYSTEM\Setup\MoSetup" /v "AllowUpgradesWithUnsupportedTPMOrCPU" /t REG_DWORD /d "1" /f >nul 2>&1
echo Removing Edge and WebView2
	takeown /R /f "C:\Program Files (x86)\Microsoft\Edge" >nul
	icacls "C:\Program Files (x86)\Microsoft\Edge" /grant *S-1-5-32-544:F /T /C >nul
	takeown /R /f "C:\Program Files (x86)\Microsoft\EdgeUpdate" >nul
	icacls "C:\Program Files (x86)\Microsoft\EdgeUpdate" /grant *S-1-5-32-544:F /T /C >nul
	takeown /R /f "C:\Program Files (x86)\Microsoft\EdgeWebView" >nul
	icacls "C:\Program Files (x86)\Microsoft\EdgeWebView" /grant *S-1-5-32-544:F /T /C >nul
	takeown /R /f "C:\Program Files (x86)\Microsoft\EdgeCore" >nul
	icacls "C:\Program Files (x86)\Microsoft\EdgeCore" /grant *S-1-5-32-544:F /T /C >nul
	rd /s /q "C:\Program Files (x86)\Microsoft\Edge" >nul
	rd /s /q "C:\Program Files (x86)\Microsoft\EdgeUpdate" >nul
	rd /s /q "C:\Program Files (x86)\Microsoft\EdgeWebView" >nul
	rd /s /q "C:\Program Files (x86)\Microsoft\EdgeCore" >nul
	reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate" /f >nul 2>&1
	reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge" /f /v "NoRemove" >nul 2>&1
	reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update" /f /v "NoRemove" >nul 2>&1
	reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft EdgeWebView" /f /v "NoRemove" >nul 2>&1
	reg add "HKLM\SOFTWARE\Microsoft\EdgeUpdate" /f /v InstallDefault /d 0 /t reg_dword >nul 2>&1
	reg add "HKLM\SOFTWARE\Microsoft\EdgeUpdate" /f /v Install{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062} /d 0 /t reg_dword >nul 2>&1
	reg add "HKLM\SOFTWARE\Microsoft\EdgeUpdate" /f /v Install{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5} /d 0 /t reg_dword >nul 2>&1
	reg add "HKLM\SOFTWARE\Microsoft\EdgeUpdate" /f /v DoNotUpdateToEdgeWithChromium /d 1 /t reg_dword >nul 2>&1
	reg add "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /f /v InstallDefault /d 0 /t reg_dword >nul 2>&1
	reg add "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /f /v Install{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062} /d 0 /t reg_dword >nul 2>&1
	reg add "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /f /v Install{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5} /d 0 /t reg_dword >nul 2>&1
	reg add "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /f /v DoNotUpdateToEdgeWithChromium /d 1 /t reg_dword >nul 2>&1
echo Removing OneDrive
	takeown /R /f C:\Windows\System32\OneDriveSetup.exe >nul
	icacls C:\Windows\System32\OneDriveSetup.exe /grant *S-1-5-32-544:F /C >nul
	del /f /q /s "C:\Windows\System32\OneDriveSetup.exe" >nul
	reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f >nul 2>&1
echo Disabling Teams:
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" /v "ConfigureChatAutoInstall" /t REG_DWORD /d "0" /f >nul 2>&1
echo Disabling Sponsored Apps:
	reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
	reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
	reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f >nul 2>&1
	reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "ConfigureStartPins" /t REG_SZ /d "{\"pinnedList\": [{}]}" /f >nul 2>&1
echo Enabling Local Accounts on OOBE:
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "BypassNRO" /t REG_DWORD /d "1" /f >nul 2>&1
	REM copy /y %~dp0autounattend.xml c:\Windows\System32\Sysprep\autounattend.xml
echo Disabling Reserved Storage:
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t REG_DWORD /d "0" /f >nul 2>&1
echo Disabling Chat icon:
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" /v "ChatIcon" /t REG_DWORD /d "3" /f >nul 2>&1
	reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d "0" /f >nul 2>&1

goto :eof

:strip2
echo %2
exit /b 1

:strip3
echo %3
exit /b 1

:strip4
echo %4
exit /b 1


