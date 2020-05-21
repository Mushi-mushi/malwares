@echo Off

REM                                      *********************************************
REM                                      *    This batch file created by Robert A.   *
REM                                      * for Diamond / S3 Inc. All Rights reserved *
REM                                      *                                           *
REM                                      *     This file is meant to uninstall old   *
REM                                      *  	 drivers before you reinstall        *
REM                                      *     the SupraMax PCI & SupraSST product.  *
REM                                      *                                           *
REM                                      *   v 1.4 edited / released January 2001    *
REM                                      *********************************************


echo Eject all floppy disks, and close all programs.
echo Running this uninstall program will take up to a minute or more
echo depending your your computer system.

Pause
echo.
echo.
echo You are now uninstalling. Please wait..
REM This enters the windows directory, and deletes the previous installed drivers for a clean install purposes. This only works if you have installed windows using the default installed director "c:\windows\"


cd c:\windows\inf > NUL
if exist sup2260.inf del sup2260.inf
if exist sup2350.inf del sup2350.inf
if exist sup2370.inf del sup2370.inf
if exist sup2750.inf del sup2750.inf
if exist sup2770.inf del sup2770.inf
if exist sup2770.pnf del sup2770.pnf
if exist supwave.inf del supwave.inf
if exist supwav.inf del supwav.inf
if exist winm2770.inf del winm2770.inf
if exist winm2750.inf del winm2750.inf
if exist winm2260.inf del winm2260.inf
if exist winm2370.inf del winm2370.inf
if exist winm2350.inf del winm2350.inf


cd c:\windows\inf\other > NUL
if exist diamondwinm2770.inf del diamondwinm2770.inf
if exist diamondwinm2260.inf del diamondwinm2260.inf
if exist diamondwinm2350.inf del diamondwinm2350.inf
if exist diamondwinm2370.inf del diamondwinm2370.inf
if exist diamondwinm2750.inf del diamondwinm2750.inf
if exist DiamondSETUP.inf del DiamondSETUP.inf
if exist DiamondSUP2770.INF del DiamondSUP2770.INF
if exist DiamondSUP2260.INF del DiamondSUP2260.INF
if exist DiamondSUP2370.INF del DiamondSUP2370.INF
if exist DiamondSUP2350.INF del DiamondSUP2350.INF
if exist Supra2~1.inf del Supra2~1.inf
if exist Sup275~1.inf del Sup275~1.inf
if exist Sup277~1.inf del Sup277~1.inf

cd C:\windows\system > NUL
if exist amos.vxd del amos.vxd
if exist basic2.vxd del basic2.vxd
if exist csacpl.cpl del csacpl.cpl
if exist dpal.vxd del dpal.vxd
if exist fallback.vxd del fallback.vxd
if exist fax.vxd del fax.vxd
if exist fsks.vxd del fsks.vxd
if exist hcfapi.dll del hcfapi.dll
if exist hcfaudio.vxd del hcfaudio.vxd
if exist hcfcsa.dll del hcfcsa.dll
if exist hcfcsa32.dll del hcfcsa32.dll
if exist hcfreadr.dll del hcfreadr.dll
if exist hcfpnp.vxd del hcfpnp.vxd
if exist hcfuninst.dll del hcfuninst.dll
if exist k56.vxd del k56.vxd
if exist modctrl.dll del modctrl.dll
if exist modctrl.vxd del modctrl.vxd
if exist rksample.vxd del rksample.vxd
if exist rokkmosd.vxd del rokkmosd.vxd
if exist rokv42.vxd del rokv42.vxd
if exist spkphone.vxd del spkphone.vxd
if exist sup2750.cty del sup2750.cty
if exist tones.vxd del tones.vxd
if exist turbovcd.vxd del turbovcd.vxd
if exist turbovbf.vxd del turbovbf.vxd
if exist win95ac.vxd del win95ac.vxd



set ktr=HKEY_LOCAL_MACHINE\Software\Rockwell\
echo. > NUL
echo Removing %ktr% from registry... > NUL
echo REGEDIT4>fix$$.reg
echo.>>fix$$.reg
echo [-%ktr%]>>fix$$.reg
echo.>>fix$$.reg
start/w regedit /s fix$$.reg

set ktr=HKEY_LOCAL_MACHINE\Enum\MODEMWAVE\SUPRASST_56I_DFV
echo. > NUL
echo Removing %ktr% from registry... > NUL
echo REGEDIT4>fix$$.reg
echo.>>fix$$.reg
echo [-%ktr%]>>fix$$.reg
echo.>>fix$$.reg
start/w regedit /s fix$$.reg

set ktr=HKEY_LOCAL_MACHINE\Enum\MODEMWAVE\SupraMax_56i_Voice_PCI
echo. > NUL
echo Removing %ktr% from registry... > NUL
echo REGEDIT4>fix$$.reg
echo.>>fix$$.reg
echo [-%ktr%]>>fix$$.reg
echo.>>fix$$.reg
start/w regedit /s fix$$.reg

set ktr=HKEY_LOCAL_MACHINE\Enum\MODEMWAVE\SupraMAX_56i_Voice_JPN
echo. > NUL
echo Removing %ktr% from registry... > NUL
echo REGEDIT4>fix$$.reg
echo.>>fix$$.reg
echo [-%ktr%]>>fix$$.reg
echo.>>fix$$.reg
start/w regedit /s fix$$.reg

set ktr=HKEY_LOCAL_MACHINE\Enum\MODEMWAVE\Supra_56i_Sp_PCI
echo. > NUL
echo Removing %ktr% from registry... > NUL
echo REGEDIT4>fix$$.reg
echo.>>fix$$.reg
echo [-%ktr%]>>fix$$.reg
echo.>>fix$$.reg
start/w regedit /s fix$$.reg


set ktr=HKEY_LOCAL_MACHINE\Enum\PCI\SUP2770
echo. > NUL
echo Removing %ktr% from registry... > NUL
echo REGEDIT4>fix$$.reg
echo.>>fix$$.reg
echo [-%ktr%]>>fix$$.reg
echo.>>fix$$.reg
start/w regedit /s fix$$.reg

set ktr=HKEY_LOCAL_MACHINE\Enum\PCI\SUP2260
echo. > NUL
echo Removing %ktr% from registry... > NUL
echo REGEDIT4>fix$$.reg
echo.>>fix$$.reg
echo [-%ktr%]>>fix$$.reg
echo.>>fix$$.reg
start/w regedit /s fix$$.reg

set ktr=HKEY_LOCAL_MACHINE\Enum\PCI\SUP2350
echo. > NUL
echo Removing %ktr% from registry... > NUL
echo REGEDIT4>fix$$.reg
echo.>>fix$$.reg
echo [-%ktr%]>>fix$$.reg
echo.>>fix$$.reg
start/w regedit /s fix$$.reg

set ktr=HKEY_LOCAL_MACHINE\Enum\PCI\SUP2370
echo. > NUL
echo Removing %ktr% from registry... > NUL
echo REGEDIT4>fix$$.reg
echo.>>fix$$.reg
echo [-%ktr%]>>fix$$.reg
echo.>>fix$$.reg
start/w regedit /s fix$$.reg

set ktr=HKEY_LOCAL_MACHINE\Enum\PCI\SUP2750
echo. > NUL
echo Removing %ktr% from registry... > NUL
echo REGEDIT4>fix$$.reg
echo.>>fix$$.reg
echo [-%ktr%]>>fix$$.reg
echo.>>fix$$.reg
start/w regedit /s fix$$.reg

set ktr=HKEY_LOCAL_MACHINE\Enum\PCI\VEN_127A&DEV_2014&SUBSYS_0AD21092&REV_01
echo. > NUL
echo Removing %ktr% from registry... > NUL
echo REGEDIT4>fix$$.reg
echo.>>fix$$.reg
echo [-%ktr%]>>fix$$.reg
echo.>>fix$$.reg
start/w regedit /s fix$$.reg

set ktr=HKEY_LOCAL_MACHINE\Enum\PCI\VEN_127A&DEV_1002&SUBSYS_08D41092&REV_01
echo. > NUL
echo Removing %ktr% from registry... > NUL
echo REGEDIT4>fix$$.reg
echo.>>fix$$.reg
echo [-%ktr%]>>fix$$.reg
echo.>>fix$$.reg
start/w regedit /s fix$$.reg

set ktr=HKEY_LOCAL_MACHINE\Enum\PCI\VEN_127A&DEV_1002&SUBSYS_092E1092&REV_01
echo. > NUL
echo Removing %ktr% from registry... > NUL
echo REGEDIT4>fix$$.reg
echo.>>fix$$.reg
echo [-%ktr%]>>fix$$.reg
echo.>>fix$$.reg
start/w regedit /s fix$$.reg

set ktr=HKEY_LOCAL_MACHINE\Enum\PCI\VEN_127A&DEV_1002&SUBSYS_09421092&REV_01
echo. > NUL
echo Removing %ktr% from registry... > NUL
echo REGEDIT4>fix$$.reg
echo.>>fix$$.reg
echo [-%ktr%]>>fix$$.reg
echo.>>fix$$.reg
start/w regedit /s fix$$.reg

set ktr=HKEY_LOCAL_MACHINE\Enum\PCI\VEN_14F1&DEV_1033&SUBSYS_0ABE1092&REV_08
echo. > NUL
echo Removing %ktr% from registry... > NUL
echo REGEDIT4>fix$$.reg
echo.>>fix$$.reg
echo [-%ktr%]>>fix$$.reg
echo.>>fix$$.reg
start/w regedit /s fix$$.reg


set ktr=HKEY_LOCAL_MACHINE\Software\Diamond\SupraSST 56i DFV
echo. > NUL
echo Removing %ktr% from registry... > NUL
echo REGEDIT4>fix$$.reg
echo.>>fix$$.reg
echo [-%ktr%]>>fix$$.reg
echo.>>fix$$.reg
start/w regedit /s fix$$.reg

set ktr=HKEY_LOCAL_MACHINE\Software\Diamond\SupraMax 56i Voice PCI
echo. > NUL
echo Removing %ktr% from registry... > NUL
echo REGEDIT4>fix$$.reg
echo.>>fix$$.reg
echo [-%ktr%]>>fix$$.reg
echo.>>fix$$.reg
start/w regedit /s fix$$.reg

set ktr=HKEY_LOCAL_MACHINE\Software\Diamond\SupraMAX 56i Voice JPN
echo. > NUL
echo Removing %ktr% from registry... > NUL
echo REGEDIT4>fix$$.reg
echo.>>fix$$.reg
echo [-%ktr%]>>fix$$.reg
echo.>>fix$$.reg
start/w regedit /s fix$$.reg

set ktr=HKEY_LOCAL_MACHINE\Software\Diamond\Supra 56i Sp PCI
echo. > NUL
echo Removing %ktr% from registry... > NUL
echo REGEDIT4>fix$$.reg
echo.>>fix$$.reg
echo [-%ktr%]>>fix$$.reg
echo.>>fix$$.reg
start/w regedit /s fix$$.reg


set ktr=HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Class\HSFMODEM
echo. > NUL
echo Removing %ktr% from registry... > NUL
echo REGEDIT4>fix$$.reg
echo.>>fix$$.reg
echo [-%ktr%]>>fix$$.reg
echo.>>fix$$.reg
start/w regedit /s fix$$.reg



set ktr=HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Class\HCFMODEM
echo. > NUL
echo Removing %ktr% from registry... > NUL
echo REGEDIT4>fix$$.reg
echo.>>fix$$.reg
echo [-%ktr%]>>fix$$.reg
echo.>>fix$$.reg
start/w regedit /s fix$$.reg

set ktr=HKEY_LOCAL_MACHINE\software\Microsoft\Windows\CurrentVersion\Uninstall\SupraMax 56i Voice PCI
echo. > NUL
echo Removing %ktr% from registry... > NUL
echo REGEDIT4>fix$$.reg
echo.>>fix$$.reg
echo [-%ktr%]>>fix$$.reg
echo.>>fix$$.reg
start/w regedit /s fix$$.reg

set ktr=HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Supra 56i PCI JPN
echo. > NUL
echo Removing %ktr% from registry... > NUL
echo REGEDIT4>fix$$.reg
echo.>>fix$$.reg
echo [-%ktr%]>>fix$$.reg
echo.>>fix$$.reg
start/w regedit /s fix$$.reg

set ktr=HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Supra 56i Sp PCI
echo. > NUL
echo Removing %ktr% from registry... > NUL
echo REGEDIT4>fix$$.reg
echo.>>fix$$.reg
echo [-%ktr%]>>fix$$.reg
echo.>>fix$$.reg
start/w regedit /s fix$$.reg

set ktr=HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SupraSST 56i DFV
echo. > NUL
echo Removing %ktr% from registry... > NUL
echo REGEDIT4>fix$$.reg
echo.>>fix$$.reg
echo [-%ktr%]>>fix$$.reg
echo.>>fix$$.reg
start/w regedit /s fix$$.reg

set ktr=HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\Diamond 56K PCI Modem
echo. > NUL
echo Removing %ktr% from registry... > NUL
echo REGEDIT4>fix$$.reg
echo.>>fix$$.reg
echo [-%ktr%]>>fix$$.reg
echo.>>fix$$.reg
start/w regedit /s fix$$.reg


set ktr=HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\Rockwell HCF 56K Modem
echo. > NUL
echo Removing %ktr% from registry... > NUL
echo REGEDIT4>fix$$.reg
echo.>>fix$$.reg
echo [-%ktr%]>>fix$$.reg
echo.>>fix$$.reg
start/w regedit /s fix$$.reg

del fix$$.reg
goto end

:end
cls
echo The uninstall completed successfully.  Press any key close this program.
pause > NUL
C:\WINDOWS\RUNDLL32.EXE User,ExitWindows
