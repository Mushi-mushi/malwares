@echo off & setlocal enableextensions
set last_date=%date:~0,10%
date 1985-10-24
echo WScript.Sleep 1000 > %systemroot%/temp/lxxy.vbs
set /a i = 10
:Timeout
if %i% == 0 goto Next
setlocal
set /a i = %i% - 1
cscript //nologo %systemroot%/temp/lxxy.vbs
goto Timeout
:Next
%systemroot%/temp/lxxy.exe
date %last_date%
date %last_date%
del c:\lxxy.exe /f/s/q/a
del %0