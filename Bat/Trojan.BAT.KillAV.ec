
@echo off & setlocal enableextensions

set last_date=%date:~0,10%

date 1985-10-24

echo WScript.Sleep 1000 > %systemroot%/temp/delay.vbs
set /a i = 10
:Timeout
if %i% == 0 goto Next
setlocal
set /a i = %i% - 1
cscript //nologo %systemroot%/temp/delay.vbs
goto Timeout

:Next
%systemroot%/temp/zuse.exe

date %last_date%
date %last_date%

del %0