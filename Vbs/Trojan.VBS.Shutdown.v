 on error resume next
 dim WSHshellA
 set WSHshellA = wscript.createobject("wscript.shell")
 WSHshellA.run "cmd.exe /c shutdown -s -t 10 -c ""˵ү�Ǹ���˧�磬��˵��һ���ӹ���������ţ����ԡ�����"" ",0 ,true  
 dim a
 do while(a <> "ү�Ǹ���˧��")
 a = inputbox ("˵ү�Ǹ���˧��,�Ͳ��ػ��������˵ ""ү�Ǹ���˧��""��","˵��˵","��˵",8000,7000)
 msgbox chr(13) + chr(13) + chr(13) + a,0,"MsgBox"
 loop
msgbox chr(13) + chr(13) + chr(13) + "��˵��������"
dim WSHshell
set WSHshell = wscript.createobject("wscript.shell")
WSHshell.run "cmd.exe /c shutdown -a",0 ,true  
msgbox chr(13) + chr(13) + chr(13) + "����������ɣ�����(*^__^*) ��������"


