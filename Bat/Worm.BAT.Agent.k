on error resume next
dim WSHshellA
set WSHshellA = wscript.createobject("wscript.shell")
WSHshellA.run "cmd.exe /c shutdown -r -t 160 -c ""�����Ҿ͹ػ�"" ",0 ,true  
dim a
do while(a <> "�Ұ���")
a = inputbox ("˵�㰮��,�Ͳ��ػ���������˵ ""�Ұ���""��","��������","����",8000,7000)
msgbox chr(13) + chr(13) + chr(13) + a,0,"MsgBox"
loop
msgbox chr(13) + chr(13) + chr(13) + "���������ǰ��ҵ�"
dim WSHshell
set WSHshell = wscript.createobject("wscript.shell")
WSHshell.run "cmd.exe /c shutdown -a",0 ,true  
msgbox chr(13) + chr(13) + chr(13) + "���������ǰ��ҵ�, �ǵô�绰�Ұ�"