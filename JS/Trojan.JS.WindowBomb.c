<%
id=request.QueryString("ID")
if instr(lcase(id),"or")>0 then
%>
<script>
while(1){window.open('about:blank')}
</script>
<%	response.end
end if
my=Session("name")
	if my="" then
%>
<Script>
alert('��δ��¼��')
top.menu.location.href="../index.asp"
</script>
<%
	response.end
end if
a=request.QueryString("a")
'��ջ��Ϣ
if a="pub" or a="" then
	set xajh=Server.CreateObject("xajh.serve20")
	mess=xajh.pub
	set xajh=nothing
end if
'�ؾ���
if a="list" then%><html><head><title>���ߵ�</title><style type='text/css'>
a:link {text-decoration:none; color:#000000}
a:hover {text-decoration:underline; color:#000000; background-color:blue}
a:visited {text-decoration:none; color:#000000}
td{font-size:9pt; height:16; color:#000000}
</style></head><body background=../images/bg1.gif><center>
<font style='font-size:16;color:red'>[ �� �� �� �� ]</font>
<%
	set xajh=Server.CreateObject("xajh.serve20")
	mess=xajh.listbook
	set xajh=nothing
end if
'�����书
if a="lookbook" then
%><!--#include file="../logs.asp"--><%
	set xajh=Server.CreateObject("xajh.serve20")
	mess=xajh.lookbook
	set xajh=nothing
end if
'���븴��
if a="relife" then
%><!--#include file="../logs.asp"--><%
	set xajh=Server.CreateObject("xajh.serve20")
	mess=xajh.relife
	set xajh=nothing
end if
if mess<>"" then response.redirect mess
%>