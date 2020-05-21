Mbop!.a & Mbop!.b
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
Here you have a little explabation of the Mbop!.a source code.
______________________________________________________________________

--------
The part of the code that creates the random word is:
-
mbophvmbop=122
mboplvmbop=97
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
THE "mbop" WORD, BEFORE AND AFTER ANY VARAIABLE IS GOING TO BE
REPLACED WHIT THE NEW RANDOM WORD, OS, IF YOU WANNA USE THIS POLY
ENGINE, YOU SHOULD ADD THE SAME WORD BEFORE AND AFTER ANY BARIABLE
AND ALSO WHEN IT'S BETWEEN "".
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