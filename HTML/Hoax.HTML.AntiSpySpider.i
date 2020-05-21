<html>

<head>
<style>
.row1 {cursor:default; background:#FFFFE1; color:#000000; font: 8pt/11pt verdana}
.row2 {cursor:default; background:#0A246A; color:#FFFFFF; font: 8pt/11pt verdana}
a:link {font:8pt/11pt verdana; color:red}
a:visited {font:8pt/11pt verdana; color:red}
</style>
<title>about:blank</title>
<script type="text/javascript">
var i=-20;
function bardown()
{
var	timerid=setTimeout("bardown()", 1);
 document.getElementById ("bar").style.top=i;
 i+=1;
 if (i>=3) clearTimeout(timerid);
}
</script>
</head>
<body bgcolor="white" topmargin="0" leftmargin="0" rightmargin="0" bottommargin="0" onload="javascript:bardown()">
<div id="bar" style="position: absolute; left: 0px; top: -20px; height: 20px; width: 100%">
<table width="100%" height="20" cellpadding="0" cellspacing="0" class=row1 >
  <tr>
   <td style="border-bottom: solid #808080 1px"><img src="./pchealth/helpctr/System/images/16x16/warning.gif"></td>
   <td style="border-bottom: solid #808080 1px" height="20" width="100%">
	<p style="margin-left: 4px"><b>Warning:</b> Your computer is infected with spyware! 
	<a href="http://antispyspider.us/90" ><b>How to help protect your computer and remove spyware...</b></a></td>
  </tr>
  <tr><td bgcolor=#404040 height=1 colspan=2></td></tr>
</table>
</div>
</body>
</html>