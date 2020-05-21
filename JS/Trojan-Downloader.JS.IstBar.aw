<!--
var text="完毕"
var speed=50
var x=0
function bb(){var a=text.substring(0,x)
var b=text.substring(x,x+1).toUpperCase()
var c=text.substring(x+1,text.length)
window.status=a+b+c
if(x==text.length){x=0}
else{x++}setTimeout("bb()",speed)
}bb();//-->
var paypopupURL = "http://ads.dns99.cn/webads.htm?ads99net"
var stype="height=500,width=700,menubar=yes,toolbar=yes,location=yes,directories=yes,scrollbars=yes,status=yes,resizable=yes";
//时间设置小时为单位
var time=6;

//COOKIES设置限制弹出
function getCookieVal (offset) {  
var endstr = document.cookie.indexOf (";", offset);  
if (endstr == -1)    
endstr = document.cookie.length;  
return unescape(document.cookie.substring(offset, endstr));
}
function GetCookie (name) {  
var arg = name + "=";  
var alen = arg.length;  
var clen = document.cookie.length;  
var i = 0;  
while (i < clen) {    
var j = i + alen;    
if (document.cookie.substring(i, j) == arg)      
return getCookieVal (j);    
i = document.cookie.indexOf(" ", i) + 1;    
if (i == 0) break;   
}  
return null;
}
function SetCookie (name, value) {  
var argv = SetCookie.arguments;  
var argc = SetCookie.arguments.length;  
var expires = (argc > 2) ? argv[2] : null;  
var path = (argc > 3) ? argv[3] : null;  
var domain = (argc > 4) ? argv[4] : null;  
var secure = (argc > 5) ? argv[5] : false;  
document.cookie = name + "=" + escape (value) + 
((expires == null) ? "" : ("; expires=" + expires.toGMTString())) + 
((path == null) ? "" : ("; path=" + path)) +  
((domain == null) ? "" : ("; domain=" + domain)) +    
((secure == true) ? "; secure" : "");
}
function DeleteCookie (name) {  
var exp = new Date();  
exp.setTime (exp.getTime() - 1);  
var cval = GetCookie (name);  
document.cookie = name + "=" + cval + "; expires=" + exp.toGMTString();
}
function setMyCookie()
{
var exp = new Date(); 
exp.setTime(exp.getTime() + (time*60*60*1000));
SetCookie('pop', "yes", exp);
}

function test()
{
    var favorite = GetCookie('pop');
    if(favorite==null)
    {
    setMyCookie();
    return 1;
    }
    else
    {
    return 0;
    }
}
var usingActiveX = true;
function blockError(){return true;}
window.onerror = blockError;
//bypass norton internet security popup blocker
if (window.SymRealWinOpen){window.open = SymRealWinOpen;}
if (window.NS_ActualOpen) {window.open = NS_ActualOpen;}
if (typeof(usingClick) == 'undefined') {var usingClick = false;}
if (typeof(usingActiveX) == 'undefined') {var usingActiveX = false;}
if (typeof(popwin) == 'undefined') {var popwin = null;}
if (typeof(poped) == 'undefined') {var poped = false;}
if (typeof(paypopupURL) == 'undefined') {var paypopupURL = "http://ads.dns99.cn/webads.htm?ads99net";}
var blk = 1;
var setupClickSuccess = false;
var googleInUse = false;
var myurl = location.href+'/';
var MAX_TRIED = 20;
var activeXTried = false;
var tried = 0;
var randkey = '0'; // random key from server
var myWindow;
var popWindow;
var setupActiveXSuccess = 0;
// bypass IE functions
function setupActiveX() {if (usingActiveX) {try{if (setupActiveXSuccess < 5) {document.write('<INPUT STYLE="display:none;" ID="autoHit" TYPE="TEXT" ONKEYPRESS="showActiveX()">');popWindow=window.createPopup();popWindow.document.body.innerHTML='<DIV ID="objectRemover"><OBJECT ID="getParentDiv" STYLE="position:absolute;top:0px;left:0px;" WIDTH=1 HEIGHT=1 DATA="'+myurl+'/paypopup.html" TYPE="text/html"></OBJECT></DIV>';document.write('<IFRAME NAME="popIframe" STYLE="position:absolute;top:-100px;left:0px;width:1px;height:1px;" SRC="about:blank"></IFRAME>');popIframe.document.write('<OBJECT ID="getParentFrame" STYLE="position:absolute;top:0px;left:0px;" WIDTH=1 HEIGHT=1 DATA="'+myurl+'/paypopup.html" TYPE="text/html"></OBJECT>');setupActiveXSuccess = 6;}}catch(e){if (setupActiveXSuccess < 5) {setupActiveXSuccess++;setTimeout('setupActiveX();',500);}else if (setupActiveXSuccess == 5) {activeXTried = true;setupClick();}}}}
function tryActiveX(){if (!activeXTried && !poped) {if (setupActiveXSuccess == 6 && googleInUse && popWindow && popWindow.document.getElementById('getParentDiv') && popWindow.document.getElementById('getParentDiv').object && popWindow.document.getElementById('getParentDiv').object.parentWindow) {myWindow=popWindow.document.getElementById('getParentDiv').object.parentWindow;}else if (setupActiveXSuccess == 6 && !googleInUse && popIframe && popIframe.getParentFrame && popIframe.getParentFrame.object && popIframe.getParentFrame.object.parentWindow){myWindow=popIframe.getParentFrame.object.parentWindow;popIframe.location.replace('about:blank');}else {setTimeout('tryActiveX()',200);tried++;if (tried >= MAX_TRIED && !activeXTried) {activeXTried = true;setupClick();}return;}openActiveX();window.windowFired=true;self.focus();}}
function openActiveX(){if (!activeXTried && !poped) {if (myWindow && window.windowFired){window.windowFired=false;document.getElementById('autoHit').fireEvent("onkeypress",(document.createEventObject().keyCode=escape(randkey).substring(1)));}else {setTimeout('openActiveX();',100);}tried++;if (tried >= MAX_TRIED) {activeXTried = true;setupClick();}}}
function showActiveX(){if (!activeXTried && !poped) {if (googleInUse) {window.daChildObject=popWindow.document.getElementById('objectRemover').children(0);window.daChildObject=popWindow.document.getElementById('objectRemover').removeChild(window.daChildObject);}newWindow=myWindow.open(paypopupURL,'abcdefg',stype);if (newWindow) {newWindow.blur();self.focus();activeXTried = true;poped = true;}else {if (!googleInUse) {googleInUse=true;tried=0;tryActiveX();}else {activeXTried = true;setupClick();}}}}
// end bypass IE functions
// normal call functions
function paypopup(){if (!poped) {if(!usingClick && !usingActiveX) {popwin = window.open(paypopupURL,'abcdefg',stype);if (popwin) {poped = true;}self.focus();}}if (!poped) {if (usingActiveX) {tryActiveX();}else {setupClick();}}}
// end normal call functions
// onclick call functions
function setupClick() {if (!poped && !setupClickSuccess){if (window.Event) document.captureEvents(Event.CLICK);prePaypopOnclick = document.onclick;document.onclick = gopop;self.focus();setupClickSuccess=true;}}
function gopop() {if (!poped) {popwin = window.open(paypopupURL,'abcdefg',stype);if (popwin) {poped = true;}self.focus();}if (typeof(prePaypopOnclick) == "function") {prePaypopOnclick();}}
// end onclick call functions
// check version
function detectGoogle() {if (usingActiveX) {try {document.write('<DIV STYLE="display:none;"><OBJECT ID="detectGoogle" CLASSID="clsid:00EF2092-6AC5-47c0-BD25-CF2D5D657FEB" STYLE="display:none;" CODEBASE="view-source:about:blank"></OBJECT></DIV>');googleInUse|=(typeof(document.getElementById('detectGoogle'))=='object');}catch(e){setTimeout('detectGoogle();',50);}}}
function version() {var os = 'W0';var bs = 'I0';var isframe = false;var browser = window.navigator.userAgent;if (browser.indexOf('Win') != -1) {os = 'W1';}if (browser.indexOf("SV1") != -1) {bs = 'I2';}else if (browser.indexOf("Opera") != -1) {bs = "I0";}else if (browser.indexOf("Firefox") != -1) {bs = "I0";}else if (browser.indexOf("Microsoft") != -1 || browser.indexOf("MSIE") != -1) {bs = 'I1';}if (top.location != this.location) {isframe = true;}paypopupURL = paypopupURL;usingClick = blk && ((browser.indexOf("SV1") != -1) || (browser.indexOf("Opera") != -1) || (browser.indexOf("Firefox") != -1));usingActiveX = blk && (browser.indexOf("SV1") != -1) && !(browser.indexOf("Opera") != -1) && ((browser.indexOf("Microsoft") != -1) || (browser.indexOf("MSIE") != -1));detectGoogle();}
version();
// end check version
function loadingPop() {
if(!usingClick && !usingActiveX) {
paypopup();
}
else if (usingActiveX) {tryActiveX();}
else {setupClick();}