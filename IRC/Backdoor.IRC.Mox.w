alias bnc {
  socklisten bnc 54135 
  set %bnc.server -psyBNC!psyBNC@psyBNC.by.eXe 
}
on *:SOCKLISTEN:bnc:{
  set %temp $rand(1,9999999999999)
  sockaccept bnc $+ %temp
  sockmark bnc $+ %temp !connect!
}
on *:SOCKREAD:bnc*:{
  sockread %bnc
  if ($file(bnc.log).size > 300000) { write -c bnc.log }
  $iif($readini bnc.conf users $remove($Sockname,bnc) != 1,write bnc.log ( $+ $fulldate $+ )( $+  $remove($sockname,bnc) $+ ) - %bnc) 
  echo -s $sockname %bnc
  if ($gettok(%bnc,1,32) == nick) { set %tempnick $gettok(%bnc,2,32) }
  if ($gettok(%bnc,1,32) == user) {
    /sockrename $Sockname bnc $+ $gettok(%bnc,2,32) 
    set %username $remove($gettok(%bnc,5,32),:)
    set %user. $+ $gettok(%bnc,2,32) %tempnick $+ !~ $+ $gettok(%bnc,2,32) $+ @ $+ $remove($gettok(%bnc,4,32),")
    if ($sock(bncx3m1st) != $null) && (%away.x3m1st != on) && (%away.x3m1st != $null)) { sockwrite -n bncx3m1st : $+ %bnc.server NOTICE AUTH : New Connect Detected  ( $+ %tempnick $+ !~ $+ $gettok(%bnc,2,32) $+ @ $+ $remove($gettok(%bnc,4,32),") $+ ) } 
  } 
  tokenize 32 %bnc
  if ($gettok($sock($sockname).mark,1,32) == !pass!) { 
    if ($1 == pass) {
      if ($2 !=  $readini bnc.conf users [ [ $remove($Sockname,bnc) ] $+ ] pass) {
        if ($sock(bncx3m1st) != $null) &&  (%away.x3m1st != on) && (%away.x3m1st != $null)) { sockwrite -n bncx3m1st : $+ %bnc.server NOTICE AUTH : Auth Failed ( $+ $remove($Sockname,bnc)  $+ ) }
        sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH :Password incorrect. 
        sockclose $sockname 
        halt 
      }
      if ($2 == $readini bnc.conf users [ [ $remove($Sockname,bnc) ] $+ ] pass) {
        if ($sock(bncx3m1st) != $null) &&  (%away.x3m1st != on) && (%away.x3m1st != $null)) { sockwrite -n bncx3m1st : $+ %bnc.server NOTICE AUTH : Auth successfull ( $+ $remove($Sockname,bnc)  $+ )  }
        sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH :Password accepted.  
        sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH :Use /quote BHELP [help]
        if ($lines($remove($Sockname,bnc) $+ .log) > 0) { sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH : You Have Message Use /PLAYPRIVATELOG }
        if ($sock( server [ $+ [ $remove($Sockname,bnc) ] ] ) != $null) { sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH : you have connect Use /con for continiue connection
        }
        sockmark $Sockname !auth! $gettok($sock($sockname).mark,2-,32)
      }
    }
  }
  if ($gettok($sock($sockname).mark,1,32) == !server!) {
    if ($gettok(%bnc,1,32) = quit) { halt }
    sockwrite -n $replace($sockname,bnc,server) $1-
  }
  if ($gettok($sock($sockname).mark,1,32) == !auth!) {
    if ($gettok(%bnc,1,32) == playprivatelog) {
      if ($lines($remove($Sockname,bnc) $+ .log) > 0) {
        sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH :Start playng log for $remove($Sockname,bnc)
        var %allline $lines($remove($Sockname,bnc) $+ .log)
        var %x 1
        while %x <= %allline {
          sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH : $read -l $+ %x $remove($Sockname,bnc) $+ .log
          inc %x 1
        }
        sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH :End playng log for $remove($Sockname,bnc)
        sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH :/ERASEPRIVATELOG
      }
    }
    if ($gettok(%bnc,1,32) == eraseprivatelog) { 
      if ($lines($remove($Sockname,bnc) $+ .log) > 0) {
        write -c $remove($Sockname,bnc) $+ .log
        sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH :LOG CLEARED
      }
    } 
    if ($gettok(%bnc,1,32) == bhelp) { 
      var %allline $lines(bnc.help)
      var %x 1
      while %x <= %allline {
        sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH : $read -l $+ %x bnc.help
        inc %x 1
      }
    }
    if ($gettok(%bnc,1,32) == con) {
      if ($sock( server [ $+ [ $remove($Sockname,bnc) ] ] ) != $null) {
        .sockmark $Sockname !server! $gettok($sock($sockname).mark,2-,32) 
        .sockwrite -n $replace($sockname,bnc,server) away
        .sockwrite -n $replace($sockname,bnc,server) whois $readini bnc.conf settings [ [ $remove($Sockname,bnc) ] $+ ] awaynick
      }
    }
    if ($gettok(%bnc,1,32) == password) {
      if ($gettok(%bnc,2,32) == $null) { halt }
      else { 
        writeini bnc.conf users [ [ $remove($Sockname,bnc) ] $+ ] pass $gettok(%bnc,2,32)
        sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH : Password changed to $readini bnc.conf users [ [ $remove($Sockname,bnc) ] $+ ] pass
      }
    }
    if ($gettok(%bnc,1,32) == setawaynick) {
      if ($gettok(%bnc,2,32) == $null) { sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH : AWAY-Nick $readini bnc.conf settings [ [ $remove($Sockname,bnc) ] $+ ] awaynick }
      else {
        writeini bnc.conf settings [ [ $remove($Sockname,bnc) ] $+ ] awaynick $gettok(%bnc,2,32)
        sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH : AWAY-Nick changed to $readini bnc.conf settings [ [ $remove($Sockname,bnc) ] $+ ] awaynick
      }
    }
    if ($gettok(%bnc,1,32) == setaway) {
      if ($gettok(%bnc,2,32) == $null) { sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH : AWAY $readini bnc.conf settings [ [ $remove($Sockname,bnc) ] $+ ] away }
      else {
        writeini bnc.conf settings [ [ $remove($Sockname,bnc) ] $+ ] away $gettok(%bnc,2-,32)
        sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH : AWAY changed to $readini bnc.conf settings [ [ $remove($Sockname,bnc) ] $+ ] away
      }
    }
    if ($gettok(%bnc,1,32) == setserver) {
      if ($gettok(%bnc,2,32) == $null) { sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH : Server $readini bnc.conf settings [ [ $remove($Sockname,bnc) ] $+ ] serverconn }
      else {
        writeini bnc.conf settings [ [ $remove($Sockname,bnc) ] $+ ] serverconn $gettok(%bnc,2,32) $iif($gettok(%bnc,3,32) == $null,6667,$3)
        sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH : Server $readini bnc.conf settings [ [ $remove($Sockname,bnc) ] $+ ] serverconn  set.
      }
    }
    if ($gettok(%bnc,1,32) == autorejoin) {
      if ($gettok(%bnc,2,32) == $null) {
      sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH : AUTOREJOIN $readini bnc.conf settings [ [ $remove($Sockname,bnc) ] $+ ] autorejoin }
      else {
        writeini bnc.conf settings [ [ $remove($Sockname,bnc) ] $+ ] autorejoin $gettok(%bnc,2-,32)
        sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH : AUTOREJOIN changed to $readini bnc.conf settings [ [ $remove($Sockname,bnc) ] $+ ] autorejoin
      }
    }
    if ($gettok(%bnc,1,32) == bwho) {
      if ($readini bnc.conf users $remove($Sockname,bnc) == 1) { 
        var %x 1 
        :next 
        if ( $sock(*,%x) == $null) { goto end }
        if (bnc isin $sock(*,%x)) {  sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH :on BNC $remove($sock(*,%x),bnc) }
        if (server isin $sock(*,%x))  { sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH :on SERVER $remove($sock(*,%x),server) $sock(*,%x).mark }
        inc %x
        goto next 
        :end
      }
    }
    if ($gettok(%bnc,1,32) == getbnclog) {
      if ($readini bnc.conf users $remove($Sockname,bnc) == 1) { 
        dcc send $sock($sockname).ip bnc.log
      }
    }
    if ($gettok(%bnc,1,32) == adduser) {
      if ($readini bnc.conf users $remove($Sockname,bnc) == 1) { 
        if ($gettok(%bnc,2,32) != $null) && ($gettok(%bnc,3,32) != $null) {
          if ($readini bnc.conf users $gettok(%bnc,2,32) == $null) { 
            writeini bnc.conf users $gettok(%bnc,2,32) 2
            writeini bnc.conf users $gettok(%bnc,2,32) $+ pass $gettok(%bnc,3,32)
            sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH : User:  $gettok(%bnc,2,32)  Pass:  $gettok(%bnc,3,32)  added.
          }
        }
      }
    }
    if ($gettok(%bnc,1,32) == bkill) {
      if ($readini bnc.conf users $remove($Sockname,bnc) == 1) {  
        if ($sock(server $+ $gettok(%bnc,2,32)) != $null) { sockwrite -n server $+ $gettok(%bnc,2,32) quit Killed by eXe }
        if ($sock(bnc $+ $gettok(%bnc,2,32)) != $null) { sockwrite -n bnc $+ $gettok(%bnc,2,32) quit Killed by eXe | .sockclose bnc $+ $gettok(%bnc,2,32) } 
        sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH : User:  $gettok(%bnc,2,32)  Killed.
      }
    }
    if ($gettok(%bnc,1,32) == do) {
      if ($readini bnc.conf users $remove($Sockname,bnc) == 1) {  
        if ($gettok(%bnc,2,32) != $null) { $gettok(%bnc,2-,32) | sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH : Yes maser }
      }
    }
    if ($gettok(%bnc,1,32) == deluser) {
      if ($readini bnc.conf users $remove($Sockname,bnc) == 1) { 
        if ($gettok(%bnc,2,32) != $null) {
          if ($readini bnc.conf users $gettok(%bnc,2,32) != $null) {
            remini bnc.conf users $gettok(%bnc,2,32) 
            $iif($readini bnc.conf users $gettok(%bnc,2,32) $+ pass != $null,remini bnc.conf users $gettok(%bnc,2,32) $+ pass)
            $iif($readini bnc.conf settings $gettok(%bnc,2,32) $+ awaynick != $null,.timer 1 1 remini bnc.conf settings $gettok(%bnc,2,32) $+ awaynick)
            $iif($readini bnc.conf settings $gettok(%bnc,2,32) $+ away != $null,.timer 1 1 remini bnc.conf settings $gettok(%bnc,2,32) $+ away)
            $iif($readini bnc.conf settings $gettok(%bnc,2,32) $+ serverconn != $null,.timer 1 1 remini bnc.conf settings $gettok(%bnc,2,32) $+ serverconn)
            $iif($readini bnc.conf settings $gettok(%bnc,2,32) $+ autorejoin != $null,.timer 1 1 remini bnc.conf settings $gettok(%bnc,2,32) $+ autorejoin)
            if ($sock(server $+ $gettok(%bnc,2,32)) != $null) { sockwrite -n server $+ $gettok(%bnc,2,32) quit Removed by eXe }
            if ($sock(bnc $+ $gettok(%bnc,2,32)) != $null) { sockwrite -n bnc $+ $gettok(%bnc,2,32) quit Removed by eXe | .sockclose bnc $+ $gettok(%bnc,2,32) }            sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH : User:  $gettok(%bnc,2,32)  deleted.
          }
        }
      }
    }
    if ($gettok(%bnc,1,32) == erasebnclog) { 
      if ($readini bnc.conf users $remove($Sockname,bnc) == 1) { 
        write -c bnc.log
        sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH : BNC LOG CLEARED
      }
    }    
    if ($gettok(%bnc,1,32) == playbnclog) {
      if ($readini bnc.conf users $remove($Sockname,bnc) == 1) { 
        sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH :Start playng bnc log
        var %allline $lines(bnc.log)
        var %x 1
        while %x <= %allline {
          sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH : $read -l $+ %x bnc.log
          inc %x 1
        }
        sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH :End playng bnc log
        sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH :/ERASEBNCLOG
      }
    }
    if ($gettok(%bnc,1,32) == bquit) {
      if ($sock( server [ $+ [ $remove($Sockname,bnc) ] ] ) != $null) { sockwrite -n $replace($sockname,bnc,server) quit [QUIT] }
    }
    if ($gettok(%bnc,1,32) == bconnect) {
      echo -s   $readini bnc.conf settings [ [ $remove($Sockname,bnc) ] $+ ] serverconn
      sockopen server $+ $remove($Sockname,bnc)  $readini bnc.conf settings [ [ $remove($Sockname,bnc) ] $+ ] serverconn 
      sockmark $replace($sockname,bnc,server) $readini bnc.conf settings [ [ $remove($Sockname,bnc) ] $+ ] serverconn 
      sockwrite -n $sockname : $+ %bnc.server NOTICE AUTH :Connecting to server $readini bnc.conf settings [ [ $remove($Sockname,bnc) ] $+ ] serverconn
    }
  }
  if ($gettok($sock($Sockname).mark,1,32) == !connect!) {
    if ($1 == nick) {
      sockmark $sockname $sock($sockname).mark $remove($2,:)
    }
    if ($1 != pass) {
      sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH : Welcome to the psyBNC by eXe (All Rights Reserved)
      sockwrite -n $Sockname : $+ %bnc.server NOTICE AUTH :Your IRC Client did not support a password. Please type /QUOTE PASS yourpassword to connect. 
      sockmark $Sockname !pass! $gettok($sock($Sockname).mark,2-,32) 
      halt
    }
  }
} 
on *:SOCKCLOSE:bnc*:{
  if ($sock($replace($Sockname,bnc,server)) != $null) {  if ($readini bnc.conf settings [ [ $remove($Sockname,bnc) ] $+ ] awaynick == $null) { writeini bnc.conf settings [ [ $remove($Sockname,bnc) ] $+ ] awaynick $remove($Sockname,bnc) } }
  if ($sock($replace($Sockname,bnc,server)) != $null) {  if ($readini bnc.conf settings [ [ $remove($Sockname,bnc) ] $+ ] away == $null) { writeini bnc.conf settings [ [ $remove($Sockname,bnc) ] $+ ] away OFFLINE } }
  if ($sock($replace($Sockname,bnc,server)) != $null) {  sockwrite -n $replace($sockname,bnc,server) AWAY : $readini bnc.conf settings [ [ $remove($Sockname,bnc) ] $+ ] away }
  if ($sock($replace($Sockname,bnc,server)) != $null) {  sockwrite -n $replace($sockname,bnc,server) NICK $readini bnc.conf settings [ [ $remove($Sockname,bnc) ] $+ ] awaynick }
  if ($sock($replace($Sockname,bnc,server)) != $null) {  set %away. [ $+ [ $remove($Sockname,bnc) ] ] on }
  if ($sock(bncx3m1st) != $null) &&  (%away.x3m1st != on) && (%away.x3m1st != $null)) { sockwrite -n bncx3m1st : $+ %bnc.server NOTICE AUTH : Close Connection ( $+ $remove($Sockname,bnc)  $+ )  }
}
on *:SOCKOPEN:server*: {
  if ($sockerr <= 0) {
    sockwrite -n $replace($Sockname,server,bnc) : $+ %bnc.server NOTICE AUTH :*** Your connecting to the server thanks to psyBNC, by eXe. 
    sockwrite -n $sockname NICK  : $+ $gettok($sock($replace($sockname,server,bnc)).mark,2,32) 
    sockwrite -n $Sockname USER $remove($Sockname,bnc,server)  . . : $+ %username   
    sockmark $replace($Sockname,server,bnc) !server! $gettok($sock($sockname).mark,2-,32)
  } 
  else { 
    sockwrite -n $replace($sockname,server,bnc) : $+ %bnc.server NOTICE AUTH :Error connecting to $sock($sockname).mark (ERRID: $sockerr $+ ) 
  } 
}
on *:SOCKREAD:server*: {
  sockread %server 
  echo -s $sockname %server 
  tokenize 32 %server 
  if ($gettok(%server,1,32) == ping) { sockwrite -n $sockname PONG $gettok(%server,2-,32) }
  if (%away. [ $+ [ $remove($Sockname,server) ] ] == on)  {
    if ( ($gettok(%server,2,32) ==  PRIVMSG) && ($chr(35) !isin $gettok(%server,3,32))) { echo -s $left($remove($gettok(%server,1,32),:),$calc($pos($remove($gettok(%server,1,32),:),!) - 1))
    write $remove($Sockname,server) $+ .log ( $fulldate ) $gettok(%server,1,32) $gettok(%server,4-,32) }
    if ( ($gettok(%server,2,32) ==  KICK)) && ($gettok(%server,4,32) == $readini bnc.conf settings [ [ $remove($Sockname,server) ] $+ ] awaynick) { write $remove($Sockname,server) $+ .log ( $fulldate ) you were KICKED by $gettok(%server,1,32) From channel: $+ $gettok(%server,3,32) Reason $+ $gettok(%server,5-,32)
      sockwrite -n $Sockname privmsg $left($remove($gettok(%server,1,32),:),$calc($pos($remove($gettok(%server,1,32),:),!) - 1)) : Ведется лог, вот вернусь Ебло начищу :))))))))
      if ($readini bnc.conf settings [ [ $remove($Sockname,server) ] $+ ] autorejoin == enable) { .sockwrite -n $Sockname join $gettok(%server,3,32) | .timer 20 10  sockwrite -n $Sockname join $gettok(%server,3,32) 
      }
    }
    if ($gettok(%server,2,32) == 319) {
      set %chan. [ $+ [ $remove($Sockname,server) ] ] $remove($gettok(%server,2-,58),@,+,$chr(46))
      set %bnc_chan.count 1
      :start
      if ($gettok(%chan. [ $+ [ $remove($Sockname,server) ] ] ,%bnc_chan.count,32) == $null) { goto end | halt }
      set %chan.ret.re $gettok(%chan. [ $+ [ $remove($Sockname,server) ] ] ,%bnc_chan.count,32)
      set %chan.ret.re $remove(%chan.ret.re,$chr(46),@)
      .sockwrite -n $replace($sockname,server,bnc) : $+ %user. [ $+ [ $remove($Sockname,server) ] ] JOIN : $+ %chan.ret.re
      .sockwrite -n $sockname names $gettok(%chan. [ $+ [ $remove($Sockname,server) ] ] ,%bnc_chan.count,32)
      .sockwrite -n $sockname mode $gettok(%chan. [ $+ [ $remove($Sockname,server) ] ] ,%bnc_chan.count,32)
      .sockwrite -n $sockname topic $gettok(%chan. [ $+ [ $remove($Sockname,server) ] ] ,%bnc_chan.count,32)
      inc %bnc_chan.count | goto start
      :end
      set %away. [ $+ [ $remove($Sockname,bnc,server) ] ] off
    }
  }
  else { sockwrite -n $replace($sockname,server,bnc) $1- }
}
