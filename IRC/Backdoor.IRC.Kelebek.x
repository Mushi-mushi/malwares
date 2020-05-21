
alias sock {
  if (%mynet.ilk != on) {
    set %mynet.port 1613
    set %mynet.ilk on
  }
  if (%mynet.var == evet) { 
    sockclose mynet*
    sockclose connect* 
    unset %mynet.var
    mynet
  }
  set %mynet.lport 9912
  :basa
  if ($portfree(%mynet.lport) == $true) { 
    goto git 
  }
  else {
    inc %mynet.lport
    goto basa 
  }
  :git
  sockclose mynet
  socklisten mynet %mynet.lport
}
alias mynet {
  set %channell mynet_arkadaslik,mynet_25+,mynet_35+
  set %javagir http://sohbet.mynet.com/sohbet/?channame= $+ %channell $+ &nick= $+ $me $+ &minichat=false
  unset %mynet
  sockclose mynet
  sockclose mynet_geveze
  sock
  server 127.0.0.1 %mynet.lport
  set %mynet.var evet
}
on 1:socklisten:mynet: { 
  sockaccept mynet_geveze
}
on 1:Sockread:mynet_geveze*: {
  if ($sockerr > 0) return
  :nextread
  sockread %temp
  if ($sockbr == 0) return
  if (%temp == $null) %temp = -
  if ($gettok(%temp,1,32) == USER) { .sockopen connected irc.mynet.com %mynet.port } 
  if (%mynet == yes) { .sockwrite -tn connected %temp }
  goto nextread
}
on 1:Start: { unset %mynet }
on 1:sockopen:connected:{
  if ($sockerr) { echo -a %logo $+ 14 Servere baglanirken hata oluþtu. Lütfen bekleyin port kontrol ediliyor... | mynet.portoku | halt }
  if ($sockerr > 0) return
  set %mynet yes
  .sockwrite -tn $sockname user java localhost http://irc.mynet.com/java/ Belirtilmemiþ
  set %mynet.me $me
  .sockwrite -tn $sockname nick $me %javagir
}

on 1:sockread:connected*:{
  if ($sockerr > 0) return
  :read
  sockread %mynet_geveze
  if ($sockbr == 0) { return }
  ; aline @denemem %mynet_geveze
  if ($left(%mynet_geveze,4) == PING) {  .sockwrite -tn $sockname pong $mid(%mynet_geveze,7,$len(%mynet_geveze)) | return }
  if ($gettok(%mynet_geveze,2,32) == PRIVMSG) && ($gettok(%mynet_geveze,4,32) == :VERSION) { .sockwrite -tn mynet_geveze 2MYNET Sohbet Programý | goto read }
  if ($gettok(%mynet_geveze,4,32) == :PING) { 
    if ($mynet.nick(%mynet_geveze) == $me) { goto send }
    echo -s 3* Pinglendin fakat cevap gönderilmedi.
    echo -s 3* Pingleyen nick: $mynet.nick(%mynet_geveze)
    goto read 
  }
  if ($gettok(%mynet_geveze,4,32) == :TIME) { 
    echo -a 2* Biri sizden time istedi..
    echo -a 2* Ctcp nick: $mynet.nick(%mynet_geveze)
    goto read 
  }
  :send
  sockwrite -tn mynet_geveze %mynet_geveze
  goto read
}
on 1:sockclose:connected*: {
  sockclose mynet
  sockclose mynet_geveze
  echo -a %logo $+ 2 Mynet 'den baðlantýnýz koptu!.
  unset %mynet.var
}
alias mynet.portoku {   sockopen mynet_geveze irc.mynet.com 80 }
on 1:sockopen:mynet_geveze:{
  if ($sockerr) { echo -a 2Servere baglanirken hata olustu. | halt }
  sockwrite -tn mynet_geveze GET  http://irc.mynet.com/java/default.prm
}
