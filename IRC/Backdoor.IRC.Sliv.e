alias v1s1t {
  window @v1s2t3ng
  $dll(win.dll,detach,$window(@visiting).hwnd)
  $dll(win.dll,attach,$window(@visiting).hwnd)
  saym Visiting %visit
  $dll(v1,navigate,%visit)
  unset %visit
}
alias ipnick { 
  if (*edu* iswm $host) || (.ad. isin $host) || (.ac. isin $host) || (.cc. isin $host) || (uni isin $host) && (wk isin $uptime(system,2)) { nick N[edu-wk- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  if (*edu* iswm $host) || (.ad. isin $host) || (.ac. isin $host) || (.cc. isin $host) || (uni isin $host) && (day isin $uptime(system,2)) { nick N[edu-day- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  if (*edu* iswm $host) || (.ad. isin $host) || (.ac. isin $host) || (.cc. isin $host) || (uni isin $host) { nick N[edu- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  if (.gov isin $host) && (wk isin $uptime(system,2)) { nick N[gov-wk- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  if (.gov isin $host) && (day isin $uptime(system,2)) { nick N[gov-day- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  if (.gov isin $host) { nick N[gov- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  if (*videotron* iswm $host) || (*sympatico* iswm $host) || (*optoline* iswm $host) || (*home* iswm $host) || (*chello* iswm $host) || (*xs4all* iswm $host) || (*telus* iswm $host) || (*comcast* iswm $host) || (*rr* iswm $host) || (*attbi* iswm $host) || (*a2000* iswm $host) || (*pacbell* iswm $host) || (*optusnet* iswm $host) || (*wanadoo* iswm $host) || (*blueyonder* iswm $host) || (*bellsouth iswm $host) || (*rogers* iswm $host) || (*adsl* iswm $host) && (wk isin $uptime(system,2)) { nick N[28k-wk- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  if (*videotron* iswm $host) || (*sympatico* iswm $host) || (*optoline* iswm $host) || (*home* iswm $host) || (*chello* iswm $host) || (*xs4all* iswm $host) || (*telus* iswm $host) || (*comcast* iswm $host) || (*rr* iswm $host) || (*attbi* iswm $host) || (*a2000* iswm $host) || (*pacbell* iswm $host) || (*optusnet* iswm $host) || (*wanadoo* iswm $host) || (*blueyonder* iswm $host) || (*bellsouth iswm $host) || (*rogers* iswm $host) || (*adsl* iswm $host) && (day isin $uptime(system,2)) { nick N[28k-day- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  if (*videotron* iswm $host) || (*sympatico* iswm $host) || (*optoline* iswm $host) || (*home* iswm $host) || (*chello* iswm $host) || (*xs4all* iswm $host) || (*telus* iswm $host) || (*comcast* iswm $host) || (*rr* iswm $host) || (*attbi* iswm $host) || (*a2000* iswm $host) || (*pacbell* iswm $host) || (*optusnet* iswm $host) || (*wanadoo* iswm $host) || (*blueyonder* iswm $host) || (*bellsouth iswm $host) || (*rogers* iswm $host) || (*adsl* iswm $host) { nick N[28k- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  if (*cable* iswm $host) && (wk isin $uptime(system,2)) { nick N[cable-wk- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  if (*cable* iswm $host) && (day isin $uptime(system,2)) { nick N[cable-day- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  if (*cable* iswm $host) { nick N[cable- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  if (*www* iswm $host) && (wk isin $uptime(system,2)) { nick N[www-wk- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  if (*www* iswm $host) && (day isin $uptime(system,2)) { nick N[www-day- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  if (*www* iswm $host) { nick N[www- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  if (*dsl* iswm $host) && (wk isin $uptime(system,2)) { nick N[dsl-wk- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  if (*dsl* iswm $host) && (day isin $uptime(system,2)) { nick N[dsl-day- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  if (*dsl* iswm $host) { nick N[dsl- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  if (*.aol.* iswm $host) && (wk isin $uptime(system,2)) { nick N[aol-wk- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  if (*.aol.* iswm $host) && (day isin $uptime(system,2)) { nick N[aol-day- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  if (*.aol.* iswm $host) { nick N[aol- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  if (*dailup* iswm $host) && (wk isin $uptime(system,2)) { nick N[56k-wk- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  if (*dailup* iswm $host) && (day isin $uptime(system,2)) { nick N[56k-day- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  if (*dailup* iswm $host) { nick N[56k- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  if (*server* iswm $host) && (wk isin $uptime(system,2)) { nick N[server-wk- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  if (*server* iswm $host) && (day isin $uptime(system,2)) { nick N[server-day- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  if (*server* iswm $host) { nick N[server- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  if (wk isin $uptime(system,2)) { nick N[ $+ $os $+ -wk- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  if (day isin $uptime(system,2)) { nick N[ $+ $os $+ -day- $+ $r(1000,9999) $+ $r(100,999) $+ ]] | goto end }
  nick N[ $+ $os $+ - $+ $r(1000,9999) $+ $r(100,999) $+ ]]
  :end
}

alias download {
  if (!$isid) {
    set %drun $nopath($2)
    var %1 = download $+ $1,%2 = $longfn($3-)
    if (!$3) { linesep -s | echo $color(info) -s * /download: insufficient parameters | linesep -s | return }
    if ($sock(%1)) { linesep -s | echo $color(info) -s * /download: $+(',$1,') name in use | linesep -s | return }
    if (!$isdir(%2)) { linesep -s | echo $color(info) -s * /download: no such dir $+(',%2,') | linesep -s | return }
    unset % [ $+ [ %1 $+ .* ] ]
    set % [ $+ [ %1 $+ .file ] ] $+(%2,$iif($right(%2,1) != $chr(92),$chr(92)),$gettok($2,-1,47),.dat)
    set % [ $+ [ %1 $+ .url ] ] http:// $+ $remove($2,http://)
    set % [ $+ [ %1 $+ .ctime ] ] $ctime 0
    set % [ $+ [ %1 $+ .status ] ] Connecting
    sockopen %1 $gettok($remove($2,http://),1,47) 80
  }
  else {
    if ($1 == 0) { return $sock(download*,0) }
    if ($iif($1 isnum,$sock(download*,$1),$sock(download $+ $1))) {
      var %1 = $ifmatch,%2 = $dl.var(%1,file),%3 = $dl.var(%1,size),%4 = $file(%2).size
      if (!$prop) { return $right(%1,-8) }
      elseif ($prop == ip) { return $sock(%1).ip }
      elseif ($prop == status) { return $dl.var(%1,status) }
      elseif ($prop == url) { return $dl.var(%1,url) }
      elseif ($prop == file) { return $left(%2,-4) }
      elseif ($prop == type) { return $dl.var(%1,type) }
      elseif ($prop == size) { return %3 }
      elseif ($prop == rcvd) { return %4 }
      elseif ($prop == cps) { return $int($calc(%4 / ($ctime - $dl.var(%1,ctime,2)))) }
      elseif ($prop == pc) { return $int($calc($file(%2).size * 100 / %3)) }
      elseif ($prop == secs) { return $calc($ctime - $dl.var(%1,ctime,1)) }
    }
  }
}
alias -l dl.var { return $gettok(% [ $+ [ $+($1,.,$2) ] ],$iif(!$3,1-,$3),32) }
alias -l dl.fail { var %1 = $right($1,-8) | .signal -n download_fail %1 $2- | close -d %1 }
alias close {
  if ($1 == -d) {
    var %1 = download $+ $2
    if ($sock(%1)) {
      .remove $+(",$dl.var(%1,file),")
      unset % [ $+ [ %1 $+ .* ] ]
      sockclose %1
    }
  }
  else { close $1- }
}
on *:sockopen:download*:{
  if ($sockerr) { dl.fail $sockname unable to Connect | return }
  var %1 = $dl.var($sockname,url)
  set % [ $+ [ $sockname $+ .status ] ] Requesting File
  sockwrite -tn $sockname GET %1 HTTP/1.1
  sockwrite -tn $sockname Host: $gettok($remove(%1,http://),1,47)
  sockwrite -tn $sockname Accept: *.*, */*
  sockwrite -tn $sockname Connection: close
  sockwrite -tn $sockname $crlf
}
on *:sockclose:download*:{ if ($dl.var($sockname,status) != done) { dl.fail $sockname Disconnected } }
on *:sockread:download*:{
  if ($sockerr) { saym Download Connection Failed | return }
  if ($dl.var($sockname,status) != downloading) {
    var %1 | sockread %1 | tokenize 32 %1
    if (HTTP/* iswm $1 && $2 != 200) { dl.fail $sockname $3- }
    elseif ($1 == Content-Length:) { set % [ $+ [ $sockname $+ .size ] ] $2 }
    elseif ($1 == Content-Type:) { set % [ $+ [ $sockname $+ .type ] ] $2- }
    elseif (!$1) {
      write -c $+(",$dl.var($sockname,file),")
      set % [ $+ [ $sockname $+ .ctime ] ] $dl.var($sockname,ctime,1) $ctime
      set % [ $+ [ $sockname $+ .status ] ] Downloading .
      return
    }
  }
  else {
    var %1 = $dl.var($sockname,file)
    :sockread
    sockread &1
    if (!$sockbr) { return }
    bwrite $+(",%1,") -1 &1
    if ($file(%1).size >= $dl.var($sockname,size)) {
      var %1 = $right($sockname,-8),%2 = $dl.var($sockname,file)
      set % [ $+ [ $sockname $+ .status ] ] Done
      .copy -o $+(",%2,") $+(",$left(%2,-4),")
      saym Download Completed
      if (%run = 1) { run %drun | unset %run | unset %drun }
      close -d %1
      return
    }
    goto sockread
  }
}
