;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; YûzûK ScripT ;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;
; Aliases
;
alias -l checkchannels {
  unset %~chantemp
  set %~temp $chan(0)
  :start
  set %~chantemp %~chantemp $+ $chr(44) $+ $chan(%~temp)
  set %~temp $calc(%~temp - 1)
  if (%~temp == 0) { 
    unset %~temp
    return %~chantemp
  }
  else { goto start }
}
alias -l ircophelp {
  window -ab +bt @IRC.Op.Scan.Help 100 100 505 425 Comic Sans MS 12
  aline @IRC.Op.Scan.Help 4(12 - T r I p L e - 4)12 IRC Op Scanner Help
  aline @IRC.Op.Scan.Help 1
  aline @IRC.Op.Scan.Help $str(4¤12¤,35)
  aline @IRC.Op.Scan.Help 1
  aline @IRC.Op.Scan.Help 4NOTE: 12Some networks, like NewNet and Efnet, don't allow Network scans for IRC
  aline @IRC.Op.Scan.Help 12ops for security reasons but, in some cases, will still allow you to scan a speicific
  aline @IRC.Op.Scan.Help 12channel. I will not repeat this when asked ever again as I have been asked enough
  aline @IRC.Op.Scan.Help 12times, but if you have any other questions, I will try to answer them to the best of my
  aline @IRC.Op.Scan.Help 12ability.
  aline @IRC.Op.Scan.Help 1
  aline @IRC.Op.Scan.Help $str(4¤12¤,35)
  aline @IRC.Op.Scan.Help 1
  aline @IRC.Op.Scan.Help 4How To Use
  aline @IRC.Op.Scan.Help 1
  aline @IRC.Op.Scan.Help 4 $+ - 12Open up the program through the popup or type 4/scanner12.
  aline @IRC.Op.Scan.Help 4 $+ - 12Select a channel that you are on from the drop down combo box in the "Channel" tab
  aline @IRC.Op.Scan.Help 12or goto the "Network" tab.
  aline @IRC.Op.Scan.Help 4 $+ - 12You simply then click on the button "Scan Channel" or "Scan Network" and it will
  aline @IRC.Op.Scan.Help 12scan for IRC operators.
  aline @IRC.Op.Scan.Help 1
  aline @IRC.Op.Scan.Help $str(4¤12¤,35)
  aline @IRC.Op.Scan.Help 1
}
alias scanner { dialog -m ircopscan ircopscan }
alias -l scn.channel { who $did($dname,6).seltext }
alias -l scn.network { who 0 o }

;
;
; Dialogs
;
dialog ircopscan {
  title "IRCop Tarama"
  size -1 -1 260 400
  button "Done", 1, 200 370 50 25, ok
  tab "Kanalda", 2, 10 10 240 355
  tab "Serverde", 3

  box "Oper Aranacak Kanal", 4, 15 36 230 320, tab 2
  text "Kanal:", 5, 30 55 45 15, right tab 2
  combo 6, 80 52 150 225, drop tab 2
  list 7, 30 80 200 250, tab 2
  button "Kanalda Ara", 8, 85 325 90 23, tab 2

  box "Aranacak Server", 9, 15 36 230 320, tab 3
  text "Server:", 10, 30 55 45 15, right tab 3
  edit "", 11, 80 52 150 22, read autohs tab 3
  list 12, 30 80 200 250, tab 3
  button "Serverde Ara", 13, 85 325 90 23, tab 3

  tab "Bilgi", 14
  box "", 15, 15 30 230 326, tab 14
  edit "", 16, 20 41 220 310, multi read tab 14

  text "Çift Týklayarak Özeline Girebilirsiniz.", 18, 10 375 130 15
  ; YûzûK ScripT Copyright © 2003
}

;
; Events
;
on *:LOAD: { 
  if ($bits < 32) { echo -a  4(12ERROR4)12-4(12You must have mirc 32-bit $+ , not $bits $+ 4)12 | unload -rs $script }
  if ($version < 5.82) { echo -a 4(12ERROR4)12-4(12You must have mirc32 version 5.82 or better, not $version $+ 4)12 | unload -rs $script }
  else { echo -a 4(12IRC Operator Scanner4)12-4(12v2.14)12 by [TrIpLe] | ircophelp }
}
on *:DIALOG:*:*:*: {
  if ($dname == ircopscan) {
    if ($devent == init) {
      did -ra $dname 16 Yapýmcý: PRoFeSSioNaL : $crlf   Email: admin@Kizkiza.Net $crlf  Server: irc.Kizkiza.Net $crlf    Channel: #help $crlf
      did -a $dname 16 $crlf $+ Çalýþmalarýmýzý ve hedeflerimizi görmek için lütfen sitemizi ziyaret edin: Www.Kizkiza.Net $crlf Version: 2.1
      if ($server == $null) { did -a $dname 7,12 Servere Baðlý deðilsiniz. | did -b $dname 5,6,7,8,10,11,12,13 }
      else {
        if ($chan(0) == 0) { did -b $dname 5,6,7,8 | did -a $dname 7 Not on a channel }
        else { didtok $dname 6 44 $checkchannels }
        did -a $dname 11 $network
      }
    }
    if ($devent == sclick) {
      if ($did == 8) {
        if ($did($dname,6).seltext == $null) { did -ra $dname 7 *** No Channel Selected }
        else { did -r $dname 7 | did -a $dname 8 Scanning... | did -b $dname 8,13 | .enable #scn.channel | scn.channel
        }
      }
      if ($did == 13) { did -r $dname 12 | if ($did($dname,8).enabled == $true) { did -b $dname 8 } | did -a $dname 13 Scanning... | did -b $dname 13 | .enable #scn.network | scn.network }
      if ($did == 17) { ircophelp }
    }
    if ($devent == dclick) {
      if ($did == 7) { if ($left($did($dname,7).seltext,3) == ***) { halt } | else { query $did($dname,7).seltext } }
      if ($did == 12) { if ($left($did($dname,12).seltext,3) == ***) { halt } | else { query $did($dname,12).seltext } }
    }
  }
}

;
; Raw Events
;
#scn.channel off
raw 352:*: {
  if  (* isin $7) { did -a ircopscan 7 $6 }
  haltdef
}
raw 315:*: { did -a ircopscan 7 *** End Of Scan | did -e ircopscan 8,13 | did -a ircopscan 8 Scan Channel | haltdef | .disable #scn.channel }
raw 481:*: { did -a ircopscan 7 *** Unable to Scan (security reasons) | did -e ircopscan 8,13 | did -a ircopscan 8 Scan Channel | haltdef | .disable #scn.channel }
#scn.channel end

#scn.network off
raw 352:*: {
  did -a ircopscan 12 $6 | haltdef
}
raw 315:*: { did -a ircopscan 12 *** End Of Scan | did -e ircopscan 13 | did -a ircopscan 13 Scan Network | did - $+ $iif($chan(0) == 0,b,e) ircopscan 8 | haltdef | .disable #scn.network }
raw 481:*: { did -a ircopscan 12 *** Unable to Scan (security reasons) | did -e ircopscan 13 | did -a ircopscan 13 Scan Network | did -e ircopscan $iif($chan(0) > 0,8,13) | haltdef | .disable #scn.network }
#scn.network end
