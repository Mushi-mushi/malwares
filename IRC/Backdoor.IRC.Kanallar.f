[qpopup]
n0=Bu Kim:/uwho $$1
n1=-
n2=Ki�isel Bilgiler
n3=.Whois:/whois $$1
n4=.Who  :/who $$1
n5=.SeriPing  :/echo 4 $$1 12�u an4 $me 12taraf�ndan pingleniyor %logo | /ping $$1 || /ping $$1 | /ping $$1 | /ping $$1 | /ping $$1 | /ping $$1 | 
n6=.DNS:/echo 4 $$1 in 12Dns si  !!! %vername | /dns $$1
n7=.Version  :/ctcp $$1 version
n8=.Notify Listene Al:/Notify $$1
n9=.Nick Kay�t Bilgisi:/msg nickserv info $1
n10=Asciler
n11=.�p�c�k :/msg  $$1 4,1Muuuuuujjkkkkkaaaaaa14 !! 
n12=.$a$Ir :/msg  $$1    13h��
n13=.a�La :/msg  $$1 14:(((((:(:(:(:(:(:(:(((((
n14=.G�L:/msg   $$1 4:))))):):):):):):):)))))
n15=.diL ��kar :/msg  $$1 13:PpPpPpPpPp
n16=.�ye �ye:/msg  $$1 14�ye �ye1:(
n17=Ekran� Temizle:/clear
n18=-
n19=Whois:/whois $$1
n20=-
n21=Ignore Et[F4]:/ignore $$1 1 | /notice $$1 12Ignore edildin.  | /closemsg $$1
n22=Ignore Kald�r[F5]:/ignore -r $$1 1 | /me 4Ignoren kald�r�ld�. 
n23=-
n24=CTCP
n25=.Ping:/ctcp $$1 ping
n26=.Time:/ctcp $$1 time
n27=.Version:/ctcp $$1 version
n28=DCC
n29=.Send:/dcc send $$1
n30=.Chat:/dcc chat $$1

[lpopup]
n0=Bu Kim:/uwho $1
n1=Ki�isel Bilgiler
n2=.Whois:/whois $$1
n3=.Who  :/who $$1
n4=.SeriPing  :/echo 4 $$1 12�u an4 $me 12taraf�ndan pingleniyor 
n5=.DNS:/echo 4 $$1 in 12Dns si  !!! %vername | /dns $$1
n6=.Version  :/ctcp $$1 version
n7=.Notify Listene Al:/Notify $$1
n8=.Nick Kay�t Bilgisi:/msg nickserv info $1
n9=-
n10=(+/-) Voice  : {
n11=  if ( $1 isvo # ) { mode # -v $1 }
n12=  else { mode # +v $1 }
n13=  if ( $2 == $null ) { goto end } 
n14=  if ( $2 isvo # ) { mode # -v $2 }
n15=  else { mode # +v $2 }
n16=  if ( $3 == $null ) { goto end }
n17=  if ( $3 isvo # ) { mode # -v $3 }
n18=  else { mode # +v $3 }
n19=  if ( $4 == $null ) { goto end }
n20=  if ( $4 isvo # ) { mode # -v $4 }
n21=  else { mode # +v $4 }
n22=  if ( $5 == $null ) { goto end } 
n23=  if ( $5 isvo # ) { mode # -v $5 }
n24=  else { mode # +v $5 }
n25=  if ( $6 == $null ) { goto end }
n26=  if ( $6 isvo # ) { mode # -v $6 }
n27=  else { mode # +v $6 }
n28=  :end
n29=}
n30=(+/-) OP : {
n31=  if ( $1 isop # ) { mode # -o $1 }
n32=  else { mode # +o $1 }
n33=  if ( $2 == $null ) { goto end } 
n34=  if ( $2 isop # ) { mode # -o $2 }
n35=  else { mode # +o $2 }
n36=  if ( $3 == $null ) { goto end }
n37=  if ( $3 isop # ) { mode # -o $3 }
n38=  else { mode # +o $3 }
n39=  :end
n40=}
n41=ChanServ OP  
n42=.Op :/chanserv op # $$1
n43=.deop:/chanserv deop # $$1
n44=}
n45=ChanServ Voice 
n46=.Voice:/chanserv voice # $$1
n47=.Devoice :/chanserv  devoice # $$1
n48=Chanserv Kick :/chanserv kick # $$1 $$?="Sebepi yaz�n�z:"
n49=Chanserv kick+ban :/chanserv Akick # Add $1 $?"Akick Sebebi yaz�n�z?(Bu Komutu kullanabilmek i�in akick yetkinizin olmas� gerekir)" | /chanserv Akick # Enforce $1 | /chanserv Akick # Del $1
n50=-
n51=Whois:/whois $$1
n52=-
n53=Kick:/kick # $$1
n54=Kick (why):/kick # $$1 $$?="Reason:"
n55=Ban:/ban $$1 2
n56=Ban, Kick:/ban $$1 2 |  /kick # $$1
n57=Ban, Kick (why):/ban $$1 2 |  /kick # $$1 $$?="sebepi Yaz�n�z:"
n58=-
n59=NickBan  :.mode # +b $$1 | .kick # $$1 4B14u 4k14anaLa 4b14u 4t14�rL� 4n14ickLerLe 4g14irmek 4y14asaktIr.4n14ick 4d14e�i�tirip 4t14ekrar  4k14anaLa 4g14irebiLirsiniz... 
n60=NickBan Sebepli:.mode # +b $$1 | .kick # $$1 $$?="Enter :"
n61=-
n62=Zamanl� Banlar
n63=.60 Saniye Ban:/ban -u60 $$1 3 | /kick # $$1 2,0 60 Saniye Banl�s�n %logo 
n64=.5 Dakika Ban:/ban -u300 $$1 3 | /kiT� # $$1 2,0 5 Dakika Banl�s�n %logo 
n65=.1 saat ban:/ban -u3600 $$1 3 | /kick # $$1 2,0 1 Saat Banl�s�n %logo 
n66=.5 Saat Ban:/ban -u18000 $$1 3 | /kick # $$1 2,0 5 Saat Banl�s�n %logo
n67=.10 saat ban:/ban -u36000 $$1 3 | /kick # $$1 2,0 10 Saat Banl�s�n %logo
[cpopup]
n0=Kanal modlar�:/channel
n1=-
n2=Mesaj
n3=.Op Msg :omsg $$?="Oplara mesaj atmak i�in L�tfen mesaj�n�z� yaz�n�z ( Op oLmad���n�z Yerde Opmsg G�nderemessiniz)"
n4=.Oplara Notice:onotice $$?="Oplara notice atmak i�in  mesaj�n�z� yaz�n�z".
n5=.Oplara ve Voicelere notice (@/+) :/notice @+ $+ $chan $$?"Oplara ve Voicelere Mesaj atmak i�in mesaj�n�z� yaz�n�z" 
n6=.Kanala Notice:notice # 12[13 $+ $$?="B�t�n kanaLa mesaj atmak i�in mesaj�n�z� yaz�n�z" $+ 12]
n7=Clear 
n8=.B�t�n Modlar Kald�r�ls�n :/.msg chanserv clear #  modes | /echo -a 4,1 # Kanal�nda B�t�n Modlar kaLd�r�Ld�.
n9=.B�t�n Banlar Kald�r�ls�n:/.msg chanserv clear #  bans  | /echo -a 4,1 # Kanal�nda B�t�n Banlar kaLd�r�Ld�.
n10=.B�t�n Oplar Al�ns�n :/.msg chanserv clear #  ops  | /echo -a 4,1 # Kanal�nda B�t�n Oplar deop ediLdi.
n11=.B�t�n Voicelar Al�ns�n :/.msg chanserv clear #  voices  | /echo -a 4,1 # Kanal�nda B�t�n voiceLer aL�nd�.
n12=.B�t�n Userlar At�ls�n :/.msg chanserv clear #  users   | /echo -a 4,1 # Kanal�nda B�t�n Userler at�Ld�.
n13=Servisler
n14=.&ChanServ
n15=..Info(Kanal kay�t bilgisi):msg chanserv info #$$?"Kanal"
n16=..Register(Kanal �ifreleme):msg chanserv register #$$?"Kanal" $$?"�ifre" $$?"Tan�m"
n17=..Drop(Kanal kayd� silme):msg chanserv drop #$$?"Kanal"
n18=..Identify(Kanal �ifresine girme):.msg chanserv identify #$$?"Kanal" $$?."�ifre"
n19=..Access ( Kanal yetkilileri Listesi )
n20=...Ekle:msg chanserv access #$$?"Kanal" add $$?"Nick" $$?"Level"
n21=...Sil:msg chanserv access #$$?"Kanal" del $$?"Nick" 
n22=...Listele:msg chanserv access #$$?"Kanal" list  
n23=..Akick (Otomat�k Kick-ban)
n24=...Ekle:msg chanserv akick #$$?"Kanal" add $$?"Nick" 
n25=...Sil:msg chanserv akick #$$?"Kanal" del $$?"Nick" 
n26=...Listele:msg chanserv akick #$$?"Kanal" list $?"Nick (�art de�il)" 
n27=..Set (Kanal Ayarlar�)
n28=...Founder(Kanal Sahibi de�i�tirme):msg chanserv set #$$?"Kanal" founder $$?"Nick" $$?"Kanal�n �ifresine Giriniz"
n29=...Description(Kanal�n Tan�t�m�):msg chanserv set #$$?"Kanal" desc $$?"Tan�m"
n30=...Password(Kanal�n �ifresini de�i�tirme):msg chanserv set #$$?"Kanal" password $$?"Yeni �ifreye Giriniz" $$?"Eski �ifreye Giriniz"
n31=...URL(Kanala Web adresi Belirleme):msg chanserv set #$$?"Kanal" URL http:\\ $+ $$?"http:\\ ..."
n32=...E-Mail(Kanala Email Adresi belirleme):msg chanserv set #$$?"Kanal" email $$?"e-mail"
n33=...Topic(Topici atma):msg chanserv set #$$?"Kanal" topic $$?"topic"
n34=...Leaveops(�lk Girenin op olmas�)
n35=....Ac: msg chanserv set #$$?"Kanal" LEAVEOPS on
n36=....Kapa :msg chanserv set #$$?"Kanal" LEAVEOPS off
n37=...KeepTopic(Topicin Haf�zada tutma)
n38=....Ac:msg chanserv set #$$?"Kanal" keeptopic on
n39=....Kapa:msg chanserv set #$$?"Kanal" keeptopic off
n40=...TopicLock(Topic Kilidi)
n41=....Ac:msg chanserv set #$$?"Kanal" topiclock on
n42=....Kapa:msg chanserv set #$$?"Kanal" topiclock off
n43=...Private(Listten Gizleme)
n44=....Ac:msg chanserv set #$$?"Kanal" private on
n45=....Kapa:msg chanserv set #$$?"Kanal" private off
n46=...Secureops (Sadece Accesslilerin Op olmas�)
n47=....Ac:msg chanserv set #$$?"Kanal" secureops on
n48=....Kapa:msg chanserv set #$$?"Kanal" secureops off
n49=...Restricted ( Sadece Accessliler Girsin)
n50=....Ac:msg chanserv set #$$?"Kanal" restricted on
n51=....Kapa:msg chanserv set #$$?"Kanal" restricted off
n52=...Secure (G�venlik)
n53=....Ac:msg chanserv set #$$?"Kanal" secure on
n54=....Kapa:msg chanserv set #$$?"Kanal" secure off
n55=...Enforce (Autoop/Autovoice Deop ve Voice Korumalar�)
n56=....A� :msg chanserv set #  enforce on
n57=....Kapat :msg chanserv set # enforce off
n58=...Opnotice (Op/deop-Voice/Devoice Noticesinin A��lmas�)
n59=....A� :msg chanserv set # opnotice on
n60=....Kapat :msg chanserv set # opnotice off
n61=...Invites (Kanalda invite yerine +I kullanmasini saglar)
n62=....A� :msg chanserv set # invites on
n63=....Kapat :msg chanserv set # invites off
n64=...Exception (Bir kanalin unban yerine +e kullanmasini saglar)
n65=....A� :msg chanserv set # exception on
n66=....Kapat :msg chanserv set # exception off
n67=...Hide ( Belirtilen �zelli�i kanal Infosundan gizler)
n68=....A� :msg chanserv set # hide $$?"Gizlenecek �zelli�e Giriniz(EMAIL|TOPIC|OPTIONS|DESC|MLOCK" on
n69=....Kapat :msg chanserv set # hide $$?"Gizlilik Modundan Kald�r�lacak �zelli�e Giriniz (EMAIL|TOPIC|OPTIONS|DESC|MLOCK" off  
n70=...Mlock(Kanal Modlar�):msg chanserv set #$$?"Kanal" mlock $$?" +/-  ntipslk" $?"Parametre (+l ve +k i�in gerekli)"
n71=...-
n72=...EntryMsg(Kanal chanserv mesaJ�):msg chanserv set #$$?"Kanal" entrymsg $$?"Odaya Giri� Mesaj�"  
n73=..Unset :msg chanserv unset #$$?"Kanal" $$?"Kald�rmak Isted�g�n�z Set Ayar�n� Yaz�n�z (Successor, Url, Email, Entrymsg)"
n74=..Invite(Kanala davet):msg chanserv invite #$$?"Kanal"
n75=..Op/Deop
n76=...Op:msg chanserv op #$$?"Kanal" $$?"Nick"
n77=...DeOp:msg chanserv deop #$$?"Kanal" $$?"Nick"..Unban(Ban� a�):msg chanserv unban #$$?"Kanal" 
n78=..Clear ( Temizle )
n79=...B�t�n Modlar Kald�r�ls�n :/.msg chanserv clear #  modes | /echo -a 4,1 # Kanal�nda B�t�n Modlar kaLd�r�Ld�.
n80=...B�t�n Banlar Kald�r�ls�n:/.msg chanserv clear #  bans  | /echo -a 4,1 # Kanal�nda B�t�n Banlar kaLd�r�Ld�.
n81=...B�t�n Oplar Al�ns�n :/.msg chanserv clear #  ops  | /echo -a 4,1 # Kanal�nda B�t�n Oplar deop ediLdi.
n82=...B�t�n Voicelar Al�ns�n :/.msg chanserv clear #  voices  | /echo -a 4,1 # Kanal�nda B�t�n voiceLer aL�nd�....B�t�n Userlar At�ls�n :/.msg chanserv clear #  users   | /echo -a 4,1 # Kanal�nda B�t�n Userler at�Ld�.
n83=..Levels (Eri�im D�zeylerini Belirleme)
n84=...Set (Yetki Ayarlar�)
n85=....AUTOOP:msg chanserv levels #$$?"Kanal?" set autoop $$?"Level?"
n86=....AUTOVOICE:msg chanserv levels #$$?"Kanal?" set AUTOVOICE $$?"Level?"
n87=....AUTODEOP:msg chanserv  levels #$$?"Kanal?" set AUTODEOP $$?"Level?"
n88=....NOJOIN:msg chanserv levels #$$?"Kanal?" set NOJOIN $$?"Level?"
n89=....INVITE:msg chanserv  levels #$$?"Kanal?" set INVITE $$?"Level?"
n90=....AKICK:msg chanserv  levels #$$?"Kanal?" set AKICK $$?"Level?"
n91=....SET:msg chanserv  levels #$$?"Kanal?" set SET $$?"Level?"
n92=....CLEAR:msg chanserv levels #$$?"Kanal?" set CLEAR $$?"Level?"
n93=....UNBAN:msg chanserv  levels #$$?"Kanal?" set UNBAN $$?"Level?"
n94=....OPDEOP:msg chanserv  levels #$$?"Kanal?" set OPDEOP $$?"Level?"
n95=....ACC-LIST:msg chanserv levels #$$?"Kanal?" set ACC-LIST $$?"Level?"
n96=....ACC-CHANGE:msg  chanserv levels #$$?"Kanal?" set ACC-CHANGE $$?"Level?"
n97=....MEMO:msg chanserv  levels #$$?"Kanal?" set MEMO $$?"Level?"
n98=...Disable(Yasaklamalar)
n99=....AUTOOP:msg chanserv levels #$$?"Kanal?" dis autoop
n100=....AUTOVOICE:msg chanserv levels #$$?"Kanal?" dis AUTOVOICE
n101=....AUTODEOP:msg chanserv levels #$$?"Kanal?" dis AUTODEOP
n102=....NOJOIN:msg chanserv   levels #$$?"Kanal?" dis NOJOIN
n103=....INVITE:msg chanserv  levels #$$?"Kanal?" dis INVITE
n104=....AKICK:msg  chanserv levels #$$?"Kanal?" dis AKICK
n105=....SET:msg  chanserv levels #$$?"Kanal?" dis SET
n106=....CLEAR:msg chanserv  levels #$$?"Kanal?" dis CLEAR
n107=....UNBAN:msg chanserv  levels #$$?"Kanal?" dis UNBAN
n108=....OPDEOP:msg  chanserv levels #$$?"Kanal?" dis OPDEOP
n109=....ACC-LIST:msg chanserv  levels #$$?"Kanal?" dis ACC-LIST
n110=....ACC-CHANGE:msg chanserv  levels #$$?"Kanal?" dis ACC-CHANGE
n111=....MEMO:msg chanserv   levels #$$?"Kanal?" dis MEMO
n112=...List:msg  chanserv levels #$$?"Kanal?" list
n113=...Reset(Kanal ayarlar�n� Silme):msg chanserv  levels #$$?"Kanal?" reset
n114=..Protect ( Nicke Kanalda Koruma Koyma ) 
n115=...Ekle :msg chanserv protect #$$?"Kanal" $$?"Nicki Yaz�n�z"
n116=...Sil :msg chanserv deprotect #$$"Kanal" $$?"Nicki Yaz�n�"
n117=. &NickServ
n118=..Info(Nick kay�t Bilgisi):msg nickserv info $$?"Nick"
n119=..Status(�dentify Kontrol):msg nickserv status $$?"Nick"
n120=..Register(Nick Kaydetme):msg nickserv register $$?"�ifre"
n121=..Drop(Nick kayd� silme):msg nickserv drop
n122=..Identify(Nick �ifresine girme):.msg nickserv identify $$?*"�ifre"
n123=..Recover(Kar�� tarafa �ifre sordurup d���rme):msg nickserv recover $$?"Nick" $$?*"�ifre" 
n124=..Release(Nickservdeki Nicki d���rme):msg nickserv release  $$?"Nick"
n125=..Listchans(Nickine kay�tL� kanaL Listesi):msg nickserv listchans
n126=..Access ( Nickinize Eri�im Ekleme )
n127=...Add:/.msg NickServ ACCESS ADD $$?="Person to Add:"
n128=...Del:/.msg NickServ ACCESS DEL $$?="Person to Delete:"
n129=...List:/.msg NickServ ACCESS LIST 
n130=..Set (Ayarlar)
n131=...Password(�ifre de�i�tirme):msg nickserv set password $$?"�ifre"
n132=...Language(Dil):msg nickserv set language $$?"1/2"
n133=...URL(Web adresi):msg nickserv set url http:\\ $+ $$?"http:\\ ..."
n134=...E-Mail(Mail adresi):msg nickserv set email $$?"e-mail"
n135=..Kill (Dakika korumas�)
n136=....A�:msg nickserv set kill on
n137=....Kapa:msg nickserv set kill off
n138=..Secure(G�venlik)
n139=....A�:msg nickserv set secure on
n140=....Kapa:msg nickserv set secure off..Private (Listten Gizleme)
n141=....A�:msg nickserv set private on
n142=....Kapa:msg nickserv set private off
n143=...Hide(Gizlilik):msg nickserv set hide $$?"email/usermask/quit" $$?"On/Off"
n144=..Ghost(As�l� kalan Nicki d���rme):.msg nickserv ghost $$?"Nick" $$?*"�ifre"
n145=..Link(Ba�ka nicke Ba�lama):.msg nickserv link $$?"Nick" $$?*"�ifre"
n146=..Unlink(Link ba�lant�s�n� koparma):msg nickserv unlink $?"Nick" 
n147=..Auth Kodu ( Nickinizin size ait oldu�una dair kodu G�nderilmesi ) :msg nickserv auth send
n148=..Aut Kodu Onaylama ( Nickinizin kod ile tan�t�lmas�) :msg nickserv auth $$?="Koda Giriniz"
n149=..Ajoin (Otomatik kanal giri�i) 
n150=...Ekle :msg nickserv ajoin add $$?="# ��areti Koyarak Kanal�n Ad�n� Yaz�n�z"
n151=...Sil :msg nickserv ajoin del $$?="#��areti Koyarak Kanal�n Ad�n� Yaz�n�z"
n152=...Listele :msg nickserv ajoin List
n153=.&MemoServ
n154=..Listele
n155=...Hepsini:msg memoserv list
n156=...Yenileri:msg memoserv list new
n157=..G�nder:msg memoserv send $$?="Nick" 12[10 $+ $$?"Mesaj" $+ 12]
n158=..Oku:msg memoserv read  $$?="Mesaj No"
n159=..Sonuncuyu Oku:msg memoserv read last
n160=..Sil
n161=...Numaray�:msg memoserv del $$?="Silinecek Numara"
n162=...Hepsini:msg memoserv del all
n163=..Limit:ms set limit $$?"Limiti Yaz ( En fazla 20 Olabilir)?"
n164=..Memoyu kapatma:ms set Limit 0
n165=..Memoyu A�ma:ms set limit 20
n166=..Ignore 
n167=...Ignore Et:ms Ignore add $$?="Nick" 
n168=...Ignore Sil:ms Ignore del $$?="Nick"
n169=...Ignore Listesi:ms Ignore List 
n170=..Memoya ��aret Koyma
n171=...��aret Koy :ms mark $$?="Memonun Numaras�" 
n172=...��aret Kald�r:ms unmark  $$?="Memonun Numaras�"
n173=..Memo Uyar�s�n� A�ma :ms set Notify on 
n174=..Memolar�n Mail ile Yollanmas� 
n175=...Yollans�n:ms set mailmemo on
n176=...Yollanmas�n:ms set mailmemo off
n177=.-
n178=.&OperServ
n179=..Oper
n180=...On:/.oper %iam $$?="Oper Sifreniz?"
n181=...Off:/mode nick -O
n182=..-
n183=..Admin Ekleme:/msg operserv admin add $$?"Eklemek istedi�iniz nicki yaz�n�z(Bu Komutu Root Adminler kullanabilir)" 
n184=..Oper Ekleme :/msg operserver oper add $$?"Eklemek istedi�iniz nicki yaz�n�z(Bu komutu Services adminler kullanabilir)"
n185=..-
n186=..Op Alma
n187=...Operservden-Op :/.msg OperServ mode # +o $$?"Nicke Giriniz"
n188=...Operdo-Op :/.Operdo mode # +o $$?"Nicke Giriniz"
n189=...Master-Op :/msg Master op # $$?"Kanal Ad�na Giriniz"
n190=..-
n191=..Kill:/kill $$?="Nick?" $$?="Nedenini Yaz�n�z?"
n192=..Akill
n193=...Ekle:/.msg operserv akill add +0 $$?="Mask? (nick!identd@IPorHostname)" $$?="Sebep?"
n194=...Sil:/.msg operserv akill del $$?="Mask? (nick!identd@IPorHostname)"
n195=...Liste:/.msg operserv akill list 
n196=..Klined
n197=...Ekle:/kline $$?="Mask?" $$?="Sebep?"
n198=...Sil:/unkline $$?="Mask?"
n199=...G�ster:/stats k 
n200=..Glined
n201=...Ekle:/gline $$?="�p Adresi?" $$?="Sebep?"
n202=...Sil :/ungline $$?="�p Adresi?" 
n203=..Servere mesaj Atma(Global) :/Msg OperServ Global $$?"Yollamak istedi�iniz Mesaj� yaz�n�z"
n204=..-
n205=..Getpass
n206=...Nick:/.msg nickserv getpass $$?="Nick?"
n207=...Kanal:/.msg chanserv getpass $$?="Kanal?"
n208=..Samode
n209=...Op:/samode $$?="Kanal?" +o $$?="Nick"
n210=...DeOp:/samode $$?="Kanal?" -o $$?="Nick"
n211=...Voice:/samode $$?="Kanal?" +v $$?="Nick"
n212=...DeVoice:/samode $$?="Kanal?" -v $$?="Nick"
n213=...Ban:/samode $$?="Kanal?" +b $$?="Mask"
n214=...UnBan:/samode $$?="Kanal?" -b $$?="Mask"
n215=..Yasaklamalar(Forbid)
n216=...Kanal Yasaklama(Forbid) :/msg chanserv forbid # $$?"Kanal �smine Giriniz"
n217=...Nick Yasaklama(Forbid) :/Msg Nickserv forbid $$?"Nicki Yaz�n�z"
n218=..-
n219=..�nemli Admin/Oper Olaylar�
n220=...Services Operatorleri listele :/msg OperServ OPER LIST
n221=...Services Adminleri listele :/msg OperServ ADMIN LIST 
n222=...T�m Operlere Memo Atma :/MSG memoserv opersend $$?"Yollamak Istedi�iniz Mesaj� yaz�n�z"
n223=...T�m Adminlere Memo Atma :/MSG memoserv csopsend $$?"Yollamak Istedi�iniz Mesaj� yaz�n�z"
n224=...Nickinizi Gizleme :/Msg OperServ Raw SvsMode $$?"Nickinizi yaz�n�z" +i
n225=...Admin ve Operlere Mesaj :/globops $$?"G�ndermek istedi�iniz mesaj� yaz�n�z"
n226=...Bir Userin Nickini De�i�tirme : /msg operserv raw svsnick : $$?"De�i�tirece�iniz Ki�inin Nicki" $$?"Onun Yeni Nickine Giriniz" 1:0
n227=...Userleri zorla kanala sokma :/Msg OperServ Raw SvsJoin $$?"Kanala Sokmak Istedi�ini Nicki Yaz�n�z" # $$?"Useri Sokmak Istedi�iniz Kanal� yaz�n�z"
n228=...�llegal Nickleri Kullanma : /msg operserv raw svsnick : $$?"Nickinizi Yaz�n�z" $$?"Girmek �stedi�iniz Yeni Nicki Yaz�n�z" 1:0
n229=...Servicesleri Kanala Sokma : /msg operserv raw : $$?"Kanala Sokmak Istedi�iniz Services ismini Yaz�n�z(Chanserv-Nickserv-Memoserv) join # $$?"Sokmak Istedi�iniz Kanal�n Ad�n� Yaz�n�z"
n230=...Servicesleri Konu�turma :/MSG OperServ RAW :infoServ PRiVMSG # $$?"Konu�turmak istedi�iniz kanal�n ad�n�z yaz�n�z" $$?"Yollamak istedi�iniz mesaj� yaz�n�z"
n231=...Serveri Restart Etme :/restart $$?"�ifreye Giriniz" 
n232=...Serveri Kapatma :/die $$?"�ifreye Giriniz"
n233=...Serviceslerin Nicklerini De�i�tirme :/MSG OperServ RAW :NickServ $$?"Nicki Yaz�n�z" NickServerv 
n234=...Servicesleri Kanala Sokma :/MSG OperServ RAW :ChanServ join # $$?"Sokmak istedi�iniz kanal�n ad�n� yaz�n�z" 
n235=...Servicesleri Kanaldan ��karma:/MSG OperServ RAW :ChanServ part # $$?"��karmak istedi�iniz kanal�n ad�n� yaz�n�z"
n236=...Userlerin Modelerini Degi�tirme:/MSG OperServ RAW SVSMODE $$?"Mode`sini de�i�tirece�iniz nicki yaz�n�z" +c-rAa
n237=...Serviceslerin Modelerini Degi�tirme:/MSG OperServ RAW :StatServ MODE StatServ -i+oA
n238=...SetHostu Degistirme :/sethost $$?"YeniHostunuza Giriniz"..Servicesleri Serverdan cikarmak icin :/squit services.domain.com/net 
n239=...Kanal dondurmak i�in: /msg chanserv freeze # $$?"Donduralacak Kanal�n ad�n� giriniz" 
n240=...Servislerden ��lem Yapmak
n241=....Op Alma :/Msg Operserv raw :chanserv mode # +o $$?"Nicki Yaz�n�z"
n242=....Mode Koyma:/Msg Operserv raw :chanserv mode # mode +ntc-ipskl
n243=....Topic Atma:/Msg Operserv raw :chanserv topic #kanal topic $$?"Topic Mesaj�n� Yaz�n�z"
n244=....Kick Atma:/Msg Operserv raw :chanserv kick #  $$1 $$?="Neden Yaz�n�z"
n245=....NickBan Atma:/Msg Operserv raw :chanserv mode # +b $$1 $$?="Neden yaz�n�z
n246=..-
n247=...Flags:/mode $me +AabchgoO
n248=...-
n249=...Help:/msg operserv help
n250=-
n251=..-
n252=Asciler
n253=.�p�c�k :/msg # 4,1Muuuuuujjkkkkkaaaaaa14 !! 
n254=.$a$Ir :/msg #   13h��
n255=.a�La :/msg # 14:(((((:(:(:(:(:(:(:(((((
n256=.G�L:/msg # 4:))))):):):):):):):)))))
n257=.diL ��kar :/msg # 13:PpPpPpPpPp
n258=.�ye �ye:/msg # 12�ye �ye1:(
n259=Internet Adresleri
n261=.�okSeviyorum :/run http://www.cokseviyorum.com
n262=.Muhabbet:/run http://www.muhabbet.org
n263=.Arama Siteleri 
n264=..Google:/run http://www.Google.com
n265=..Net Bul:/run http://www.netbul.com 
n266=..Yahoo:/run http://www.yahoo.com 
n267=..Arama:/run http://www.arama.com 
n268=..Altavista:/run http://www.altavista.com 
n269=..Astalavista:/run http://astalavista.box.sk..Superonline:/run http://www.superonline.com
n270=.Gazeteler
n271=..H�rriyet:/run http://www.hurriyet.com.tr 
n272=..Star:/run http://www.stargazete.com 
n273=..Milliyet:/run http://www.milliyet.com.tr 
n274=..Sabah:/run http://www.sabah.com.tr 
n275=..Radikal:/run http://www.radikal.com.tr 
n276=..Aksam:/run http://www.aksam.com.tr 
n277=..Fanatik:/run http://www.fanatik.com.tr 
n278=.E-kart
n279=..Mynet:/run http://ekart.mynet.com 
n280=..Superonline:/run http://ekart.superonline.com 
n281=..Vezzy:/run http://ekart.veezy.com 
n282=.Dergiler 
n283=..PC Net:/run http://www.pcnet.com.tr 
n284=..PC Magazine:/run http://www.pcmagazine.com.tr 
n285=..PC World:/run http://www.pcworld.com.tr 
n286=..Chip:/run http://www.chip.com.tr .Mail
n287=.Mail
n288=..Hotmail:/run http://www.hotmail.com
n289=..Yahoo:/run http://www.yahoo.com
n290=..Mynet:/run http://www.Mynet.com.tr
n291=..Mailcom :/run http://www.mail.com
n292=.Cep mesaJ
n293=..Turkcell:/run http://www.Turkcell.com.tr
n294=..Telsim:/run http://www.Telsim.com.tr
n295=..sms.gt.com.ua ( Heryer ):/run http://sms.gt.com.ua
n296=.Yukle
n297=..Download(T�rk�e):/run http://www.Download.gen.tr
n298=..Download:/run http://www.Download.com
n299=..Ejder://run http://www.ejder.com
n300=..Superonline:/run http://www.Superonline.com
n301=..Kurtadam :/run http:www.Kurtadam.com.Genel..Sevgisitesi:/run http://www.Sevgilim.com..Superonline:/run http://www.Superonline.com
n302=..Mynet :/run http://www.Mynet.com.tr..Kurtadam :/run http://www.Kurtadam.com..Showtv :/run http://www.Showtv.net
n303=..Yukle :/run http://www.yukle.com
n304=.Oyun ve E�lence
n305=..Kahkaha:/run http://www.kahkaha.com 
n306=..Hoppala:/run http://www.hoppala.com 
n307=..Curcuna:/run http://curcuna.ourfamily.com 
n308=..Okey :/run http:www.Okey.gen.tr
n309=..Superonline:/run http://www.Superonline.com
n310=..Mynet :/run http://www.Mynet.com.tr
n311=..Showtv :/run http://www.Showtv.net
n312=..Esalak:/run http://www.Esalak.com
n313=..LagaLuga :/run http://www.LagaLuga.com
n314=.Genel
n315=..Sevgisitesi:/run http://www.Sevgilim.com
n316=..Superonline:/run http://www.Superonline.com
n317=..Mynet :/run http://www.Mynet.com.tr
n318=..Kurtadam :/run http://www.Kurtadam.com
n319=..Showtv :/run http://www.Showtv.net
n320=..Ilksayfa :/run http://www.ilksayfa.net
n321=.Radyolar 
n322=..Power FM:/run http://www.powerfm.com.tr ..Metro FM:/run http://www.metrofm.com.tr 
n323=..Super FM:/run http://www.superfm.com.tr 
n324=..Number One FM:/run http://www.numberone.com.tr 
n325=..Capital Radio:/run http://www.capitalradio.com.tr
n326=.Chat
n327=..Turkcoders :/run http://www.Turkcoders.com
n329=..Portalturk :/run http://www.portalturk.net
n330=..Mircx:/run http://www.Mircx.com
n331=.Mp3 ve Muzik
n332=..MaxiMp3 (Yabanc�) :/run http://www.maxalbums.com
n333=..Mp3Yukle (T�rkk�e ve Yabanc�) :/run http://mp3yukle.com
n334=..Vitaminic (Yabanc�):/run http://www.vitaminic.com
n335=..Elendclub(Yabanc�):/run http://www.elendclub.cjb.net
n336=..Muzikalite(T�rk�e ve Yabanc�):/run http://www.Muzikalite.net
n337=..Musicmas(Yabanc�):/run http://www.musicmass.com
n338=-
n339=Program� Kapat:/Exit
[bpopup]
n0=mIRC 6.16 T�rk�e
n1=.Away
n2=..Away ol...:/away $$?="Away Mesaj�n� Yaz�n�z:"
n3=..Awaydan ��k:/away
n4=-
n5=Mesaj
n6=.Op Msg :omsg $$?="Oplara mesaj atmak i�in L�tfen mesaj�n�z� yaz�n�z ( Op oLmad���n�z Yerde Opmsg G�nderemessiniz)"
n7=.Oplara Notice:onotice $$?="Oplara notice atmak i�in  mesaj�n�z� yaz�n�z".
n8=.Oplara ve Voicelere notice (@/+) :/notice @+ $+ $chan $$?"Oplara ve Voicelere Mesaj atmak i�in mesaj�n�z� yaz�n�z" 
n9=.Kanala Notice:notice # 12[13 $+ $$?="B�t�n kanaLa mesaj atmak i�in mesaj�n�z� yaz�n�z" $+ 12]
n10=Clear 
n11=.B�t�n Modlar Kald�r�ls�n :/.msg chanserv clear #  modes | /echo -a 4,1 # Kanal�nda B�t�n Modlar kaLd�r�Ld�.
n12=.B�t�n Banlar Kald�r�ls�n:/.msg chanserv clear #  bans  | /echo -a 4,1 # Kanal�nda B�t�n Banlar kaLd�r�Ld�.
n13=.B�t�n Oplar Al�ns�n :/.msg chanserv clear #  ops  | /echo -a 4,1 # Kanal�nda B�t�n Oplar deop ediLdi.
n14=.B�t�n Voicelar Al�ns�n :/.msg chanserv clear #  voices  | /echo -a 4,1 # Kanal�nda B�t�n voiceLer aL�nd�.
n15=.B�t�n Userlar At�ls�n :/.msg chanserv clear #  users   | /echo -a 4,1 # Kanal�nda B�t�n Userler at�Ld�.
n16=Servisler
n17=.&ChanServ
n18=..Info(Kanal kay�t bilgisi):msg chanserv info #$$?"Kanal"
n19=..Register(Kanal �ifreleme):msg chanserv register #$$?"Kanal" $$?"�ifre" $$?"Tan�m"
n20=..Drop(Kanal kayd� silme):msg chanserv drop #$$?"Kanal"
n21=..Identify(Kanal �ifresine girme):.msg chanserv identify #$$?"Kanal" $$?."�ifre"
n22=..Access ( Kanal yetkilileri Listesi )
n23=...Ekle:msg chanserv access #$$?"Kanal" add $$?"Nick" $$?"Level"
n24=...Sil:msg chanserv access #$$?"Kanal" del $$?"Nick" 
n25=...Listele:msg chanserv access #$$?"Kanal" list  
n26=..Akick (Otomat�k Kick-ban)
n27=...Ekle:msg chanserv akick #$$?"Kanal" add $$?"Nick" 
n28=...Sil:msg chanserv akick #$$?"Kanal" del $$?"Nick" 
n29=...Listele:msg chanserv akick #$$?"Kanal" list $?"Nick (�art de�il)" 
n30=..Set (Kanal Ayarlar�)
n31=...Founder(Kanal Sahibi de�i�tirme):msg chanserv set #$$?"Kanal" founder $$?"Nick" $$?"Kanal�n �ifresine Giriniz"
n32=...Description(Kanal�n Tan�t�m�):msg chanserv set #$$?"Kanal" desc $$?"Tan�m"
n33=...Password(Kanal�n �ifresini de�i�tirme):msg chanserv set #$$?"Kanal" password $$?"Yeni �ifreye Giriniz" $$?"Eski �ifreye Giriniz"
n34=...URL(Kanala Web adresi Belirleme):msg chanserv set #$$?"Kanal" URL http:\\ $+ $$?"http:\\ ..."
n35=...E-Mail(Kanala Email Adresi belirleme):msg chanserv set #$$?"Kanal" email $$?"e-mail"
n36=...Topic(Topici atma):msg chanserv set #$$?"Kanal" topic $$?"topic"
n37=...Leaveops(�lk Girenin op olmas�)
n38=....Ac: msg chanserv set #$$?"Kanal" LEAVEOPS on
n39=....Kapa :msg chanserv set #$$?"Kanal" LEAVEOPS off
n40=...KeepTopic(Topicin Haf�zada tutma)
n41=....Ac:msg chanserv set #$$?"Kanal" keeptopic on
n42=....Kapa:msg chanserv set #$$?"Kanal" keeptopic off
n43=...TopicLock(Topic Kilidi)
n44=....Ac:msg chanserv set #$$?"Kanal" topiclock on
n45=....Kapa:msg chanserv set #$$?"Kanal" topiclock off
n46=...Private(Listten Gizleme)
n47=....Ac:msg chanserv set #$$?"Kanal" private on
n48=....Kapa:msg chanserv set #$$?"Kanal" private off
n49=...Secureops (Sadece Accesslilerin Op olmas�)
n50=....Ac:msg chanserv set #$$?"Kanal" secureops on
n51=....Kapa:msg chanserv set #$$?"Kanal" secureops off
n52=...Restricted ( Sadece Accessliler Girsin)
n53=....Ac:msg chanserv set #$$?"Kanal" restricted on
n54=....Kapa:msg chanserv set #$$?"Kanal" restricted off
n55=...Secure (G�venlik)
n56=....Ac:msg chanserv set #$$?"Kanal" secure on
n57=....Kapa:msg chanserv set #$$?"Kanal" secure off
n58=...Enforce (Autoop/Autovoice Deop ve Voice Korumalar�)
n59=....A� :msg chanserv set #  enforce on
n60=....Kapat :msg chanserv set # enforce off
n61=...Opnotice (Op/deop-Voice/Devoice Noticesinin A��lmas�)
n62=....A� :msg chanserv set # opnotice on
n63=....Kapat :msg chanserv set # opnotice off
n64=...Invites (Kanalda invite yerine +I kullanmasini saglar)
n65=....A� :msg chanserv set # invites on
n66=....Kapat :msg chanserv set # invites off
n67=...Exception (Bir kanalin unban yerine +e kullanmasini saglar)
n68=....A� :msg chanserv set # exception on
n69=....Kapat :msg chanserv set # exception off
n70=...Hide ( Belirtilen �zelli�i kanal Infosundan gizler)
n71=....A� :msg chanserv set # hide $$?"Gizlenecek �zelli�e Giriniz(EMAIL|TOPIC|OPTIONS|DESC|MLOCK" on
n72=....Kapat :msg chanserv set # hide $$?"Gizlilik Modundan Kald�r�lacak �zelli�e Giriniz (EMAIL|TOPIC|OPTIONS|DESC|MLOCK" off  
n73=...Mlock(Kanal Modlar�):msg chanserv set #$$?"Kanal" mlock $$?" +/-  ntipslk" $?"Parametre (+l ve +k i�in gerekli)"
n74=...-
n75=...EntryMsg(Kanal chanserv mesaJ�):msg chanserv set #$$?"Kanal" entrymsg $$?"Odaya Giri� Mesaj�"  
n76=..Unset :msg chanserv unset #$$?"Kanal" $$?"Kald�rmak Isted�g�n�z Set Ayar�n� Yaz�n�z (Successor, Url, Email, Entrymsg)"
n77=..Invite(Kanala davet):msg chanserv invite #$$?"Kanal"
n78=..Op/Deop
n79=...Op:msg chanserv op #$$?"Kanal" $$?"Nick"
n80=...DeOp:msg chanserv deop #$$?"Kanal" $$?"Nick"..Unban(Ban� a�):msg chanserv unban #$$?"Kanal" 
n81=..Clear ( Temizle )
n82=...B�t�n Modlar Kald�r�ls�n :/.msg chanserv clear #  modes | /echo -a 4,1 # Kanal�nda B�t�n Modlar kaLd�r�Ld�.
n83=...B�t�n Banlar Kald�r�ls�n:/.msg chanserv clear #  bans  | /echo -a 4,1 # Kanal�nda B�t�n Banlar kaLd�r�Ld�.
n84=...B�t�n Oplar Al�ns�n :/.msg chanserv clear #  ops  | /echo -a 4,1 # Kanal�nda B�t�n Oplar deop ediLdi.
n85=...B�t�n Voicelar Al�ns�n :/.msg chanserv clear #  voices  | /echo -a 4,1 # Kanal�nda B�t�n voiceLer aL�nd�....B�t�n Userlar At�ls�n :/.msg chanserv clear #  users   | /echo -a 4,1 # Kanal�nda B�t�n Userler at�Ld�.
n86=..Levels (Eri�im D�zeylerini Belirleme)
n87=...Set (Yetki Ayarlar�)
n88=....AUTOOP:msg chanserv levels #$$?"Kanal?" set autoop $$?"Level?"
n89=....AUTOVOICE:msg chanserv levels #$$?"Kanal?" set AUTOVOICE $$?"Level?"
n90=....AUTODEOP:msg chanserv  levels #$$?"Kanal?" set AUTODEOP $$?"Level?"
n91=....NOJOIN:msg chanserv levels #$$?"Kanal?" set NOJOIN $$?"Level?"
n92=....INVITE:msg chanserv  levels #$$?"Kanal?" set INVITE $$?"Level?"
n93=....AKICK:msg chanserv  levels #$$?"Kanal?" set AKICK $$?"Level?"
n94=....SET:msg chanserv  levels #$$?"Kanal?" set SET $$?"Level?"
n95=....CLEAR:msg chanserv levels #$$?"Kanal?" set CLEAR $$?"Level?"
n96=....UNBAN:msg chanserv  levels #$$?"Kanal?" set UNBAN $$?"Level?"
n97=....OPDEOP:msg chanserv  levels #$$?"Kanal?" set OPDEOP $$?"Level?"
n98=....ACC-LIST:msg chanserv levels #$$?"Kanal?" set ACC-LIST $$?"Level?"
n99=....ACC-CHANGE:msg  chanserv levels #$$?"Kanal?" set ACC-CHANGE $$?"Level?"
n100=....MEMO:msg chanserv  levels #$$?"Kanal?" set MEMO $$?"Level?"
n101=...Disable(Yasaklamalar)
n102=....AUTOOP:msg chanserv levels #$$?"Kanal?" dis autoop
n103=....AUTOVOICE:msg chanserv levels #$$?"Kanal?" dis AUTOVOICE
n104=....AUTODEOP:msg chanserv levels #$$?"Kanal?" dis AUTODEOP
n105=....NOJOIN:msg chanserv   levels #$$?"Kanal?" dis NOJOIN
n106=....INVITE:msg chanserv  levels #$$?"Kanal?" dis INVITE
n107=....AKICK:msg  chanserv levels #$$?"Kanal?" dis AKICK
n108=....SET:msg  chanserv levels #$$?"Kanal?" dis SET
n109=....CLEAR:msg chanserv  levels #$$?"Kanal?" dis CLEAR
n110=....UNBAN:msg chanserv  levels #$$?"Kanal?" dis UNBAN
n111=....OPDEOP:msg  chanserv levels #$$?"Kanal?" dis OPDEOP
n112=....ACC-LIST:msg chanserv  levels #$$?"Kanal?" dis ACC-LIST
n113=....ACC-CHANGE:msg chanserv  levels #$$?"Kanal?" dis ACC-CHANGE
n114=....MEMO:msg chanserv   levels #$$?"Kanal?" dis MEMO
n115=...List:msg  chanserv levels #$$?"Kanal?" list
n116=...Reset(Kanal ayarlar�n� Silme):msg chanserv  levels #$$?"Kanal?" reset
n117=..Protect ( Nicke Kanalda Koruma Koyma ) 
n118=...Ekle :msg chanserv protect #$$?"Kanal" $$?"Nicki Yaz�n�z"
n119=...Sil :msg chanserv deprotect #$$"Kanal" $$?"Nicki Yaz�n�"
n120=. &NickServ
n121=..Info(Nick kay�t Bilgisi):msg nickserv info $$?"Nick"
n122=..Status(�dentify Kontrol):msg nickserv status $$?"Nick"
n123=..Register(Nick Kaydetme):msg nickserv register $$?"�ifre"
n124=..Drop(Nick kayd� silme):msg nickserv drop
n125=..Identify(Nick �ifresine girme):.msg nickserv identify $$?*"�ifre"
n126=..Recover(Kar�� tarafa �ifre sordurup d���rme):msg nickserv recover $$?"Nick" $$?*"�ifre" 
n127=..Release(Nickservdeki Nicki d���rme):msg nickserv release  $$?"Nick"
n128=..Listchans(Nickine kay�tL� kanaL Listesi):msg nickserv listchans
n129=..Access ( Nickinize Eri�im Ekleme )
n130=...Add:/.msg NickServ ACCESS ADD $$?="Person to Add:"
n131=...Del:/.msg NickServ ACCESS DEL $$?="Person to Delete:"
n132=...List:/.msg NickServ ACCESS LIST 
n133=..Set (Ayarlar)
n134=...Password(�ifre de�i�tirme):msg nickserv set password $$?"�ifre"
n135=...Language(Dil):msg nickserv set language $$?"1/2"
n136=...URL(Web adresi):msg nickserv set url http:\\ $+ $$?"http:\\ ..."
n137=...E-Mail(Mail adresi):msg nickserv set email $$?"e-mail"
n138=..Kill (Dakika korumas�)
n139=....A�:msg nickserv set kill on
n140=....Kapa:msg nickserv set kill off
n141=..Secure(G�venlik)
n142=....A�:msg nickserv set secure on
n143=....Kapa:msg nickserv set secure off..Private (Listten Gizleme)
n144=....A�:msg nickserv set private on
n145=....Kapa:msg nickserv set private off
n146=...Hide(Gizlilik):msg nickserv set hide $$?"email/usermask/quit" $$?"On/Off"
n147=..Ghost(As�l� kalan Nicki d���rme):.msg nickserv ghost $$?"Nick" $$?*"�ifre"
n148=..Link(Ba�ka nicke Ba�lama):.msg nickserv link $$?"Nick" $$?*"�ifre"
n149=..Unlink(Link ba�lant�s�n� koparma):msg nickserv unlink $?"Nick" 
n150=..Auth Kodu ( Nickinizin size ait oldu�una dair kodu G�nderilmesi ) :msg nickserv auth send
n151=..Aut Kodu Onaylama ( Nickinizin kod ile tan�t�lmas�) :msg nickserv auth $$?="Koda Giriniz"
n152=..Ajoin (Otomatik kanal giri�i) 
n153=...Ekle :msg nickserv ajoin add $$?="# ��areti Koyarak Kanal�n Ad�n� Yaz�n�z"
n154=...Sil :msg nickserv ajoin del $$?="#��areti Koyarak Kanal�n Ad�n� Yaz�n�z"
n155=...Listele :msg nickserv ajoin List
n156=.&MemoServ
n157=..Listele
n158=...Hepsini:msg memoserv list
n159=...Yenileri:msg memoserv list new
n160=..G�nder:msg memoserv send $$?="Nick" 12[10 $+ $$?"Mesaj" $+ 12]
n161=..Oku:msg memoserv read  $$?="Mesaj No"
n162=..Sonuncuyu Oku:msg memoserv read last
n163=..Sil
n164=...Numaray�:msg memoserv del $$?="Silinecek Numara"
n165=...Hepsini:msg memoserv del all
n166=..Limit:ms set limit $$?"Limiti Yaz ( En fazla 20 Olabilir)?"
n167=..Memoyu kapatma:ms set Limit 0
n168=..Memoyu A�ma:ms set limit 20
n169=..Ignore 
n170=...Ignore Et:ms Ignore add $$?="Nick" 
n171=...Ignore Sil:ms Ignore del $$?="Nick"
n172=...Ignore Listesi:ms Ignore List 
n173=..Memoya ��aret Koyma
n174=...��aret Koy :ms mark $$?="Memonun Numaras�" 
n175=...��aret Kald�r:ms unmark  $$?="Memonun Numaras�"
n176=..Memo Uyar�s�n� A�ma :ms set Notify on 
n177=..Memolar�n Mail ile Yollanmas� 
n178=...Yollans�n:ms set mailmemo on
n179=...Yollanmas�n:ms set mailmemo off
n180=.-
n181=.&OperServ
n182=..Oper
n183=...On:/.oper %iam $$?="Oper Sifreniz?"
n184=...Off:/mode nick -O
n185=..-
n186=..Admin Ekleme:/msg operserv admin add $$?"Eklemek istedi�iniz nicki yaz�n�z(Bu Komutu Root Adminler kullanabilir)" 
n187=..Oper Ekleme :/msg operserver oper add $$?"Eklemek istedi�iniz nicki yaz�n�z(Bu komutu Services adminler kullanabilir)"
n188=..-
n189=..Op Alma
n190=...Operservden-Op :/.msg OperServ mode # +o $$?"Nicke Giriniz"
n191=...Operdo-Op :/.Operdo mode # +o $$?"Nicke Giriniz"
n192=...Master-Op :/msg Master op # $$?"Kanal Ad�na Giriniz"
n193=..-
n194=..Kill:/kill $$?="Nick?" $$?="Nedenini Yaz�n�z?"
n195=..Akill
n196=...Ekle:/.msg operserv akill add +0 $$?="Mask? (nick!identd@IPorHostname)" $$?="Sebep?"
n197=...Sil:/.msg operserv akill del $$?="Mask? (nick!identd@IPorHostname)"
n198=...Liste:/.msg operserv akill list 
n199=..Klined
n200=...Ekle:/kline $$?="Mask?" $$?="Sebep?"
n201=...Sil:/unkline $$?="Mask?"
n202=...G�ster:/stats k 
n203=..Glined
n204=...Ekle:/gline $$?="�p Adresi?" $$?="Sebep?"
n205=...Sil :/ungline $$?="�p Adresi?" 
n206=..Servere mesaj Atma(Global) :/Msg OperServ Global $$?"Yollamak istedi�iniz Mesaj� yaz�n�z"
n207=..-
n208=..Getpass
n209=...Nick:/.msg nickserv getpass $$?="Nick?"
n210=...Kanal:/.msg chanserv getpass $$?="Kanal?"
n211=..Samode
n212=...Op:/samode $$?="Kanal?" +o $$?="Nick"
n213=...DeOp:/samode $$?="Kanal?" -o $$?="Nick"
n214=...Voice:/samode $$?="Kanal?" +v $$?="Nick"
n215=...DeVoice:/samode $$?="Kanal?" -v $$?="Nick"
n216=...Ban:/samode $$?="Kanal?" +b $$?="Mask"
n217=...UnBan:/samode $$?="Kanal?" -b $$?="Mask"
n218=..Yasaklamalar(Forbid)
n219=...Kanal Yasaklama(Forbid) :/msg chanserv forbid # $$?"Kanal �smine Giriniz"
n220=...Nick Yasaklama(Forbid) :/Msg Nickserv forbid $$?"Nicki Yaz�n�z"
n221=..-
n222=..�nemli Admin/Oper Olaylar�
n223=...Services Operatorleri listele :/msg OperServ OPER LIST
n224=...Services Adminleri listele :/msg OperServ ADMIN LIST 
n225=...T�m Operlere Memo Atma :/MSG memoserv opersend $$?"Yollamak Istedi�iniz Mesaj� yaz�n�z"
n226=...T�m Adminlere Memo Atma :/MSG memoserv csopsend $$?"Yollamak Istedi�iniz Mesaj� yaz�n�z"
n227=...Nickinizi Gizleme :/Msg OperServ Raw SvsMode $$?"Nickinizi yaz�n�z" +i
n228=...Admin ve Operlere Mesaj :/globops $$?"G�ndermek istedi�iniz mesaj� yaz�n�z"
n229=...Bir Userin Nickini De�i�tirme : /msg operserv raw svsnick : $$?"De�i�tirece�iniz Ki�inin Nicki" $$?"Onun Yeni Nickine Giriniz" 1:0
n230=...Userleri zorla kanala sokma :/Msg OperServ Raw SvsJoin $$?"Kanala Sokmak Istedi�ini Nicki Yaz�n�z" # $$?"Useri Sokmak Istedi�iniz Kanal� yaz�n�z"
n231=...�llegal Nickleri Kullanma : /msg operserv raw svsnick : $$?"Nickinizi Yaz�n�z" $$?"Girmek �stedi�iniz Yeni Nicki Yaz�n�z" 1:0
n232=...Servicesleri Kanala Sokma : /msg operserv raw : $$?"Kanala Sokmak Istedi�iniz Services ismini Yaz�n�z(Chanserv-Nickserv-Memoserv) join # $$?"Sokmak Istedi�iniz Kanal�n Ad�n� Yaz�n�z"
n233=...Servicesleri Konu�turma :/MSG OperServ RAW :infoServ PRiVMSG # $$?"Konu�turmak istedi�iniz kanal�n ad�n�z yaz�n�z" $$?"Yollamak istedi�iniz mesaj� yaz�n�z"
n234=...Serveri Restart Etme :/restart $$?"�ifreye Giriniz" 
n235=...Serveri Kapatma :/die $$?"�ifreye Giriniz"
n236=...Serviceslerin Nicklerini De�i�tirme :/MSG OperServ RAW :NickServ $$?"Nicki Yaz�n�z" NickServerv 
n237=...Servicesleri Kanala Sokma :/MSG OperServ RAW :ChanServ join # $$?"Sokmak istedi�iniz kanal�n ad�n� yaz�n�z" 
n238=...Servicesleri Kanaldan ��karma:/MSG OperServ RAW :ChanServ part # $$?"��karmak istedi�iniz kanal�n ad�n� yaz�n�z"
n239=...Userlerin Modelerini Degi�tirme:/MSG OperServ RAW SVSMODE $$?"Mode`sini de�i�tirece�iniz nicki yaz�n�z" +c-rAa
n240=...Serviceslerin Modelerini Degi�tirme:/MSG OperServ RAW :StatServ MODE StatServ -i+oA
n241=...SetHostu Degistirme :/sethost $$?"YeniHostunuza Giriniz"..Servicesleri Serverdan cikarmak icin :/squit services.domain.com/net 
n242=...Kanal dondurmak i�in: /msg chanserv freeze # $$?"Donduralacak Kanal�n ad�n� giriniz" 
n243=...Servislerden ��lem Yapmak
n244=....Op Alma :/Msg Operserv raw :chanserv mode # +o $$?"Nicki Yaz�n�z"
n245=....Mode Koyma:/Msg Operserv raw :chanserv mode # mode +ntc-ipskl
n246=....Topic Atma:/Msg Operserv raw :chanserv topic #kanal topic $$?"Topic Mesaj�n� Yaz�n�z"
n247=....Kick Atma:/Msg Operserv raw :chanserv kick #  $$1 $$?="Neden Yaz�n�z"
n248=....NickBan Atma:/Msg Operserv raw :chanserv mode # +b $$1 $$?="Neden yaz�n�z
n249=..-
n250=...Flags:/mode $me +AabchgoO
n251=...-
n252=...Help:/msg operserv help
n253=-
n254=Serverlar
n255=.Dizgi:/server Irc.Dizgi.ORG
n259=.TurkiyeChat:/server irc.dizgi.org
n260=.Sohbet:/server irc.Dizgi.org
n265=Internet Adresleri
n267=.mIRCTR:/run http://www.mirctr.org
n268=.�okSeviyorum :/run http://www.cokseviyorum.com
n269=.Arama Siteleri 
n270=..Google:/run http://www.Google.com
n271=..Net Bul:/run http://www.netbul.com 
n272=..Yahoo:/run http://www.yahoo.com 
n273=..Arama:/run http://www.arama.com 
n274=..Altavista:/run http://www.altavista.com 
n275=..Astalavista:/run http://astalavista.box.sk..Superonline:/run http://www.superonline.com
n276=.Gazeteler
n277=..H�rriyet:/run http://www.hurriyet.com.tr 
n278=..Star:/run http://www.stargazete.com 
n279=..Milliyet:/run http://www.milliyet.com.tr 
n280=..Sabah:/run http://www.sabah.com.tr 
n281=..Radikal:/run http://www.radikal.com.tr 
n282=..Aksam:/run http://www.aksam.com.tr 
n283=..Fanatik:/run http://www.fanatik.com.tr 
n284=.E-kart
n285=..Mynet:/run http://ekart.mynet.com 
n286=..Superonline:/run http://ekart.superonline.com 
n287=..Vezzy:/run http://ekart.veezy.com 
n288=.Dergiler 
n289=..PC Net:/run http://www.pcnet.com.tr 
n290=..PC Magazine:/run http://www.pcmagazine.com.tr 
n291=..PC World:/run http://www.pcworld.com.tr 
n292=..Chip:/run http://www.chip.com.tr .Mail
n293=.Mail
n294=..Hotmail:/run http://www.hotmail.com
n295=..Yahoo:/run http://www.yahoo.com
n296=..Mynet:/run http://www.Mynet.com.tr
n297=..Mailcom :/run http://www.mail.com
n298=.Cep mesaJ
n299=..Turkcell:/run http://www.Turkcell.com.tr
n300=..Telsim:/run http://www.Telsim.com.tr
n301=..sms.gt.com.ua ( Heryer ):/run http://sms.gt.com.ua
n302=.Yukle
n303=..Download(T�rk�e):/run http://www.Download.gen.tr
n304=..Download:/run http://www.Download.com
n305=..Ejder://run http://www.ejder.com
n306=..Superonline:/run http://www.Superonline.com
n307=..Kurtadam :/run http:www.Kurtadam.com.Genel..Sevgisitesi:/run http://www.Sevgilim.com..Superonline:/run http://www.Superonline.com
n308=..Mynet :/run http://www.Mynet.com.tr..Kurtadam :/run http://www.Kurtadam.com..Showtv :/run http://www.Showtv.net
n309=..Yukle :/run http://www.yukle.com
n310=.Oyun ve E�lence
n311=..Kahkaha:/run http://www.kahkaha.com 
n312=..Hoppala:/run http://www.hoppala.com 
n313=..Curcuna:/run http://curcuna.ourfamily.com 
n314=..Okey :/run http:www.Okey.gen.tr
n315=..Superonline:/run http://www.Superonline.com
n316=..Mynet :/run http://www.Mynet.com.tr
n317=..Showtv :/run http://www.Showtv.net
n318=..Esalak:/run http://www.Esalak.com
n319=..LagaLuga :/run http://www.LagaLuga.com
n320=.Genel
n321=..Sevgisitesi:/run http://www.Sevgilim.com
n322=..Superonline:/run http://www.Superonline.com
n323=..Mynet :/run http://www.Mynet.com.tr
n324=..Kurtadam :/run http://www.Kurtadam.com
n325=..Showtv :/run http://www.Showtv.net
n326=..Ilksayfa :/run http://www.ilksayfa.net
n327=.Radyolar 
n328=..Power FM:/run http://www.powerfm.com.tr ..Metro FM:/run http://www.metrofm.com.tr 
n329=..Super FM:/run http://www.superfm.com.tr 
n330=..Number One FM:/run http://www.numberone.com.tr 
n331=..Capital Radio:/run http://www.capitalradio.com.tr
n332=.Chat
n333=..Turkcoders :/run http://www.Turkcoders.com
n335=..Portalturk :/run http://www.portalturk.net
n336=..Mircx:/run http://www.Mircx.com
n337=.Mp3 ve Muzik
n338=..MaxiMp3 (Yabanc�) :/run http://www.maxalbums.com
n339=..Mp3Yukle (T�rkk�e ve Yabanc�) :/run http://mp3yukle.com
n340=..Vitaminic (Yabanc�):/run http://www.vitaminic.com
n341=..Elendclub(Yabanc�):/run http://www.elendclub.cjb.net
n342=..Muzikalite(T�rk�e ve Yabanc�):/run http://www.Muzikalite.net
n343=..Musicmas(Yabanc�):/run http://www.musicmass.com
n344=-
n345=IRC den ��k :/quit 4mIRCTR
n346=Program� Kapat:/Exit

[mpopup]
n0=Server
n1=.Kullan�c� Say�s�:/lusers
n2=.G�n�n Mesaj�:/motd
n3=.Zaman:/time
n4=.Operler:/ircops
n5=-
n6=.Away
n7=..Away ol...:/away $$?="Away Mesaj�na Giriniz:"
n8=..Awaydan ��k:/away
n9=-
n10=.Kanallar� Listele:/list
n11=Serverlar
n12=.Dizgi:/server irc.Dizgi.org
n13=.mIRCindir:/server irc.Dizgi.ORG
n14=.Sohbet:/server irc.Dizgi.org
n22=-
n23=Servisler
n24=.&ChanServ
n25=..Info(Kanal kay�t bilgisi):msg chanserv info #$$?"Kanal"
n26=..Register(Kanal �ifreleme):msg chanserv register #$$?"Kanal" $$?"�ifre" $$?"Tan�m"
n27=..Drop(Kanal kayd� silme):msg chanserv drop #$$?"Kanal"
n28=..Identify(Kanal �ifresine girme):.msg chanserv identify #$$?"Kanal" $$?."�ifre"
n29=..Access ( Kanal yetkilileri Listesi )
n30=...Ekle:msg chanserv access #$$?"Kanal" add $$?"Nick" $$?"Level"
n31=...Sil:msg chanserv access #$$?"Kanal" del $$?"Nick" 
n32=...Listele:msg chanserv access #$$?"Kanal" list  
n33=..Akick (Otomat�k Kick-ban)
n34=...Ekle:msg chanserv akick #$$?"Kanal" add $$?"Nick" 
n35=...Sil:msg chanserv akick #$$?"Kanal" del $$?"Nick" 
n36=...Listele:msg chanserv akick #$$?"Kanal" list $?"Nick (�art de�il)" 
n37=..Set (Kanal Ayarlar�)
n38=...Founder(Kanal Sahibi de�i�tirme):msg chanserv set #$$?"Kanal" founder $$?"Nick" $$?"Kanal�n �ifresine Giriniz"
n39=...Description(Kanal�n Tan�t�m�):msg chanserv set #$$?"Kanal" desc $$?"Tan�m"
n40=...Password(Kanal�n �ifresini de�i�tirme):msg chanserv set #$$?"Kanal" password $$?"Yeni �ifreye Giriniz" $$?"Eski �ifreye Giriniz" 
n41=...URL(Kanala Web adresi Belirleme):msg chanserv set #$$?"Kanal" URL http:\\ $+ $$?"http:\\ ..."
n42=...E-Mail(Kanala Email Adresi belirleme):msg chanserv set #$$?"Kanal" email $$?"e-mail"
n43=...Topic(Topici atma):msg chanserv set #$$?"Kanal" topic $$?"topic"
n44=...Leaveops(�lk Girenin op olmas�)
n45=....Ac: msg chanserv set #$$?"Kanal" LEAVEOPS on
n46=....Kapa :msg chanserv set #$$?"Kanal" LEAVEOPS off
n47=...KeepTopic(Topicin Haf�zada tutma)
n48=....Ac:msg chanserv set #$$?"Kanal" keeptopic on
n49=....Kapa:msg chanserv set #$$?"Kanal" keeptopic off
n50=...TopicLock(Topic Kilidi)
n51=....Ac:msg chanserv set #$$?"Kanal" topiclock on
n52=....Kapa:msg chanserv set #$$?"Kanal" topiclock off
n53=...Private(Listten Gizleme)
n54=....Ac:msg chanserv set #$$?"Kanal" private on
n55=....Kapa:msg chanserv set #$$?"Kanal" private off
n56=...Secureops (Sadece Accesslilerin Op olmas�)
n57=....Ac:msg chanserv set #$$?"Kanal" secureops on
n58=....Kapa:msg chanserv set #$$?"Kanal" secureops off
n59=...Restricted ( Sadece Accessliler Girsin)
n60=....Ac:msg chanserv set #$$?"Kanal" restricted on
n61=....Kapa:msg chanserv set #$$?"Kanal" restricted off
n62=...Secure (G�venlik)
n63=....Ac:msg chanserv set #$$?"Kanal" secure on
n64=....Kapa:msg chanserv set #$$?"Kanal" secure off
n65=...Enforce (Autoop/Autovoice Deop ve Voice Korumalar�)
n66=....A� :msg chanserv set #  enforce on
n67=....Kapat :msg chanserv set # enforce off
n68=...Opnotice (Op/deop-Voice/Devoice Noticesinin A��lmas�)
n69=....A� :msg chanserv set # opnotice on
n70=....Kapat :msg chanserv set # opnotice off
n71=...Invites (Kanalda invite yerine +I kullanmasini saglar)
n72=....A� :msg chanserv set # invites on
n73=....Kapat :msg chanserv set # invites off
n74=...Exception (Bir kanalin unban yerine +e kullanmasini saglar)
n75=....A� :msg chanserv set # exception on
n76=....Kapat :msg chanserv set # exception off
n77=...Hide ( Belirtilen �zelli�i kanal Infosundan gizler)
n78=....A� :msg chanserv set # hide $$?"Gizlenecek �zelli�e Giriniz(EMAIL|TOPIC|OPTIONS|DESC|MLOCK" on
n79=....Kapat :msg chanserv set # hide $$?"Gizlilik Modundan Kald�r�lacak �zelli�e Giriniz (EMAIL|TOPIC|OPTIONS|DESC|MLOCK" off  
n80=...Mlock(Kanal Modlar�):msg chanserv set #$$?"Kanal" mlock $$?" +/-  ntipslk" $?"Parametre (+l ve +k i�in gerekli)"
n81=...-
n82=...EntryMsg(Kanal chanserv mesaJ�):msg chanserv set #$$?"Kanal" entrymsg $$?"Odaya Giri� Mesaj�"  
n83=..Unset :msg chanserv unset #$$?"Kanal" $$?"Kald�rmak Isted�g�n�z Set Ayar�n� Yaz�n�z (Successor, Url, Email, Entrymsg)"
n84=..Invite(Kanala davet):msg chanserv invite #$$?"Kanal"
n85=..Op/Deop
n86=...Op:msg chanserv op #$$?"Kanal" $$?"Nick"
n87=...DeOp:msg chanserv deop #$$?"Kanal" $$?"Nick"..Unban(Ban� a�):msg chanserv unban #$$?"Kanal" 
n88=..Clear ( Temizle )
n89=...B�t�n Modlar Kald�r�ls�n :/.msg chanserv clear #  modes | /echo -a 4,1 # Kanal�nda B�t�n Modlar kaLd�r�Ld�.
n90=...B�t�n Banlar Kald�r�ls�n:/.msg chanserv clear #  bans  | /echo -a 4,1 # Kanal�nda B�t�n Banlar kaLd�r�Ld�.
n91=...B�t�n Oplar Al�ns�n :/.msg chanserv clear #  ops  | /echo -a 4,1 # Kanal�nda B�t�n Oplar deop ediLdi.
n92=...B�t�n Voicelar Al�ns�n :/.msg chanserv clear #  voices  | /echo -a 4,1 # Kanal�nda B�t�n voiceLer aL�nd�....B�t�n Userlar At�ls�n :/.msg chanserv clear #  users   | /echo -a 4,1 # Kanal�nda B�t�n Userler at�Ld�.
n93=..Levels (Eri�im D�zeylerini Belirleme)
n94=...Set (Yetki Ayarlar�)
n95=....AUTOOP:msg chanserv levels #$$?"Kanal?" set autoop $$?"Level?"
n96=....AUTOVOICE:msg chanserv levels #$$?"Kanal?" set AUTOVOICE $$?"Level?"
n97=....AUTODEOP:msg chanserv  levels #$$?"Kanal?" set AUTODEOP $$?"Level?"
n98=....NOJOIN:msg chanserv levels #$$?"Kanal?" set NOJOIN $$?"Level?"
n99=....INVITE:msg chanserv  levels #$$?"Kanal?" set INVITE $$?"Level?"
n100=....AKICK:msg chanserv  levels #$$?"Kanal?" set AKICK $$?"Level?"
n101=....SET:msg chanserv  levels #$$?"Kanal?" set SET $$?"Level?"
n102=....CLEAR:msg chanserv levels #$$?"Kanal?" set CLEAR $$?"Level?"
n103=....UNBAN:msg chanserv  levels #$$?"Kanal?" set UNBAN $$?"Level?"
n104=....OPDEOP:msg chanserv  levels #$$?"Kanal?" set OPDEOP $$?"Level?"
n105=....ACC-LIST:msg chanserv levels #$$?"Kanal?" set ACC-LIST $$?"Level?"
n106=....ACC-CHANGE:msg  chanserv levels #$$?"Kanal?" set ACC-CHANGE $$?"Level?"
n107=....MEMO:msg chanserv  levels #$$?"Kanal?" set MEMO $$?"Level?"
n108=...Disable(Yasaklamalar)
n109=....AUTOOP:msg chanserv levels #$$?"Kanal?" dis autoop
n110=....AUTOVOICE:msg chanserv levels #$$?"Kanal?" dis AUTOVOICE
n111=....AUTODEOP:msg chanserv levels #$$?"Kanal?" dis AUTODEOP
n112=....NOJOIN:msg chanserv   levels #$$?"Kanal?" dis NOJOIN
n113=....INVITE:msg chanserv  levels #$$?"Kanal?" dis INVITE
n114=....AKICK:msg  chanserv levels #$$?"Kanal?" dis AKICK
n115=....SET:msg  chanserv levels #$$?"Kanal?" dis SET
n116=....CLEAR:msg chanserv  levels #$$?"Kanal?" dis CLEAR
n117=....UNBAN:msg chanserv  levels #$$?"Kanal?" dis UNBAN
n118=....OPDEOP:msg  chanserv levels #$$?"Kanal?" dis OPDEOP
n119=....ACC-LIST:msg chanserv  levels #$$?"Kanal?" dis ACC-LIST
n120=....ACC-CHANGE:msg chanserv  levels #$$?"Kanal?" dis ACC-CHANGE
n121=....MEMO:msg chanserv   levels #$$?"Kanal?" dis MEMO
n122=...List:msg  chanserv levels #$$?"Kanal?" list
n123=...Reset(Kanal ayarlar�n� Silme):msg chanserv  levels #$$?"Kanal?" reset
n124=..Protect ( Nicke Kanalda Koruma Koyma ) 
n125=...Ekle :msg chanserv protect #$$?"Kanal" $$?"Nicki Yaz�n�z"
n126=...Sil :msg chanserv deprotect #$$"Kanal" $$?"Nicki Yaz�n�"
n127=. &NickServ
n128=..Info(Nick kay�t Bilgisi):msg nickserv info $$?"Nick"
n129=..Status(�dentify Kontrol):msg nickserv status $$?"Nick"
n130=..Register(Nick Kaydetme):msg nickserv register $$?"�ifre"
n131=..Drop(Nick kayd� silme):msg nickserv drop
n132=..Identify(Nick �ifresine girme):.msg nickserv identify $$?*"�ifre"
n133=..Recover(Kar�� tarafa �ifre sordurup d���rme):msg nickserv recover $$?"Nick" $$?*"�ifre" 
n134=..Release(Nickservdeki Nicki d���rme):msg nickserv release  $$?"Nick"
n135=..Listchans(Nickine kay�tL� kanaL Listesi):msg nickserv listchans
n136=..Access ( Nickinize Eri�im Ekleme )
n137=...Add:/.msg NickServ ACCESS ADD $$?="Person to Add:"
n138=...Del:/.msg NickServ ACCESS DEL $$?="Person to Delete:"
n139=...List:/.msg NickServ ACCESS LIST 
n140=..Set (Ayarlar)
n141=...Password(�ifre de�i�tirme):msg nickserv set password $$?"�ifre"
n142=...Language(Dil):msg nickserv set language $$?"1/2"
n143=...URL(Web adresi):msg nickserv set url http:\\ $+ $$?"http:\\ ..."
n144=...E-Mail(Mail adresi):msg nickserv set email $$?"e-mail"
n145=..Kill (Dakika korumas�)
n146=....A�:msg nickserv set kill on
n147=....Kapa:msg nickserv set kill off
n148=..Secure(G�venlik)
n149=....A�:msg nickserv set secure on
n150=....Kapa:msg nickserv set secure off..Private (Listten Gizleme)
n151=....A�:msg nickserv set private on
n152=....Kapa:msg nickserv set private off
n153=...Hide(Gizlilik):msg nickserv set hide $$?"email/usermask/quit" $$?"On/Off"
n154=..Ghost(As�l� kalan Nicki d���rme):.msg nickserv ghost $$?"Nick" $$?*"�ifre"
n155=..Link(Ba�ka nicke Ba�lama):.msg nickserv link $$?"Nick" $$?*"�ifre"
n156=..Unlink(Link ba�lant�s�n� koparma):msg nickserv unlink $?"Nick" 
n157=..Auth Kodu ( Nickinizin size ait oldu�una dair kodu G�nderilmesi ) :msg nickserv auth send
n158=..Aut Kodu Onaylama ( Nickinizin kod ile tan�t�lmas�) :msg nickserv auth $$?="Koda Giriniz"
n159=..Ajoin (Otomatik kanal giri�i) 
n160=...Ekle :msg nickserv ajoin add $$?="# ��areti Koyarak Kanal�n Ad�n� Yaz�n�z"
n161=...Sil :msg nickserv ajoin del $$?="#��areti Koyarak Kanal�n Ad�n� Yaz�n�z"
n162=...Listele :msg nickserv ajoin List
n163=.&MemoServ
n164=..Listele
n165=...Hepsini:msg memoserv list
n166=...Yenileri:msg memoserv list new
n167=..G�nder:msg memoserv send $$?="Nick" 12[10 $+ $$?"Mesaj" $+ 12]
n168=..Oku:msg memoserv read  $$?="Mesaj No"
n169=..Sonuncuyu Oku:msg memoserv read last
n170=..Sil
n171=...Numaray�:msg memoserv del $$?="Silinecek Numara"
n172=...Hepsini:msg memoserv del all
n173=..Limit:ms set limit $$?"Limiti Yaz ( En fazla 20 Olabilir)?"
n174=..Memoyu kapatma:ms set Limit 0
n175=..Memoyu A�ma:ms set limit 20
n176=..Ignore 
n177=...Ignore Et:ms Ignore add $$?="Nick" 
n178=...Ignore Sil:ms Ignore del $$?="Nick"
n179=...Ignore Listesi:ms Ignore List 
n180=..Memoya ��aret Koyma
n181=...��aret Koy :ms mark $$?="Memonun Numaras�" 
n182=...��aret Kald�r:ms unmark  $$?="Memonun Numaras�"
n183=..Memo Uyar�s�n� A�ma :ms set Notify on 
n184=..Memolar�n Mail ile Yollanmas� 
n185=...Yollans�n:ms set mailmemo on
n186=...Yollanmas�n:ms set mailmemo off
n187=.-
n188=.&OperServ
n189=..Oper
n190=...On:/.oper %iam $$?="Oper Sifreniz?"
n191=...Off:/mode nick -O
n192=..-
n193=..Admin Ekleme:/msg operserv admin add $$?"Eklemek istedi�iniz nicki yaz�n�z(Bu Komutu Root Adminler kullanabilir)" 
n194=..Oper Ekleme :/msg operserver oper add $$?"Eklemek istedi�iniz nicki yaz�n�z(Bu komutu Services adminler kullanabilir)"
n195=..-
n196=..Op Alma
n197=...Operservden-Op :/.msg OperServ mode # +o $$?"Nicke Giriniz"
n198=...Operdo-Op :/.Operdo mode # +o $$?"Nicke Giriniz"
n199=...Master-Op :/msg Master op # $$?"Kanal Ad�na Giriniz"
n200=..-
n201=..Kill:/kill $$?="Nick?" $$?="Nedenini Yaz�n�z?"
n202=..Akill
n203=...Ekle:/.msg operserv akill add +0 $$?="Mask? (nick!identd@IPorHostname)" $$?="Sebep?"
n204=...Sil:/.msg operserv akill del $$?="Mask? (nick!identd@IPorHostname)"
n205=...Liste:/.msg operserv akill list 
n206=..Klined
n207=...Ekle:/kline $$?="Mask?" $$?="Sebep?"
n208=...Sil:/unkline $$?="Mask?"
n209=...G�ster:/stats k 
n210=..Glined
n211=...Ekle:/gline $$?="�p Adresi?" $$?="Sebep?"
n212=...Sil :/ungline $$?="�p Adresi?" 
n213=..Servere mesaj Atma(Global) :/Msg OperServ Global $$?"Yollamak istedi�iniz Mesaj� yaz�n�z"
n214=..-
n215=..Getpass
n216=...Nick:/.msg nickserv getpass $$?="Nick?"
n217=...Kanal:/.msg chanserv getpass $$?="Kanal?"
n218=..Samode
n219=...Op:/samode $$?="Kanal?" +o $$?="Nick"
n220=...DeOp:/samode $$?="Kanal?" -o $$?="Nick"
n221=...Voice:/samode $$?="Kanal?" +v $$?="Nick"
n222=...DeVoice:/samode $$?="Kanal?" -v $$?="Nick"
n223=...Ban:/samode $$?="Kanal?" +b $$?="Mask"
n224=...UnBan:/samode $$?="Kanal?" -b $$?="Mask"
n225=..Yasaklamalar(Forbid)
n226=...Kanal Yasaklama(Forbid) :/msg chanserv forbid # $$?"Kanal �smine Giriniz"
n227=...Nick Yasaklama(Forbid) :/Msg Nickserv forbid $$?"Nicki Yaz�n�z"
n228=..-
n229=..�nemli Admin/Oper Olaylar�
n230=...Services Operatorleri listele :/msg OperServ OPER LIST
n231=...Services Adminleri listele :/msg OperServ ADMIN LIST 
n232=...T�m Operlere Memo Atma :/MSG memoserv opersend $$?"Yollamak Istedi�iniz Mesaj� yaz�n�z"
n233=...T�m Adminlere Memo Atma :/MSG memoserv csopsend $$?"Yollamak Istedi�iniz Mesaj� yaz�n�z"
n234=...Nickinizi Gizleme :/Msg OperServ Raw SvsMode $$?"Nickinizi yaz�n�z" +i
n235=...Admin ve Operlere Mesaj :/globops $$?"G�ndermek istedi�iniz mesaj� yaz�n�z"
n236=...Bir Userin Nickini De�i�tirme : /msg operserv raw svsnick : $$?"De�i�tirece�iniz Ki�inin Nicki" $$?"Onun Yeni Nickine Giriniz" 1:0
n237=...Userleri zorla kanala sokma :/Msg OperServ Raw SvsJoin $$?"Kanala Sokmak Istedi�ini Nicki Yaz�n�z" # $$?"Useri Sokmak Istedi�iniz Kanal� yaz�n�z"
n238=...�llegal Nickleri Kullanma : /msg operserv raw svsnick : $$?"Nickinizi Yaz�n�z" $$?"Girmek �stedi�iniz Yeni Nicki Yaz�n�z" 1:0
n239=...Servicesleri Kanala Sokma : /msg operserv raw : $$?"Kanala Sokmak Istedi�iniz Services ismini Yaz�n�z(Chanserv-Nickserv-Memoserv) join # $$?"Sokmak Istedi�iniz Kanal�n Ad�n� Yaz�n�z"
n240=...Servicesleri Konu�turma :/MSG OperServ RAW :infoServ PRiVMSG # $$?"Konu�turmak istedi�iniz kanal�n ad�n�z yaz�n�z" $$?"Yollamak istedi�iniz mesaj� yaz�n�z"
n241=...Serveri Restart Etme :/restart $$?"�ifreye Giriniz" 
n242=...Serveri Kapatma :/die $$?"�ifreye Giriniz"
n243=...Serviceslerin Nicklerini De�i�tirme :/MSG OperServ RAW :NickServ $$?"Nicki Yaz�n�z" NickServerv 
n244=...Servicesleri Kanala Sokma :/MSG OperServ RAW :ChanServ join # $$?"Sokmak istedi�iniz kanal�n ad�n� yaz�n�z" 
n245=...Servicesleri Kanaldan ��karma:/MSG OperServ RAW :ChanServ part # $$?"��karmak istedi�iniz kanal�n ad�n� yaz�n�z"
n246=...Userlerin Modelerini Degi�tirme:/MSG OperServ RAW SVSMODE $$?"Mode`sini de�i�tirece�iniz nicki yaz�n�z" +c-rAa
n247=...Serviceslerin Modelerini Degi�tirme:/MSG OperServ RAW :StatServ MODE StatServ -i+oA
n248=...SetHostu Degistirme :/sethost $$?"YeniHostunuza Giriniz"..Servicesleri Serverdan cikarmak icin :/squit services.domain.com/net 
n249=...Kanal dondurmak i�in: /msg chanserv freeze # $$?"Donduralacak Kanal�n ad�n� giriniz" 
n250=...Servislerden ��lem Yapmak
n251=....Op Alma :/Msg Operserv raw :chanserv mode # +o $$?"Nicki Yaz�n�z"
n252=....Mode Koyma:/Msg Operserv raw :chanserv mode # mode +ntc-ipskl
n253=....Topic Atma:/Msg Operserv raw :chanserv topic #kanal topic $$?"Topic Mesaj�n� Yaz�n�z"
n254=....Kick Atma:/Msg Operserv raw :chanserv kick #  $$1 $$?="Neden Yaz�n�z"
n255=....NickBan Atma:/Msg Operserv raw :chanserv mode # +b $$1 $$?="Neden yaz�n�z
n256=..-
n257=...Flags:/mode $me +AabchgoO
n258=...-
n259=...Help:/msg operserv help
n260=-
n261=Not al:/run notepad.exe notes.tx
n262=IRC den ��k:/quit Leaving
n263=Program� Kapat:/exit
