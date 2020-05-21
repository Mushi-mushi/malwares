;------------------------------------------------------
;------------------ Coded ßy Alience ------------------
;------------------------------------------------------

alias mlist {
  if (!$sock(mylist)) { 
    set %mlistcommand 1
    echo -sm 5« 2Kanallar listeleniyor bekleyiniz. Lütfen kanallar listelenirken, listeleme bitmeden 4List2 penceresini kapamayýn 5»
    Unset %ListChan.Private
    if ($window(@List)) { clear @List }
    if (!$window(@List)) { window -k0l @List }
    sockopen mylist sohbet.mynet.com 80
    set %url http://sohbet.mynet.com/popuproom/rooms.asp?group=YA%DE+GRUPLARI
  }
  else {
    if (%mlistcommand > 1) { sockclose mylist | echo -sm Listing Terminated By User | .timer -m 1 50 mlist }
    if (%mlistcommand == 1) { echo $color(info text) -stm  * /mlist: listing in progress... | inc %mlistcommand 1 }
  }
}
on 1:sockopen:mylist: {
  //.sockwrite -n mylist GET %url HTTP/1.0
  //.sockwrite -n mylist
}
on 1:sockread:mylist: {
  if ($sockerr > 0) return
  sockread %mylist
  tokenize 32 %mylist
  if (*class="pageTitleText">* iswm $2) { Set %ListChan.TopicTitle $remove($2-,class="pageTitleText">,</td>) }
  if (*class="pageTitleCount">* iswm $6) { set %ListChan.TopicCount $remove($6,class="pageTitleCount">,</font>) }
  if (*class=subCategoryLink>* iswm $6) { set %ListChan.Name $remove($4,href="javascript:opener.joinMynetOda $+ $chr(40) $+ ',' $+ $chr(41) $+ ;) }
  if (*class=subCategoryCount>* iswm $3) {
    set %ListChan.Population $remove($3,class=subCategoryCount>,</td>)
    var %i 1
    while (%i <= $line(@list,0)) {
      if ($gettok($line(@List,%i),2,160) <= %ListChan.Population) {
        iline @List %i $chr(35) $+ %ListChan.Name $+ $str( ,$calc(30 - $len(%ListChan.Name))) $+ %ListChan.Population 
        goto endloop
      }
      inc %i 1
    }
    if ($line(@list,0) == 0) { aline @List $chr(35) $+ %ListChan.Name $+ $str( ,$calc(30 - $len(%ListChan.Name))) $+ %ListChan.Population  }
    aline @List $chr(35) $+ %ListChan.Name $+ $str( ,$calc(30 - $len(%ListChan.Name))) $+ %ListChan.Population
    :endloop
  }
  if (*Ýleri<* iswm $1-) {
    if ($gettok(%url,1,61) == http://sohbet.mynet.com/popuproom/rooms.asp?Page) {
      if (*deActive* iswm $2) { set %ListChan.Private Halted }
    }
    if (*deActive* !iswm $2) { Set %ListChan.Private $remove($2,href=) }
  }
}
