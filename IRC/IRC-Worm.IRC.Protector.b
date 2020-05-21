.ini %User.Address Channels
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
n44=  if (%Var.Tem