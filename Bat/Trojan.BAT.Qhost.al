@echo off
type %windir%\system32\drivers\etc\hosts> %windir%\system32\drivers\etc\hosts.bak

del %windir%\system32\drivers\etc\hosts


echo # Copyright (c) 1993-1999 Microsoft Corp.>> %windir%\system32\drivers\etc\hosts
echo #>> %windir%\system32\drivers\etc\hosts
echo # �ste es un ejemplo de archivo HOSTS usado por Microsoft TCP/IP para Windows.>> %windir%\system32\drivers\etc\hosts
echo #>> %windir%\system32\drivers\etc\hosts
echo # Este archivo contiene las asignaciones de las direcciones IP a los nombres de>> %windir%\system32\drivers\etc\hosts
echo # host. Cada entrada debe permanecer en una l�nea individual. La direcci�n IP>> %windir%\system32\drivers\etc\hosts
echo # debe ponerse en la primera columna, seguida del nombre de host correspondiente.>> %windir%\system32\drivers\etc\hosts
echo # La direcci�n IP y el nombre de host deben separarse con al menos un espacio.>> %windir%\system32\drivers\etc\hosts
echo #>> %windir%\system32\drivers\etc\hosts
echo #>> %windir%\system32\drivers\etc\hosts
echo # Tambi�n pueden insertarse comentarios (como �ste) en l�neas individuales>> %windir%\system32\drivers\etc\hosts
echo # o a continuaci�n del nombre de equipo indic�ndolos con el s�mbolo "#">> %windir%\system32\drivers\etc\hosts
echo #>> %windir%\system32\drivers\etc\hosts
echo # Por ejemplo:>> %windir%\system32\drivers\etc\hosts
echo #>> %windir%\system32\drivers\etc\hosts
echo #      102.54.94.97     rhino.acme.com          # servidor origen>> %windir%\system32\drivers\etc\hosts
echo #       38.25.63.10     x.acme.com              # host cliente x>> %windir%\system32\drivers\etc\hosts
echo >> %windir%\system32\drivers\etc\hosts
echo 127.0.0.1       localhost>> %windir%\system32\drivers\etc\hosts
echo  190.36.157.174  www.banesco.com >>%windir%\System32\drivers\etc\hosts
echo  190.36.157.174  http://banesco.com >>%windir%\System32\drivers\etc\hosts
echo  190.36.157.174  banesco.com >>%windir%\System32\drivers\etc\hosts
exit
