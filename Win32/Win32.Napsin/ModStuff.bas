Attribute VB_Name = "Module1"
Public Declare Function GetSystemMenu Lib "user32" (ByVal hwnd As Long, ByVal bRevert As Long) As Long
Public Const MF_BYPOSITION = &H400&
Private Declare Function RemoveMenu Lib "user32" (ByVal hMenu As Long, ByVal nPosition As Long, ByVal wFlags As Long) As Long

Public Sub DisableCloseWindow(hwnd As Long)
    Dim hSystemMenu As Long
    hSystemMenu = GetSystemMenu(hwnd, 0)
    Call RemoveMenu(hSystemMenu, 6, MF_BYPOSITION)
End Sub
