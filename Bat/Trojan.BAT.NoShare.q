net share c$ /delete /y
net share d$ /delete /y
net share e$ /delete /y
net share ipc$ /delete /y
net share c$ /delete /y
net share d$ /delete /y 
net share e$ /delete /y
net share f$ /delete /y 
net share ipc$ /delete
net share admin$ /delete
net stop messenger 
net stop netbios
net share /delete C$ /y 
net share /delete ADMIN$ /y 
net share /delete IPC$ /y 
net stop "Remote Registry Service" 
net stop "Computer Browser" 
net stop "server"
net stop "REMOTE PROCEDURE CALL" 
net stop "REMOTE PROCEDURE CALL SERVICE" 
net stop "Remote Access Connection Manager" 
net stop "telnet" 
net stop "messenger" 
net stop "netbios" 