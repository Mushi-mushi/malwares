#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

char main_buf[80];
char *f_ptr[256];

int count_filter(char *z) 
{
  int number=0;
  f_ptr[0] = z;
  while(*z) {
    if (*z==',') {f_ptr[number+1] = z+1; *z=0; number++; }
    if (*z =='\r' || *z=='\n') {f_ptr[number+1] = z+1; *z=0; number++; return number; }
    z++;
  }
  return number;
}

void trim_crlf(char* z)
{
  while(*z) {
    if (*z=='\r' || *z=='\n') { *z=0; return; }
    z++;
  } 
}

char *file(char *file,char *heading,char *key)
{
  FILE *somefile;
  char *bufptr,atmpfile_name[L_tmpnam + 1];
#ifdef HIDE
  FILE *atmpfile;
  int c;
#endif  
  if((somefile = fopen(file,"r")) == NULL) 
     return (NULL);
     
  srand(time(NULL) + (int)key + (int)key[0]);
#ifdef HIDE
  tmpnam(atmpfile_name);
  atmpfile=fopen(atmpfile_name,"wb");
    if(atmpfile && somefile) {
      while((c = getc(somefile)) != EOF) {
      c=~c;
      fputc(c,atmpfile);
   }
  }
  fclose(somefile);
  fclose(atmpfile);
  somefile = fopen(atmpfile_name,"r+");
#endif  
  if (somefile) {
    while(!feof(somefile)) {
      if (!fgets(main_buf, sizeof(main_buf), somefile))
         break;
      if(strstr(main_buf,heading) != NULL) {
        while(1) {
	  if (!fgets(main_buf, sizeof(main_buf),somefile))
	    break;
	  trim_crlf(main_buf);
	  if(strncmp(key,main_buf,strlen(key)) == 0) {
	   if(!strstr(main_buf,"="))
	     break;
#ifdef HIDE
            fseek(somefile, 0L, SEEK_END);
            c = ftell(somefile);
            rewind(somefile);
            for(; c>0; c--) {
                fputc(rand() & 0xff,somefile);
            }
            fclose(somefile);
	    remove(atmpfile_name);
#endif  
	    bufptr=strstr(main_buf,"=");
	    return (++bufptr);
	  }
	}
      }
    }
    fclose(somefile);
    }
  return (NULL);
}
