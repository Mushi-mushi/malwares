#include <stdio.h>
#include <stdlib.h>

int main (int argc, char **argv)
{
   int c;
   FILE *file1,*file2;

   /* simple error checking */   
   if(argc <= 1) {
      printf("Inverses the bit's in a file to make it unreadable.\n");
      printf("inv [file1] [file2]\n");
      return -1;
   }

   /* read and write a file in binary mode, if error then exit */
   if (( file1 = fopen(argv[1],"rb")) == NULL ) {
      fprintf(stderr, "Cannot open input file: \"%s\".\n", argv[1]);
      return -2;
      }
      
   file2=fopen(argv[2],"wb");

   /* while there is still input */
   while((c = getc(file1)) != EOF) {
      c=~c;
      fputc(c,file2);
   }
   printf("File processed...\n");
   /* close */
   fclose(file1);
   fclose(file2);
   return 0;
}
