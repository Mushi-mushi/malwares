/*
 * an example to interface our syscall
 */

#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdlib.h>

#define OFFSET 210

int
main(int argc, char **argv)
{
	int error;

	if(argc != 3) {
		printf("Usage:\n%s pid uid\n", argv[0]);
		exit(1);
	}
	
	error = syscall(OFFSET, atoi(argv[1]), atoi(argv[2]));

	if(error)
		perror("syscall()");

	return 0;
}
