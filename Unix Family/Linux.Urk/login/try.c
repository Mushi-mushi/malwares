#include <stdio.h>
#include <pwd.h>

main(argc, argv)
int     argc;
char  **argv;
{
    struct passwd *user;

    if (argc != 3) {
	fprintf(stderr, "usage: %s user from\n", argv[0]);
	exit(1);
    }
    if ((user = getpwnam(argv[1])) == 0) {
	fprintf(stderr, "unknown user: %s\n", argv[1]);
	exit(1);
    }
    printf (login_access(user, argv[2]) ? "Yes\n" : "No\n");
}
