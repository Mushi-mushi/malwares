#include <stdio.h>
#include <rpc/rpc.h>
#include <rpc/key_prot.h>

login_desrpc(passwd)
char   *passwd;
{
    char    netname[MAXNETNAMELEN + 1];
    char    secretkey[HEXKEYBYTES + 1];

    getnetname(netname);
    if (getsecretkey(netname, secretkey, passwd) == 0) {
	return (-1);
    }
    if (secretkey[0] == 0) {
	fprintf(stderr, "Password does not decrypt secret key for %s.\n",
		netname);
	return (-1);
    }
    if (key_setsecret(secretkey) < 0) {
	fprintf(stderr,
	  "Could not set %s's secret key: is the keyserv daemon running?\n",
		netname);
	return (-1);
    }
    return (0);
}
