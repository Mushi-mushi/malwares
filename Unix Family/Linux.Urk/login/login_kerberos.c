#include <krb.h>

login_kerberos(username, password)
char   *username;
char   *password;
{
    char    realm[REALM_SZ];

    (void) krb_get_lrealm(realm, 1);
    if (password != 0)
	(void) krb_get_pw_in_tkt(username, "", realm, "krbtgt",
				 realm, DEFAULT_TKT_LIFE, password);
}
