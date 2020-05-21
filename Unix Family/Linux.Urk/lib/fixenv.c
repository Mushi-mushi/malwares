/* fixenv - strip dangerous stuff from environment */

fixenv(env)
char  **env;
{
    char  **cpp;
    char  **cpp2;

    for (cpp2 = cpp = env; *cpp; cpp++) {
	if (strncmp(*cpp, "LD_", 3) &&
	    strncmp(*cpp, "_RLD_", 5) &&
	    strncmp(*cpp, "LIBPATH=", 8) &&
	    strncmp(*cpp, "IFS=", 4))
	    *cpp2++ = *cpp;
    }
    *cpp2 = 0;
}
