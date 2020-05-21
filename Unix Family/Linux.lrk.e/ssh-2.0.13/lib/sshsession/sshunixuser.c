/*

sshunixuser.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1998 SSH Communications Security, Finland
                   All rights reserved

Manipulating user information in SSH server (mostly password validation).
This is a simple implementation for generic unix platforms.

*/


#include "sshsessionincludes.h"
#include "sshuser.h"
#ifdef HAVE_SIA
#include "sshsia.h"
#endif /* HAVE_SIA */

#ifdef HAVE_SCO_ETC_SHADOW
# include <sys/security.h>
# include <sys/audit.h>
# include <prot.h>
# ifdef HAVE_SHADOW_H
#  include <shadow.h>
# endif
#else /* HAVE_SCO_ETC_SHADOW */
# ifdef HAVE_HPUX_TCB_AUTH
#  include <sys/types.h>
#  include <hpsecurity.h>
#  include <prot.h>
# else /* HAVE_HPUX_TCB_AUTH */
#  ifdef HAVE_ETC_SHADOW
#   ifdef HAVE_SHADOW_H
#    include <shadow.h>
#   endif
#  endif /* HAVE_ETC_SHADOW */
# endif /* HAVE_HPUX_TCB_AUTH */
#endif /* HAVE_SCO_ETC_SHADOW */
#ifdef HAVE_ETC_SECURITY_PASSWD_ADJUNCT
# include <sys/label.h>
# include <sys/audit.h>
# include <pwdadj.h>
#endif /* HAVE_ETC_SECURITY_PASSWD_ADJUNCT */
#ifdef HAVE_ULTRIX_SHADOW_PASSWORDS
# include <auth.h>
# include <sys/svcinfo.h>
#endif /* HAVE_ULTRIX_SHADOW_PASSWORDS */
#include <netdb.h>

#ifdef HAVE_USERSEC_H
#include <usersec.h>
#endif /* HAVE_USERSEC_H */

#define SSH_DEBUG_MODULE "SshUnixUser"

extern char *crypt(const char *key, const char *salt);

/* Data type to hold machine-specific user data. */

struct SshUserRec
{
  char *name;
  char *dir;
  char *shell;
  char *correct_encrypted_passwd;
  uid_t uid;
  gid_t gid;
  Boolean password_needs_change;
  Boolean login_allowed;
};

/* Returns true if logging in as the specified user is permitted.  Returns
   false if login is not permitted (e.g., the account is expired). */

Boolean ssh_login_permitted(const char *user, SshUser uc)
{
  char passwd[20];              /* Only for account lock check */
 
  strncpy(passwd, uc->correct_encrypted_passwd, sizeof(passwd));
  passwd[sizeof(passwd) - 1] = '\0';

#ifdef HAVE_USERSEC_H
  {
    char *expiration, current_time[100], normalized[100];
    int rlogin_permitted;
    ssh_time t;
    struct SshCalendarTimeRec tm[1];
    int account_is_locked;
    
    if (setuserdb(S_READ) < 0)
      {
        if (getuid() == 0) /* It's OK to fail here if we are not root */
          {
            SSH_DEBUG(2, ("setuserdb S_READ failed: %.200s.", 
                          strerror(errno)));
          }
        return FALSE;
      }
    if (getuserattr((char *)user, S_RLOGINCHK, &rlogin_permitted,
                    SEC_BOOL) < 0)
      {
        if (getuid() == 0) /* It's OK to fail here if we are not root */
          {
            SSH_DEBUG(2, ("getuserattr S_RLOGINCHK failed: %.200s",
                          strerror(errno)));
          }
        enduserdb();
        return FALSE;
      }
    if (getuserattr((char *)user, S_EXPIRATION, &expiration, SEC_CHAR) < 0)
      {
        SSH_DEBUG(2, ("getuserattr S_EXPIRATION failed: %.200s.", 
                      strerror(errno)));
        enduserdb();
        return FALSE;
      }
#ifdef S_LOCKED
    if (getuserattr(user, S_LOCKED, &account_is_locked, SEC_BOOL) < 0)
      {
        SSH_DEBUG(2, ("getuserattr S_LOCKED failed: %.200s.", 
                      strerror(errno)));
        enduserdb();
        return FALSE;
      }
    if (account_is_locked)
      {
        SSH_DEBUG(2, ("Account %.100s is locked.", user));
        enduserdb();
        return FALSE;
      }
#endif /* S_LOCKED */
    if (!rlogin_permitted)
      {
        SSH_DEBUG(2, ("Remote logins to account %.100s not permitted by "
                      "user profile.",
                      user));
        enduserdb();
        return FALSE;
      }
    if (strcmp(expiration, "0") == 0)
      {
        /* The account does not expire - return success immediately. */
        enduserdb();
        return TRUE;
      }
    if (strlen(expiration) != 10)
      {
        SSH_DEBUG(2, ("Account %.100s expiration date is in wrong format.", 
                      user));
        enduserdb();
        return FALSE;
      }
    t = ssh_time();
    ssh_calendar_time(t, tm, TRUE);
    snprintf(current_time, sizeof(current_time), "%04d%02d%02d%02d%02d",
             tm->year, tm->month + 1, tm->monthday,
             tm->hour, tm->minute);
    if (expiration[8] < '7') /* Assume year < 70 is 20YY. */
      strcpy(normalized, "20");
    else
      strcpy(normalized, "19");
    strcat(normalized, expiration + 8);
    strcat(normalized, expiration);
    normalized[12] = '\0';
    if (strcmp(normalized, current_time) < 0)
      {
        SSH_DEBUG(2, ("Account %.100s has expired - access denied.", user));
        enduserdb();
        return FALSE;
      }
    enduserdb();
  }
#endif /* HAVE_USERSEC_H */
#ifdef HAVE_ETC_SHADOW
  {
    struct spwd *sp;
    
    sp = (struct spwd *)getspnam(user);
#if defined(SECURE_RPC) && defined(NIS_PLUS)
    if (geteuid() == UID_ROOT && ssh_user_uid(uc) != UID_ROOT
        && (!sp || !sp->sp_pwdp || !strcmp(sp->sp_pwdp,"*NP*")))
      {
        if (seteuid(ssh_user_uid(uc)) >= 0)
          {
            sp = getspnam(user); /* retry as user */
            seteuid(UID_ROOT); 
          }
      }
#endif /* SECURE_RPC && NIS_PLUS */
    if (!sp)
      {
        /*
         * Some systems, e.g.: IRIX, may or may not have /etc/shadow.
         * Just check if there is one. If such system is also an YP
         * client, then valid password might already be present in passwd
         * structure. Just check if it's other than "x". Assume that
         * YP server is always right if this is the case.
         *                                      appro@fy.chalmers.se
         */
        struct stat sbf;
        
        if ((stat(SHADOW, &sbf) == 0) &&
            strcmp(uc->correct_encrypted_passwd, "x") == 0)
          {
            SSH_DEBUG(2, ("Can't find %.100s's shadow - access denied.", 
                          user));
            endspent();
            return FALSE;
          }
      }
    else
      {
        SshTime today = ssh_time()/24/60/60; /* what a day! */

#ifdef HAVE_STRUCT_SPWD_EXPIRE
        /* Check for expiration date */
        if (sp->sp_expire > 0 && today > sp->sp_expire)
          {
            SSH_DEBUG(2, ("Account %.100s has expired - access denied.", 
                          user));
            endspent();
            return FALSE;
          }
#endif
        
#ifdef HAVE_STRUCT_SPWD_INACT
        /* Check for last login */
        if (sp->sp_inact > 0)
          {
            char buf[64];
            SshTime llt;
            
            llt = ssh_user_get_last_login_time(uc, buf, sizeof(buf));
            if (llt && (today - llt/24/60/60) > sp->sp_inact)
              {
                SSH_DEBUG(2, ("Account %.100s was inactive for more than %d days.",
                              user, sp->sp_inact));
                endspent();
                return FALSE;
              }
          }
#endif
        
        /* Check if password is valid */
        if (sp->sp_lstchg == 0 ||
            (sp->sp_max > 0 && today > sp->sp_lstchg + sp->sp_max))
          {
            SSH_DEBUG(2, ("Account %.100s's password is too old - forced to change.",
                          user));
            uc->password_needs_change = TRUE;
          }
        strncpy(passwd, sp->sp_pwdp, sizeof(passwd));
        passwd[sizeof(passwd) - 1] = '\0';
      }
    endspent();
  }
#endif /* HAVE_ETC_SHADOW */
  /*
   * Check if account is locked. Check if encrypted password starts
   * with "*LK*".
   */
  {
    if (strncmp(passwd,"*LK*", 4) == 0)
      {
        SSH_DEBUG(2, ("Account %.100s is locked.", user));
        return FALSE;
      }
  }
#ifdef CHECK_ETC_SHELLS
  {
    int  invalid = 1;
    char *shell = pwd->pw_shell, *etc_shell, *getusershell();
    
    if (!shell || !*shell)
      shell = DEFAULT_SHELL;
    
    while (invalid && (etc_shell = getusershell()))
      invalid = strcmp(etc_shell, shell);
    endusershell();
    
    if (invalid)
      {
        SSH_DEBUG(2, ("Account %.100s doesn't have valid shell", user));
        return FALSE;
      }
  }
#endif /* CHECK_ETC_SHELLS */

  return TRUE;
}

/* Forward declaration. */
SshUser ssh_user_initialize_with_pw(struct passwd *pw, Boolean privileged);

/* Allocates and initializes a context for the user.  The context is used
   to cache information about the particular user.  Returns NULL if the
   user does not exist. If `user' is NULL, use getuid(). 'privileged'
   should only be set, when the process is supposedly run with root
   privileges. If it is FALSE, ssh_user_initialize doesn't try to look for
   shadow passwords etc. */

SshUser ssh_user_initialize(const char *user, Boolean privileged)
{
  struct passwd *pw;

  if (user == NULL)
    pw = getpwuid(getuid());
  else 
    pw = getpwnam(user);

  return ssh_user_initialize_with_pw(pw, privileged);
}

/* As above, but we explicitely want to use uid (instead of name). */
SshUser ssh_user_initialize_with_uid(uid_t uid, Boolean privileged)
{
  struct passwd *pw;

  pw = getpwuid(uid);

  return ssh_user_initialize_with_pw(pw, privileged);
}

/* As above, but uses struct passwd. This function does all the work. */
SshUser ssh_user_initialize_with_pw(struct passwd *pw, Boolean privileged)
{
  SshUser uc;

  char correct_passwd[200];

  if (!pw)
    return NULL;
  
  uc = ssh_xcalloc(1, sizeof(*uc));

  uc->name = ssh_xstrdup(pw->pw_name);
  uc->dir = ssh_xstrdup(pw->pw_dir);
  uc->uid = pw->pw_uid;
  uc->gid = pw->pw_gid;

  if (strcmp(pw->pw_shell, "") == 0)
    {
      uc->shell = ssh_xstrdup("/bin/sh");
    }
  else
    {    
      uc->shell = ssh_xstrdup(pw->pw_shell);
    }
  
  if (privileged)
    {
      
      /* Save the encrypted password. */
      strncpy(correct_passwd, pw->pw_passwd, sizeof(correct_passwd));

#ifdef HAVE_SIA
      /* pr->pw_passwd may not be the real encrypted password (it won't be
         under Enhanced Security), but we don't care because we never look at
         uc->correct_encrypted_passwd.  We let my_sia_validate_user() do all
         the work instead. */
#else /* HAVE_SIA */
      /* If we have shadow passwords, lookup the real encrypted password from
         the shadow file, and replace the saved encrypted password with the
         real encrypted password. */
#if defined(HAVE_SCO_ETC_SHADOW) || defined(HAVE_HPUX_TCB_AUTH)
      {
        struct pr_passwd *pr = getprpwnam(ssh_user_name(uc));
        pr = getprpwnam(ssh_user_name(uc));
        if (pr)
          strncpy(correct_passwd, pr->ufld.fd_encrypt, sizeof(correct_passwd));
        endprpwent();
      }
#else /* defined(HAVE_SCO_ETC_SHADOW) || defined(HAVE_HPUX_TCB_AUTH) */
#ifdef HAVE_ETC_SHADOW
      {
        struct spwd *sp = getspnam(ssh_user_name(uc));
#if defined(SECURE_RPC) && defined(NIS_PLUS)
        if (geteuid() == UID_ROOT && ssh_user_uid(uc) != UID_ROOT &&
            (!sp || !sp->sp_pwdp || !strcmp(sp->sp_pwdp,"*NP*")))
          if (seteuid(ssh_user_uid(uc)) >= 0)
            {
              sp = getspnam(ssh_user_name(uc)); /* retry as user */   
              seteuid(UID_ROOT);
            }
#endif /* SECURE_RPC && NIS_PLUS */
        if (sp)
          strncpy(correct_passwd, sp->sp_pwdp, sizeof(correct_passwd));
        endspent();
      }
#else /* HAVE_ETC_SHADOW */
#ifdef HAVE_ETC_SECURITY_PASSWD_ADJUNCT
      {
        struct passwd_adjunct *sp = getpwanam(ssh_user_name(uc));
        if (sp)
          strncpy(correct_passwd, sp->pwa_passwd, sizeof(correct_passwd));
        endpwaent();
      }
#else /* HAVE_ETC_SECURITY_PASSWD_ADJUNCT */
#ifdef HAVE_ETC_SECURITY_PASSWD /* AIX, at least.  Is there an easier way? */
      {
        FILE *f;
        char line[1024], looking_for_user[200], *cp;
        int found_user = 0;
        f = fopen("/etc/security/passwd", "r");
        if (f)
          {
            /* XXX: user next line was server_user, is this OK? */
            snprintf(looking_for_user, sizeof(looking_for_user), "%.190s:", user);
            while (fgets(line, sizeof(line), f))
              {
                if (strchr(line, '\n'))
                  *strchr(line, '\n') = 0;
                if (strcmp(line, looking_for_user) == 0)
                  found_user = 1;
                else
                  if (line[0] != '\t' && line[0] != ' ')
                    found_user = 0;
                  else
                    if (found_user)
                      {
                        for (cp = line; *cp == ' ' || *cp == '\t'; cp++)
                          ;
                        if (strncmp(cp, "password = ", strlen("password = ")) == 0)
                          {
                            strncpy(correct_passwd, cp + strlen("password = "), 
                                    sizeof(correct_passwd));
                            correct_passwd[sizeof(correct_passwd) - 1] = 0;
                            break;
                          }
                      }
              }
            fclose(f);
          }
      }
#endif /* HAVE_ETC_SECURITY_PASSWD */
#endif /* HAVE_ETC_SECURITY_PASSWD_ADJUNCT */
#endif /* HAVE_ETC_SHADOW */
#endif /* HAVE_SCO_ETC_SHADOW */
#endif /* HAVE_SIA */

      uc->correct_encrypted_passwd = ssh_xstrdup(correct_passwd);

      uc->login_allowed = ssh_login_permitted(uc->name, uc);
    }
  else /* !privileged */
    {
      uc->correct_encrypted_passwd = NULL;
      uc->login_allowed = TRUE;
      uc->password_needs_change = FALSE;
    }
  
  /* XXX should check password expirations (some systems already do this in
     ssh_login_permitted). */
  
  return uc;
}

/* Frees information about the user.  If ``undo'' is TRUE, undoes any
   cached state related to e.g. Kerberos and Secure RPC.  Returns
   FALSE if undo was requested, but was unable to undo everything; otherwise
   returns TRUE. */

Boolean ssh_user_free(SshUser uc, Boolean undo)
{
  /* XXX undoing kerberos / secure rpc state. */

  ssh_xfree(uc->name);
  ssh_xfree(uc->dir);
  ssh_xfree(uc->shell);
  if (uc->correct_encrypted_passwd)
    ssh_xfree(uc->correct_encrypted_passwd);

  memset(uc, 'F', sizeof(*uc));
  ssh_xfree(uc);
  return TRUE;
}

/* Returns TRUE if logging in as the specified user is allowed. */

Boolean ssh_user_login_is_allowed(SshUser uc)
{
  return uc->login_allowed;
}

/* Returns TRUE if login is allowed with the given local password. */

#ifdef HAVE_SIA
Boolean ssh_user_validate_local_password(SshUser uc,
                                         const char *password,
                                         const char *remote_host)
#else /* HAVE_SIA */
Boolean ssh_user_validate_local_password(SshUser uc,
                                         const char *password)
#endif /* HAVE_SIA */
{
  char *encrypted_password;
  const char *correct_passwd = uc->correct_encrypted_passwd;

#ifdef HAVE_ULTRIX_SHADOW_PASSWORDS
  {
    struct svcinfo *svp;
    struct passwd *pw;

    pw = getpwnam(uc->name);
    if (!pw)
      return FALSE;

    svp = getsvc();
    if (svp == NULL)
      {
        error("getsvc() failed in ultrix code in auth_passwd");
        return FALSE;
      }
    if ((svp->svcauth.seclevel == SEC_UPGRADE &&
         strcmp(pw->pw_passwd, "*") == 0) ||
        svp->svcauth.seclevel == SEC_ENHANCED)
      return authenticate_user(pw, password, "/dev/ttypXX") >= 0;
  }
#endif /* HAVE_ULTRIX_SHADOW_PASSWORDS */

#ifdef HAVE_SIA
  {
    int argc;
    char **argv;

    /* Passing a collection routine to my_sia_validate_user() here would
       be useless and could be harmful.

       It would be useless because at this point, stdin/stdout/stderr
       are all redirected to /dev/null.

       It would be harmful if the collection routine tried to print
       anything to stdout, say, a warning that the password is incorrect.
       At this point, nothing has been printed to stdout yet and it's
       redirected to /dev/null.  Printing to stdout now would initialize
       it as fully buffered (not line buffered) since /dev/null isn't a
       tty.  That would cause problems later on in the child, which gets
       a copy of the stdout structure.  When the child printed /etc/motd
       and the mail notice, the user wouldn't see them because they'd
       be stuck in the stdout buffer. */

    get_sia_args(&argc, &argv);
    if (my_sia_validate_user(NULL, argc, argv,
                             (char *)remote_host, uc->name,
                             NULL, 0, NULL, (char *)password) == SIASUCCESS)
      return TRUE;
    else
      return FALSE;
  }
#endif /* HAVE_SIA */

  /* Encrypt the candidate password using the proper salt. */
#if defined(HAVE_SCO_ETC_SHADOW) || defined(HAVE_HPUX_TCB_AUTH)
  encrypted_password = bigcrypt(password, 
                                (correct_passwd[0] && correct_passwd[1]) ?
                                correct_passwd : "xx");
#else /* defined(HAVE_SCO_ETC_SHADOW) || defined(HAVE_HPUX_TCB_AUTH) */
  encrypted_password = crypt(password, 
                             (correct_passwd[0] && correct_passwd[1]) ?
                             correct_passwd : "xx");
#endif /* HAVE_SCO_ETC_SHADOW */

  /* Authentication is accepted if the encrypted passwords are identical. */
  return strcmp(encrypted_password, correct_passwd) == 0;
  
}

/* Returns TRUE if the user's password needs to be changed. */

Boolean ssh_user_password_must_be_changed(SshUser uc,
                                          char **prompt_return)
{
  if (uc->password_needs_change)
    *prompt_return = ssh_xstrdup("Your password has expired.");
  return uc->password_needs_change;
}

/* Changes the user's password.  Returns TRUE if the change was successful,
   FALSE if the change failed. */

Boolean ssh_user_change_password(SshUser uc,
                                 const char *old_password,
                                 const char *new_password)
{
  SSH_DEBUG(2, ("ssh_user_change_password: XXX changing not yet implemented"));
  return FALSE;
}

/* Tries to log in with the given kerberos password.  If successful,
   obtains a kerberos ticket for the user, and the ticket will be used
   for further access by the current process.  Returns TRUE on success. */

Boolean ssh_user_validate_kerberos_password(SshUser uc,
                                            const char *password)
{
  SSH_DEBUG(2, ("ssh_user_validate_kerberos_password: not yet implemented"));
  return FALSE;
}

/* Tries to login with the given secure rpc password.  If successful,
   obtains a secure rpc key from the key server, and starts using that
   key for further communication.  Returns TRUE on success. */

Boolean ssh_user_validate_secure_rpc_password(SshUser uc,
                                              const char *password)
{
  SSH_DEBUG(2, ("ssh_user_validate_secure_rpc_password: not yet implemented"));
  return FALSE;
}

#ifdef CRAY
/*
 On a Cray, set the account number for the current process to the user's 
 default account.  If this is not done, the process will have an account 
 of zero and accounting (Cray System Accounting and/or SDSC Resource
 Management (realtime)) will not operate correctly.

 This routine also calls setjob to set up an Cray Job (also known 
 as a Session).  This is needed for CRI's Cray System Accounting 
 and SDSC's Resource Management accounting/management system.

 It also calls setlimit, to set up limits and permissions.
 
 Wayne Schroeder
 San Diego Supercomputer Center
 schroeder@sdsc.edu
 
*/

#include <udb.h>
#include <unistd.h>
#include <sys/category.h>
extern char *setlimits();

int ssh_cray_setup(uid, username)
     uid_t uid;
     char *username;
{
  register struct udb *p;
  extern struct udb *getudb();
  int i, j;
  int accts[MAXVIDS];
  int naccts;
  int err, jid;
  char *sr;
  int pid;

  /* Find all of the accounts for a particular user */
  err = setudb();    /* open and rewind the Cray User DataBase */
  if(err != 0)
    {
      SSH_DEBUG(2, ("ssh_cray_setup: UDB open failure"));
      return(-1);
    }
  naccts = 0;
  while ((p = getudb()) != UDB_NULL) 
    {
      if (p->ue_uid == -1) break;
      if(uid == p->ue_uid) 
        {
          for(j = 0; p->ue_acids[j] != -1 && j < MAXVIDS; j++) 
            {
              accts[naccts] = p->ue_acids[j];
              naccts++;
            }
        }
    }
  endudb();        /* close the udb */
  if (naccts == 0 || accts[0] == 0)
    {
      SSH_DEBUG(2, ("ssh_cray_setup: No Cray accounts found"));
      return(-1);
    }
 
  /* Perhaps someday we'll prompt users who have multiple accounts
     to let them pick one (like CRI's login does), but for now just set 
     the account to the first entry. */
  if (acctid(0, accts[0]) < 0) 
    {
      SSH_DEBUG(2, ("ssh_cray_setup: System call acctid failed, accts[0]=%d",
                accts[0]));
      return(-1);
    } 
 
  /* Now call setjob to create a new job(/session).  This assigns a new Session
     ID and session table entry to the calling process.  This process will be
     the first process in the job/session. */
  jid = setjob(uid, 0);
  if (jid < 0) 
    {
      SSH_DEBUG(2, ("ssh_cray_setup: System call setjob failure"));
      return(-1);
    }

  /* Now set limits, including CPU time for the (interactive) job and process,
     and set up permissions (for chown etc), etc.  This is via an internal CRI
     routine, setlimits, used by CRI's login. */

  pid = getpid();
  sr = setlimits(username, C_PROC, pid, UDBRC_INTER);
  if (sr != NULL) 
    {
      SSH_DEBUG(2, ("%.100s", sr));
      return(-1);
    }
  sr = setlimits(username, C_JOB, jid, UDBRC_INTER);
  if (sr != NULL) 
    {
      SSH_DEBUG(2, ("%.100s", sr));
      return(-1);
    }

  return(0);
}
#endif /* CRAY */

/* Switches the current process to the permissions and privileges of the
   specified user.  The process should not hold any confidential information
   at this point.  This returns FALSE if switching to the given user failed
   for some reason.  The return value of this function MUST BE CHECKED! */

Boolean ssh_user_become(SshUser uc)
{
  /* At this point, this process should no longer be holding any confidential
     information, as changing uid below will permit the user to attach with
     a debugger on some machines. */
  
  int i;
  
#ifdef HAVE_SETLOGIN
  /* Set login name in the kernel.  Warning: setsid() must be called before
     this. */
  if (setlogin(ssh_user_name(uc)) < 0)
    SSH_DEBUG(2, ("setlogin failed: %.100s", strerror(errno)));
#endif /* HAVE_SETLOGIN */

#ifdef HAVE_USERSEC_H
  /* On AIX, this "sets process credentials".  I am not sure what this
     includes, but it seems to be important.  This also does setuid
     (but we do it below as well just in case). */
  if (setpcred(ssh_user_name(uc), NULL))
    SSH_DEBUG(2, ("setpcred %.100s: %.100s", strerror(errno)));
#endif /* HAVE_USERSEC_H */

  /* Close any extra file descriptors.  Note that there may still be
     descriptors left by system functions.  They will be closed later. */
  endpwent();
  endhostent();

  /* Close any extra open file descriptors so that we don\'t have them
     hanging around in clients.  Note that we want to do this after
     initgroups, because at least on Solaris 2.3 it leaves file descriptors
     open. */
  endgrent();

#ifdef HAVE_SIA
  /* Close later on, after calling sia_become_user().  Closing now could
     break that call. */
#else /* HAVE_SIA */
  for (i = 3; i < 1000; i++)
    close(i);
#endif /* HAVE_SIA */

#ifdef CRAY   /* set up accounting account number, job, limits, permissions  */
  if (cray_setup(ssh_user_uid(uc), ssh_user_name(uc)) < 0)
    {
      SSH_DEBUG(2, ("ssh_user_become: Failure in Cray job setup for user %d.",
                    (int)ssh_user_uid(uc)));
      return FALSE;
    }
#endif

  /* Set uid, gid, and groups. */
  if (getuid() == UID_ROOT || geteuid() == UID_ROOT)
    { 
      if (setgid(ssh_user_gid(uc)) < 0)
        {
          SSH_DEBUG(2, ("ssh_user_become: setgid: %s", strerror(errno)));
          return FALSE;
        }
#ifdef HAVE_INITGROUPS
      /* Initialize the group list. */
      if (initgroups(ssh_user_name(uc), ssh_user_gid(uc)) < 0)
        {
          SSH_DEBUG(2, ("ssh_user_become: initgroups: %s", strerror(errno)));
          return FALSE;
        }
#endif /* HAVE_INITGROUPS */
      endgrent();
          
#ifdef HAVE_SIA
      /* Temporarily switch to the desired uid.  We'll permanently switch
         in ssh_user_become_real(). */
      if (seteuid(ssh_user_uid(uc)) < 0)
        {
          SSH_DEBUG(2, ("ssh_user_become: seteuid %d: %s",
                        (int)ssh_user_uid(uc), strerror(errno)));
          return FALSE;
        }
      if (geteuid() != ssh_user_uid(uc))
        {
          SSH_DEBUG(2, ("ssh_user_become: failed to set euid to %d.",
                        (int)ssh_user_uid(uc)));
          return FALSE;
        }
#else /* HAVE_SIA */
#ifdef HAVE_SETLUID
  /* Set login uid, if we have setluid(). */
      if (setluid(ssh_user_uid(uc)) < 0)
        {
          SSH_DEBUG(2, ("ssh_user_become); setluid %d: %s",
                        (int)ssh_user_uid(uc), strerror(errno));
          return FALSE;
        }
#endif /* HAVE_SETLUID */
      /* Permanently switch to the desired uid. */
      if (setuid(ssh_user_uid(uc)) < 0)
        {
          SSH_DEBUG(2, ("ssh_user_become: setuid %d: %s",
                        (int)ssh_user_uid(uc), strerror(errno)));
          return FALSE;
        }
      if (getuid() != ssh_user_uid(uc) || geteuid() != ssh_user_uid(uc))
        {
          SSH_DEBUG(2, ("ssh_user_become: failed to set uids to %d.",
                        (int)ssh_user_uid(uc)));
          return FALSE;
        }
#endif /* HAVE_SIA */
    }
  
  /* We are now running with the user's privileges. */
  return TRUE;
}

#ifdef HAVE_SIA
/* Last chance to finish anything that ssh_user_become() left undone.  The
   difference between the two functions is that ssh_user_become() is called
   before the user's environment is set, while we're called after.

   Switches the current process to the permissions and privileges of the
   specified user.  The process should not hold any confidential information
   at this point.  This returns FALSE if switching to the given user failed
   for some reason.  The return value of this function MUST BE CHECKED! */
Boolean ssh_user_become_real(SshUser uc,
                             const char *remote_host,
                             const char *ttyname)
{
  int i;
  int argc;
  char **argv;

  SSH_DEBUG(7, ("before going-back-to-uid uid = %d and euid = %d", 
                (int)getuid(), (int)geteuid()));
  /* Switch back temporarily to our own uid (typically root, but
     not always) in case sia_become_user() needs to access protected
     account databases. */
  if (seteuid(getuid()) != 0)
    {
      SSH_DEBUG(2, ("ssh_user_become_real: seteuid %d: %s",
                    (int)getuid(), strerror(errno)));
      return FALSE;
    }

  SSH_DEBUG(7, ("after seteuid-to-uid uid = %d and euid = %d", 
                (int)getuid(), (int)geteuid()));

  get_sia_args(&argc, &argv);
  /* Enhanced Security calls setluid() here in sia_become_user(). */
  if (sia_become_user(sia_collect_trm, argc, argv, (char *)remote_host,
                      (char *)ssh_user_name(uc), (char *)ttyname, 0, NULL,
                      NULL, SIA_BEU_REALLOGIN) != SIASUCCESS)
    {
      SSH_DEBUG(2, ("ssh_user_become_real: sia_become_user() failed for user %d.",
                    (int)ssh_user_uid(uc)));
      return FALSE;
    }
  /* Our sia calls are complete, so we can finally close any extra
     open file descriptors. */
  for (i = getdtablesize() - 1; i > 2; i--)
    close(i);

  /* We can now completely become the user.  We need to do this
     with setreuid() instead of setuid() because sia_become_user()
     has set our euid to the user's uid. */
  if (setreuid(ssh_user_uid(uc), ssh_user_uid(uc)) < 0)
    {
      SSH_DEBUG(2, ("ssh_user_become_real: setreuid %d: %s",
                    (int)ssh_user_uid(uc), strerror(errno)));
      return FALSE;
    }

  if (getuid() != ssh_user_uid(uc) || geteuid() != ssh_user_uid(uc))
    {
      SSH_DEBUG(2, ("ssh_user_become_real: failed to set uids to %d.",
                    (int)ssh_user_uid(uc)));
      return FALSE;
    }

  SSH_DEBUG(7, ("after completion uid = %d and euid = %d", 
                (int)getuid(), (int)geteuid()));

  /* We are now running with the user's complete privileges. */
  return TRUE;
}
#endif /* HAVE_SIA */

/* Returns the login name of the user. */

const char *ssh_user_name(SshUser uc)
{
  return uc->name;
}

/* Returns the uid of the user.  This is unix-specific. */

uid_t ssh_user_uid(SshUser uc)
{
  return uc->uid;
}

/* Returns the gid of the user.  This is unix-specific. */

gid_t ssh_user_gid(SshUser uc)
{
  return uc->gid;
}

/* Returns the user's home directory.  This is unix-specific. */

const char *ssh_user_dir(SshUser uc)
{
  return uc->dir;
}

/* Returns the user's shell.  This is unix-specific. */

const char *ssh_user_shell(SshUser uc)
{
  return uc->shell;
}
