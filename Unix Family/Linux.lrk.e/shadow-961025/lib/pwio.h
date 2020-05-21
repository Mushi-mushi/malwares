#ifndef _PWIO_H
#define _PWIO_H

#include <pwd.h>

/* pwio.c */
extern struct passwd *__pw_dup P_((const struct passwd *));
extern int pw_close P_((void));
extern const struct passwd *pw_locate P_((const char *));
extern int pw_lock P_((void));
extern int pw_name P_((const char *));
extern const struct passwd *pw_next P_((void));
extern int pw_open P_((int));
extern int pw_remove P_((const char *));
extern int pw_rewind P_((void));
extern int pw_unlock P_((void));
extern int pw_update P_((const struct passwd *));

#ifdef NEED_PW_FILE_ENTRY
struct pw_file_entry {
	char *pwf_line;
	int pwf_changed;
	struct passwd *pwf_entry;
	struct pw_file_entry *pwf_next;
};
#endif
#endif /* _PWIO_H */
