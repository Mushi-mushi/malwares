#ifndef _GROUPIO_H
#define _GROUPIO_H

#include <grp.h>

/* groupio.c */
extern struct group *__gr_dup P_((const struct group *));
extern int gr_close P_((void));
extern const struct group *gr_locate P_((const char *));
extern int gr_lock P_((void));
extern int gr_name P_((const char *));
extern const struct group *gr_next P_((void));
extern int gr_open P_((int));
extern int gr_remove P_((const char *));
extern int gr_rewind P_((void));
extern int gr_unlock P_((void));
extern int gr_update P_((const struct group *));

#ifdef NEED_GR_FILE_ENTRY
struct gr_file_entry {
	char *grf_line;
	int grf_changed;
	struct group *grf_entry;
	struct gr_file_entry *grf_next;
};
#endif
#endif /* _GROUPIO_H */
