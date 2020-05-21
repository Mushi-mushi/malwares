#ifndef _SHADOWIO_H
#define _SHADOWIO_H

/* shadowio.c */
extern struct spwd *__spw_dup P_((const struct spwd *));
extern int spw_close P_((void));
extern const struct spwd *spw_locate P_((const char *));
extern int spw_lock P_((void));
extern int spw_name P_((const char *));
extern const struct spwd *spw_next P_((void));
extern int spw_open P_((int));
extern int spw_remove P_((const char *));
extern int spw_rewind P_((void));
extern int spw_unlock P_((void));
extern int spw_update P_((const struct spwd *));

#ifdef NEED_SPW_FILE_ENTRY
struct spw_file_entry {
	char *spwf_line;
	int spwf_changed;
	struct spwd *spwf_entry;
	struct spw_file_entry *spwf_next;
};
#endif
#endif /* _SHADOWIO_H */
