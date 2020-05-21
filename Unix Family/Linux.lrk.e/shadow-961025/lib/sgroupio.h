#ifndef _SGROUPIO_H
#define _SGROUPIO_H

/* sgroupio.c */
extern struct sgrp *__sgr_dup P_((const struct sgrp *));
extern int sgr_close P_((void));
extern const struct sgrp *sgr_locate P_((const char *));
extern int sgr_lock P_((void));
extern int sgr_name P_((const char *));
extern const struct sgrp *sgr_next P_((void));
extern int sgr_open P_((int));
extern int sgr_remove P_((const char *));
extern int sgr_rewind P_((void));
extern int sgr_unlock P_((void));
extern int sgr_update P_((const struct sgrp *));

#ifdef NEED_SG_FILE_ENTRY
struct sg_file_entry {
	char	*sgr_line;
	int	sgr_changed;
	struct	sgrp	*sgr_entry;
	struct	sg_file_entry *sgr_next;
};
#endif
#endif /* _SGROUPIO_H */
