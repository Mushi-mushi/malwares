#include "ps.h"

char *
status(struct ps_proc *task)
{
    static char buf[5] = "    ";

    buf[0] = task->state;
    if (task->rss == 0 && task->state != 'Z')
        buf[1] = 'W';
    else
        buf[1] = ' ';
    if (task->priority > PZERO)
	buf[2] = '<';
    else if (task->priority < PZERO)
	buf[2] = 'N';
    else
	buf[2] = ' ';

    return(buf);
}
