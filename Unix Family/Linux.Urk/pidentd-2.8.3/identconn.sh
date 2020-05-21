#! /bin/sh
:
PATH=/usr/sbin:/usr/etc:/usr/bin:/usr/ucb:xDESTROOTx/bin ; export PATH

netstat -f inet -n | grep ESTAB | itest

