/*
  File: t-dns.c

  Authors: 
        Tero T Mononen <tmo@ssh.fi>

  Description: 
        Test DNS routines. This is an interactive program,
        and should not be run from the automatic tests.

  Copyright:
        Copyright (c) 1999 SSH Communications Security, Finland
        All rights reserved
*/

#include "sshincludes.h"
#include "sshtcp.h"

void byname_cb(SshIpError error, const char *name, void *context)
{
  char *addr = (char *)context;

  if (name)
    fprintf(stderr, "++ ADDR=%s NAME=%s\n", addr, name);
  else
    fprintf(stderr, "-- ADDR=%s NAME=none\n", addr); 

  ssh_xfree(context);
}  

void byaddr_cb(SshIpError error, const char *result, void *context)
{
  char *name = (char *)context, *addr, *addrs;

  if (error == SSH_IP_OK)
    {
      addrs = ssh_xstrdup(result);
      fprintf(stderr, "++ NAME=%s, ADDRS=%s\n", name, addrs);
      addr = strtok(addrs, ",");
      while (addr)
        {
          ssh_tcp_get_host_by_addr(addr, byname_cb, ssh_xstrdup(addr));
          addr = strtok(NULL, ",");
        }
      ssh_xfree(addrs);
    }
  else
    fprintf(stderr, "-- NAME=%s, ADDRS=none\n", name); 
}

int main(int ac, char **av)
{
  char *addrs, *addr, *name, *oname;

  if (ac < 2)
    name = oname = "www.ssh.fi";
  else
    name = oname = av[1];
  /* map name to address; then map the address back to the name */
  addrs = ssh_tcp_get_host_addrs_by_name_sync(oname);
  if (addrs)
    {
      fprintf(stderr, "++ NAME=%s, ADDRS=%s\n", name, addrs);
      addr = strtok(addrs, ",");
      while (addr)
        {
          name = ssh_tcp_get_host_by_addr_sync(addr);
          if (name)
            {
              fprintf(stderr, "++ ADDR=%s NAME=%s\n", addr, name);
              ssh_xfree(name);
            }
          else
            fprintf(stderr, "-- ADDR=%s NAME=none\n", addr); 
          
          addr = strtok(NULL, ",");
        }
      ssh_xfree(addrs);
    }
  else
    fprintf(stderr, "-- NAME=%s, ADDRS=none\n", name); 
      
  /* do the same using the asyncronous interface */
  ssh_tcp_get_host_addrs_by_name(oname, byaddr_cb, oname);

  return 0;
}
/* eof */
