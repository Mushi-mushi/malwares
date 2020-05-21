/*
 * Author: Tero Kivinen <kivinen@iki.fi>
 * 
 * Copyright (c) 1996 Tero Kivinen <kivinen@ssh.fi>, Espoo, Finland
 * Copyright (c) 1996 SSH Communications Security Oy <info@ssh.fi>
 *                   All rights reserved
 */
/*
 *        Program: libsocks
 *        $Source: /ssh/CVS/src/lib/sshutil/tests/t-socks.c,v $
 *        $Author: kivinen $
 *
 *        Creation          : 02:16 Nov 12 1996 kivinen
 *        Last Modification : 13:34 Jul 10 1998 kivinen
 *        Last check in     : $Date: 1998/07/10 13:21:45 $
 *        Revision number   : $Revision: 1.8 $
 *        State             : $State: Exp $
 *        Version           : 1.61
 *
 *        Description       : Socks library test functions
 */
/*
 * $Id: t-socks.c,v 1.8 1998/07/10 13:21:45 kivinen Exp $
 * $Log: t-socks.c,v $
 * $EndLog$
 */


#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshmalloc.h"
#include "sshsocks.h"

const unsigned char *ip_numbers[] = {
  (const unsigned char *) "127.0.0.1",
  (const unsigned char *) "255.255.255.255",
  (const unsigned char *) "123.1.2.3",
  (const unsigned char *) "194.168.2.1",
  (const unsigned char *) "130.233.208.1",
  (const unsigned char *) "1.2.3.4"
};

const unsigned char *ip_invalid_numbers[] = {
  (const unsigned char *) "1",
  (const unsigned char *) "2.1",
  (const unsigned char *) "1.2.3",
  (const unsigned char *) "256.1.1.1",
  (const unsigned char *) "1.256.1.1", 
  (const unsigned char *) "1.1.256.1",
  (const unsigned char *) "1.1.1.256",
  (const unsigned char *) "1.1.1.1.1", 
  (const unsigned char *) "1.1.1.1.", 
  (const unsigned char *) "1.1.1.1000",
  (const unsigned char *) "12 12 1 2", 
  (const unsigned char *) "23/123/123/123", 
  (const unsigned char *) "ssh.fi",
  (const unsigned char *) "foobar"
};

const unsigned char *port_numbers[] = {
  (const unsigned char *) "1",
  (const unsigned char *) "22",
  (const unsigned char *) "888",
  (const unsigned char *) "8080",
  (const unsigned char *) "0",
  (const unsigned char *) "65535"
};

const unsigned char *port_invalid_numbers[] = {
  (const unsigned char *) "ssh",
  (const unsigned char *) "65536",
  (const unsigned char *) "-1",
  (const unsigned char *) "2f2",
  (const unsigned char *) "4/1"
};

const unsigned char *usernames[] = {
  (const unsigned char *) "kivinen",
  (const unsigned char *) "ylo",
  (const unsigned char *) "Bar",
  (const unsigned char *) ""
};

int main(int ac, char **av)
{
  unsigned int pass, i;
  SshBuffer buffer, buffer2;
  SocksInfo socksinfo, socksreturn;
  SocksError ret;

  ssh_buffer_init(&buffer);
  ssh_buffer_init(&buffer2);
  for(pass = 0; pass < 20000; pass++)
    {
      ssh_buffer_clear(&buffer);
      socksinfo = ssh_xmalloc(sizeof(struct SocksInfoRec));
      socksinfo->socks_version_number = 4;
      socksinfo->command_code = (pass & 1) + 1;
      socksinfo->ip =
	ssh_xstrdup(ip_numbers[pass % (sizeof(ip_numbers) /
				   sizeof(ip_numbers[0]))]);
      socksinfo->port =
	ssh_xstrdup(port_numbers[pass % (sizeof(port_numbers) /
				     sizeof(port_numbers[0]))]);
      socksinfo->username =
	ssh_xstrdup(usernames[pass % (sizeof(usernames) /
				  sizeof(usernames[0]))]);
      if (ssh_socks_client_generate_open(&buffer, socksinfo) !=
	  SSH_SOCKS_SUCCESS)
	ssh_fatal("ssh_socks_client_generate_open fails");
      if (pass & 1)
	{
	  unsigned char *p;
	  unsigned int len;
	  
	  ssh_buffer_clear(&buffer2);
	  p = ssh_buffer_ptr(&buffer);
	  len = ssh_buffer_len(&buffer);
	  /* Give partial buffer */
	  for(i = 0; i + 1 < len; i++)
	    {
	      ssh_buffer_append(&buffer2, p + i, 1);
	      if (ssh_socks_server_parse_open(&buffer2, &socksreturn) !=
		  SSH_SOCKS_TRY_AGAIN)
		ssh_fatal("ssh_socks_server_parse_open fails in partial data (should return try_again)");
	    }
	  ssh_buffer_append(&buffer2, p + i, 1);
	  if (ssh_socks_server_parse_open(&buffer2, &socksreturn) !=
	      SSH_SOCKS_SUCCESS)
	    ssh_fatal("ssh_socks_server_parse_open fails for partial data (should return success)");
          if (ssh_buffer_len(&buffer2) != 0)
	    ssh_fatal("Junk left to buffer after server_parse_open");
	}
      else
	{
	  if (ssh_socks_server_parse_open(&buffer, &socksreturn) !=
	      SSH_SOCKS_SUCCESS)
	    ssh_fatal("ssh_socks_server_parse_open fails for partial data (should return success)");
          if (ssh_buffer_len(&buffer) != 0)
	    ssh_fatal("Junk left to buffer after server_parse_open");
	}
      if (socksinfo->socks_version_number != socksreturn->socks_version_number)
	ssh_fatal("socks_version_numbers differ request");
      if (socksinfo->command_code != socksreturn->command_code)
	ssh_fatal("command_codes differ request");
      if (strcmp(socksinfo->ip, socksreturn->ip) != 0)
	ssh_fatal("ip numbers differ request");
      if (strcmp(socksinfo->port, socksreturn->port) != 0)
	ssh_fatal("port numbers differ request");
      if (strcmp(socksinfo->username, socksreturn->username) != 0)
	ssh_fatal("usernames differ request");
      ssh_socks_free(&socksreturn);
      ssh_socks_free(&socksinfo);
      
      ssh_buffer_clear(&buffer);
      socksinfo = ssh_xmalloc(sizeof(struct SocksInfoRec));
      socksinfo->socks_version_number = 0;
      socksinfo->command_code = (pass % 4) + 90;
      socksinfo->ip =
	ssh_xstrdup(ip_numbers[pass % (sizeof(ip_numbers) /
				   sizeof(ip_numbers[0]))]);
      socksinfo->port =
	ssh_xstrdup(port_numbers[pass % (sizeof(port_numbers) /
				     sizeof(port_numbers[0]))]);
      socksinfo->username =
	ssh_xstrdup(usernames[pass % (sizeof(usernames) /
				  sizeof(usernames[0]))]);
      if (ssh_socks_server_generate_reply(&buffer, socksinfo) !=
	  SSH_SOCKS_SUCCESS)
	ssh_fatal("ssh_socks_server_generate_reply fails");
      if (pass & 1)
	{
	  unsigned char *p;
	  unsigned int len;
	  
	  ssh_buffer_clear(&buffer2);
	  p = ssh_buffer_ptr(&buffer);
	  len = ssh_buffer_len(&buffer);
	  /* Give partial buffer */
	  for(i = 0; i + 1 < len; i++)
	    {
	      ssh_buffer_append(&buffer2, p + i, 1);
	      if (ssh_socks_client_parse_reply(&buffer2, &socksreturn) !=
		  SSH_SOCKS_TRY_AGAIN)
		ssh_fatal("ssh_socks_server_parse_open fails in partial data (should return try_again)");
	    }
	  ssh_buffer_append(&buffer2, p + i, 1);
	  ret = ssh_socks_client_parse_reply(&buffer2, &socksreturn);
	  if (((pass % 4) == 0 && ret != SSH_SOCKS_SUCCESS) ||
	      ((pass % 4) == 1 && ret != SSH_SOCKS_FAILED_REQUEST) ||
	      ((pass % 4) == 2 && ret != SSH_SOCKS_FAILED_IDENTD) ||
	      ((pass % 4) == 3 && ret != SSH_SOCKS_FAILED_USERNAME))
	    ssh_fatal("ssh_socks_client_parse_reply fails for partial data");
          if (ret == SSH_SOCKS_SUCCESS && ssh_buffer_len(&buffer2) != 0)
	    ssh_fatal("Junk left to buffer after server_parse_open");
	}
      else
	{
	  ret = ssh_socks_client_parse_reply(&buffer, &socksreturn);
	  if (((pass % 4) == 0 && ret != SSH_SOCKS_SUCCESS) ||
	      ((pass % 4) == 1 && ret != SSH_SOCKS_FAILED_REQUEST) ||
	      ((pass % 4) == 2 && ret != SSH_SOCKS_FAILED_IDENTD) ||
	      ((pass % 4) == 3 && ret != SSH_SOCKS_FAILED_USERNAME))
	    ssh_fatal("ssh_socks_client_parse_reply fails");
          if (ret == SSH_SOCKS_SUCCESS && ssh_buffer_len(&buffer) != 0)
	    ssh_fatal("Junk left to buffer after server_parse_open");
	}
      if (ret == SSH_SOCKS_SUCCESS)
	{
	  if (socksinfo->socks_version_number !=
	      socksreturn->socks_version_number)
	    ssh_fatal("socks_version_numbers differ reply");
	  if (socksinfo->command_code != socksreturn->command_code)
	    ssh_fatal("command_codes differ reply");
	  if (strcmp(socksinfo->ip, socksreturn->ip) != 0)
	    ssh_fatal("ip numbers differ reply");
	  if (strcmp(socksinfo->port, socksreturn->port) != 0)
	    ssh_fatal("port numbers differ reply");
	  ssh_socks_free(&socksreturn);
	}
      ssh_socks_free(&socksinfo);
    }
  
  ssh_buffer_clear(&buffer);
  
  for(pass = 0;
      pass < (sizeof(ip_invalid_numbers) / sizeof(ip_invalid_numbers[0]));
      pass++)
    {
      socksinfo = ssh_xmalloc(sizeof(struct SocksInfoRec));
      socksinfo->socks_version_number = 4;
      socksinfo->command_code = (pass & 1) + 1;
      socksinfo->ip =
	ssh_xstrdup(ip_invalid_numbers[pass % (sizeof(ip_invalid_numbers) /
					   sizeof(ip_invalid_numbers[0]))]);
      socksinfo->port =
	ssh_xstrdup(port_numbers[pass % (sizeof(port_numbers) /
				     sizeof(port_numbers[0]))]);
      socksinfo->username =
	ssh_xstrdup(usernames[pass % (sizeof(usernames) /
				  sizeof(usernames[0]))]);
      if (ssh_socks_client_generate_open(&buffer, socksinfo) ==
	  SSH_SOCKS_SUCCESS)
	ssh_fatal("ssh_socks_client_generate_open success (should fail, ip)");
      socksinfo->socks_version_number = 0;
      socksinfo->command_code = (pass % 4) + 90;
      if (ssh_socks_server_generate_reply(&buffer, socksinfo) ==
	  SSH_SOCKS_SUCCESS)
	ssh_fatal("ssh_socks_server_generate_reply success (should fail, ip)");
      ssh_socks_free(&socksinfo);
    }
  for(pass = 0;
      pass < (sizeof(port_invalid_numbers) / sizeof(port_invalid_numbers[0]));
      pass++)
    {
      socksinfo = ssh_xmalloc(sizeof(struct SocksInfoRec));
      socksinfo->socks_version_number = 4;
      socksinfo->command_code = (pass & 1) + 1;
      socksinfo->ip =
	ssh_xstrdup(ip_numbers[pass % (sizeof(ip_numbers) /
				   sizeof(ip_numbers[0]))]);
      socksinfo->port =
	ssh_xstrdup(port_invalid_numbers[pass % (sizeof(port_invalid_numbers) /
					     sizeof(port_invalid_numbers[0]))]);
      socksinfo->username =
	ssh_xstrdup(usernames[pass % (sizeof(usernames) /
				  sizeof(usernames[0]))]);
      if (ssh_socks_client_generate_open(&buffer, socksinfo) ==
	  SSH_SOCKS_SUCCESS)
	ssh_fatal("ssh_socks_client_generate_open success (should fail, port)");
      socksinfo->command_code = (pass % 4) + 90;
      socksinfo->socks_version_number = 0;
      if (ssh_socks_server_generate_reply(&buffer, socksinfo) ==
	  SSH_SOCKS_SUCCESS)
	ssh_fatal("ssh_socks_server_generate_reply success (should fail, port)");
      ssh_socks_free(&socksinfo);
    }
  if (ssh_buffer_len(&buffer) != 0)
    ssh_fatal("some of the failed ssh_socks_*_generate_* function wrote something to buffer, size != 0");
  ssh_buffer_uninit(&buffer);
  ssh_buffer_uninit(&buffer2);
  return 0;
}
