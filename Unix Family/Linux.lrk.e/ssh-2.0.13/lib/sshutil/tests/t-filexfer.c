/*

t-filexfer.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1998 SSH Communications Security, Finland
                   All rights reserved

Simple test program for the file transfer functions.

*/

#include "sshincludes.h"
#include "sshunixeloop.h"
#include "sshstreampair.h"
#include "sshfilexfer.h"

SshFileServer server;
SshFileClient client;
SshFileHandle dir_handle;
SshFileHandle file_handle;
off_t file_offset;

int got_realpath;
char *new_dir;


void attrs_cb(SshFileClientError error,  SshFileAttributes attrs,
              void *context)
{
  if (error != SSH_FX_OK)
    {
      printf("attrs_cb: error %d\n", (int) error);
      return;
    }  
  
  printf("attrs_cb: flags=%x uid=%u gid=%u perm=%lo\n", 
         (unsigned) attrs->flags,
         (unsigned) attrs->uid,
         (unsigned) attrs->gid,
         attrs->permissions);  
}

void readdir_cb(SshFileClientError error, 
                const char *name, 
                const char *long_name, SshFileAttributes attrs,
                void *context)
{
  if (error != SSH_FX_OK)
    {
      printf("readdir_cb: error %d\n", (int)error);
      return;
    }

  printf("short name: %s\nlong name:  %s\nflags:      %lo\n\n", 
         name, long_name, attrs->permissions);
  ssh_file_client_readdir(dir_handle, readdir_cb, NULL);
}

void realpath_cb(SshFileClientError error, 
                const char *name, 
                const char *long_name, SshFileAttributes attrs,
                void *context)
{
  got_realpath = 1;
  
  if (error != SSH_FX_OK)
    {
      printf("realpath_cb: error %d\n", (int)error);
      return;
    }

  printf("realpath\nshort name: %s\nlong name:  %s\nflags:      %lo\n\n", 
          name, long_name, attrs->permissions);  
}

void rmdir_cb(SshFileClientError error, void *context)
{
  if (error != SSH_FX_OK)
    {
      printf("rmdir_cb: error %d\n", (int)error);
      return;
    }
  printf("successfully removed directory \"%s\"\n", new_dir);
  
}

void mkdir_cb(SshFileClientError error, void *context)
{
  if (error != SSH_FX_OK)
    {
      printf("mkdir_cb: error %d\n", (int)error);
      return;
    }

  printf("successfully created directory \"%s\"\n", new_dir);
  
  ssh_file_client_rmdir(client, new_dir, rmdir_cb, NULL);
}

void opendir_cb(SshFileClientError error, SshFileHandle handle, void *context)
{
  if (error != SSH_FX_OK)
    {
      printf("opendir_cb: error %d\n", (int)error);
      return;
    }

  dir_handle = handle;
  ssh_file_client_readdir(handle, readdir_cb, NULL);
}

void close_cb(SshFileClientError error, void *context)
{
  if (error != SSH_FX_OK)
    printf("close_cb: error %d\n", (int)error);
}

void read_cb(SshFileClientError error, const unsigned char *data, size_t len,
             void *context)
{
  if (error != SSH_FX_OK)
    {
      if (error != SSH_FX_EOF)
        printf("read_cb: error %d\n", (int)error);
      ssh_file_client_close(file_handle, close_cb, NULL);
      return;
    }
  write(1, data, len);
  file_offset += len;
  ssh_file_client_read(file_handle, file_offset, 100, read_cb, NULL);
}

void open_cb(SshFileClientError error, SshFileHandle handle, void *context)
{
  if (error != SSH_FX_OK)
    {
      printf("open_cb: %d\n", (int)error);
      return;
    }

  file_handle = handle;
  file_offset = 0;
  ssh_file_client_read(handle, file_offset, 100, read_cb, NULL);

}

int main(int argc, char **argv)
{
  SshStream s1, s2;
  char temp_string[256];
  

  new_dir = NULL;
  
  ssh_event_loop_initialize();
  
  ssh_stream_pair_create(&s1, &s2);
  server = ssh_file_server_wrap(s1);
  client = ssh_file_client_wrap(s2);

  got_realpath = 0;  

  snprintf(temp_string, sizeof(temp_string), "temp%d", getpid());
  new_dir = ssh_xstrdup(temp_string);
  printf("Trying to create directory \"%s\"\n", new_dir);
  
  ssh_file_client_mkdir(client, new_dir, NULL, mkdir_cb, NULL);
  ssh_file_client_realpath(client, ".", realpath_cb, NULL); 
  ssh_event_loop_run();  

  ssh_file_client_opendir(client, ".", opendir_cb, NULL);
  ssh_file_client_open(client, "t-filexfer.c", O_RDONLY, NULL, open_cb, NULL);
  ssh_event_loop_run();
   
  ssh_file_client_stat(client, "t-filexfer", attrs_cb, NULL);
  ssh_event_loop_run();
  
  ssh_event_loop_uninitialize();
  fflush(stdout);
  return 0;
}
