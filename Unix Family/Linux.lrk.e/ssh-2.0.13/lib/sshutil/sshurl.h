/*
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 * Copyright (c) 1998 Tero Kivinen <kivinen@ssh.fi>, Espoo, Finland
 * Copyright (c) 1998 SSH Communications Security Oy <info@ssh.fi>
 *                   All rights reserved
 */
/*
 *        Program: Urlparse
 *        $Source: /ssh/CVS/src/lib/sshutil/sshurl.h,v $
 *        $Author: tmo $
 *
 *        Creation          : 11:09 Jul 10 1998 kivinen
 *        Last Modification : 17:20 Jan 28 1999 kivinen
 *        Last check in     : $Date: 1999/04/22 14:21:23 $
 *        Revision number   : $Revision: 1.6 $
 *        State             : $State: Exp $
 *        Version           : 1.28
 *
 *        Description       : Header for library to parse urls
 */
/*
 * $Id: sshurl.h,v 1.6 1999/04/22 14:21:23 tmo Exp $
 * $EndLog$
 */

#ifndef SSHURL_H
#define SSHURL_H

#include "sshmapping.h"

/*
 * Parses url given in format
 * [<scheme>:][//[<user>[:<password>]@]<host>[:<port>]]/[<path>]
 * Returns true if the url is syntactically valid, false otherwise.
 * If the incorrect url format "www.ssh.fi" is given then returns FALSE and
 * sets host to contain whole url. If some piece of url is not given it is
 * set to NULL. If some of the pieces are not needed they can be NULL and
 * those pieces will be skipped.
 *
 * The values filled into `scheme', `host', `port´, `username´, 
 * `password', and `path' (if non null) are allocated by this call and 
 * should be freed by the caller.
 */
Boolean ssh_url_parse(const char *url, char **scheme, char **host,
                      char **port, char **username, char **password,
                      char **path);

/*
 * Decode url coding. If url_out is NULL then decode inplace, and
 * modify url.  Otherwise return new allocated string containing the
 * decoded buffer. Returns TRUE if decoding was successfull and FALSE
 * otherwise. Len is the length of the input url and length of the
 * returned url is in stored in the len_out if it is not NULL. The
 * decoded url is returned even if the decoding fails.
 *
 * Note that the the decoded buffer will always be null terminated.
 * If you are decoding in-place (url_out is NULL), the input url <url>
 * must have space for the trailing '\0' character.
 */
Boolean ssh_url_decode_bin(char *url, size_t len,
                           char **url_out, size_t *len_out);

/*
 * Decode url coding. If url_out is NULL then decode inplace, and modify url.
 * Otherwise return new allocated string containing the decoded buffer. Returns
 * TRUE if decoding was successfull and FALSE otherwise. The decoded url is
 * returned even if the decoding fails.
 */
Boolean ssh_url_decode(char *url, char **url_out);

/*
 * Parses url given in format
 * [<scheme>:][//[<user>[:<password>]@]<host>[:<port>]]/[<path>]
 * Returns true if the url is syntactically valid, false otherwise.
 * If the incorrect url format "www.ssh.fi" is given then returns FALSE and
 * sets host to contain whole url. If some piece of url is not given it is
 * set to NULL. If some of the pieces are not needed they can be NULL and
 * those pieces will be skipped. This version also decodeds url %-codings.
 *
 * The values filled into pieces are allocated by this call and they
 * should be freed by the caller.  
 */
Boolean ssh_url_parse_and_decode(const char *url, char **scheme, char **host,
                                 char **port, char **username, char **password,
                                 char **path);

/*
 * Decode http get url which have format:
 *
 *   /path?name=value&name=value&...&name=value
 *
 * The function returns the path in the beginning and a Mapping that
 * has all the name and value pairs stored.  If the same name appears
 * more than once in the URL, the values are concatenated into one
 * string and the individual values are separated with a newline
 * character.  The function also decodes all the %-encodings from the
 * name and values after splitting them.
 *
 * If `path' is not NULL then a mallocated copy of decoded path
 * component is stored there.
 *
 * The returned mapping is storing only pointers to the variable
 * length strings, and it has internal destructor, so calling
 * ssh_mapping_free will destroy it and its contents.
 *
 * Returns TRUE if everything went ok, and FALSE if there was a
 * decoding error while processing the url.  */
Boolean ssh_url_parse_form(const char *url,
                           char **path,
                           size_t *path_length,
                           SshMapping *mapping);

/*
 * Decode http post data which have format:
 *
 *   name=value&name=value&...&name=value
 *
 * Returns a Mapping that has all the name and value pairs stored. If
 * the same name appears more than once in the URL, the values are
 * concatenated into one string and the individual values are
 * separated with a newline character.  The function also decodes all
 * the %-encodings from the name and values after splitting them.
 *
 * Returned mapping is storing only pointers to the variable length
 * strings, and it has internal destructor, so calling
 * ssh_mapping_free will destroy it and its contents.
 *
 * Returns TRUE if everything went ok, and FALSE if there was a
 * decoding error while processing the url.
 */
Boolean ssh_url_parse_post_form(const char *url, SshMapping *mapping);

#endif /* SSHURL_H */
