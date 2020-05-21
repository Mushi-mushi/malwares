/*
 *
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 * Copyright (c) 1998 SSH Communications Security Oy <info@ssh.fi>
 */
/*
 *        Program: sshutil
 *        $Source: /ssh/CVS/src/lib/sshutil/sshfileio.h,v $
 *        $Author: kivinen $
 *
 *        Creation          : 11:16 Oct  9 1998 kivinen
 *        Last Modification : 04:22 Nov 13 1998 kivinen
 *        Last check in     : $Date: 1998/11/18 14:06:37 $
 *        Revision number   : $Revision: 1.3 $
 *        State             : $State: Exp $
 *        Version           : 1.24
 *
 *        Description       : Read and write file from and to the disk
 *                            in various formats.
 *
 *        $Log: sshfileio.h,v $
 *        $EndLog$
 */

#ifndef SSHFILEIO_H
#define SSHFILEIO_H

/* Read binary file from the disk. Return mallocated buffer and the size of the
   buffer. If the reading of file failes return FALSE. If the file name is NULL
   or "-" then read from the stdin. */
Boolean ssh_read_file(const char *file_name,
                      unsigned char **buf,
                      size_t *buf_len);

/* Read base 64 encoded file from the disk. Return mallocated buffer and the
   size of the buffer. If the reading of file failes return FALSE. If the file
   name is NULL or "-" then read from the stdin. */
Boolean ssh_read_file_base64(const char *file_name,
                             unsigned char **buf,
                             size_t *buf_len);

/* Read hexl encoded file from the disk. Return mallocated buffer and the size
   of the buffer. If the reading of file failes return FALSE. If the file name
   is NULL or "-" then read from the stdin. */
Boolean ssh_read_file_hexl(const char *file_name,
                           unsigned char **buf,
                           size_t *buf_len);

/* Read pem/hexl/binary file from the disk. Return mallocated buffer and the
   size of the buffer. If the reading of file failes return FALSE. If the file
   name starts with :p: then assume file is pem encoded, if it starts with :h:
   then it is assumed to be hexl format, and if it starts with :b: then it is
   assumed to be binary. If no :[bph]: is given then file is assumed to be
   binary. If any other letter is given between colons then warning message is
   printed and operation fails. If the file name is NULL or "-" then
   read from the stdin (":p:-" == stdin in pem encoded format). */
Boolean ssh_read_gen_file(const char *file_name,
                          unsigned char **buf,
                          size_t *buf_len);

/* Write binary file to the disk. If the write fails retuns FALSE. If the file
   name is NULL or "-" then write to the stdout */
Boolean ssh_write_file(const char *file_name,
                       const unsigned char *buf,
                       size_t buf_len);

/* Write base 64 encoded file to the disk. If the write fails retuns FALSE. If
   the file name is NULL or "-" then write to the stdout. Begin and end are the
   PEM headers written before and after the PEM block. If they are NULL then no
   header/footer is written. */
Boolean ssh_write_file_base64(const char *file_name,
                              const char *begin,
                              const char *end,
                              const unsigned char *buf,
                              size_t buf_len);

/* Write hexl encoded file to the disk. If the write fails retuns FALSE. If the
   file name is NULL or "-" then write to the stdout */
Boolean ssh_write_file_hexl(const char *file_name,
                            const unsigned char *buf,
                            size_t buf_len);

/* Write pem/hexl/binary file from the disk. If the write fails retuns FALSE.
   If the file name starts with :p: then assume file is pem encoded, if it
   starts with :h: then it is assumed to be hexl format, and if it starts with
   :b: then it is assumed to be binary. If no :[bph]: is given then file is
   assumed to be binary. If any other letter is given between colons then
   warning message is printed and operation fails. If the file name is NULL or
   "-" then read from the stdout (":p:-" == stdout in pem encoded format). */
Boolean ssh_write_gen_file(const char *file_name,
                           const char *begin, 
                           const char *end, 
                           unsigned char *buf,
                           size_t buf_len);

/* Commonly used PEM begin and end strings */

/* Generic pem encoded block */
#define SSH_PEM_GENERIC_BEGIN     "-----BEGIN PEM ENCODED DATA-----"
#define SSH_PEM_GENERIC_END       "-----END PEM ENCODED DATA-----"
#define SSH_PEM_GENERIC           SSH_PEM_GENERIC_BEGIN, SSH_PEM_GENERIC_END

/* X.509 Certificate Block */
#define SSH_PEM_X509_BEGIN        "-----BEGIN X509 CERTIFICATE-----"
#define SSH_PEM_X509_END          "-----END X509 CERTIFICATE-----"
#define SSH_PEM_X509              SSH_PEM_X509_BEGIN, SSH_PEM_X509_END

/* SSH X.509 Private Key Block */
#define SSH_PEM_SSH_PRV_KEY_BEGIN "-----BEGIN SSH X.509 PRIVATE KEY-----"
#define SSH_PEM_SSH_PRV_KEY_END   "-----END SSH X.509 PRIVATE KEY-----"
#define SSH_PEM_SSH_PRV_KEY SSH_PEM_SSH_PRV_KEY_BEGIN, SSH_PEM_SSH_PRV_KEY_END

/* X.509 Certificate Revocation List Block */
#define SSH_PEM_X509_CRL_BEGIN    "-----BEGIN X509 CRL-----"
#define SSH_PEM_X509_CRL_END      "-----END X509 CRL-----"
#define SSH_PEM_X509_CRL          SSH_PEM_X509_CRL_BEGIN, SSH_PEM_X509_CRL_END

/* PKCS#10 Certificate Request Block */
#define SSH_PEM_CERT_REQ_BEGIN    "-----BEGIN CERTIFICATE REQUEST-----"
#define SSH_PEM_CERT_REQ_END      "-----END CERTIFICATE REQUEST-----"
#define SSH_PEM_CERT_REQ          SSH_PEM_CERT_REQ_BEGIN, SSH_PEM_CERT_REQ_END

#endif /* SSHFILEIO_H */
