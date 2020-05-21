/*

  dlglue.h
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Thu May 22 16:28:11 1997 [mkojo]

  Discrete logarithms based public key routines.

  Note: this interface was not deviced to be called directly from
  applications. It is hard to use by standard applications. One should
  use the general interface, which is much more easier and as
  basically fast.

  */

/*
 * $Id: dlglue.h,v 1.5 1998/06/07 10:00:34 mkojo Exp $
 * $Log: dlglue.h,v $
 * $EndLog$
 */

#ifndef DLGLUE_H
#define DLGLUE_H

/* Action routines. */
unsigned int ssh_dlp_action_private_key_put(void *context, va_list *ap,
					    void *input_context,
					    SshPkFormat format);
unsigned int ssh_dlp_action_private_key_get(void *context, va_list *ap,
					    void **output_context,
					    SshPkFormat format);

unsigned int ssh_dlp_action_public_key_put(void *context, va_list *ap,
					    void *input_context,
					    SshPkFormat format);
unsigned int ssh_dlp_action_public_key_get(void *context, va_list *ap,
					   void **output_context,
					   SshPkFormat format);

unsigned int ssh_dlp_action_param_put(void *context, va_list *ap,
				      void *input_context,
				      SshPkFormat format);
unsigned int ssh_dlp_action_param_get(void *context, va_list *ap,
				      void **output_context,
				      SshPkFormat format);

/* Scheme flag setting functions. */
void ssh_dlp_dsa_nist(void *context);

/* Control of the action context. */
void *ssh_dlp_action_init(SshRandomState state);
void *ssh_dlp_action_public_key_init(void);

void *ssh_dlp_param_action_make(void *context);
void *ssh_dlp_private_key_action_make(void *context);
void *ssh_dlp_public_key_action_make(void *context);

void ssh_dlp_action_free(void *context);

/* Handle parameters. */
Boolean ssh_dlp_param_import(const unsigned char *buf, size_t len,
			     void **parameters);
Boolean ssh_dlp_param_export(const void *parameters,
			     unsigned char **buf, size_t *length_return);
void ssh_dlp_param_free(void *parameters);
void ssh_dlp_param_copy(void *param_src, void **param_dest);
char *ssh_dlp_param_get_predefined_groups(void);

/* Randomizer control. */
unsigned int ssh_dlp_param_count_randomizers(void *parameters);
Boolean ssh_dlp_param_generate_randomizer(void *parameters,
					  SshRandomState state);
Boolean ssh_dlp_param_export_randomizer(void *parameters,
					unsigned char **buf,
					size_t *length_return);
Boolean ssh_dlp_param_import_randomizer(void *parameters,
					unsigned char *buf,
					size_t length);

/* Basic public key functions. */
Boolean ssh_dlp_public_key_import(const unsigned char *buf,
				  size_t len,
				  void **public_key);
Boolean ssh_dlp_public_key_export(const void *public_key,
				  unsigned char **buf,
				  size_t *length_return);
void ssh_dlp_public_key_free(void *public_key);
void ssh_dlp_public_key_copy(void *key_src, void **key_dest);
void ssh_dlp_public_key_derive_param(void *public_key,
				     void **parameters);

/* Basic private key functions. */
Boolean ssh_dlp_private_key_import(const unsigned char *buf,
				   size_t len,
				   void **private_key);
Boolean ssh_dlp_private_key_export(const void *private_key,
				   unsigned char **buf,
				   size_t *length_return);
void ssh_dlp_private_key_free(void *private_key);
void ssh_dlp_private_key_derive_public_key(const void *private_key,
					   void **public_key);
void ssh_dlp_private_key_copy(void *key_src, void **key_dest);
void ssh_dlp_private_key_derive_param(void *private_key,
				      void **parameters);

/* Signature methods. */

size_t
ssh_dlp_dsa_private_key_max_signature_input_len(const void *private_key);
size_t
ssh_dlp_dsa_private_key_max_signature_output_len(const void *private_key);
Boolean ssh_dlp_dsa_private_key_sign(const void *private_key,
				     Boolean need_hashing,
				     const unsigned char *data,
				     size_t data_len,
				     unsigned char *signature_buffer,
				     size_t ssh_buffer_len,
				     size_t *signature_length_return,
				     SshRandomState state,
				     const SshHashDef *hash_def);
Boolean ssh_dlp_dsa_public_key_verify(const void *public_key,
				      const unsigned char *signature,
				      size_t signature_len,
				      Boolean need_hashing,
				      const unsigned char *data,
				      size_t data_len,
				      const SshHashDef *hash_def);
     
/* Encryption methods. */

/* Diffie-Hellman. */

size_t
ssh_dlp_diffie_hellman_exchange_length(const void *parameters);
size_t
ssh_dlp_diffie_hellman_shared_secret_length(const void *parameters);
Boolean ssh_dlp_diffie_hellman_generate(void *parameters,
					void **diffie_hellman,
					unsigned char *exchange,
					size_t exchange_length,
					size_t *return_length,
					SshRandomState state);
Boolean ssh_dlp_diffie_hellman_final(void *parameters,
				     void *diffie_hellman,
				     unsigned char *exchange,
				     size_t exchange_length,
				     unsigned char *secret_buffer,
				     size_t secret_buffer_length,
				     size_t *return_length);

/* Unified Diffie-Hellman */

size_t
ssh_dlp_unified_diffie_hellman_shared_secret_length(const void *parameters);
Boolean ssh_dlp_unified_diffie_hellman_final(const void *public_key,
					     const void *private_key,
					     void *diffie_hellman,
					     unsigned char *exchange,
					     size_t exchange_length,
					     unsigned char *secret_buffer,
					     size_t secret_buffer_length,
					     size_t *return_length);

/* One-way authentication. */


#endif /* DLGLUE.H */
