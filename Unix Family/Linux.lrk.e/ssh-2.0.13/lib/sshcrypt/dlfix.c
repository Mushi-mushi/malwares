/*

  dlfix.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996,1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Mon Jul 21 15:01:19 1997 [mkojo]
  
  Discrete logarithm predefined parameters. 

  */

/*
 * $Id: dlfix.c,v 1.7 1999/04/29 13:37:52 huima Exp $
 * $Log: dlfix.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshmp.h" /* was "gmp.h" */
#include "sshcrypt.h"
#include "genmp.h"
#include "sshbuffer.h"
#include "sshgetput.h"

/* Structure definition of parameters that are needed to store. */

typedef struct
{
  const char *name;
  const char *p;
  const char *q;
  const char *g;
} SshDLFixedParams;

/* All fixed parameters should satisfy atleast:

   - generate randomly (as much as possible)
   - p = q*c, where p and q are both prime
   - g^q (mod p) = 1

   Those restrictions can be ignored somewhat but then naming should not
   include "ssh". XXX */

#define SSH_DEFAULT_DL_MODP_PARAM_NAME "ssh-dl-modp-group-1024bit-1"

const SshDLFixedParams ssh_dlp_fixed_params[] =
{
  {
    /* 1024 bits with 160 bit order. */
    "ssh-dl-modp-group-dsa-1024bit-1",

     /* p */
    "18870663758990450276373834564151209634609185541696849681710763012"
    "47168050869633674293178701749077483982698046837347550634094699186"
    "01446907583820305901431915822615633146396545907952461810328182170"
    "35078613084684987462347222332164074368740586436373161810202065699"
    "4755732156870258013519880675646961814649650297159",

    /* q */
    "994432737688160994497917820104112624205251325913",

    /* g */
    "13752365807134022918504845143590215341528782407193227118193168220"
    "74331779978192018552914874329836913766220048777129900873815708450"
    "16796174527842910698477887372037694495736629521026242476079522482"
    "50227332682970988562298735692890934535992768521461586958206432475"
    "6777888883265989982517946734947352536810316486901"
  },
  
  {
    /* 1024 bits DSA style. */
    "ssh-dl-modp-group-1024bit-1",

    "179769313486231590770839156793787453197860296048756011706444"
    "423684197180216158519368947833795864925541502180565485980503"
    "646440548199239100050792877003355816639229553136239076508735"
    "759914822574862575007425302077447712589550957937778424442426"
    "617334727629299387668709205606050270810842907692932019128194"
    "467627007",
    "898846567431157953854195783968937265989301480243780058532222"
    "118420985901080792596844739168979324627707510902827429902518"
    "232202740996195500253964385016779083196147765681195382543678"
    "799574112874312875037126510387238562947754789688892122212133"
    "086673638146496938343546028030251354054214538464660095640972"
    "33813503",
     "2" },

  /* IKE groups. */
  {
    "ietf-ike-grp-modp-768",
    "0x"
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
    "E485B576 625E7EC6 F44C42E9 A63A3620 FFFFFFFF FFFFFFFF",
    "0x"
    "7FFFFFFF FFFFFFFF E487ED51 10B4611A 62633145 C06E0E68"
    "94812704 4533E63A 0105DF53 1D89CD91 28A5043C C71A026E"
    "F7CA8CD9 E69D218D 98158536 F92F8A1B A7F09AB6 B6A8E122"
    "F242DABB 312F3F63 7A262174 D31D1B10 7FFFFFFF FFFFFFFF",
    "0x2"
  },
  {
    "ietf-ike-grp-modp-1024",
    /* prime */
    "0x"
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381"
    "FFFFFFFF FFFFFFFF",
    /* LPF */
    "0x"
    "7FFFFFFF FFFFFFFF E487ED51 10B4611A 62633145 C06E0E68"
    "94812704 4533E63A 0105DF53 1D89CD91 28A5043C C71A026E"
    "F7CA8CD9 E69D218D 98158536 F92F8A1B A7F09AB6 B6A8E122"
    "F242DABB 312F3F63 7A262174 D31BF6B5 85FFAE5B 7A035BF6"
    "F71C35FD AD44CFD2 D74F9208 BE258FF3 24943328 F67329C0"
    "FFFFFFFF FFFFFFFF",
    /* generator */
    "0x2"
  },
  {
    "ietf-ike-grp-modp-1536",
    /* prime */
    "0x"
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
    "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
    "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
    "670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF",
    /* LPF */
    "0x"
    "7FFFFFFF FFFFFFFF E487ED51 10B4611A 62633145 C06E0E68"
    "94812704 4533E63A 0105DF53 1D89CD91 28A5043C C71A026E"
    "F7CA8CD9 E69D218D 98158536 F92F8A1B A7F09AB6 B6A8E122"
    "F242DABB 312F3F63 7A262174 D31BF6B5 85FFAE5B 7A035BF6"
    "F71C35FD AD44CFD2 D74F9208 BE258FF3 24943328 F6722D9E"
    "E1003E5C 50B1DF82 CC6D241B 0E2AE9CD 348B1FD4 7E9267AF"
    "C1B2AE91 EE51D6CB 0E3179AB 1042A95D CF6A9483 B84B4B36"
    "B3861AA7 255E4C02 78BA3604 6511B993 FFFFFFFF FFFFFFFF",
    /* generator */
    "0x2"
  },  
  { NULL }
};

char *ssh_dlp_param_get_predefined_groups(void)
{
  char *list;
  SshBuffer buffer;
  unsigned int i;

  ssh_buffer_init(&buffer);
  for (i = 0; ssh_dlp_fixed_params[i].name; i++)
    {
      if (ssh_buffer_len(&buffer) > 0)
        ssh_buffer_append(&buffer, (unsigned char *) ",", 1);
      ssh_buffer_append(&buffer,
                        (unsigned char *) ssh_dlp_fixed_params[i].name,
                        strlen(ssh_dlp_fixed_params[i].name));
    }
  ssh_buffer_append(&buffer, (unsigned char *) "\0", 1);
  list = ssh_xstrdup(ssh_buffer_ptr(&buffer));
  ssh_buffer_uninit(&buffer);
  return list;
}

Boolean ssh_dlp_set_param(const char *name, const char **outname,
                          SshInt *p, SshInt *q, SshInt *g)
{
  int i;

  if (name == NULL)
    name = SSH_DEFAULT_DL_MODP_PARAM_NAME;

  for (i = 0; ssh_dlp_fixed_params[i].name; i++)
    {
      if (strcmp(ssh_dlp_fixed_params[i].name, name) == 0)
        break;
    }
  if (ssh_dlp_fixed_params[i].name == NULL)
    return FALSE;

  *outname = ssh_dlp_fixed_params[i].name;
  
  ssh_mp_set_str(p, ssh_dlp_fixed_params[i].p, 0);
  ssh_mp_set_str(q, ssh_dlp_fixed_params[i].q, 0);
  ssh_mp_set_str(g, ssh_dlp_fixed_params[i].g, 0);
  
  return TRUE;
}

/* dlfix.c */
