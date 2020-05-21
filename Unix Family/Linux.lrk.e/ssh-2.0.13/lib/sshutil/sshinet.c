/*
  File: sshinet.c

  Authors: 
        Tero T Mononen <tmo@ssh.fi>
        Tero Kivinen <kivinen@ssh.fi>
        Tatu Ylonen <ylo@ssh.fi>

  Description: 
        IP related functions and definitions.

  Copyright:
        Copyright (c) 1998-1999 SSH Communications Security, Finland
        All rights reserved
*/

#include "sshincludes.h"
#include "sshinet.h"

#define SSH_DEBUG_MODULE "SshInet"

#define MAX_IP_ADDR_LEN 16

/* Mapping between protocol name and doi protocol number */
const SshKeyword ssh_ip_protocol_id_keywords[] = 
{
  { "any", SSH_IPPROTO_ANY },
  { "icmp", SSH_IPPROTO_ICMP },
  { "igmp", SSH_IPPROTO_IGMP },
  { "ggp", SSH_IPPROTO_GGP },
  { "ipip", SSH_IPPROTO_IPIP },
  { "st", SSH_IPPROTO_ST },
  { "tcp", SSH_IPPROTO_TCP },
  { "cbt", SSH_IPPROTO_CBT },
  { "egp", SSH_IPPROTO_EGP },
  { "igp", SSH_IPPROTO_IGP },
  { "bbn", SSH_IPPROTO_BBN },
  { "nvp", SSH_IPPROTO_NVP },
  { "pup", SSH_IPPROTO_PUP },
  { "argus", SSH_IPPROTO_ARGUS },
  { "emcon", SSH_IPPROTO_EMCON },
  { "xnet", SSH_IPPROTO_XNET },
  { "chaos", SSH_IPPROTO_CHAOS },
  { "udp", SSH_IPPROTO_UDP },
  { "mux", SSH_IPPROTO_MUX },
  { "dcn", SSH_IPPROTO_DCN },
  { "hmp", SSH_IPPROTO_HMP },
  { "prm", SSH_IPPROTO_PRM },
  { "xns", SSH_IPPROTO_XNS },
  { "trunk1", SSH_IPPROTO_TRUNK1 },
  { "trunk2", SSH_IPPROTO_TRUNK2 },
  { "leaf1", SSH_IPPROTO_LEAF1 },
  { "leaf2", SSH_IPPROTO_LEAF2 },
  { "rdp", SSH_IPPROTO_RDP },
  { "irtp", SSH_IPPROTO_IRTP },
  { "isotp4", SSH_IPPROTO_ISOTP4 },
  { "netblt", SSH_IPPROTO_NETBLT },
  { "mfe", SSH_IPPROTO_MFE },
  { "merit", SSH_IPPROTO_MERIT },
  { "sep", SSH_IPPROTO_SEP },
  { "3pc", SSH_IPPROTO_3PC },
  { "idpr", SSH_IPPROTO_IDPR },
  { "xtp", SSH_IPPROTO_XTP },
  { "ddp", SSH_IPPROTO_DDP },
  { "idprc", SSH_IPPROTO_IDPRC },
  { "tp", SSH_IPPROTO_TP },
  { "il", SSH_IPPROTO_IL },
  { "ipv6", SSH_IPPROTO_IPV6 },
  { "sdrp", SSH_IPPROTO_SDRP },
  { "ipv6route", SSH_IPPROTO_IPV6ROUTE },
  { "ipv6frag", SSH_IPPROTO_IPV6FRAG },
  { "idrp", SSH_IPPROTO_IDRP },
  { "rsvp", SSH_IPPROTO_RSVP },
  { "gre", SSH_IPPROTO_GRE },
  { "mhrp", SSH_IPPROTO_MHRP },
  { "bna", SSH_IPPROTO_BNA },
  { "esp", SSH_IPPROTO_ESP },
  { "ah", SSH_IPPROTO_AH },
  { "inlsp", SSH_IPPROTO_INLSP },
  { "swipe", SSH_IPPROTO_SWIPE },
  { "narp", SSH_IPPROTO_NARP },
  { "mobile", SSH_IPPROTO_MOBILE },
  { "tlsp", SSH_IPPROTO_TLSP },
  { "skip", SSH_IPPROTO_SKIP },
  { "ipv6icmp", SSH_IPPROTO_IPV6ICMP },
  { "ipv6nonxt", SSH_IPPROTO_IPV6NONXT },
  { "ipv6opts", SSH_IPPROTO_IPV6OPTS },
  { "cftp", SSH_IPPROTO_CFTP },
  { "local", SSH_IPPROTO_LOCAL },
  { "sat", SSH_IPPROTO_SAT },
  { "kryptolan", SSH_IPPROTO_KRYPTOLAN },
  { "rvd", SSH_IPPROTO_RVD },
  { "ippc", SSH_IPPROTO_IPPC },
  { "distfs", SSH_IPPROTO_DISTFS },
  { "satmon", SSH_IPPROTO_SATMON },
  { "visa", SSH_IPPROTO_VISA },
  { "ipcv", SSH_IPPROTO_IPCV },
  { "cpnx", SSH_IPPROTO_CPNX },
  { "cphb", SSH_IPPROTO_CPHB },
  { "wsn", SSH_IPPROTO_WSN },
  { "pvp", SSH_IPPROTO_PVP },
  { "brsatmon", SSH_IPPROTO_BRSATMON },
  { "sunnd", SSH_IPPROTO_SUNND },
  { "wbmon", SSH_IPPROTO_WBMON },
  { "wbexpak", SSH_IPPROTO_WBEXPAK },
  { "isoip", SSH_IPPROTO_ISOIP },
  { "vmtp", SSH_IPPROTO_VMTP },
  { "securevmtp", SSH_IPPROTO_SECUREVMTP },
  { "vines", SSH_IPPROTO_VINES },
  { "ttp", SSH_IPPROTO_TTP },
  { "nsfnet", SSH_IPPROTO_NSFNET },
  { "dgp", SSH_IPPROTO_DGP },
  { "tcf", SSH_IPPROTO_TCF },
  { "eigrp", SSH_IPPROTO_EIGRP },
  { "ospfigp", SSH_IPPROTO_OSPFIGP },
  { "sprite", SSH_IPPROTO_SPRITE },
  { "larp", SSH_IPPROTO_LARP },
  { "mtp", SSH_IPPROTO_MTP },
  { "ax25", SSH_IPPROTO_AX25 },
  { "ipwip", SSH_IPPROTO_IPWIP },
  { "micp", SSH_IPPROTO_MICP },
  { "scc", SSH_IPPROTO_SCC },
  { "etherip", SSH_IPPROTO_ETHERIP },
  { "encap", SSH_IPPROTO_ENCAP },
  { "encrypt", SSH_IPPROTO_ENCRYPT },
  { "gmtp", SSH_IPPROTO_GMTP },
  { "ifmp", SSH_IPPROTO_IFMP },
  { "pnni", SSH_IPPROTO_PNNI },
  { "pim", SSH_IPPROTO_PIM },
  { "aris", SSH_IPPROTO_ARIS },
  { "scps", SSH_IPPROTO_SCPS },
  { "qnx", SSH_IPPROTO_QNX },
  { "an", SSH_IPPROTO_AN },
  { "ippcp", SSH_IPPROTO_IPPCP },
  { "snp", SSH_IPPROTO_SNP },
  { "compaq", SSH_IPPROTO_COMPAQ },
  { "ipxip", SSH_IPPROTO_IPXIP },
  { "vrrp", SSH_IPPROTO_VRRP },
  { "pgm", SSH_IPPROTO_PGM },
  { "0hop", SSH_IPPROTO_0HOP },
  { "l2tp", SSH_IPPROTO_L2TP },
  { "reserved", SSH_IPPROTO_RESERVED },
  { NULL, 0 }
};

/* Determines whether the given string is a valid numeric IP address.
   (This currently only works for IPv4 addresses, but might be changed
   in future to accept also IPv6 addresses on systems that support
   them. */

Boolean ssh_inet_is_valid_ip_address(const char *address)
{
  int i, num;

  /* Loop over four groups of numbers. */
  for (i = 0; i < 4; i++)
    {
      /* Each but the first group must be preceded by a dot. */
      if (i != 0)
        {    
          if (*address != '.')
            return FALSE;
          else
            address++;
        }
      
      /* Each group must begin with a digit (now that we have skipped the
         dot). */
      if (*address < '0' || *address > '9')
        return FALSE;

      /* Parse the group of digits as a number.  Check that the group does
         not have a value greater than 255.  Beware of overflows. */
      for (num = 0; *address >= '0' && *address <= '9' && num < 256; address++)
        num = 10 * num + *address - '0';
      if (num > 255)
        return FALSE;
    }

  /* After the four groups of numbers, we must be at end of string. */
  if (*address != '\0')
    return FALSE;

  /* Yes, it is a valid IPv4 address. */
  return TRUE;
}

/* Convert ip number string to binary format. The binary format is
   unsigned character array containing the ip address in network byte
   order. If the ip address is ipv4 address then this fills 4 bytes to
   the buffer, if it is ipv6 address then this will fills 16 bytes to
   the buffer. The buffer length is modified accordingly. This returns
   TRUE if the address is valid and conversion is successful (the
   buffer is large enough) and FALSE otherwise.  */

Boolean ssh_inet_strtobin(const char *ip_address, 
                          unsigned char *out_buffer,
                          size_t *out_buffer_len_in_out)
{
  SshIpAddr ipaddr;

  /* Parse the IP address.  Return FALSE on error.*/
  if (!ssh_ipaddr_parse(&ipaddr, ip_address))
    return FALSE;

  /* Convert the IP address to binary. */
  if (SSH_IP_IS6(&ipaddr))
    {
      if (*out_buffer_len_in_out < 16)
        return FALSE;
      SSH_IP6_ENCODE(&ipaddr, out_buffer);
      *out_buffer_len_in_out = 16;
    }
  else
    {
      if (*out_buffer_len_in_out < 4)
        return FALSE;
      SSH_IP4_ENCODE(&ipaddr, out_buffer);
      *out_buffer_len_in_out = 4;
    }
  return TRUE;
}

/* Compares comma separated list of ip nets and ip-address. Returns
   TRUE if ip-address is inside one of the nets given in
   net-address/netmask-bits format. */

Boolean ssh_inet_compare_netmask(const char *netmask, const char *ip_in)
{
  unsigned char net[MAX_IP_ADDR_LEN], mask[MAX_IP_ADDR_LEN],
    ip[MAX_IP_ADDR_LEN];
  size_t len;
  char temp_buffer[256], *p, *next;
  int mask_bits;

  memset(net, 0, MAX_IP_ADDR_LEN);
  memset(ip, 0, MAX_IP_ADDR_LEN);

  len = MAX_IP_ADDR_LEN;
  if (!ssh_inet_strtobin(ip_in, ip, &len))
    return FALSE;

  if (len == 4)
    {
      memmove(ip + 12, ip, 4);
      memset(ip, 0, 4);
    }
  do {
    p = strchr(netmask, ',');
    if (p != NULL)
      {
        next = p + 1;
        if (p - netmask < sizeof(temp_buffer))
          {
            strncpy(temp_buffer, netmask, p - netmask);
            temp_buffer[p - netmask] = '\0';
          }
        else
          {
            strncpy(temp_buffer, netmask, sizeof(temp_buffer));
            temp_buffer[sizeof(temp_buffer) - 1] = '\0';
          }
      }
    else
      {
        next = NULL;
        strncpy(temp_buffer, netmask, sizeof(temp_buffer));
        temp_buffer[sizeof(temp_buffer) - 1] = '\0';
      }
    p = strrchr(temp_buffer, '/');
    if (p == NULL)
      {
        mask_bits = MAX_IP_ADDR_LEN * 8;
      }
    else
      {
        *p++ = '\0';
        if (*p < '0' || *p > '9')
          mask_bits = -1;
        else
          {
            for (mask_bits = 0; *p >= '0' && *p <= '9'; p++)
              mask_bits = 10 * mask_bits + *p - '0';
          }
      }
    len = MAX_IP_ADDR_LEN;
    if (ssh_inet_strtobin(temp_buffer, net, &len) && mask_bits != -1)
      {
        if (len == 4)
          {
            memmove(net + 12, net, 4);
            memset(net, 0, 4);
            mask_bits += 96;
          }
        if (mask_bits > 128)
          mask_bits = 128;

        memset(mask, 0, MAX_IP_ADDR_LEN);
        memset(mask, 255, mask_bits / 8);
        if (mask_bits % 8 != 0)
          mask[mask_bits / 8] =
            "\000\200\300\340\360\370\374\376"[mask_bits % 8];
        for(len = 0; len < MAX_IP_ADDR_LEN; len++)
          {
            if ((ip[len] & mask[len]) != (net[len] & mask[len]))
              break;
          }
        if (len == MAX_IP_ADDR_LEN)
          return TRUE;
      }
    netmask = next;
  } while (netmask != NULL);
  return FALSE;
}


/* Compares two IP addresses, and returns <0 if address1 is smaller
   (in some implementation-defined sense, usually numerically), 0 if
   they denote the same address (though possibly written differently),
   and >0 if address2 is smaller (in the implementation-defined
   sense).  The result is zero if either address is invalid. */

int ssh_inet_ip_address_compare(const char *address1, const char *address2)
{
  SshIpAddr ipaddr1, ipaddr2;

  if (!ssh_ipaddr_parse(&ipaddr1, address1) ||
      !ssh_ipaddr_parse(&ipaddr2, address2))
    return 0;

  if (SSH_IP_EQUAL(&ipaddr1, &ipaddr2))
    return 0;

  if (SSH_IP_IS6(&ipaddr1) || SSH_IP_IS6(&ipaddr2))
    {
      SSH_DEBUG(0, ("ipv6 not yet supported"));
      return 0;
    }

  if (SSH_IP4_TO_INT(&ipaddr1) < SSH_IP4_TO_INT(&ipaddr2))
    return -1;
  else
    return 1;
}

/* Produces a value that can (modulo a prime) be used as a hash value for
   the ip address.  The value is suitable for use with a prime-sized hash
   table. */

unsigned long ssh_ipaddr_hash(SshIpAddr *ip)
{
  unsigned long value;
  size_t len;
  unsigned int i;

  len = SSH_IP_IS6(ip) ? 16 : 4;
  for (i = 0, value = 0; i < len; i++)
    value = 257 * value + ip->data[i] + 3 * (value >> 23);
  return value;
}

/* Sets all rightmost bits after keeping `keep_bits' bits on the left to
   the value specified by `value'. */

void ssh_ipaddr_set_bits(SshIpAddr *result, SshIpAddr *ip,
                         unsigned int keep_bits, unsigned int value)
{
  size_t len;
  unsigned int i;

  len = SSH_IP_IS6(ip) ? 16 : 4;

  *result = *ip;
  for (i = keep_bits / 8; i < len; i++)
    {
      if (8 * i >= keep_bits)
        result->data[i] = value ? 0xff : 0;
      else
        {
          SSH_ASSERT(keep_bits - 8 * i < 8);
          result->data[i] &= (0xff << (8 - keep_bits - 8 * i));
          if (value)
            result->data[i] |= (0xff >> (keep_bits - 8 * i));
        }
    }
}

/* Parses an IP address from the string to the internal representation. */

Boolean ssh_ipaddr_parse(SshIpAddr *ip, const char *str)
{
  int i, value;
  
  /* Currently, only IPv4 is supported. */
  ip->is6 = 0;
  for (i = 0; i < 4; i++)
    {
      if (i != 0)
        {
          if (*str == '.')
            str++;
          else
            return FALSE;
        }
      for (value = 0; *str >= '0' && *str <= '9'; str++)
        {
          value = 10 * value + *str - '0';
          if (value > 255)
            return FALSE;
        }
      ip->data[i] = value;
    }
  if (*str)
    return FALSE;
  return TRUE;
}

/* Prints the IP address into the buffer in string format.  If the buffer
   is too short, the address is truncated.  This returns `buf'. */

char *ssh_ipaddr_print(SshIpAddr *ip, char *buf, size_t buflen)
{
  char largebuf[64];

  /* Currently, only IPv4 is supported. */
  if (!SSH_IP_IS6(ip))
    snprintf(largebuf, sizeof(largebuf), "%d.%d.%d.%d",
             SSH_IP4_BYTE1(ip), SSH_IP4_BYTE2(ip),
             SSH_IP4_BYTE3(ip), SSH_IP4_BYTE4(ip));
  else
    ssh_fatal("ssh_ipaddr_print: unsupported address type %d", (int)ip->is6);

  /* Copy to the caller-supplied buffer. */
  strncpy(buf, largebuf, buflen);
  buf[buflen - 1] = '\0';
  return buf;
}

/* Compares two IP addresses in the internal representation and returns
   TRUE if they are equal. */

Boolean ssh_ipaddr_mask_equal(SshIpAddr *ip1, SshIpAddr *ip2, SshIpAddr *mask)
{
  unsigned int i, len;
  if (ip1->is6 != ip2->is6 || ip2->is6 != mask->is6)
    return FALSE;
  len = SSH_IP_IS6(ip1) ? 16 : 4;
  for (i = 0; i < len; i++)
    {
      if ((ip1->data[i] & mask->data[i]) != (ip2->data[i] & mask->data[i]))
        return FALSE;
    }
  return TRUE;
}
