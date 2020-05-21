/* random.c  -	random number generator
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


/****************
 * This random number generator is modelled after the one described
 * in Peter Gutmann's Paper: "Software Generation of Practically
 * Strong Random Numbers".
 */


#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#ifdef	HAVE_GETHRTIME
  #include <sys/times.h>
#endif
#ifdef HAVE_GETTIMEOFDAY
  #include <sys/times.h>
#endif
#ifdef HAVE_CLOCK_GETTIME
  #include <time.h>
#endif
#ifdef HAVE_GETRUSAGE
  #include <sys/resource.h>
#endif
#ifdef __MINGW32__
  #include <process.h>
#endif
#include "util.h"
#include "ttyio.h"
#include "i18n.h"
#include "random.h"
#include "rand-internal.h"
#include "dynload.h"


#ifndef RAND_MAX   /* for SunOS */
  #define RAND_MAX 32767
#endif


#if SIZEOF_UNSIGNED_LONG == 8
  #define ADD_VALUE 0xa5a5a5a5a5a5a5a5
#elif SIZEOF_UNSIGNED_LONG == 4
  #define ADD_VALUE 0xa5a5a5a5
#else
  #error weird size for an unsigned long
#endif

#define BLOCKLEN  64   /* hash this amount of bytes */
#define DIGESTLEN 20   /* into a digest of this length (rmd160) */
/* poolblocks is the number of digests which make up the pool
 * and poolsize must be a multiple of the digest length
 * to make the AND operations faster, the size should also be
 * a multiple of ulong
 */
#define POOLBLOCKS 30
#define POOLSIZE (POOLBLOCKS*DIGESTLEN)
#if (POOLSIZE % SIZEOF_UNSIGNED_LONG)
  #error Please make sure that poolsize is a multiple of ulong
#endif
#define POOLWORDS (POOLSIZE / SIZEOF_UNSIGNED_LONG)


static int is_initialized;
#define MASK_LEVEL(a) do {if( a > 2 ) a = 2; else if( a < 0 ) a = 0; } while(0)
static char *rndpool;	/* allocated size is POOLSIZE+BLOCKLEN */
static char *keypool;	/* allocated size is POOLSIZE+BLOCKLEN */
static size_t pool_readpos;
static size_t pool_writepos;
static int pool_filled;
static int pool_balance;
static int just_mixed;
static int did_initial_extra_seeding;
static char *seed_file_name;
static int allow_seed_file_update;

static int secure_alloc;
static int quick_test;
static int faked_rng;


static void read_pool( byte *buffer, size_t length, int level );
static void add_randomness( const void *buffer, size_t length, int source );
static void random_poll(void);
static void read_random_source( int requester, size_t length, int level);
static int gather_faked( void (*add)(const void*, size_t, int), int requester,
						    size_t length, int level );

static struct {
    ulong mixrnd;
    ulong mixkey;
    ulong slowpolls;
    ulong fastpolls;
    ulong getbytes1;
    ulong ngetbytes1;
    ulong getbytes2;
    ulong ngetbytes2;
    ulong addbytes;
    ulong naddbytes;
} rndstats;

static void
initialize(void)
{
    /* The data buffer is allocated somewhat larger, so that
     * we can use this extra space (which is allocated in secure memory)
     * as a temporary hash buffer */
    rndpool = secure_alloc ? m_alloc_secure_clear(POOLSIZE+BLOCKLEN)
			   : m_alloc_clear(POOLSIZE+BLOCKLEN);
    keypool = secure_alloc ? m_alloc_secure_clear(POOLSIZE+BLOCKLEN)
			   : m_alloc_clear(POOLSIZE+BLOCKLEN);
    is_initialized = 1;
/*    cipher_modules_constructor(); */
}


void
random_dump_stats()
{
    fprintf(stderr,
	    "random usage: poolsize=%d mixed=%lu polls=%lu/%lu added=%lu/%lu\n"
	    "              outmix=%lu getlvl1=%lu/%lu getlvl2=%lu/%lu\n",
	POOLSIZE, rndstats.mixrnd, rndstats.slowpolls, rndstats.fastpolls,
		  rndstats.naddbytes, rndstats.addbytes,
	rndstats.mixkey, rndstats.ngetbytes1, rndstats.getbytes1,
		    rndstats.ngetbytes2, rndstats.getbytes2 );
}

void
secure_random_alloc()
{
    secure_alloc = 1;
}


int
quick_random_gen( int onoff )
{
    int last;

    read_random_source(0,0,0); /* init */
    last = quick_test;
    if( onoff != -1 )
	quick_test = onoff;
    return faked_rng? 1 : last;
}


/****************
 * Fill the buffer with LENGTH bytes of cryptographically strong
 * random bytes. level 0 is not very strong, 1 is strong enough
 * for most usage, 2 is good for key generation stuff but may be very slow.
 */
void
randomize_buffer( byte *buffer, size_t length, int level )
{
    char *p = get_random_bits( length*8, level, 1 );
    memcpy( buffer, p, length );
    m_free(p);
}


int
random_is_faked()
{
    if( !is_initialized )
	initialize();
    return faked_rng || quick_test;
}

/****************
 * Return a pointer to a randomized buffer of level 0 and LENGTH bits
 * caller must free the buffer.
 * Note: The returned value is rounded up to bytes.
 */
byte *
get_random_bits( size_t nbits, int level, int secure )
{
    byte *buf, *p;
    size_t nbytes = (nbits+7)/8;
    if( quick_test && level > 1 )
	level = 1;
    MASK_LEVEL(level);
    if( level == 1 ) {
	rndstats.getbytes1 += nbytes;
	rndstats.ngetbytes1++;
    }
    else if( level >= 2 ) {
	rndstats.getbytes2 += nbytes;
	rndstats.ngetbytes2++;
    }

    buf = malloc(nbytes);
    for( p = buf; nbytes > 0; ) {
	size_t n = nbytes > POOLSIZE? POOLSIZE : nbytes;
	read_pool( p, n, level );
	nbytes -= n;
	p += n;
    }
    return buf;
}


/****************
 * Mix the pool
 */
static void
mix_pool(byte *pool)
{
    char *hashbuf = pool + POOLSIZE;
    char *p, *pend;
    int i, n;

 #if DIGESTLEN != 20
    #error must have a digest length of 20 for ripe-md-160
 #endif
    /* loop over the pool */
    pend = pool + POOLSIZE;
    memcpy(hashbuf, pend - DIGESTLEN, DIGESTLEN );
    memcpy(hashbuf+DIGESTLEN, pool, BLOCKLEN-DIGESTLEN);
    memcpy(pool, hashbuf, 20 );

    p = pool;
    for( n=1; n < POOLBLOCKS; n++ ) {
	memcpy(hashbuf, p, DIGESTLEN );

	p += DIGESTLEN;
	if( p+DIGESTLEN+BLOCKLEN < pend )
	    memcpy(hashbuf+DIGESTLEN, p+DIGESTLEN, BLOCKLEN-DIGESTLEN);
	else {
	    char *pp = p+DIGESTLEN;
	    for(i=DIGESTLEN; i < BLOCKLEN; i++ ) {
		if( pp >= pend )
		    pp = pool;
		hashbuf[i] = *pp++;
	    }
	}

	memcpy(p, hashbuf, 20 );
    }
}


void
set_random_seed_file( const char *name )
{
    if( seed_file_name )
	BUG();
    seed_file_name = m_strdup( name );
}

/****************
 * Read in a seed form the random_seed file
 * and return true if this was successful
 */
static int
read_seed_file()
{
    int fd;
    struct stat sb;
    unsigned char buffer[POOLSIZE];
    int n;

    if( !seed_file_name )
	return 0;

  #ifdef HAVE_DOSISH_SYSTEM
    fd = open( seed_file_name, O_RDONLY | O_BINARY );
  #else
    fd = open( seed_file_name, O_RDONLY );
  #endif
    if( fd == -1 && errno == ENOENT) {
	allow_seed_file_update = 1;
	return 0;
    }

    if( fd == -1 ) {
	log_info(_("can't open `%s': %s\n"), seed_file_name, strerror(errno) );
	return 0;
    }
    if( fstat( fd, &sb ) ) {
	log_info(_("can't stat `%s': %s\n"), seed_file_name, strerror(errno) );
	close(fd);
	return 0;
    }
    if( !S_ISREG(sb.st_mode) ) {
	log_info(_("`%s' is not a regular file - ignored\n"), seed_file_name );
	close(fd);
	return 0;
    }
    if( !sb.st_size ) {
	log_info(_("note: random_seed file is empty\n") );
	close(fd);
	allow_seed_file_update = 1;
	return 0;
    }
    if( sb.st_size != POOLSIZE ) {
	log_info(_("warning: invalid size of random_seed file - not used\n") );
	close(fd);
	return 0;
    }
    do {
	n = read( fd, buffer, POOLSIZE );
    } while( n == -1 && errno == EINTR );
    if( n != POOLSIZE ) {
	log_fatal(_("can't read `%s': %s\n"), seed_file_name,strerror(errno) );
	close(fd);
	return 0;
    }

    close(fd);

    add_randomness( buffer, POOLSIZE, 0 );
    /* add some minor entropy to the pool now (this will also force a mixing) */
    {	pid_t x = getpid();
	add_randomness( &x, sizeof(x), 0 );
    }
    {	time_t x = time(NULL);
	add_randomness( &x, sizeof(x), 0 );
    }
    {	clock_t x = clock();
	add_randomness( &x, sizeof(x), 0 );
    }
    /* And read a few bytes from our entropy source.  By using
     * a level of 0 this will not block and might not return anything
     * with some entropy drivers, however the rndlinux driver will use
     * /dev/urandom and return some stuff - Do not read to much as we
     * want to be friendly to the scare system entropy resource. */
    read_random_source( 0, 16, 0 );

    allow_seed_file_update = 1;
    return 1;
}

void
update_random_seed_file()
{
    ulong *sp, *dp;
    int fd, i;

    if( !seed_file_name || !is_initialized || !pool_filled )
	return;
    if( !allow_seed_file_update ) {
	log_info(_("note: random_seed file not updated\n"));
	return;
    }


    /* copy the entropy pool to a scratch pool and mix both of them */
    for(i=0,dp=(ulong*)keypool, sp=(ulong*)rndpool;
				    i < POOLWORDS; i++, dp++, sp++ ) {
	*dp = *sp + ADD_VALUE;
    }
    mix_pool(rndpool); rndstats.mixrnd++;
    mix_pool(keypool); rndstats.mixkey++;

  #ifdef HAVE_DOSISH_SYSTEM
    fd = open( seed_file_name, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY,
							S_IRUSR|S_IWUSR );
  #else
    fd = open( seed_file_name, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR );
  #endif
    if( fd == -1 ) {
	log_info(_("can't create `%s': %s\n"), seed_file_name, strerror(errno) );
	return;
    }
    do {
	i = write( fd, keypool, POOLSIZE );
    } while( i == -1 && errno == EINTR );
    if( i != POOLSIZE ) {
	log_info(_("can't write `%s': %s\n"), seed_file_name, strerror(errno) );
    }
    if( close(fd) )
	log_info(_("can't close `%s': %s\n"), seed_file_name, strerror(errno) );
}


static void
read_pool( byte *buffer, size_t length, int level )
{
    int i;
    ulong *sp, *dp;

    if( length >= POOLSIZE ) 
     length = POOLSIZE - 2;
    
/*{
	log_fatal(_("too many random bits requested; the limit is %d\n"),
		  POOLSIZE*8-1 );
    }*/

    if( !pool_filled ) {
	if( read_seed_file() )
	    pool_filled = 1;
    }

    /* For level 2 quality (key generation) we alwas make
     * sure that the pool has been seeded enough initially */
    if( level == 2 && !did_initial_extra_seeding ) {
	size_t needed;

	pool_balance = 0;
	needed = length - pool_balance;
	if( needed < POOLSIZE/2 )
	    needed = POOLSIZE/2;
	else if( needed > POOLSIZE )
	    BUG();
	read_random_source( 3, needed, 2 );
	pool_balance += needed;
	did_initial_extra_seeding=1;
    }

    /* for level 2 make sure that there is enough random in the pool */
    if( level == 2 && pool_balance < length ) {
	size_t needed;

	if( pool_balance < 0 )
	    pool_balance = 0;
	needed = length - pool_balance;
	if( needed > POOLSIZE )
	    BUG();
	read_random_source( 3, needed, 2 );
	pool_balance += needed;
    }

    /* make sure the pool is filled */
    while( !pool_filled )
	random_poll();

    /* do always a fast random poll */
    fast_random_poll();

    if( !level ) { /* no need for cryptographic strong random */
	/* create a new pool */
	for(i=0,dp=(ulong*)keypool, sp=(ulong*)rndpool;
				    i < POOLWORDS; i++, dp++, sp++ )
	    *dp = *sp + ADD_VALUE;
	/* must mix both pools */
	mix_pool(rndpool); rndstats.mixrnd++;
	mix_pool(keypool); rndstats.mixkey++;
	memcpy( buffer, keypool, length );
    }
    else {
	/* mix the pool (if add_randomness() didn't it) */
	if( !just_mixed ) {
	    mix_pool(rndpool);
	    rndstats.mixrnd++;
	}
	/* create a new pool */
	for(i=0,dp=(ulong*)keypool, sp=(ulong*)rndpool;
				    i < POOLWORDS; i++, dp++, sp++ )
	    *dp = *sp + ADD_VALUE;
	/* and mix both pools */
	mix_pool(rndpool); rndstats.mixrnd++;
	mix_pool(keypool); rndstats.mixkey++;
	/* read the required data
	 * we use a readpoiter to read from a different postion each
	 * time */
	while( length-- ) {
	    *buffer++ = keypool[pool_readpos++];
	    if( pool_readpos >= POOLSIZE )
		pool_readpos = 0;
	    pool_balance--;
	}
	if( pool_balance < 0 )
	    pool_balance = 0;
	/* and clear the keypool */
	memset( keypool, 0, POOLSIZE );
    }
}


/****************
 * Add LENGTH bytes of randomness from buffer to the pool.
 * source may be used to specify the randomness source.
 * Source is:
 *	0 - used ony for initialization
 *	1 - fast random poll function
 *	2 - normal poll function
 *	3 - used when level 2 random quality has been requested
 *	    to do an extra pool seed.
 */
static void
add_randomness( const void *buffer, size_t length, int source )
{
    const byte *p = buffer;

    if( !is_initialized )
	initialize();
    rndstats.addbytes += length;
    rndstats.naddbytes++;
    while( length-- ) {
	rndpool[pool_writepos++] = *p++;
	if( pool_writepos >= POOLSIZE ) {
	    if( source > 1 )
		pool_filled = 1;
	    pool_writepos = 0;
	    mix_pool(rndpool); rndstats.mixrnd++;
	    just_mixed = !length;
	}
    }
}



static void
random_poll()
{
    rndstats.slowpolls++;
    read_random_source( 2, POOLSIZE/5, 1 );
}


void
fast_random_poll()
{
    static void (*fnc)( void (*)(const void*, size_t, int), int) = NULL;
    static int initialized = 0;

    rndstats.fastpolls++;
    if( !initialized ) {
	if( !is_initialized )
	    initialize();
	initialized = 1;
	fnc = NULL;
    }

    /* fall back to the generic function */
  #if HAVE_GETHRTIME
    {	hrtime_t tv;
	tv = gethrtime();
	add_randomness( &tv, sizeof(tv), 1 );
    }
  #elif HAVE_GETTIMEOFDAY
    {	struct timeval tv;
	if( gettimeofday( &tv, NULL ) )
	    BUG();
	add_randomness( &tv.tv_sec, sizeof(tv.tv_sec), 1 );
	add_randomness( &tv.tv_usec, sizeof(tv.tv_usec), 1 );
    }
  #elif HAVE_CLOCK_GETTIME
    {	struct timespec tv;
	if( clock_gettime( CLOCK_REALTIME, &tv ) == -1 )
	    BUG();
	add_randomness( &tv.tv_sec, sizeof(tv.tv_sec), 1 );
	add_randomness( &tv.tv_nsec, sizeof(tv.tv_nsec), 1 );
    }
  #else /* use times */
    #ifndef HAVE_DOSISH_SYSTEM
    {	struct tms buf;
	times( &buf );
	add_randomness( &buf, sizeof buf, 1 );
    }
    #endif
  #endif
  #ifdef HAVE_GETRUSAGE
    #ifndef RUSAGE_SELF
      #ifdef __GCC__
	#warning There is no RUSAGE_SELF on this system
      #endif
    #else
    {	struct rusage buf;
	if( getrusage( RUSAGE_SELF, &buf ) )
	    BUG();
	add_randomness( &buf, sizeof buf, 1 );
	memset( &buf, 0, sizeof buf );
    }
    #endif
  #endif
    /* time and clock are availabe on all systems - so
     * we better do it just in case one of the above functions
     * didn't work */
    {	time_t x = time(NULL);
	add_randomness( &x, sizeof(x), 1 );
    }
    {	clock_t x = clock();
	add_randomness( &x, sizeof(x), 1 );
    }
}



static void
read_random_source( int requester, size_t length, int level )
{
    static int (*fnc)(void (*)(const void*, size_t, int), int,
                                                    size_t, int) = NULL;
    if( !fnc ) {
        if( !is_initialized )
            initialize();
/*        fnc = dynload_getfnc_gather_random(); */
        if( !fnc ) {
            faked_rng = 1;
            fnc = gather_faked;
        }
        if( !requester && !length && !level )
            return; /* init only */
    }
    if( (*fnc)( add_randomness, requester, length, level ) < 0 )
        log_fatal("No way to gather entropy for the RNG\n");
}


static int
gather_faked( void (*add)(const void*, size_t, int), int requester,
	      size_t length, int level )
{
    static int initialized=0;
    size_t n;
    char *buffer, *p;

    if( !initialized ) {
	initialized=1;
      #ifdef HAVE_RAND
	srand(time(NULL)*getpid());
      #else
	srandom(time(NULL)*getpid());
      #endif
    }

    p = buffer = m_alloc( length );
    n = length;
  #ifdef HAVE_RAND
    while( n-- )
	*p++ = ((unsigned)(1 + (int) (256.0*rand()/(RAND_MAX+1.0)))-1);
  #else
    while( n-- )
	*p++ = ((unsigned)(1 + (int) (256.0*random()/(RAND_MAX+1.0)))-1);
  #endif
    add_randomness( buffer, length, requester );
    m_free(buffer);
    return 0; /* okay */
}

