/* g10m.c  -  Wrapper for MPI
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include "mpi.h"
#include "util.h"

/* FIXME: The modules should use functions from libgcrypt */

const char *g10m_revision_string(int dummy) { return "$Revision: 1.7 $"; }

MPI
g10m_new( unsigned nbits )
{
    return mpi_alloc( (nbits+BITS_PER_MPI_LIMB-1) / BITS_PER_MPI_LIMB );
}

MPI
g10m_new_secure( unsigned nbits )
{
    return mpi_alloc_secure( (nbits+BITS_PER_MPI_LIMB-1) / BITS_PER_MPI_LIMB );
}

void
g10m_release( MPI a )
{
    mpi_free(a);
}

void
g10m_resize( MPI a, unsigned nbits )
{
    mpi_resize( a, (nbits+BITS_PER_MPI_LIMB-1) / BITS_PER_MPI_LIMB );
}

MPI  g10m_copy( MPI a ) 	   { return mpi_copy( a );   }
void g10m_swap( MPI a, MPI b)	   { mpi_swap( a, b );	     }
void g10m_set( MPI w, MPI u)	   { mpi_set( w, u );	     }
void g10m_set_ui( MPI w, ulong u ) { mpi_set_ui( w, u ); }

int  g10m_cmp( MPI u, MPI v )	    { return mpi_cmp( u, v ); }
int  g10m_cmp_ui( MPI u, ulong v )  { return mpi_cmp_ui( u, v ); }

void g10m_add(MPI w, MPI u, MPI v)	  { mpi_add( w, u, v ); }
void g10m_add_ui(MPI w, MPI u, ulong v )  { mpi_add_ui( w, u, v ); }
void g10m_sub( MPI w, MPI u, MPI v)	  { mpi_sub( w, u, v ); }
void g10m_sub_ui(MPI w, MPI u, ulong v )  { mpi_sub_ui( w, u, v ); }

void g10m_mul( MPI w, MPI u, MPI v)	     { mpi_mul( w, u, v ); }
void g10m_mulm( MPI w, MPI u, MPI v, MPI m)  { mpi_mulm( w, u, v, m ); }
void g10m_mul_2exp( MPI w, MPI u, ulong cnt) { mpi_mul_2exp( w, u, cnt ); }
void g10m_mul_ui(MPI w, MPI u, ulong v )     { mpi_mul_ui( w, u, v ); }

void g10m_fdiv_q( MPI q, MPI d, MPI r )      { mpi_fdiv_q( q, d, r ); }

void g10m_powm( MPI r, MPI b, MPI e, MPI m)  { mpi_powm( r, b, e, m );	}

int  g10m_gcd( MPI g, MPI a, MPI b )	{ return mpi_gcd( g, a, b ); }
int  g10m_invm( MPI x, MPI u, MPI v )	{ mpi_invm( x, u, v ); return 0; }

unsigned g10m_get_nbits( MPI a )   { return mpi_get_nbits( a ); }

unsigned
g10m_get_size( MPI a )
{
    return mpi_get_nlimbs( a ) * BITS_PER_MPI_LIMB;
}


void
g10m_set_buffer( MPI a, const char *buffer, unsigned nbytes, int sign )
{
    mpi_set_buffer( a, buffer, nbytes, sign );
}


