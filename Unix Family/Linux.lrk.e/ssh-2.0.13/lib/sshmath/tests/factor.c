/*

  factor.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996-98 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Sat May 30 22:32:59 1998 [mkojo]

  Factorization code for sshmath libraries. This might be useful
  for some computational problems. 

  TODO:

    fix all the code modified to work with montgomery representation
    is possible. Fix the curve initialization. Fix the factor detections
    etc.

    This should be good test bed for speed against GMP and for correction
    of implementation.

    
  
  */

/*
 * $Id: factor.c,v 1.1 1998/10/29 11:36:04 mkojo Exp $
 * $Log: factor.c,v $
