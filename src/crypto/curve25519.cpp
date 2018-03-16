/* Ported parts from Java to C# and refactored by Hans Wolff, 17/09/2013
   Original: https://github.com/hanswolff/curve25519
*/

/* Ported from C to Java by Dmitry Skiba [sahn0], 23/02/08.
 * Original: http://code.google.com/p/curve25519-java/
 */

/* Generic 64-bit integer implementation of Curve25519 ECDH
 * Written by Matthijs van Duin, 200608242056
 * Public domain.
 *
 * Based on work by Daniel J Bernstein, http://cr.yp.to/ecdh.html
 */

#include <crypto/curve25519.h>

extern "C" {
#include <crypto/curve/curve25519_i64.h>
}

namespace crypto {

void curve25519(unsigned char publicKey[32], unsigned char signingKey[32], unsigned char privateKey[32])
{
    //Curve25519::keygen(publicKey, signingKey, privateKey);
    keygen25519(*((pub25519*)publicKey),
        (signingKey == nullptr ? NULL : *((spriv25519*)signingKey)),
        *((priv25519*)privateKey));
}

}