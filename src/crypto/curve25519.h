#ifndef BITCOIN_CRYPTO_CURVE25519_H
#define BITCOIN_CRYPTO_CURVE25519_H

namespace crypto {

void curve25519(unsigned char publicKey[32], unsigned char signingKey[32], unsigned char privateKey[32]);

}

#endif // BITCOIN_CRYPTO_CURVE25519_H