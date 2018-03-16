#ifndef BITCOIN_CRYPTO_SHABAL256_H
#define BITCOIN_CRYPTO_SHABAL256_H

extern "C" {
#include <crypto/shabal/sph_shabal.h>
}

/** A hasher class for SHABAL-256. */
class CShabal256
{
private:
    sph_shabal256_context context;

public:
    static const size_t OUTPUT_SIZE = 32;

    CShabal256();
    CShabal256& Write(const unsigned char* data, size_t len);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    CShabal256& Reset();
};

#endif // BITCOIN_CRYPTO_SHABAL256_H