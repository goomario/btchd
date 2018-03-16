#include <crypto/shabal256.h>

CShabal256::CShabal256()
{
    ::sph_shabal256_init(&context);
}

CShabal256& CShabal256::Write(const unsigned char* data, size_t len)
{
    ::sph_shabal256(&context, (const void*)data, len);
    return *this;
}

void CShabal256::Finalize(unsigned char hash[OUTPUT_SIZE])
{
    ::sph_shabal256_close(&context, hash);
}

CShabal256& CShabal256::Reset()
{
    ::sph_shabal256_init(&context);
    return *this;
}
