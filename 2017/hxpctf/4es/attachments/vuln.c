#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <mbedtls/aes.h>

typedef unsigned char byte;
typedef ssize_t (*ft)(int, byte *, size_t);

static int o(char const *s)
{
    int r;
    if (0 > (r = open(s, O_RDONLY)))
        exit(1);
    return r;
}

static void c(int d)
{
    if (close(d))
        exit(2);
}

static void t(ft f, int d, byte *s, size_t l, bool e)
{
    for (ssize_t n = -1; l && n; s += n, l -= n)
        if (0 >= (n = f(d, s, l)) && (e || n))
            exit(3);
}

void k(mbedtls_aes_context *a, size_t l)
{
    byte w[l];
    {
        int d = o("/dev/urandom");
        t((ft) read, d, w, sizeof(w), true);
        c(d);
    }
    mbedtls_aes_setkey_enc(a, w, 8 * sizeof(w));
    a->nr = 4;
}

int main()
{
    byte x[64] = {0}, y[sizeof(x)], z[16];
    mbedtls_aes_context aes;

    mbedtls_aes_init(&aes);
    k(&aes, 32);
    {
        int d = o("flag.txt");
        t((ft) read, d, x, sizeof(x) - 1, false);
        c(d);
    }

    for (unsigned i = 0; i < 0x100; ++i) {
        t((ft) read, 0, z, sizeof(z), true);
        if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, sizeof(x), z, x, y)) exit(5);
        t((ft) write, 1, y, sizeof(y), true);
    }
    mbedtls_aes_free(&aes);
}

