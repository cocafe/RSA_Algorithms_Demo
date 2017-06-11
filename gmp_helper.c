#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <gmp.h>

#include "gmp_helper.h"
#include "rsa_digest.h"

/**
 * urandom_read() - read /dev/urandom
 *
 * @return  random uint64
 */
uint64_t urandom_read()
{
        FILE *dev;
        uint64_t res;

        dev = fopen("/dev/urandom", "r");
        if (!dev)
                return EIO;

        fread(&res, sizeof(uint64_t), 1, dev);

        fclose(dev);

        return res;
}