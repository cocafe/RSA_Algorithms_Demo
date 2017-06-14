#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include "misc_helper.h"

/**
 * urandom_read() - read /dev/urandom
 *
 * @return  random uint64
 */
uint64_t urandom_read(void)
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