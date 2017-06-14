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

/**
 * memory_byte_dump() - dump memory by bytes to file stream
 *
 * @param blk: pointer to memory block
 * @param size: memory block in bytes
 * @param stream: file stream to dump to
 */
void memory_byte_dump(uint8_t *blk, size_t size, FILE *stream)
{
#define COUNT_RETURN_LINE               (4 * 8)
#define COUNT_MAKE_SPACE                (4)
        size_t i;
        int c;

        for (i = 0, c = 1; i < size; ++i) {
                fprintf(stream, "%02x", blk[i]);

                if (!(c % COUNT_RETURN_LINE)) {
                        fprintf(stdout, "\n");
                } else if (!(c % COUNT_MAKE_SPACE)) {
                        fprintf(stdout, " ");
                }

                c++;
        }

#undef COUNT_MAKE_SPACE
#undef COUNT_RETURN_LINE
}