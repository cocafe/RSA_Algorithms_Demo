/**
 * misc_helper.c - Miscellaneous functions
 *
 *      Author: cocafe <cocafehj@gmail.com> 2016
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
 * memdump_byte() - dump memory by bytes to file stream
 *
 * @param blk: pointer to memory block
 * @param size: memory block in bytes
 * @param stream: file stream to dump to
 */
void memdump_byte(void *blk, size_t size, FILE *stream)
{
#define COUNT_RETURN_LINE               (4 * 8)
#define COUNT_MAKE_SPACE                (4)
        uint8_t *b;
        size_t i;
        int c;

        for (i = 0, c = 1, b = blk; i < size; ++i) {
                fprintf(stream, "%02x", b[i]);

                if (!(c % COUNT_RETURN_LINE)) {
                        fprintf(stream, "\n");
                } else if (!(c % COUNT_MAKE_SPACE)) {
                        fprintf(stream, " ");
                }

                c++;
        }

#undef COUNT_MAKE_SPACE
#undef COUNT_RETURN_LINE
}