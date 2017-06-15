/**
 * misc_helper.h - Miscellaneous public functions
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

#ifndef SIMPLERSADIGEST_MISC_HELPER_H
#define SIMPLERSADIGEST_MISC_HELPER_H

#include <stdio.h>

#define ARRAY_SIZE(arr)                 (sizeof(arr) / sizeof((arr)[0]))

uint64_t urandom_read(void);
void memdump_byte(void *blk, size_t size, FILE *stream);

#endif //SIMPLERSADIGEST_MISC_HELPER_H
