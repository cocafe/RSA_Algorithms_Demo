/**
 * gmp_helper.h - GNU MP library helper functions
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

#ifndef SIMPLERSADIGEST_GMP_HELPER_H
#define SIMPLERSADIGEST_GMP_HELPER_H

#include <gmp.h>

void __mpz_urandomb(mpz_t rop, mp_bitcnt_t n);
void __mpz_urandomm(mpz_t rop, const mpz_t n);

int mpz_rand_bitlen(mpz_t rop, uint64_t len);
int mpz_check_binlen(const mpz_t src, uint64_t len);

#endif //SIMPLERSADIGEST_GMP_HELPER_H
