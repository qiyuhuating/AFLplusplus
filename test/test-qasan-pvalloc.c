// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * Regression coverage for libqasan's pvalloc() interceptor.
 * Run under QEMU with AFL_USE_QASAN=1 so poisoned short allocations fail.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <malloc.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

static int check_allocation(size_t requested, size_t expected, size_t page) {

  volatile unsigned char *p = (volatile unsigned char *)pvalloc(requested);
  if (!p) return 1;
  if ((uintptr_t)p % page) {
    free((void *)p);
    return 2;
  }

  /* Touch the last byte of the rounded allocation, not only the input size. */
  p[0] = 0xa5;
  p[expected - 1] = 0x5a;
  free((void *)p);
  return 0;

}

int main(void) {

  long page_long = sysconf(_SC_PAGESIZE);
  if (page_long <= 0) return 1;
  size_t page = (size_t)page_long;
  if (page > SIZE_MAX / 4) return 2;

  if (check_allocation(page, page, page)) return 3;
  if (check_allocation(2 * page, 2 * page, page)) return 4;
  if (check_allocation(2 * page + 1, 3 * page, page)) return 5;
  if (check_allocation(4 * page, 4 * page, page)) return 6;

  errno = 0;
  void *overflow = pvalloc(SIZE_MAX);
  if (overflow) {
    free(overflow);
    return 7;
  }
  if (errno != ENOMEM) return 8;

  return 0;

}
