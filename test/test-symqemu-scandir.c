// SPDX-License-Identifier: AGPL-3.0-or-later
#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

static void *scan_allocations[256];
static int   scan_allocation_count;
static int   fail_read;
static int   fail_open;
static int   fail_scan;

static int tracked_scandir(const char *dir, struct dirent ***entries,
                           int (*filter)(const struct dirent *),
                           int (*compar)(const struct dirent **,
                                         const struct dirent **)) {

  assert(scan_allocation_count == 0);
  if (fail_scan) {

    errno = ENOENT;
    return -1;

  }

  int count = scandir(dir, entries, filter, compar);
  if (count >= 0) {

    assert(count + 1 <= 256);
    scan_allocations[scan_allocation_count++] = *entries;
    for (int i = 0; i < count; ++i)
      scan_allocations[scan_allocation_count++] = (*entries)[i];

  }

  return count;

}

static void tracked_free(void *ptr) {

  for (int i = 0; i < scan_allocation_count; ++i) {

    if (ptr && scan_allocations[i] == ptr) { scan_allocations[i] = NULL; }

  }

  free(ptr);

}

static ssize_t test_read(int fd, void *buf, size_t size) {

  if (fail_read) {

    errno = EIO;
    return -1;

  }

  return read(fd, buf, size);

}

static void check_scan_released(void) {

  for (int i = 0; i < scan_allocation_count; ++i)
    assert(scan_allocations[i] == NULL);
  scan_allocation_count = 0;

}

static int test_open(const char *path, int flags, ...) {

  if (fail_open) {

    errno = EACCES;
    return -1;

  }

  if (flags & O_CREAT) {

    va_list args;
    va_start(args, flags);
    mode_t mode = va_arg(args, int);
    va_end(args);
    return open(path, flags, mode);

  }

  return open(path, flags);

}

#define scandir tracked_scandir
#define free tracked_free
#define read test_read
#define open test_open

#include "../custom_mutators/symqemu/symqemu.c"

#undef scandir
#undef free
#undef read
#undef open

static void write_input(const char *path) {

  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  assert(fd >= 0);
  assert(write(fd, "input", 5) == 5);
  assert(close(fd) == 0);

}

int main(int argc, char **argv) {

  assert(argc == 3);
  char out_dir[4096], input_file[4096], generated[4096], pending[4096];
  char ignored[4096];
  snprintf(out_dir, sizeof(out_dir), "%s/out", argv[2]);
  snprintf(input_file, sizeof(input_file), "%s/input", argv[2]);
  snprintf(generated, sizeof(generated), "%s/out/000000", argv[2]);
  snprintf(pending, sizeof(pending), "%s/out/000001", argv[2]);
  snprintf(ignored, sizeof(ignored), "%s/out/ignored", argv[2]);
  assert(mkdir(out_dir, 0700) == 0);
  write_input(ignored);

  my_mutator_t data = {0};
  data.out_dir = (u8 *)out_dir;
  data.mutator_buf = malloc(MAX_FILE);
  assert(data.mutator_buf);

  u8 *out_buf = NULL;
  if (!strcmp(argv[1], "success")) {

    write_input(generated);
    write_input(pending);
    found_items = 2;
    assert(afl_custom_fuzz(&data, NULL, 0, &out_buf, NULL, 0, MAX_FILE) == 5);
    assert(out_buf == data.mutator_buf);
    assert(!memcmp(out_buf, "input", 5));
    assert((access(generated, F_OK) == 0) != (access(pending, F_OK) == 0));
    assert(found_items == 1);
    check_scan_released();
    assert(afl_custom_fuzz(&data, NULL, 0, &out_buf, NULL, 0, MAX_FILE) == 5);
    assert(!memcmp(out_buf, "input", 5));
    assert(access(generated, F_OK) != 0 && access(pending, F_OK) != 0);
    assert(found_items == 0);

  } else if (!strcmp(argv[1], "count")) {

    write_input(generated);
    write_input(input_file);
    afl_struct = calloc(1, sizeof(afl_state_t));
    assert(afl_struct);
    struct queue_entry entry = {0};
    entry.favored = 1;
    entry.fname = (u8 *)input_file;
    afl_struct->queue_cur = &entry;
    afl_struct->fsrv.dev_null_fd = open("/dev/null", O_RDWR);
    assert(afl_struct->fsrv.dev_null_fd >= 0);
    data.input_file = (u8 *)input_file;
    u8 *args[] = {(u8 *)"/bin/true", NULL};
    data.argv = args;
    data.argc = 1;
    assert(afl_custom_fuzz_count(&data, (u8 *)"input", 5) == 1);
    assert(close(afl_struct->fsrv.dev_null_fd) == 0);
    free(afl_struct);
    afl_struct = NULL;
    assert(unlink(generated) == 0);
    assert(unlink(input_file) == 0);

  } else if (!strcmp(argv[1], "read-error") || !strcmp(argv[1], "open-error")) {

    write_input(generated);
    fail_read = !strcmp(argv[1], "read-error");
    fail_open = !strcmp(argv[1], "open-error");
    assert(afl_custom_fuzz(&data, NULL, 0, &out_buf, NULL, 0, MAX_FILE) == 0);
    assert(out_buf == NULL);
    assert(unlink(generated) == 0);

  } else {

    assert(!strcmp(argv[1], "empty") || !strcmp(argv[1], "scan-error"));
    fail_scan = !strcmp(argv[1], "scan-error");
    assert(afl_custom_fuzz(&data, NULL, 0, &out_buf, NULL, 0, MAX_FILE) == 0);
    assert(out_buf == NULL);

  }

  check_scan_released();

  assert(access(ignored, F_OK) == 0);
  assert(unlink(ignored) == 0);
  assert(rmdir(out_dir) == 0);
  free(data.mutator_buf);
  return 0;

}
