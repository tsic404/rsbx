#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
/* Mimics an atomic write: create tmp, write, rename, reopen. */
int main(int argc, char **argv) {
  if (argc < 3) { printf("usage: atom DIR NAME\n"); return 2; }
  char tmp[512], fin[512];
  snprintf(tmp, sizeof tmp, "%s/.%s.tmp", argv[1], argv[2]);
  snprintf(fin, sizeof fin, "%s/%s", argv[1], argv[2]);

  int fd = open(tmp, O_WRONLY|O_CREAT|O_TRUNC, 0600);
  if (fd < 0) { printf("create tmp: %s\n", strerror(errno)); return 1; }
  if (write(fd, "payload\n", 8) != 8) { printf("write tmp: %s\n", strerror(errno)); return 1; }
  close(fd);

  if (rename(tmp, fin) != 0) { printf("rename: %s\n", strerror(errno)); return 1; }
  printf("rename ok\n");

  fd = open(fin, O_RDONLY);
  if (fd < 0) { printf("reopen after rename: %s\n", strerror(errno)); return 1; }
  char b[16] = {0}; read(fd, b, 8); close(fd);
  printf("reopen ok: %s", b);
  return 0;
}
