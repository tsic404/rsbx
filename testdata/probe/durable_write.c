#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
/* SQLite-like: create db, write, then create -wal and fsync both. */
int main(int argc, char **argv) {
  char p[512]; snprintf(p, sizeof p, "%s/db.sqlite", argv[1]);
  int fd = open(p, O_RDWR|O_CREAT, 0644);
  if (fd < 0) { printf("open db: %s\n", strerror(errno)); return 1; }
  if (write(fd, "data", 4) != 4) { printf("write db: %s\n", strerror(errno)); return 1; }
  if (fsync(fd) != 0) { printf("fsync db: %s\n", strerror(errno)); return 1; }
  close(fd);
  char w[512]; snprintf(w, sizeof w, "%s/db.sqlite-wal", argv[1]);
  int wf = open(w, O_RDWR|O_CREAT, 0644);
  if (wf < 0) { printf("open wal: %s\n", strerror(errno)); return 1; }
  if (write(wf, "wal", 3) != 3) { printf("write wal: %s\n", strerror(errno)); return 1; }
  if (fsync(wf) != 0) { printf("fsync wal: %s\n", strerror(errno)); return 1; }
  close(wf);
  printf("sqlite-like ok\n");
  return 0;
}
