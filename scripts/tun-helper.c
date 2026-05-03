#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static void die(const char *msg) {
  perror(msg);
  exit(1);
}

static int create_tun(const char *iface_name, char *actual_name, size_t actual_name_len) {
  int fd = open("/dev/net/tun", O_RDWR);
  if (fd < 0) {
    die("open(/dev/net/tun)");
  }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  /* Allow toggling packet-info (PI) mode via environment variable
     TUN_USE_PI=1  -> enable PI (do not set IFF_NO_PI)
     default (unset) -> use IFF_NO_PI for raw packet data without extra header */
  const char *use_pi = getenv("TUN_USE_PI");
  if (use_pi && (use_pi[0] == '1')) {
    ifr.ifr_flags = IFF_TUN; /* include PI (packet info) */
  } else {
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; /* no packet info (default) */
  }

  if (iface_name && iface_name[0] != '\0') {
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
  }

  if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
    close(fd);
    die("ioctl(TUNSETIFF)");
  }

  if (actual_name && actual_name_len > 0) {
    snprintf(actual_name, actual_name_len, "%s", ifr.ifr_name);
  }

  return fd;
}

static void usage(const char *prog) {
  fprintf(stderr,
    "Usage: %s [--iface tun0] -- <command> [args...]\n\n"
    "Creates a TUN interface, exports TUN_FD/TUN_IFACE, then execs the command.\n",
    prog);
}

int main(int argc, char **argv) {
  const char *iface = "ai0";
  int cmd_index = -1;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--iface") == 0) {
      if (i + 1 >= argc) {
        usage(argv[0]);
        return 1;
      }
      iface = argv[i + 1];
      i++;
      continue;
    }
    if (strcmp(argv[i], "--") == 0) {
      cmd_index = i + 1;
      break;
    }
  }

  if (cmd_index < 0 || cmd_index >= argc) {
    usage(argv[0]);
    return 1;
  }

  char actual_ifname[IFNAMSIZ];
  int fd = create_tun(iface, actual_ifname, sizeof(actual_ifname));

  // Keep the fd open across exec so the child can use it.
  int flags = fcntl(fd, F_GETFD);
  if (flags < 0) {
    close(fd);
    die("fcntl(F_GETFD)");
  }
  flags &= ~FD_CLOEXEC;
  if (fcntl(fd, F_SETFD, flags) < 0) {
    close(fd);
    die("fcntl(F_SETFD)");
  }

  char fd_buf[32];
  snprintf(fd_buf, sizeof(fd_buf), "%d", fd);
  if (setenv("TUN_FD", fd_buf, 1) < 0) {
    close(fd);
    die("setenv(TUN_FD)");
  }
  if (setenv("TUN_IFACE", actual_ifname, 1) < 0) {
    close(fd);
    die("setenv(TUN_IFACE)");
  }

  fprintf(stderr, "[tun-helper] created %s (fd=%d)\n", actual_ifname, fd);
  fflush(stderr);

  execvp(argv[cmd_index], &argv[cmd_index]);
  die("execvp");
  return 1;
}
