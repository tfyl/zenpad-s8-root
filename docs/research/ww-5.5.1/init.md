# ASUS ZenPad S 8.0 (Z580CA / P01MA) — WW 5.5.1 stock boot: `init` binary + all rc trigger chains

Historical WW 5.5.1 static analysis of init and its rc files. The LogTool and
policy-reload routes in section 4 are unvalidated proposals. The implemented
unlock uses the bugreport/logcat carrier, a zygote child domain transition, and
Magisk persistence; see [methodology](../../methodology.md). Policy-dependent
questions are discussed in [the policy report](selinux-policy.md).

- Artifact analyzed: the stock ASUS **WW 5.5.1.0** boot ramdisk from
  `UL-P01M-WW-5.5.1.0-user.zip`. Its policy and init text files are retained in
  `reference/ww-5.5.1/ramdisk/`; the original init ELF can be extracted from
  `firmware/boot-stock-WW-5.5.1.img`. These are WW firmware references, not a
  capture of the original PGDO boot ramdisk.
- Target device context: Android 6.0.1 (MRA58K-based ASUS build), locked bootloader, dirtycow-vulnerable
  kernel, stock `init` + ASUS rc set (confirmed active on device: `init.svc.logtool-mos-user=stopped`).
- `init` binary: ELF 32-bit LSB **statically linked, stripped** (`stripped`), Intel 80386, entry `0x8049f96`,
  text/rodata LOAD at `0x08048000` (file offset 0 → **vaddr = file offset + 0x08048000**), RW LOAD at
  `0x081ac580`. libselinux is linked inside it. All addresses cited below are the binary's own vaddrs.
- Tooling: `strings -a -t x`, `objdump -d` (Intel syntax), `readelf`. Sepolicy *parsing* is deliberately
  out of scope here (covered by the companion `selinux-policy.md`); only the reload *mechanism* in init/libselinux is covered.

## Contents
1. [init binary analysis](#1-init-binary-analysis)
   - 1a. `selinux.reload_policy` reload path
   - 1b. `asus_exec` command handler
   - 1c. Full built-in command table sweep (non-AOSP additions)
   - 1d. Service seclabel/user/group/uid semantics
2. [Full rc inventory](#2-full-rc-inventory)
3. [RW-path file creation / root-read enumeration](#3-how-could-a-file-under-data-or-cache-ever-come-to-exist-with-attacker-chosen-content-before-it-is-read-by-a-root-process)
4. [Historical proposals and precondition queries](#4-historical-proposals-and-precondition-queries)

---

# 1. init binary analysis

## Binary facts

| Property | Value |
|---|---|
| Format | ELF32, Intel 80386, **statically linked, stripped**, ET_EXEC |
| Entry | `0x8049f96` |
| Text+rodata LOAD | file offset 0 → vaddr `0x08048000`; **rodata string vaddr = file offset + 0x8048000** |
| RW LOAD | file offset `0x163580` → vaddr `0x081ac580`; **RW vaddr = file offset + 0x8049000** |
| Sections | `.text` 0x08048110..0x0816e82a, `.rodata` 0x0816e840..0x08187404, `.data.rel.ro.local` 0x081ac580, `.data` 0x081b0000, `.bss` 0x081b1700 |
| GOT base (PIC code) | **ebx = 0x081AFFDC** (`.got.plt`); set up per-function via `call 0x804a0a4; pop %ebx; add $imm,%ebx` — every string ref in code is `lea disp(%ebx)` with `disp = string_vaddr − 0x081AFFDC` |
| Key globals | keyword/policy index global at GOT+0x1e50 = `0x081B1E2C` (libselinux "which file set" 0=root, 1=/data/security/current); init's `sehandle` at GOT+0x1748 = `0x081B1724`; property-contexts handle at GOT+0x174c = `0x081B1728` |

Analysis method: `objdump -d` (332k lines) + `strings -a -t x` + GOT-relative xref resolution as above. No symbols exist; function boundaries were derived from prologues (`push %ebp; ...; call thunk`) and referenced as `init+0x…`.

---

## 1a. The `selinux.reload_policy` property → policy reload path

**Conclusion up front: yes — this init build genuinely re-loads its live SELinux policy from `/data/security/current/sepolicy` at boot, before services start, if — and only if — a full, self-consistent file set is planted there.** The conditions are exact and are all listed below. This path is an AOSP "SELinux policy OTA" mechanism (KitKat-era) that ASUS kept enabled in their M build.

### 1a.1 Where the property is handled: `property_set()` at `init+0x8052930`

`property_set(name, value)` (init/properties.cpp equivalent) does, in order:

1. `is_legal_property_name()` — length ≤ 31, first/last char not `.` and the usual charset walk (`init+0x8052980..0x8052a14`).
2. `strlen(value) >= 92` → reject (`cmpl $0x5b` at `init+0x8052a14`; PROP_VALUE_MAX=92).
3. **`strcmp(name, "selinux.reload_policy") == 0` →** (xref `init+0x8052a1f`, string at `0x081703e6`)
   **`strcmp(value, "1") == 0` → call `selinux_reload_policy()` at `init+0x8052a89` → callee `init+0x8050730`.**
   If the reload returns non-zero → `KLOG_ERROR("Failed to reload policy\n")` (`0x081703fc`).
   ⇒ the reload fires **only when the value is exactly the string `"1"`**; any other value silently does nothing special.
4. **`strcmp(name, "selinux.restorecon_recursive") == 0 && value != ""` →** `restorecon_recursive(value)` via `init+0x8059990` (failure → `KLOG_ERROR("Failed to restorecon_recursive %s\n")`).
   ⇒ **`selinux.restorecon_recursive=<path>` is a second live security property**: setting it relabels an entire directory tree at runtime with the *currently loaded* file_contexts.
5. Normal path continues: `ro.` immutability check while booting (`init+0x8052ab4`, string `"ro."`), `net.`/`net.change` handling, `persist.` write-through to `/data/property` (see §3), then property-trigger queueing.

### 1a.2 `selinux_reload_policy()` at `init+0x8050730`

```
init+0x8050748   access("/sys/fs/selinux", F_OK)          ; != 0 → return -1 (abort, no reload)
init+0x8050767   call init+0x8051d10                       ; kernel-cmdline "androidboot.selinux" evaluator
                 ; returns 0=disabled, 1=permissive, 2=enforcing
                 ;   (callback at init+0x8051ed0: strcmp "androidboot.selinux" →
                 ;    value=="disabled"→0 / value=="permissive"→1; default 2)
                 ; == 0 → return -1 (abort)
init+0x805077a   KLOG_INFO "SELinux: Attempting to reload policy files"   (string 0x127889)
init+0x8050786   call init+0x8079ba0  = selinux_android_reload_policy()
                 ; == -1 → return -1  → property_set logs "Failed to reload policy"
init+0x8050790   destroy old file-contexts handle  (call init+0x8074e20 if [0x081B1724] != 0)
init+0x80507a4   destroy old property-contexts handle (same, for [0x081B1728])
init+0x80507b8   [0x081B1724] = init+0x8078fd0()  = selinux_android_file_context_handle()
init+0x80507c2   call init+0x8079b80(handle)      = set global sehandle for restorecon
init+0x80507c7   [0x081B1728] = init+0x80798b0()  = selinux_android_prop_context_handle()
init+0x80507cc   return 0
```

Notable: **no `security_setenforce` here** (mode unchanged — stays enforcing), **no seapp_contexts / service_contexts reload** (seapp has its own reload function `init+0x8077530`-ish that is *not* called from this path; see below).

### 1a.3 `selinux_android_reload_policy()` at `init+0x8079ba0` — the EXACT decision tree

libselinux's policy-file selector is driven by a global index `G` at `0x081B1E2C` and two parallel file lists in `.data.rel.ro.local` at `0x081AC9F0`:

```
G == 0 → "/sepolicy"                       (rootfs, read-only, stock)
G == 1 → "/data/security/current/sepolicy" (attacker-controllable /data path)
```

The function body (`init+0x8079bb6` … `init+0x8079fd6`):

1. `G_old = [0x081B1E2C]; G = 0`.
2. `open("/selinux_version", O_RDONLY|O_NOFOLLOW)` → on ANY failure go to step 8 (G stays 0).
   `fstat(fd)` → on failure close+go to step 8.
3. `open("/data/security/current/selinux_version", O_RDONLY|O_NOFOLLOW)` → on failure (incl. ENOENT) **close and go to step 8** — i.e. **the check is existence-first: if the version file is missing, the whole /data policy set is silently ignored.**
   `fstat(fd2)` → on failure close+go to step 8.
4. Compare **`st_size`** (64-bit: `stat+0x2c`/`stat+0x30`, bionic x86 `stat64`) of the two version files.
   **Different size → close both → step 8 (G stays 0).**
5. Sizes equal → `mmap` both, **`memcmp` full contents**.
   **Contents differ → close both → step 8 (G stays 0).**
6. Contents identical → probe with `access(path, R_OK)` **each of**:
   `/data/security/current/sepolicy`, `/data/security/current/file_contexts`,
   `/data/security/current/property_contexts`, `/data/security/current/service_contexts`,
   `/data/security/current/seapp_contexts`   (`init+0x8079f2a … 0x8079fc6`)
   **If ALL FIVE succeed → `G = 1`** (`init+0x8079fcc`). Any single failure → G stays 0.
7. close both version fds → step 8.
8. **`if (G_old | G) == 0 → return 0`** (`init+0x8079c63 → epilogue`) — **silent no-op: no policy load, no error, no fallback load of `/sepolicy`.** This is the steady-state behaviour on a stock device (no `/data/security/current`): every boot the property set is a no-op.
9. Otherwise (`G == 1`, or `G_old == 1` with a now-failed re-check): `open(list[G], O_RDONLY|O_NOFOLLOW)`, `fstat`, `mmap`, hand to the sepol policy loader (`init+0x808e1d0` etc.). Failure → return −1 → init logs "Failed to reload policy" but **keeps running the previously loaded policy**.

### 1a.4 The same gate drives the *context* files too

Five parallel `{root, /data/security/current}` lists exist in `.data.rel.ro.local`:

| kind | root file | /data file | list base | consumer |
|---|---|---|---|---|
| sepolicy | `/sepolicy` | `/data/security/current/sepolicy` | `0x081AC9F0` (stride 4) | initial load `init+0x8079fe0`, reload `init+0x8079ba0` |
| file_contexts | `/file_contexts` | `…/file_contexts` | `0x081AC9FC` (stride 8) | `selinux_android_file_context_handle` `init+0x8078fd0` |
| property_contexts | `/property_contexts` | `…/property_contexts` | `0x081AC9D8` | `selinux_android_prop_context_handle` `init+0x80798b0` |
| seapp_contexts | `/seapp_contexts` | `…/seapp_contexts` | `0x081ACA14` | seapp reload fn (uses list[G] at `init+0x807762c`) |
| service_contexts | `/service_contexts` | `…/service_contexts` | `0x081AC9C0` | **dead in this build** — list + strings exist but **no code path opens service_contexts** (only the `access()` gate in step 6 references it) |

The decision procedure (steps 2–6 above) exists as a shared helper at `init+0x8077060` (called by the file-contexts handle) and is also **inlined** into the sepolicy loader, the property-contexts handle, the seapp reload and the initial load — all with identical semantics, all reading/writing the **same global index** `0x081B1E2C`.

Consequences, stated exactly:
- `/data/security/current/selinux_version` must be **byte-identical in content and equal in size** to the on-device `/selinux_version` (the ramdisk root carries a `selinux_version`, 72 bytes; also extracted here), **and** all five files must be present and `access(R_OK)`-able **for init's uid** — otherwise G stays 0 and nothing happens.
- When the gate passes, init **loads the planted `/data/security/current/sepolicy` as the live policy** and rebuilds its file/property context handles from the planted `file_contexts`/`property_contexts`.
- `service_contexts` content is never read (dead), but the file must still exist to pass the gate.
- On failure of the *load* after the gate passed, init keeps the old policy (reload is not destructive on failure).
- seapp_contexts is **not** reloaded by this path — the planted seapp file is required only to pass the access gate on this reload path (it IS consumed by the separate initial-load/seapp-reload machinery).

### 1a.5 When in boot does this happen?

- `init.aosp.rc` line 401 (inside `on post-fs-data`): `setprop selinux.reload_policy 1` — **fired on every boot**, after `/data` is mounted and after `mkdir /data/security 0711 system system` (line ~386). Device fact "selinux.reload_policy is currently 1" matches.
- Because it is an init command inside the `post-fs-data` action, `selinux_reload_policy()` runs **synchronously during post-fs-data, before any `on boot` / `class_start` services** — an adopted `/data/security/current/sepolicy` therefore governs zygote, adbd and everything else.
- Runtime `setprop selinux.reload_policy 1` from any domain the policy allows (`security_prop` label, see `property_contexts` line 46) triggers the same reload immediately.

**Section 3 must answer: can `/data/security/current/*` ever come to exist?** (Short answer: `/data/security` is created by init every boot, but `current/` is not; creation needs a uid-0-or-1000 foothold — see §3/§4.)

---

## 1b. `asus_exec` — **not implemented in this init build**

`init.logtool.rc` lines 340–341 use an init *command* `asus_exec`:

```
on property:persist.logtool.upi.loglv=rst
	asus_exec /system/bin/upi_ug31xx force_reset_totally
	asus_exec /system/bin/setprop persist.logtool.upi.loglv 0
```

Findings from the binary:

- The byte string `asus_exec` does **not occur anywhere** in the 1.48 MB init binary (`grep -abo` over the raw file: zero hits; also zero in `.rodata`/`.data` pointer tables).
- The complete built-in command table (§1c) contains no `asus_exec` entry.
- Therefore init's action parser hits its "unknown command" path: the keyword table lookup fails the command-type flag test and the parser calls the error logger with **`"invalid command '%s'"`** (string at file offset `0x129680` → vaddr `0x08171680`, used at `init+0x8057cad` and `init+0x8058248` in the action/onrestart command parsers). The error goes to the kernel log as `<3>init: /init.logtool.rc: <line>: invalid command 'asus_exec'` and **parsing continues on the next line** (`init+0x8057e7f → init+0x8058650 → return`), so the rest of init.logtool.rc (its services and triggers) still registers — consistent with the device running `init.svc.logtool-mos-user`.

**Static effect:** `asus_exec` is a **dead command on this firmware** — both `asus_exec` lines in init.logtool.rc are boot-time no-ops (modulo a klog error line). In particular:

- `asus_exec /system/bin/upi_ug31xx force_reset_totally` never execs anything.
- The "reset" semantics of `persist.logtool.upi.loglv=rst` (which on other ASUS builds would run `upi_ug31xx force_reset_totally` and then re-set the prop to 0 via `setprop`) **do not exist** here — if `/data/property/persist.logtool.upi.loglv` ever contains `rst`, the trigger fires, the two commands are skipped as parse errors, and the prop **stays `rst`** forever (no `asus_exec /system/bin/setprop` line runs to reset it).

*If a disassembly question is ambiguous*: there is no handler to find — this is a verified absence, not an ambiguity. The parse-error path was traced to confirm non-fatal behaviour.

---

## 1c. Complete built-in command table sweep

The keyword table is a flat sorted array at `.data.rel.ro` `0x081AE2F0`–`0x081AE59A` with 12-byte entries `{const char *name; void *fn; uint32_t flags}`; a parallel flag-byte array (indexed by keyword) marks option/command type (tested e.g. at `init+0x8057c9b`, `testb $0x2,-0x1cef(%ebx,idx*12)`). The flags word is `(section<<8) | low-byte-arg-info` (0x1xx = section header `on`/`service`/`import`, 0x2xx = command, 0x4xx = service option); the exact per-keyword min/max argument validation encoded in the low byte was not needed for this analysis and is left undecoded rather than guessed. All 57 entries:

| keyword | fn | flags | class |
|---|---|---|---|
| bootchart_init | 0x0804a0c0 | 0x201 | cmd, 0 args |
| chmod | 0x0804ce20 | 0x203 | cmd, 2 args |
| chown | 0x0804cd80 | 0x203 | cmd, 2 args |
| class | – | 0x401 | svc option |
| class_reset | 0x0804b540 | 0x202 | cmd |
| class_start | 0x0804b470 | 0x202 | cmd |
| class_stop | 0x0804b500 | 0x202 | cmd |
| console | – | 0x401 | svc option |
| copy | 0x0804cc00 | 0x203 | cmd, 2 args |
| critical | – | 0x401 | svc option |
| disabled | – | 0x401 | svc option |
| domainname | 0x0804b580 | 0x202 | cmd |
| enable | 0x0804b5c0 | 0x202 | cmd |
| exec | 0x0804b620 | 0x202 | cmd |
| export | 0x0804b670 | 0x203 | cmd |
| group | – | 0x401 | svc option |
| hostname | 0x0804b6b0 | 0x202 | cmd |
| ifup | 0x0804b6f0 | 0x202 | cmd |
| import | – | 0x102 | section |
| insmod | 0x0804b7c0 | 0x202 | cmd |
| installkey | 0x0804d140 | 0x202 | cmd |
| ioprio | – | 0x401 | svc option |
| keycodes | – | 0x401 | svc option |
| load_system_props | 0x0804d0b0 | 0x201 | cmd, 0 args |
| load_persist_props | 0x0804d080 | 0x201 | cmd, 0 args |
| loglevel | 0x0804cfa0 | 0x202 | cmd |
| mkdir | 0x0804b9f0 | 0x202 | cmd, 1–4 args |
| mount_all | 0x0804c130 | 0x202 | cmd |
| mount | 0x0804bb30 | 0x204 | cmd, ≥3 args |
| oneshot | – | 0x401 | svc option |
| onrestart | – | 0x401 | svc option |
| on | – | 0x101 | section |
| powerctl | 0x0804c6e0 | 0x202 | cmd |
| restart | 0x0804c6a0 | 0x202 | cmd |
| restorecon | 0x0804cec0 | 0x202 | cmd |
| restorecon_recursive | 0x0804cf30 | 0x202 | cmd |
| rm | 0x0804c950 | 0x202 | cmd |
| rmdir | 0x0804c980 | 0x202 | cmd |
| seclabel | – | 0x401 | svc option |
| service | – | 0x101 | section |
| setenv | – | 0x403 | svc option (non-AOSP-M) |
| setprop | 0x0804c520 | 0x203 | cmd |
| setrlimit | 0x0804c5c0 | 0x204 | cmd |
| setusercryptopolicies | 0x0804d240 | 0x202 | cmd (non-AOSP-M) |
| socket | – | 0x401 | svc option |
| start | 0x0804c620 | 0x202 | cmd |
| stop | 0x0804c660 | 0x202 | cmd |
| swapon_all | 0x0804c4d0 | 0x202 | cmd |
| symlink | 0x0804c910 | 0x202 | cmd |
| sysclktz | 0x0804c9b0 | 0x202 | cmd |
| trigger | 0x0804c8d0 | 0x202 | cmd |
| user | – | 0x401 | svc option |
| verity_load_state | 0x0804ca20 | 0x201 | cmd (non-AOSP-M) |
| verity_update_state | 0x0804ca80 | 0x201 | cmd |
| wait | 0x0804d0e0 | 0x202 | cmd |
| write | 0x0804cb60 | 0x203 | cmd |
| writepid | – | 0x401 | svc option |

Deltas vs. stock AOSP 6.0 `BuiltinFunctionMap` (marshmallow-mr1):

- **Absent from AOSP-M (vendor/Intel additions):** `setusercryptopolicies` (FBE prep helper, `init+0x804d240`), `verity_load_state`, service option `setenv` (env vars for the execed service, 2 args), `load_system_props` (AOSP-M calls the equivalent `load_all_props`), `bootchart_init` (AOSP-M has command `bootchart`; here it is named `bootchart_init` — AOSP-M's init.rc also ships a `bootchart_init` *service*, so this build turned it into a builtin command name instead).
- **AOSP-M commands missing here:** `bootchart` (renamed), `load_all_props` (renamed to `load_system_props`), `swapon` (only `swapon_all` present), `copy_per_line` (not an AOSP-M command; *not present either*).
- **No `asus_exec`** (see §1b). **No command that execs a *property-supplied* path.**

### Property expansion (`${prop}`) — where it does and does not apply

This build (like AOSP-M) implements `expand_props()` at `init+0x8055f70`: syntax `${name}` (and deprecated `$name` → klog warning "using deprecated syntax for specifying property '%s', use ${name} instead"); errors: missing property ("property '%s' doesn't exist while expanding '%s'"), missing `}`, name > 31 chars, destination overflow. **Any existing property can be referenced — no `ro.`/`persist.` restriction is enforced in this build.** Expansion is applied in exactly these builtins (via direct call sites to `init+0x8055f70`):

| builtin | expanded argument |
|---|---|
| `setprop` (`init+0x804c520`) | the **value** (error: "cannot expand '%s' while assigning to '%s'") |
| `write` (`init+0x804cb60`) | the **content** (error: "cannot expand '%s' while writing to '%s'") |
| `powerctl` (`init+0x804c6e0`) | the argument |
| `loglevel` (`init+0x804cfa0`) | the argument |
| `insmod` (`init+0x804b7c0`, helper `init+0x804b840`) | arguments |
| rc parser `import` line (`init+0x80564af` inside `parse_config`) | the import path |

**Not expanded:** `exec`, `start`, `stop`, `mkdir`, `chmod`, `chown`, `symlink`, `copy`, `mount`… (args are taken literally).

**Security note (feeds §4):** `write <path> ${persist.X}` with an attacker-controlled persisted property is a **root-context (u:r:init:s0, uid 0) file-write primitive with attacker-chosen content** (≤ 91 bytes per expansion, properties are capped at 92 bytes), gated only on which `on property:` triggers exist in the rc set — see §2. Properties are also expandable **inside the value of another `setprop`**, and the rc parser expands `import` paths.

### `exec` semantics (do_exec `init+0x804b620` → `init+0x80570b0` → Service::Start)

- Argument grammar (backported from newer AOSP; not stock M): scan args for a literal `"--"`; everything before it is the *option prefix*; error `"exec called with too many supplementary group id"` if the prefix would overflow 16 entries.
- Prefix forms: `exec <seclabel> -- cmd args…` (args[1] stored to the Service `seclabel` field at offset 0x60), or `exec - <user> <group> [<group>…] -- cmd args…` (uid/gid/extra gids decoded with `decode_uid`, `init+0x8058940`, into Service fields 0x24/0x28/0x2c+0x5c).
- A synthetic service is created, named `"exec %d (%s)"` (`init+0x8057211`, counter at GOT+0x181c), state flag 0x402, and started asynchronously via the shared `Service::Start` (`init+0x804f420`); init does **not** block (klog shows `SVC_EXEC pid %d finished...`, string `0x12894b`).
- So: **any `exec` command in any trigger runs the named binary as root in init's own SELinux context (u:r:init:s0) unless `- user group` / `<seclabel>` overrides are given.** This is a trigger-driven arbitrary-exec *of rc-specified paths* (not property-supplied paths — see expansion list above).

Other exec-adjacent builtins for the record: `installkey` (`init+0x804d140`) gates on `ro.crypto.type == file` and execs the vold key-install flow (fixed path, not attacker-influenceable via rc args).

---

## 1d. Service seclabel / user / group semantics (`Service::Start` at `init+0x804f420`)

Verified in disassembly of the fork/child path:

```
init+0x804fbf3  set signal-handling/cloexec cleanups (0x8106e80 dup2s, 0x8106a60)
init+0x804fc0b  pid = fork()                      ; syscall 57 (0x811d300) — child continues below
init+0x804fc10  if (svc->gid  (field +0x28) != 0)  → setgid(gid)  [syscall 214, init+0x811d2a0]
init+0x804fc27  if (svc->ngroups(field +0x5c) != 0) → setgroups(n, &svc->groups[0x2c]) [syscall 206, init+0x811d2d0]
init+0x804fc45  if (svc->uid  (field +0x24) != 0)  → setuid(uid)  [syscall 213, init+0x811d410]
init+0x804fc5c  if (svc->seclabel(field +0x60) != 0 && is_selinux_enabled() > 0 [init+0x80731c0])
                   → setexeccon(seclabel) [init+0x80735d0]
                ; setexeccon/setcon here write /proc/self/task/<tid>/attr/{exec,current}
                ;   (format string "/proc/self/task/%d/attr/%s", file 0x1300ac / 0x130094)
                ;   setexeccon failure → klog error + _exit(127)
init+0x804fd07  execve(args[0], argv, envp)       [syscall 11, init+0x811cb90]; failure → _exit(127) [init+0x811ca00]
```

- **`user root` (uid 0) and `group root`/no group (gid 0) are no-ops by design** — the `!= 0` guards mean the child keeps init's own uid/gid 0. A `user root` service runs **uid 0 / gid 0** plus the supplementary groups given via `group`.
- **`seclabel u:r:dumpstate:s0`** is applied in the child **after** the setuid/setgid calls and **before** `execve` — so the execed binary transitions into `u:r:dumpstate:s0` while **still running uid 0** (SELinux identity and Unix identity are independent; setuid does not change the SELinux domain).
- ⇒ **Any service block with `user root` + `seclabel u:r:dumpstate:s0` gives: uid 0, gid 0 (+ declared groups), SELinux domain `u:r:dumpstate:s0`, at boot, whenever the trigger that starts it fires.** This is exactly the LogTool service set (§2).
- Note for completeness: when `seclabel` is empty the child relies on a domain auto-transition from the file label of the execed binary (not verified further here; not needed for the LogTool services which set seclabel explicitly).
- Service fields confirmed from the exec-service constructor (`init+0x80570b0`): uid @+0x24, gid @+0x28, groups @+0x2c, ngroups @+0x5c, seclabel @+0x60 — the same layout the `user`/`group`/`seclabel` options populate for normal services (via `decode_uid` @`init+0x8058940`, which maps names via the built-in uid name table at `0x081ACA40`: root=0, system=1000, radio=1001, bluetooth=1002, graphics=1003, input=1004, audio=1005, camera=1006, log=1007, compass=1008, mount=1009, wifi=1010, …).

---

# 2. Full rc inventory

## 2.0 Import graph / parse order (which files are actually live in normal boot)

```
init  → parse /init.rc
init.rc:11      import /init.aosp.rc
init.aosp.rc:7  import /init.environ.rc
init.aosp.rc:8  import /init.usb.rc
init.aosp.rc:9  import /init.${ro.hardware}.rc  = /init.mofd_v1.rc   (ro.hardware from default.prop)
init.aosp.rc:10 import /init.usb.configfs.rc
init.aosp.rc:11 import /init.${ro.zygote}.rc   = /init.zygote32.rc
init.aosp.rc:12 import /init.trace.rc
init.mofd_v1.rc:1-14 imports: init.common.rc, init.debug.rc, init.diag.rc, init.avc.rc,
                 init.wifi.rc, init.platform.usb.rc, init.platform.gfx.rc, init.gps.rc,
                 init.nfc.rc(ABSENT), init.bt.rc, init.modem.rc(ABSENT), init.config_init.rc,
                 init.camera.rc, init.logtool.rc
init.common.rc:1-7 imports: /init.watchdog.rc, /init.firmware.rc, /init.ksm.rc(ABSENT),
                 /init.readahead.rc, /init.dirtybackground.rc, /init.zram.rc, /init.adbon.rc
init.debug.rc:1 import /init.internal_props.rc (ABSENT — parse error logged, skipped)
```

- **Not imported in normal boot:** `init.recovery.mofd_v1.rc` (recovery OS only), `init.largeram.rc`/`init.normalram.rc` (unreferenced), `ueventd.rc`/`ueventd.mofd_v1.rc` (parsed by ueventd, not init).
- A service name defined twice is kept from the **first parse**: `media` and `keystore` come from init.rc (with ASUS overrides); `flash_recovery` from init.rc **with `seclabel u:r:install_recovery:s0`** (init.aosp.rc's later copy is ignored); `dhcpcd_eth0` from the first of the two init.common.rc definitions.
- Missing-import files only produce a klog parse error; parsing continues (same non-fatal behaviour as §1b).

## 2.1 Boot phase ordering that matters for exploitation (from init.aosp.rc `late-init`)

```
early-fs → fs → post-fs → load_system_props_action → post-fs-data → load_persist_props_action
         → firmware_mounts_complete → early-boot → boot
```

Key facts:
- `on fs` (init.common.rc:43): `mount_all /fstab` → **/data, /cache, /config, /factory are mounted here** (fstab: `/data` + `/cache` + `/config` + `/factory` ext4 **rw**, `nosuid,nodev`, **no `noexec`**; `/system` `ro,verify`).
- `on post-fs-data` (init.aosp.rc:286+): /data dirs created; **line 387 `mkdir /data/security 0711 system system`**; line 401 **`setprop selinux.reload_policy 1`** (→ §1a reload attempt, synchronously here); line 404 **`restorecon_recursive /data`** (relabels all of /data with the — possibly reloaded — file_contexts).
- `on load_persist_props_action`: **`load_persist_props`** → reads every regular file `/data/property/persist.*` and `property_set(name, value)` → **all `on property:persist.*` triggers fire here, before `on boot` services start.** This is when a planted persist prop value activates attacker triggers.
- `on boot` → `class_start core`; `on nonencrypted` → `class_start main` + `class_start late_start`.

## 2.2 Service inventory (every `service` block in the live set)

Flags: **R** = runs as uid 0 (no `user` line, or `user root`), **DS** = `seclabel u:r:dumpstate:s0`, **W** = oneshot, dis = `disabled`. "*" marks services whose script argument lives on a RW path (/data) — the critical set.

| file:line | service | binary + args | user/group | seclabel | notes |
|---|---|---|---|---|---|
| init.rc:18 | media | /system/bin/mediaserver | media | – | ASUS override (extra groups) |
| init.rc:24 | keystore | /system/bin/keystore /data/misc/keystore | keystore | – | reads /data path (arg) |
| init.rc:29 | flash_recovery | /system/bin/install-recovery.sh | – (R) | u:r:install_recovery:s0 | W, class main — runs every boot as root |
| init.aosp.rc:564 | ueventd | /sbin/ueventd | – (R) | u:r:ueventd:s0 | critical |
| init.aosp.rc:569 | logd | /system/bin/logd | group root system | – | |
| init.aosp.rc:577 | logd-reinit | /system/bin/logd --reinit | – (R) | – | W, dis |
| init.aosp.rc:582 | healthd | /sbin/healthd | group root system | u:r:healthd:s0 | critical |
| init.aosp.rc:588 | console | /system/bin/sh | shell | u:r:shell:s0 | dis, console |
| init.aosp.rc:600 | adbd | /sbin/adbd --root_seclabel=u:r:su:s0 | – (R) | u:r:adbd:s0 | dis; started by usb triggers |
| init.aosp.rc:610 | lmkd | /system/bin/lmkd | – (R) | – | critical |
| init.aosp.rc:616 | servicemanager | /system/bin/servicemanager | system | – | critical |
| init.aosp.rc:627 | vold | /system/bin/vold --blkid_context=… | – (R) | – | |
| init.aosp.rc:635 | netd | /system/bin/netd | – (R) | – | |
| init.aosp.rc:642/646 | debuggerd(64) | /system/bin/debuggerd(64) | – (R) | – | |
| init.aosp.rc:650 | surfaceflinger | /system/bin/surfaceflinger | system | – | |
| init.aosp.rc:657 | drm | /system/bin/drmserver | drm | – | |
| init.aosp.rc:662 | media | (dupe — init.rc wins) | | | |
| init.aosp.rc:669 | defaultcrypto | /system/bin/vdc --wait cryptfs mountdefaultencrypted | – (R) | – | dis, W |
| init.aosp.rc:676 | encrypt | /system/bin/vdc --wait cryptfs enablecrypto … | – (R) | – | dis, W |
| init.aosp.rc:682 | bootanim | /system/bin/bootanimation | graphics | – | dis, W |
| init.aosp.rc:689 | gatekeeperd | /system/bin/gatekeeperd /data/misc/gatekeeper | system | – | reads /data path |
| init.aosp.rc:693 | installd | /system/bin/installd | – (**R**) | – | socket 0600 system system |
| init.aosp.rc:697 | flash_recovery | (dupe) | | | |
| init.aosp.rc:701 | racoon | /system/bin/racoon | group vpn… | – | dis, W |
| init.aosp.rc:709 | mtpd | /system/bin/mtpd | vpn | – | dis, W |
| init.aosp.rc:717 | keystore | (dupe) | | | |
| init.aosp.rc:722 | dumpstate | /system/bin/dumpstate -s | – (**R**) | (dumpstate_exec label) | dis, W |
| init.aosp.rc:728 | mdnsd | /system/bin/mdnsd | mdnsr | – | dis, W |
| init.aosp.rc:736/741 | uncrypt / pre-recovery | /system/bin/uncrypt [--reboot] | – (**R**) | – | dis, W |
| init.aosp.rc:746 | perfprofd | /system/xbin/perfprofd | **root** | – | W, class late_start |
| init.aosp.rc:759 | logcatd | /system/bin/logcat -b all … -f /data/misc/logd/logcat | logd | – | dis; started by persist.logd.logpersistd=logcatd |
| init.zygote32.rc:1 | zygote | /system/bin/app_process … | – (**R**) | – | socket zygote |
| init.platform.gfx.rc | pvrsrvctl | /system/vendor/bin/pvrsrvctl --no-module --start | **root** | – | W, class core |
| init.mofd_v1.rc:298 | fg_conf | /system/bin/fg_conf -w | group system (**R**) | – | dis, W; `start`ed post-fs-data |
| init.mofd_v1.rc:324 | sensorhubd | /system/bin/sensorhubd | system | – | |
| init.mofd_v1.rc:331 | sensors_config | /system/bin/sensors_config | **root** | **u:r:init:s0** | dis, W; `start`ed post-fs-data; reads /data/sensors/*.conf |
| init.mofd_v1.rc:339 | dpst | /system/bin/dpstmgr | system | – | |
| init.mofd_v1.rc:347 | rfid_monzaxd | /system/bin/rfid_monzaxd | system | – | |
| init.mofd_v1.rc:384 | info_setting | /system/bin/info_setting | – (**R**) | **u:r:init:s0** | W, class core — runs every boot as root in init domain |
| init.mofd_v1.rc:389 | VerifyVouchers | /system/bin/VerifyVouchers | – (**R**) | **u:r:init:s0** | W, dis; `start`ed on sys.boot_completed=1 |
| init.common.rc:158 | thermald | /sbin/thermald | **root** | u:r:thermald:s0 | dis (started in charger/recovery) |
| init.common.rc:164 | bcu_cpufreqrel | /system/bin/bcu_cpufreqrel | group system (**R**) | – | W, dis; started on sys.boot_completed |
| init.common.rc:169 | ct_monitor | /system/bin/ct_monitor | **root** | – | W, class core — runs every boot as root |
| init.common.rc:174 | charger_app | /charger (= /sbin/healthd) | **root** | u:r:healthd:s0 | class charger |
| init.common.rc:222 | bugreport | /system/bin/dumpstate -d -p -B -o /data/data/com.android.shell/files/bugreports/bugreport | – (**R**) | (dumpstate_exec) | dis, W; **triggered by keycodes 114 115 116 (Vol-, Vol+, Pwr)** — repeatable at will |
| init.common.rc:231 | dts_hpx_service | /system/bin/dts_hpx_service | system | – | |
| init.common.rc:237/242 | dhcpcd_eth0 ×2 | /system/bin/dhcpcd … | – (R) | – | first definition wins |
| init.common.rc:247 | iprenew_eth0 | /system/bin/dhcpcd -n | – (R) | – | dis, W |
| init.common.rc:253 | demoapp_chmod | /system/bin/sh /system/etc/demoapp_chmod | **root** | – | dis, W; started by persist.sys.enableAPD=1 |
| init.debug.rc | acmed | /system/bin/acmed … | system | – | |
| init.wifi.rc | ifcfg_mac80211 | /system/bin/ifconfig wlan0 up | – (R) | – | dis, W |
| init.wifi.rc | dhcpcd_wlan0 / iprenew_wlan0 | /system/bin/dhcpcd … | groups incl. wifi | – | dis, W |
| init.wifi.rc | WiFiMACtoProp | /system/bin/WiFiMACtoProp | **root** | – | W, class main — every boot as root |
| init.wifi.rc | wifitest_runcmd | /system/bin/wifitest_runcmd.sh | **root** | – | dis (started externally) |
| init.wifi.vendor.rc | wlan_prov | /system/bin/wlan_prov | **root** | – | dis, W; `start`ed on boot |
| init.wifi.vendor.rc | wpa_supplicant / p2p_supplicant | /system/bin/wpa_supplicant -c/data/misc/wifi/wpa_supplicant.conf … | groups system wifi… | – | dis, W; **read /data config** |
| init.wifi.vendor.rc | wifi_driver_init | /system/bin/wifi_driver_init | **root** | – | dis, W; started on boot |
| init.bt.rc | dhcpcd_bt-pan / iprenew_bt-pan | /system/bin/dhcpcd … | bluetooth… | – | dis, W |
| init.bt.rc | bd_prov | /system/bin/bd_prov | **root**, group system bluetooth | u:r:bluetooth:s0 | dis, W; `start`ed early-boot; **reads /config/bt/bd_addr.conf** |
| init.bt.rc | bdt | /system/bin bdt s | – | – | **malformed** (binary = /system/bin directory); never execs |
| init.bt.rc | BrcmService / BrcmChmod | /system/bin/BrcmService.sh / BrcmChmod.sh | – (R) | – | dis, W |
| init.bt.vendor.rc | rfkill_bt | /system/bin/sh **/rfkill_bt.sh** (ramdisk) | **root** | u:r:rfkill_bt:s0 | W, class core — every boot as root, script in boot image |
| init.gps.rc | gpsd_4752(31)_[n]debug | /system/bin/gpsd_475xx -c /system/etc/gps_*.xml | gps | u:r:gpsd:s0 | dis |
| init.gps.rc | gpsd_mgr | /system/bin/gpsd_mgr.sh | – (**R**) | u:r:gpsd:s0 | W, class main — every boot as root |
| init.watchdog.rc | watchdogd | /sbin/watchdogd 60 20 | – (R) | u:r:watchdogd:s0 | W, class core |
| init.firmware.rc | intel_prop | /sbin/intel_prop | – (**R**) | u:r:intel_prop:s0 | W; `start`ed on boot; reads intel_prop.cfg (fs:…:propname) |
| init.config_init.rc | config_init | /system/bin/sh **/config_init.sh** (ramdisk) | – (**R**) | u:r:config_init:s0 | dis, W; `start`ed on fs |
| init.adbon.rc | enable_adb | /system/bin/sh /system/bin/adbon.sh | – (**R**) | – | W, class main — every boot as root |
| init.logtool.rc:18 | logtool-mos-user | /system/bin/sh /system/bin/logt_bootup_mos | – (**R**) | **DS** | W, **class main — runs every boot as uid0 in dumpstate domain** (matches device `init.svc.logtool-mos-user=stopped`) |
| init.logtool.rc:23 | logtool-cos-user | /system/bin/sh /system/bin/logt_bootup_cos | **root** | **DS** | dis, W (charger only) |
| init.logtool.rc:30 | logtool-cos | /system/bin/sh /system/bin/logt_coslogdog | – (R) | **DS** | dis, class logging-services (charger) |
| init.logtool.rc:36 | logtool-cosk | /system/bin/sh /system/bin/logt_cosklogdog | – (R) | **DS** | dis, class logging-services (charger) |
| init.logtool.rc:42 | *logtool-executor* | /system/bin/sh **/data/data/com.asus.LogTool/files/logtool-executor.sh** | **root** | **DS** | dis, W |
| init.logtool.rc:50 | *logtool-trigger* | /system/bin/sh **…/logtool-trigger.sh** | **root** | **DS** | dis, W |
| init.logtool.rc:58/62 | logMemLight/Heavy | /system/bin/get_mem_raw_data.sh -m2 / -l -v -m3 | – (R) | – | dis, class late_start |
| init.logtool.rc:79 | logt_bootup | /system/bin/sh /system/bin/logt_bootup | – (**R**) | **DS** | W, class main — every boot as root in dumpstate domain |
| init.logtool.rc:84 | *logdog-conf* | /system/bin/sh **…/logdog-conf.sh** | **root** | **DS** | dis, W |
| init.logtool.rc:91–121 | *logdog-{logcat,main,radio,events,system}* | /system/bin/sh **…/logdog-starter.sh** \<buffer\> | **root** | **DS** | dis, class logging-services |
| init.logtool.rc:122 | *klogdog* | /system/bin/sh **…/klogdog-starter.sh** | **root** | **DS** | dis, class logging-services |
| init.logtool.rc:128 | *tcpdump* | /system/bin/sh **…/tcpdump-starter.sh** | **root** | **DS** | dis, class logging-services |
| init.logtool.rc:134 | *hcidump* | /system/bin/sh **…/hcidump-starter.sh** | **root** | **DS** | dis, class logging-services |
| init.logtool.rc:140 | *modemtrace* | /system/bin/sh **…/modemtrace-starter.sh** | **root** | **DS** | dis, class logging-services |
| init.logtool.rc:147 | modemstop | /system/bin/configure_trace_modem -d -t0 | **root** | **DS** | dis, W |
| init.logtool.rc:155 | *archive-logs* | /system/bin/sh **…/archive-logs.sh** | **root** | **DS** | dis, W |
| init.logtool.rc:161 | *clear-logs* | /system/bin/sh **…/clear-logs.sh** | **root** | **DS** | dis, W |
| init.logtool.rc:168 | reset_modem | /system/bin/stmd-test 7 | – (R) | **DS** | W, class logging-services |
| init.logtool.rc:179 | *stop_modem_trace* | /system/bin/sh **…/modem-stopall.sh** | – (R) | **DS** | dis, W |
| init.logtool.rc:185 | logt_onechance | /system/bin/sh /system/bin/logt_onechance | **root** | **DS** | dis, class logging-services |
| init.logtool.rc:193 | *logbackup* | /system/bin/sh **…/packlogs.sh** | **root**, group sdcard_rw | **DS** | dis, W, class late_start |
| init.logtool.rc:208 | *psh_logging* | /system/bin/sh **…/pshdog-starter.sh** | **root** | **DS** | dis, class logging-services; **started by persist.logtool.sensor.psh=1** |
| init.logtool.rc:222 | m_usb_log | /system/bin/sh /system/bin/start_modem_setting | **root** | **DS** | W, dis; started by persist.logtool.modem.usblog=1 |
| init.logtool.rc:231 | *audio_logging* | /system/bin/sh **…/audiolog-toggle.sh** | **root** | **DS** | W, dis; **started by `persist.logtool.audio=*` (any value!)** |

**The 18 star-marked services** all run `/system/bin/sh <path-under-/data/data/com.asus.LogTool/files/…>` with **uid 0** (17 via `user root`; `stop_modem_trace` via a missing `user` line) **and `seclabel u:r:dumpstate:s0`**. None of those script files exist on the PGDO device (the LogTool app is not installed), so every start attempt fails with exec/ENOENT — consistent with the observed `init.svc.logtool-mos-user=stopped`.

## 2.3 Trigger inventory — every `on <trigger>` in the live set that touches a RW path, execs, loads props, or is conditioned on `persist.*`/`logtool.*`

**Ⓐ = conditioned on a `persist.*` prop (value read from `/data/property/persist.*` at boot by `load_persist_props` — attacker-controllable after one root foothold, and runtime-settable by any domain the policy allows for the prop's label); Ⓑ = conditioned on a non-persist `logtool.*` prop (runtime only); Ⓒ = expansion (`${…}`) of a property into the command arguments.**

| file:line | trigger | commands | prop label |
|---|---|---|---|
| init.aosp.rc:206 | sys.boot_from_charger_mode=1 | class_stop charger; trigger late-init | system_prop |
| init.aosp.rc:211/214 | load_system_props_action / load_persist_props_action | **load_system_props / load_persist_props** (+start logd, logd-reinit) | — |
| init.aosp.rc:220 | firmware_mounts_complete | rm /dev/.booting | — |
| init.aosp.rc:224 | late-init | trigger chain (see §2.1) | — |
| init.aosp.rc:246 | post-fs | **chown/chmod /cache 0770; restorecon_recursive /cache; mkdir /cache/recovery 0770; mkdir /cache/lost+found; chmod 0444 /sys/fs/selinux/policy** | — |
| init.aosp.rc:286 | post-fs-data | **chown/chmod /data 0771; restorecon /data; mkdir /data/media…; start logd; start vold; installkey /data; mkdir /data/bootchart 0755 shell shell; bootchart_init; copy /data/system/entropy.dat /dev/urandom; ~35 mkdirs (§2.2/§3.1); symlink /data/data/com.android.shell/files/bugreports /data/bugreports; mkdir /data/security 0711 system system; setusercryptopolicies /data/user; setprop selinux.reload_policy 1; restorecon_recursive /data; exec - system system -- /system/bin/tzdatacheck …/data/misc/zoneinfo** | — |
| init.aosp.rc:511–542 | vold.decrypt=… (7 triggers) | start defaultcrypto/encrypt; class_start/reset; **trigger post-fs-data; load_persist_props** | vold_prop |
| init.aosp.rc:518 | sys.init_log_level=* | loglevel ${sys.init_log_level} Ⓒ | system_prop |
| init.aosp.rc:548 | sys.powerctl=* | powerctl ${sys.powerctl} Ⓒ | powerctl_prop |
| init.aosp.rc:554 | sys.sysctl.extra_free_kbytes=* | **write /proc/sys/vm/extra_free_kbytes ${…}** Ⓒ | system_prop |
| init.aosp.rc:558 | sys.sysctl.tcp_def_init_rwnd=* | **write /proc/sys/net/ipv4/tcp_default_init_rwnd ${…}** Ⓒ | system_prop |
| init.aosp.rc:596 | ro.debuggable=1 | start console | (fixed 0 on device) |
| init.aosp.rc:607 | ro.kernel.qemu=1 | start adbd | (fixed 0) |
| init.aosp.rc:752 | persist.logd.logpersistd=logcatd | **mkdir /data/misc/logd 0700 logd log; exec - logd log -- /system/bin/logcat … -f /data/misc/logd/logcat …; start logcatd** Ⓐ | logd_prop |
| init.mofd_v1.rc:204 | persist.asus.dclick=* | **write /proc/mxt_double_tap ${persist.asus.dclick}; write /proc/gt928_gesture "${persist.asus.dclick}${persist.asus.gesture.type}"** ⒶⒸ | logtool_prop |
| init.mofd_v1.rc:208 | persist.asus.gesture.type=* | **write /proc/mxt_gesture ${persist.asus.gesture.type}; write /proc/gt928_gesture "${…}${…}"** ⒶⒸ | logtool_prop |
| init.mofd_v1.rc:212/215 | persist.asus.zstylus=* / zstylus_only_mode=* | write /proc/mxt_stylus ${…} / /proc/mxt_zstylus_only_mode ${…} ⒶⒸ | logtool_prop |
| init.mofd_v1.rc:16/20/50/163/218/295 | early-init/init/boot/post-fs-data/post-fs (static) | setprop ro.boot.min.cap; insmod ~20 modules from /lib/modules (ramdisk); **mount sepfs; mkdir /data/misc/audio; mkdir /data/misc/firmware; mkdir /data/silent_lake 0777; mkdir /data/sensorhubdcal 0755; mkdir /data/sensors 0766; start sensors_config; start fg_conf; mkdir /data/misc/dnsmasq 0755 root root; mkdir /data/misc/dnsmasq/dalvik-cache 0755 root root (oddity, §3.1); restorecon_recursive /data/misc/dnsmasq; chmod/chown /data/sensors/COMPS.conf; mkdir /data/logs; symlink /data/logs /logs; chown/chmod /sys cpufreq…; restorecon_recursive /factory /config /logs** | — |
| init.mofd_v1.rc:303 | init.svc.pvrsrvctl=stopped | insmod /lib/modules/dfrgx.ko | init-managed |
| init.mofd_v1.rc:307/310 | service.mmgr.smp=1/0 | write /proc/irq/36/smp_affinity … | system_prop |
| init.mofd_v1.rc:313/317 | sys.camera.factory_mode=1/0 | write /sys/module/ov680/parameters/factory_mode …; setprop camera.hal.factory … | system_prop |
| init.mofd_v1.rc:321 | sensors.accelboost=1 | write /sys/devices/…/boostpulse 2 | default_prop |
| init.mofd_v1.rc:344 | persist.sys.display.iris.absent=0 | stop dpst Ⓐ | system_prop |
| init.mofd_v1.rc:352 | sys.boot_completed=1 | write …/cpufreq/interactive/boost 0; **start VerifyVouchers (root, init domain)** | system_server |
| init.mofd_v1.rc:356/380 | charger | **mount ext4 …/system /system ro; mount ext4 /dev/block/by-name/logs /logs**; start watchdogd; insmod …; write /sys/…; setprop thermal.lite.crash 0 | — |
| init.common.rc:9/20/30 | early-init/init/boot (static) | chmod /charger; chown/chmod /dev/dri/card0; symlink card0; mount binfmt_misc; mount debugfs; mkdir /mnt/shell 0700 shell shell; symlink /sdcard /mnt/sdcard|/storage/sdcard0; sysfs writes | — |
| init.common.rc:43 | fs | **mkdir /factory 0775; mkdir /config 0775; mkdir /media 0775; mount_all /fstab; mkdir /config/wifi + chown system wifi; mkdir /config/em + chown system system; chown /sys usb_otg; restorecon_recursive /config; restorecon_recursive /factory; restorecon_recursive /logs; chown system system /factory/Voucher_enc.bin** | — |
| init.common.rc:60 | post-fs | chown/chmod /sys cpufreq interactive…; write irq_load_threshold | — |
| init.common.rc:76 | post-fs-data | **mkdir /data/system 0770; write /proc/sys/kernel/ctrl-alt-del 0; mkdir /mnt/asec/media; setprop ro.com.android.dataroaming/debug.rs.default-CPU-driver/ro.fmrx.sound.forced; symlink /sys/…/emmc_total_size /data/data/emmc_total_size (oddity §3.1); chown /sys gt_max_freq_mhz; copy /proc/emmc_ipanic_{header,console,threads,gbuffer} → /data/dontpanic/… (4×); chown root log + chmod 0640 each; mount ext4 /dev/block/by-name/ADF /ADF rw…; chown/chmod /ADF /APD 0775; restorecon_recursive /ADF; rm /data/system/preload_category.db; symlink /system/etc/preload_category.db → /data/system/preload_category.db; mkdir /data/misc/dts 0771 media audio; chmod 666 /dev/dts_eagle** | — |
| init.common.rc:134 | sys.boot_completed=1 | start bcu_cpufreqrel | system_server |
| init.common.rc:137 | charger | start intel_prop; setprop thermal.lite.crash 0; chown/chmod /dev/dri/card0; symlink card0; **setprop sys.usb.config charging**; trigger firmware_mounts_complete | — |
| init.common.rc:180 | ro.enable.native.bridge.exec=1 | **copy /system/vendor/etc/binfmt_misc/arm_{exe,dyn} /proc/sys/fs/binfmt_misc/register** | system_prop |
| init.common.rc:184 | ro.enable.native.bridge.exec64=1 | copy arm64_{exe,dyn} → binfmt_misc/register | system_prop |
| init.common.rc:195 | service.adb.root=1 | write android_usb enable 0/1; **restart adbd** | **shell_prop — settable by adb shell** |
| init.common.rc:200–213 | sys.property_forcedshutdown=1; sys.shutdown.requested={0,1,1recovery,1bootloader} | write /sys/module/intel_mid_osip/…; write /sys/devices/virtual/misc/watchdog/{shutdown,reboot}_ongoing 1 | system_prop |
| init.common.rc:216/218 | ro.serialno=* / atd.serialno=* | **write /sys/class/android_usb/android0/iSerial ${ro.serialno} / ${atd.serialno}** Ⓒ | ro.* (init) / **default_prop** |
| init.common.rc:259 | persist.sys.enableAPD=1 | **mount ext4 /dev/block/by-name/APD /ADF rw…; chown/chmod /ADF; restorecon_recursive /ADF; start demoapp_chmod (root)** Ⓐ | system_prop |
| init.common.rc:266 | persist.sys.enableAPD=0 | umount /APD Ⓐ | system_prop |
| init.debug.rc:1 | (import internal_props.rc — ABSENT) | symlink /data/logs /logs (first-wins vs mofd copy); write kptr_restrict 2 | — |
| init.diag.rc | post-fs | chown root diag /dev/msr* /dev/mid_ipc; chmod 0640 | — |
| init.avc.rc | init/post-fs | insmod videobuf*.ko; chown system vibrator sysfs | — |
| init.wifi.rc:4 | post-fs-data | mkdir /data/misc/wifi 0770 wifi wifi (dup of aosp) | — |
| init.wifi.rc:7 | boot | write /proc/sys/net/ipv4/tcp_limit_output_bytes | — |
| init.wifi.rc:10 | post-fs-data | mkdir /data/misc/wifi/sockets; mkdir /data/misc/dhcp 0770 dhcp wifi; mkdir /data/misc/firmware | — |
| init.wifi.rc:14 | init.svc.wpa_supplicant=stopped | stop dhcpcd | init-managed |
| init.wifi.vendor.rc:5 | post-fs | mkdir /factory/wifi; chown system wifi; chmod 0770; setprop wifi.interface/ap.interface; **start wlan_prov; start wifi_driver_init (both root)** | — |
| init.bt.rc:3 | post-fs | mkdir /config/bt; chown system bluetooth; chmod 0770 | — |
| init.bt.vendor.rc:2–18 | init | chmod/chown /dev/ttyMFD0, rfkill sysfs, /proc/host_wake, /dev/rfkill; insmod bcm_bt_lpm | — |
| init.bt.vendor.rc:18 | post-fs | mkdir /config/bt; mkdir /factory/bt; chown/chmod 0770 both | — |
| init.bt.vendor.rc:28 | early-boot | **chmod 0644 /config/bt/bd_addr.conf; setprop ro.bt.bdaddr_path "/config/bt/bd_addr.conf"; start bd_prov (root, bluetooth domain)** | — |
| init.bt.vendor.rc:32 | (service) | rfkill_bt — root, class core, ramdisk script (§2.2) | — |
| init.camera.rc | post-fs | insmod camera modules (lm3559, t4kxx, ov5670, hm2051, atomisp…) | — |
| init.gps.rc:2 | post-fs-data | mkdir /data/gps 0770 gps system | — |
| init.gps.rc | post-fs; ro.spid.gps.tty={ttyMFD1,ttyMFD3,ttyS2} | chmod/chown tty; mkdir /dev/gps 0770; symlink /dev/ttyX /dev/gps/ttyGPS; symlink power/control /dev/gps/ttyGPSPowerControl | system_prop |
| init.gps.rc | persist.gps.chip={BCM4752,BCM47531} | setprop gps.version.driver … Ⓐ | gpsd_prop / gps_prop |
| init.watchdog.rc | sys.boot_completed=1; init.svc.{droidboot,charger_app}=running | write /sys/devices/virtual/misc/watchdog/counter "0" | — |
| init.firmware.rc:1 | boot | start intel_prop (root, init domain) | — |
| init.config_init.rc:1 | fs | mkdir /local_cfg; **start config_init (root, config_init domain)** | — |
| init.logtool.rc:1 | charger | **mount ext4 /dev/block/by-name/cache /cache…; mkdir /cache/logtool; mkdir /cache/logtool/cos; start logtool-cosk; start logtool-cos; start logtool-cos-user (all root+DS)** | — |
| init.logtool.rc:9 | post-fs-data | **mkdir /data/uts 0750; mkdir /data/boot 0777; mkdir /data/debug 0777; mkdir /data/logtool 0777; mkdir /data/coslog 0777; mkdir /data/roslog 0777; mkdir /data/poslog 0777 — all system system** | — |
| init.logtool.rc:66 | persist.logtool.mem.logging=light | stop logMemHeavy; start logMemLight Ⓐ | logtool_prop |
| init.logtool.rc:70 | …=heavy | stop logMemLight; start logMemHeavy Ⓐ | logtool_prop |
| init.logtool.rc:74 | …=stop | stop both; write /sys/module/lowmemorykiller/parameters/debug_level 1 Ⓐ | logtool_prop |
| init.logtool.rc:173 | logtool.modem.nologging=-1 | restart reset_modem Ⓑ | logtool_prop |
| init.logtool.rc:176 | logtool.modem.relogging=1 | **restart modemtrace → /data/data/com.asus.LogTool/files/modemtrace-starter.sh as root+DS** Ⓑ | logtool_prop |
| init.logtool.rc:215 | persist.logtool.sensor.psh=1 | **start psh_logging → …/pshdog-starter.sh as root+DS** Ⓐ | logtool_prop |
| init.logtool.rc:218 | …=0 | stop psh_logging Ⓐ | logtool_prop |
| init.logtool.rc:263 | persist.logtool.audio=* | **start audio_logging → …/audiolog-toggle.sh as root+DS** Ⓐ (**any value**) | logtool_prop |
| init.logtool.rc:266/270/273 | persist.logtool.modem.usblog=1/0; persist.logtool.modem.logging=1 | setprop cross-links; **start m_usb_log (root+DS, /system script)** Ⓐ | logtool_prop |
| init.logtool.rc:277/281 | persist.logtool.uart=1/0 | write i2c uart_switch; **write /proc/sys/kernel/printk 7/0** Ⓐ | logtool_prop |
| init.logtool.rc:286–310 | persist.logtool.{cos,pos,ros}.logging=1/0 | **mkdir /cache/logtool; write /cache/logtool/{cos,pos,ros}_enable 1/0** Ⓐ | logtool_prop |
| init.logtool.rc:313–324 | persist.logtool.touch.{logging,logrd}=1/0 | write /proc/{,p72g_}touch_debug_log Ⓐ | logtool_prop |
| init.logtool.rc:327–341 | persist.logtool.upi.loglv={0,4,8,12} | write /sys/module/ug31xx_battery/parameters/op_options N Ⓐ | logtool_prop |
| init.logtool.rc:339 | persist.logtool.upi.loglv=rst | **asus_exec ×2 — INVALID COMMAND, both lines are no-ops (§1b); the prop is never reset, so `rst` persists and re-fires every boot doing nothing** Ⓐ | logtool_prop |
| init.logtool.rc:344/347 | persist.logtool.sensor.gravity=1/0 | write /sys/bus/i2c/devices/5-000e/message Ⓐ | logtool_prop |
| init.logtool.rc:352/355 | logtool.onechance.logging=1/0 | start/stop logt_onechance (root+DS, /system script) Ⓑ | logtool_prop |
| init.platform.usb.rc / init.usb.rc | sys.usb.config=…; persist.sys.usb.config=*; sys.usb.vbus=… | stop/start adbd; ~30 android_usb sysfs writes; setprop sys.usb.state ${…} Ⓒ; **mkdir /dev/usb-ffs/adb 0770 shell shell; mount functionfs** | system_radio_prop / system_prop / ffs_prop |
| init.usb.configfs.rc | sys.usb.config=… && sys.usb.configfs=1 | configfs gadget writes + rm/symlink under /config/usb_gadget (inactive: configfs=0) | ffs_prop |
| init.trace.rc | boot | chmod/chown /sys/kernel/debug/tracing/* (trace_marker 0222 etc.) | — |
| init.zram.rc / init.readahead.rc / init.dirtybackground.rc / init.largeram.rc / init.normalram.rc | boot/post-fs-data | sysfs/proc writes; swapon_all /fstab.zram | — |

**Property-label cross-note (from `property_contexts`):** `persist.logtool.*`, `persist.asus.*`, `persist.bt.*`, `persist.adb.*`, `persist.service.mts.*`, `system.at-proxy.*`, `logtool.*`, `uts.*`, `ro.uts.*` → **`u:object_r:logtool_prop`** (ASUS custom label); `persist.sys.*`, `persist.service.*`, `sys.*`, `service.*` → `system_prop`; `selinux.reload_policy` → `security_prop` (`selinux.` prefix); `selinux.restorecon_recursive` → `restorecon_prop`; `service.adb.{root,tcp.port}` → `shell_prop` (settable by adb shell); `persist.gps.*` → `gpsd_prop`/`gps_prop`; `atd.serialno` → falls to `*` → `default_prop`. Which domains may `set` each label is answered in the companion (`selinux-policy.md` §6; queries used: `allow <domain> logtool_prop:property_service set`, `… security_prop …`, `… default_prop …`).

---

# 3. How could a file under /data or /cache ever come to exist with attacker-chosen content before it is read by a root process?

## 3.1 What init itself creates on RW paths (every boot)

Created **as uid 0 in u:r:init:s0** (or via `exec` child), on attacker-visible RW filesystems:

| path | created by | notes |
|---|---|---|
| `/data/*` ~50 dirs | init.aosp.rc:294–396 | standard labels after `restorecon_recursive /data` |
| **`/data/security` 0711 system system** | init.aosp.rc:387 | **exists on device; `current/` is NOT created** — the §1a gate fails today solely because the subtree is absent |
| `/data/{boot,debug,logtool,coslog,roslog,poslog}` **0777** system system | init.logtool.rc:10–16 | world-writable dirs, recreated every boot |
| `/data/sensors` 0766 system:input, `/data/silent_lake` 0777 | init.mofd_v1.rc:175/166 | world-writable |
| **`/data/misc/dnsmasq` + `/data/misc/dnsmasq/dalvik-cache` 0755 root root** | init.mofd_v1.rc:189–190 | **the oddity**: `dalvik-cache` under *dnsmasq* is a botched line (nothing references it — almost certainly a mangled `mkdir /data/dalvik-cache`). Root-owned 0755 beneath sticky 01771 `/data/misc`; `restorecon_recursive /data/misc/dnsmasq` relabels. No service reads them. Benign. |
| `/data/logs` + `symlink /logs → /data/logs` | init.mofd_v1.rc:201–202 (init.debug.rc:3 duplicate — first wins) | `/logs` is the `logs`-partition mount point in charger mode; in normal boot it is a symlink into /data |
| `symlink /data/data/emmc_total_size → /sys/devices/pci0000:00/0000:00:01.0/emmc_total_size` | init.common.rc:97 | **second oddity**: init (root) plants a symlink inside system-owned `/data/data` pointing at a sysfs file. Read-only side effect; shows init writing into `/data/data`. |
| `symlink /data/system/preload_category.db → /system/etc/preload_category.db` (after `rm` of the /data side) | init.common.rc:126–127 | init replaces a /data/system path with a symlink into RO /system every boot |
| `symlink /data/data/com.android.shell/files/bugreports /data/bugreports` | init.aosp.rc:384 | dangling (app may not exist) |
| `/cache/logtool{,/cos}` + `write /cache/logtool/{cos,pos,ros}_enable` | init.logtool.rc:3–4, 286–310 | **init creates + writes files on /cache** — fixed content (`1`/`0`), fixed paths; trigger-gated by `persist.logtool.{cos,pos,ros}.logging` Ⓐ |
| `/data/dontpanic/emmc_ipanic_{header,console,threads,gbuffer}` via `copy /proc/…` | init.common.rc:102–116 | init copies kernel panic buffers into /data (`copy` = open dst O_WRONLY|O_CREAT|O_TRUNC → init-created /data files). **`/data/dontpanic` is not mkdir'ed anywhere in this rc set**, so these fail unless the dir already exists on the device. |
| `/data/bootchart` 0755 shell shell + `bootchart_init` | init.aosp.rc:303–304 | bootchart reads `/data/bootchart/start` (root read of a /data file) |

## 3.2 Root processes that READ (or exec) files on RW paths

| reader (context) | file | consequence |
|---|---|---|
| **`load_persist_props` (init itself)** | every `/data/property/persist.*` regular file. Acceptance check (decoded at `init+0x80531c0`): name starts with `persist.`, `d_type == DT_REG`, opened with O_NOFOLLOW, fstat ok, **st_uid == 0 && st_gid == 0 && st_nlink == 1 && (st_mode & 077) == 0** — else klog `"skipping insecure property file %s (uid=%u gid=%u nlink=%u mode=%o)"`; value ≤ 91 bytes read | value becomes a property → **all matching `on property:` triggers fire** → the whole Ⓐ table of §2.3 becomes attacker-gated |
| **18 LogTool services** (uid 0 + `seclabel u:r:dumpstate:s0`) | `/system/bin/sh /data/data/com.asus.LogTool/files/*.sh` | **missing files** — the (a) pivot of §4: create them once → root code exec every boot |
| logt_bootup / logtool-mos-user (root+DS, class main, every boot) | /system/bin/logt_bootup{,_mos} (RO fs) | same-boot dirtycow exec target |
| `sensors_config` (root, **u:r:init:s0**, post-fs-data) | /data/sensors/COMPS.conf, ACCEL.conf, ALS_P.conf (in world-writable /data/sensors) | init-domain root parses /data files every boot (binary parser, no script exec); the binary itself is a same-boot dirtycow target landing in **u:r:init:s0** |
| `VerifyVouchers` (root, **u:r:init:s0**, sys.boot_completed) | /factory/Voucher_enc.bin (chown'ed system on `fs`) | init-domain dirtycow target; parses a /factory-partition file |
| `config_init` (root, u:r:config_init:s0, `on fs`) | ramdisk `/config_init.sh`; `getprop ro.swconf.forced` (set ⇒ skip); else `cat /config/local_config`; then `for f in /local_cfg/*/init.props` → **`setprop` per line** | the `/config`-file-driven branch is dead here (ro.swconf.forced baked in boot image); init.props loop reads /system only. Same-boot dirtycow target (ramdisk script). |
| `intel_prop` (root, u:r:intel_prop:s0, on boot) | intel_prop.cfg: `fs:/sys/...:sys.prop.name` — copies /sys file contents into properties | file-content→property pump (sysfs sources) |
| `bd_prov` (root, u:r:bluetooth:s0, early-boot) | `/config/bt/bd_addr.conf` (chmod 0644; ro.bt.bdaddr_path points there) | root bluetooth-domain parser of a **/config-partition** file (RW partition, system-writable) |
| `wpa_supplicant` (wifi uid) | `/data/misc/wifi/wpa_supplicant.conf` | uid wifi — not root |
| `tzdatacheck` (`exec - system system`) | /data/misc/zoneinfo | uid 1000 |
| `bootchart_init` (init) | /data/bootchart/start | existence check |
| `keystore` (keystore), `gatekeeperd` (system) | /data/misc/… | not root |

## 3.3 Can attacker-chosen content exist before a root process reads it? — the mechanisms

Given only **dirtycow** (arbitrary overwrite of *existing* files; no creation, no mkdir) and *no* initial privilege:

1. **No — not pre-foothold.** Every candidate location needs either a *directory* that does not exist (`/data/data/com.asus.LogTool/files`, `/data/security/current`) or a *file* that does not exist (`/data/property/persist.<name>` for a prop never set on this device). Dirtycow cannot create either. The only init-created files with trigger-gated existence (`/cache/logtool/*_enable`) have fixed content.
2. **Overwrite-existing** needs the attacking process to open the file at all: `/data/property/*` is root:root 0700, `/data/data/*` is system-owned ⇒ the initial foothold must already be uid 0 (or uid 1000). Candidate footholds (dirtycow + exec of an existing binary; the setuid/group bits of each target are on-device facts to confirm via §4.2 step 8):
   - `/system/bin/run-as` (labeled `runas_exec`; on stock user builds it is setuid-root and group-shell-executable, the classic dirtycow target) execed by adb shell → euid 0 in shell domain;
   - `/system/bin/dumpstate` + the **keychord** (§4.1 B) → uid 0 in dumpstate domain, **repeatable in-session**;
   - any always-running root service binary (`logt_bootup_mos`, `ct_monitor`, `wlan_prov`, `rfkill_bt` …) → one-shot per boot.
3. **After any uid-0 foothold**, DAC is gone; the remaining constraint is SELinux labeling of the target: `/data/data/...` → `system_data_file`, `/data/property/...` → `property_data_file`, `/data/security/...` → `security_file` (labels per the stock `file_contexts`; `restorecon_recursive /data` re-applies them every boot). Which of {shell, dumpstate, installd, init, system} may create/write those types is answered in the companion (`selinux-policy.md` §5–6). Strong prior: **init's own domain (u:r:init:s0) demonstrably creates `/data/security` and dozens of /data dirs every boot** — an init-domain payload can almost certainly plant everything (§4.1 C).
4. **The only pure-creation primitive init has** (no foothold needed): `write <path> <content>` with `${persist.X}` expansion (§1c). But every `write` target in the rc set is a fixed path and the only ones under /data|/cache are `/cache/logtool/{cos,pos,ros}_enable` with *constant* content and `/data/misc/logd/logcat` (created by logd-uid logcat, not init). No property-controlled *path* is ever written, execed, or copied. ⇒ **pre-foothold attacker-chosen file creation does not exist in this rc set.**

---

# 4. Historical proposals and precondition queries

## 4.1 Unvalidated persistence proposals

The paths below describe what the init code might permit if their DAC, SELinux,
and trigger preconditions were satisfied. No working LogTool script persistence
or policy-replacement installation was established. The final implementation
used Magisk for persistence. These archived steps are not tested instructions.

- (a) *get a root-exec'd file created with controlled content* — **a proposed LogTool-script route** (A below);
- (b) *pivot to another RW-path root-exec primitive* — the repeatable one is the keychord bugreport service (B);
- (c) *reload-policy direct route* — **a proposed policy-reload route** (C): the init code has a version/file-access gate for loading `/data/security/current/sepolicy` (§1a); successful planting and reload were not established.

### A: proposed LogTool script persistence

The 18 `user root`-or-implicit-root + `seclabel u:r:dumpstate:s0` services exec `/system/bin/sh /data/data/com.asus.LogTool/files/<name>.sh`; the directory was absent (app not installed). The archived proposal required:

1. **Foothold (one boot):** dirtycow-overwrite `/system/bin/run-as` (verify its setuid/group-shell bits on device, §4.2 step 8) with a payload doing `setresgid/setresuid(0,0,0); execve("/system/bin/sh")` → euid 0 in shell domain; *or* overwrite `/system/bin/dumpstate` and press the keychord (B) for uid 0 in dumpstate domain — the proposal favored dumpstate because the service also names that domain. Matching a domain name alone does not establish that the resulting files, credentials, and permissions allow the whole chain.
2. **Plant the script:** `mkdir -p /data/data/com.asus.LogTool/files` (0755), write `pshdog-starter.sh` (or `audiolog-toggle.sh`) with the root payload, `chmod 0755`. At next boot `restorecon_recursive /data` labels it `system_data_file`; the execing `sh` runs in dumpstate domain, so only *read* access matters.
3. **Plant the trigger:** write `/data/property/persist.logtool.sensor.psh` with content `1` (root:root, mode with no group/other bits, nlink 1 — exactly what init's own writer produces, §3.2 row 1), or `/data/property/persist.logtool.audio` with any non-empty value (the `=*` trigger fires on any set). At `load_persist_props` (after post-fs-data, before `on boot`) init sets the prop → the trigger fires → `start psh_logging` execs `/system/bin/sh /data/data/com.asus.LogTool/files/pshdog-starter.sh` **as uid 0 in u:r:dumpstate:s0**. If the file-access and trigger preconditions held, this would repeat at boot without another Dirty COW overwrite. That persistence was not validated.
4. *(In-session, without reboot)*: `setprop logtool.modem.relogging 1` (logtool_prop) restarts `modemtrace` → execs `modemtrace-starter.sh` immediately; `setprop persist.logtool.sensor.psh 1` both plants the persist file (init writes it to /data/property) and starts psh_logging immediately. Gated on which domains may set `logtool_prop` — answered in the companion (`selinux-policy.md` §6:
asus_init_shell, dumpstate, system_app, system_server, toolbox — **not** shell); if the foothold domain may not, the reboot path of step 3 still works.

The proposed script/policy chain depended on write access to
`system_data_file`, `property_data_file`, and `security_file`, property-service
grants for `logtool_prop`, and any block-device access required by its payload.
Those reference permission queries do not establish that a working script or
policy replacement was installed. The final chain avoided relying on these
persistence proposals.

### B: proposed direct dumpstate replacement

`init.common.rc:222`: `service bugreport /system/bin/dumpstate -d -p -B -o …` — `disabled oneshot`, **`keycodes 114 115 116`** (Vol−, Vol+, Power). init's keychord handler starts it on demand; **no `user` line → uid 0**, file-label transition → `u:r:dumpstate:s0`. The historical proposal was to replace dumpstate directly before invoking the chord. The final chain instead replaced its logcat child, then used a zygote payload to reach the required identity. The direct-replacement persistence proposal was not validated.

Other same-boot root-exec pivots found in §2 (overwrites lost at reboot, so *sequence* primitives, not persistence): `logt_bootup`, `logtool-mos-user` (class main, every boot, dumpstate domain), `ct_monitor`, `enable_adb`, `WiFiMACtoProp`, `wlan_prov`, `wifi_driver_init`, `gpsd_mgr`, `perfprofd`, `pvrsrvctl`, `bcu_cpufreqrel`, `fg_conf`, `thermald` (charger), `charger_app`, `rfkill_bt` (ramdisk script), `config_init` (ramdisk script), `sensors_config` / `VerifyVouchers` / `info_setting` (**u:r:init:s0** — the privileged set for C), and the `insmod /lib/modules/*.ko` commands (kernel-module load from the boot image, same-boot).

### C: proposed policy-reload route

Section 1a identifies the version/file-access gate for these paths:

```
/data/security/current/selinux_version      ← byte-identical copy of the device's /selinux_version
/data/security/current/sepolicy             ← attacker policy, same policydb version as stock /sepolicy
/data/security/current/file_contexts        ← stock copy (or attacker-augmented)
/data/security/current/property_contexts    ← stock copy
/data/security/current/service_contexts     ← stock copy (content never read — gate only, §1a.4)
/data/security/current/seapp_contexts       ← stock copy
```

If these files could be created with the required access and matching version, init's every-boot `setprop selinux.reload_policy 1` (post-fs-data) would attempt to load **the supplied sepolicy as the live policy** (and adopt the planted file/property contexts) before zygote or any service starts. Simplest policy content: stock policy with the permissive bit set for all types (or extra allow rules for init/dumpstate/shell), version-matched to the device kernel (read the version from the stock `/sepolicy` — also present in this ramdisk).

- Requires: create `/data/security/current` + 6 files — a uid-0 payload in a domain allowed to write `security_file`. **Init's own domain demonstrably writes that label every boot** (it creates `/data/security` itself, init.aosp.rc:387), so the natural planter is an init-domain payload: dirtycow `sensors_config`/`VerifyVouchers`/`info_setting` in-session (all root + `seclabel u:r:init:s0`), or — once A gives a working dumpstate-domain script each boot — the script itself can plant C on the next boot if dumpstate may write `security_file` (sepolicy cross-check; if not, iterate: the A-script can in turn dirtycow an init-domain binary and re-trigger it in the same boot).
- Intended result: a permissive policy after reboot. This was not installed or validated; whether the proposed foothold could plant the files and complete a reload remained unresolved.
- Conditional effect: if supplied `file_contexts` were adopted, `setprop selinux.restorecon_recursive <path>` (restorecon_prop) relabels arbitrary trees at runtime.

### Failure modes / caveats

- `persist.logtool.upi.loglv=rst`: trigger fires but both commands are parse-error no-ops (§1b); the value, once `rst`, is never reset. Avoid setting it while experimenting (harmless but noisy).
- `selinux.reload_policy` reload failures leave the old policy loaded; this does not establish that a replacement policy is safe or usable.
- `restorecon_recursive /data` (post-fs-data) relabels planted /data files each boot — plant at paths whose stock label grants dumpstate read (system_data_file does).
- The archived proposal favored executable targets not continuously mapped. This target-selection assumption was not a complete staging procedure.
- `copy /proc/emmc_ipanic_* → /data/dontpanic` and bootchart assume dirs that this rc set never creates — check `adb shell ls -la /data/dontpanic /data/bootchart` if those directories matter to the hypothesis.

## 4.2 Historical read-only precondition queries

These queries were proposed to assess the hypotheses above. Their expected
values describe the historical stock-device context. The keychord trigger is
separate from the read-only queries.

```bash
# 0. Baseline
adb shell id
adb shell getprop ro.build.fingerprint          # expect ...WW_P01M-V5.5.1-... user/release-keys
adb shell getprop ro.debuggable                 # expect 0
adb shell getprop ro.secure                     # expect 1
adb shell getenforce                            # expect Enforcing

# 1. Reload path is armed on device
adb shell getprop selinux.reload_policy         # expect 1  (init.aosp.rc:401 ran)
adb shell 'cat /proc/cmdline | tr " " "\n" | grep selinux'   # expect androidboot.selinux=enforcing (gate §1a.2)

# 2. Reload gate state: /data/security exists, current/ absent
adb shell ls -la /data/security                 # expect: dir 0711 system system, no "current"
adb shell ls -la /data/security/current         # expect: No such file or directory (ENOENT, not EACCES)

# 3. The version file to mirror (gate §1a.3: content+size must match exactly)
adb shell ls -la /selinux_version
adb shell 'md5sum /selinux_version; wc -c /selinux_version'   # if denied to shell, read after the foothold

# 4. LogTool services are registered and their /data scripts are absent
adb shell getprop init.svc.logtool-mos-user     # expect stopped (ran & exited) — registration proof
adb shell pm list packages com.asus.LogTool     # expect nothing / not found
adb shell dumpsys package com.asus.LogTool      # expect Not Found
adb shell ls -la /data/data/com.asus.LogTool    # expect: No such file or directory
adb shell ls -la /data/data | head              # which app dirs exist (system:system 0771)

# 5. Which LogTool persist props exist on the device (→ which Ⓐ triggers fire at each boot)
adb shell 'getprop | grep -E "persist\.logtool|persist\.asus"'
adb shell getprop persist.logtool.sensor.psh    # if "1": psh_logging starts every boot already
adb shell getprop persist.logtool.audio         # if non-empty: audio_logging starts every boot already
adb shell getprop init.svc.psh_logging          # state of the /data-script service (if registered)

# 6. /data/property is root-only (persist planting needs the foothold)
adb shell ls -la /data/property                 # expect Permission denied (dir 0700 root root)

# 7. Exec-bit sanity of the RW mounts (fstab has no noexec on /data|/cache|/config|/factory)
adb shell 'cat /proc/mounts | grep -E " /data | /cache | /config | /factory | /system "'

# 8. Dirtycow target inventory + labels
adb shell ls -laZ /system/bin/run-as /system/bin/dumpstate /system/bin/logt_bootup_mos \
                  /system/bin/sensors_config /system/bin/VerifyVouchers /system/bin/info_setting \
                  /system/bin/sh /system/bin/ct_monitor /system/bin/wlan_prov \
                  /system/bin/logt_bootup /system/bin/install-recovery.sh
adb shell ls -laZ /sbin/ueventd /init /sepolicy /selinux_version   # rootfs inventory

# 9. Keychord bugreport service (repeatable root-exec pivot B)
adb shell getprop init.svc.bugreport            # query the current service state

# 10. Runtime-settability probes (read-only checks of current state, no writes):
adb shell getprop service.adb.root              # shell_prop — shows whether the adb-root trigger was ever used
adb shell 'dmesg | grep -E "init: .*invalid command|reload policy|SELinux"'   # boot parse errors + reload attempt log
```

The commands above query state. Invoking the Volume Down + Volume Up + Power
keychord would start the bugreport service and is a separate state-changing
trigger. The proposed planting operations in section 4.1 were not validated.

## 4.3 What the static analysis establishes

- The rc set does not provide a pre-foothold primitive for arbitrary file
  creation at the proposed LogTool or policy paths (section 3.3).
- A uid-0 process would still need the relevant SELinux grants. The possible
  script locations, trigger properties, and policy-version gate are static
  findings, not evidence of working persistence.
- The keychord starts init's bugreport service. The final implementation used
  that trigger with the logcat carrier and zygote child; it did not establish
  the LogTool or policy-reload proposals as additional implementations.
- The companion policy report supplies the reference permission rows. Runtime
  access and successful policy replacement cannot be inferred from init code
  or a matching uid alone.

---

*Policy-dependent questions retained from the original analysis:

(1) `allow <domain> security_file:{dir,file} …` for domain ∈ {dumpstate, shell, init, system, installd}; (2) `allow <domain> logtool_prop:property_service set` for domain ∈ {dumpstate, shell, init, untrusted_app-with-logtool-seinfo}; (3) `allow dumpstate system_data_file:dir {search write add_name}` + `:file {read open getattr create}`; (4) `allow dumpstate property_data_file:{dir,file} …` (5) permissive flags of the stock policy's types; (6) policydb version of stock /sepolicy vs kernel-supported (kernel 3.4.x, Intel Moorefield).*
