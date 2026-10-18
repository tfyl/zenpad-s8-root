# ASUS ZenPad S 8.0 (Z580CA / P01M) — WW 5.5.1.0 compiled SELinux policy + vendor binary analysis

Static analysis of the WW reference policy and vendor binaries. The historical
chain assessment below includes proposals that were not implemented. The final
chain and its runtime evidence limits are described in the methodology.

> Historical WW 5.5.1 research. Bundled boot and policy files came from the WW OTA,
> not a capture of the original PGDO boot. The completed tablet run and later
> evidence limits are in [methodology](../../methodology.md) and
> [artifacts](../../artifacts.md).

Artifacts analyzed here:

- `reference/ww-5.5.1/ramdisk/` — the retained boot-ramdisk inputs: compiled
  `sepolicy` (162,715 B, SE Linux policy **v30**, MLS, 8 symbol tables, 7 ocontexts),
  `file_contexts`, `property_contexts`, `service_contexts`, `seapp_contexts`, all `init*.rc`,
  `default.prop`.
- The WW `system.new.dat` converted to ext4 ("system.img", see §8) — analysed from a local conversion. The converted image is not
  distributed. It can be regenerated from a separately acquired matching
  `UL-P01M-WW-5.5.1.0-user.zip` with `tools/ota/extract_block_image.py`; acquisition
  metadata gaps are recorded in [artifacts](../../artifacts.md#acquisition-and-licensing-gaps).

Companion document (init binary disassembly, NOT repeated here): `init.md`.
Device facts verified live and treated as ground truth are quoted in the sections below.

Complete. All nine sections below; every policy claim is from the compiled `sepolicy` itself
and was cross-checked twice (own parser + patched-copy setools, §0.2).

## 0. Tooling note

### 0.1 Why setools "cannot" read this policy — root cause found

`setools`/`seinfo` 4.4.4 are installed but abort on the stock file with
`libsepol.avtab_read_item: more than one specifier` at avtab entry **311 of 5658**.
This is NOT a bad entry and not a version problem: **ASUS's policy is an AOSP-marshmallow-format
policy, and its avtab xperm ("ioctl operations") datums use the AOSP-M 33-byte layout, while
upstream libsepol expects the 34-byte layout** that upstream invented later:

- AOSP M (external/selinux marshmallow-release, `avtab_operations`):
  `u8 type; u32 perms[8];` → **33-byte datum**, key spec bits `AVTAB_OPNUM_*` 0x0100/0x0200/0x0400
  (ioctl by command number; `type` byte = ioctl magic, e.g. 0x54='T', 0x89=SIOC*) and
  `AVTAB_OPTYPE_*` 0x1000/0x2000/0x4000 (ioctl by driver-type bitmap).
- Upstream libsepol: `u8 specified; u8 driver; u32 perms[8];` → 34-byte datum
  (`AVTAB_XPERMS_*` semantics).

The device kernel agrees with AOSP-M: `LineageOS/android_kernel_asus_moorefield` cm-13.0
`security/selinux/ss/avtab.h` has `AVTAB_OPNUM_*`/`AVTAB_OPTYPE_*` exactly as above, and
`avc_has_operation()` matches OPNUM entries by `(type byte, _IOC_NR)` and OPTYPE entries by
the type bitmap. `ioctl_has_perm()` passes `(u16) cmd` (type=(cmd>>8)&0xff, nr=cmd&0xff).

Because upstream reads xperm datums one byte too long, entry 310 (the first xperm, a
`udp_socket` ioctl rule) desynchronises the stream and entry 311 lands on garbage whose
`specified` has several bits set → "more than one specifier". The same misparse is why the
earlier "more than one specifier ⇒ corrupt entry" reading of this policy (see the sibling
notes) is wrong.

### 0.2 Two independent parsers agreeing

1. **Policy parser** `tools/selinux/parse_policy.py` and query CLI
   `tools/selinux/query_policy.py`: full kernel binary
   policy v30 reader (ebitmaps, 8 symbol tables, avtab incl. AOSP-M ioctl-ops datums,
   conditionals, role_trans/allow, pre-COMP_FTRANS filename_trans, 7 ocontext tables,
   genfs, range_trans, type_attr_map). Validates **exactly**: `parsed_end == 162715 == file
   size` (zero trailing bytes), avtab nel = **5658** (identical to libsepol's own count),
   0 conditional nodes, 632 types (637 entries incl. aliases), 87 classes, 1 role
   (object_r not stored), 1 user, 1024 categories. Spec histogram: 5394 allow, 142
   typetransition, 92 dontaudit, 10 auditallow, 20 ioctl-opnum allows (no AVTAB_ENABLED
   stale flags present).
2. **setools cross-check** `sepolicy-upstream.bin` (temporary verification file, not committed):
   byte-patched copy of the stock policy (each of the 20 xperm datums: `type` byte set to 0x01,
   0x00 driver byte inserted → upstream layout). `sepol_policydb_read OK`, and every
   spot-check below matches the own parser exactly (init/frp, system_server/frp, shell
   property sets, shell/factory_file, init/security_file, dumpstate blk_file = none,
   zygote dyntransition).

The parser and query CLI are committed under `tools/selinux/`. The stock
reference policy is unmodified.

### 0.3 Quick type map (values are binary-policy primary values)

`init`=311, `shell`=558, `dumpstate`=125, `factory_file`=315, `frp_block_device`=583,
`block_device`=581 (plain type, catch-all for /dev/block/*), `voucher_exec`=12,
`info_setting_exec`=183, `logtool_prop`=520, `security_prop`=262, `restorecon_prop`=286,
`property_data_file`=120, `security_file`=/data/security label.

---

## 1. frp / block-device grants

`file_contexts`: `/dev/block/mmcblk0p9  u:object_r:frp_block_device:s0` (the frp/persistent
partition; `/dev/block/by-name/persistent` is a symlink to it). `frp_block_device` is a
plain type whose only attribute is `dev_type` (74 device types).

**Every rule whose target set covers `frp_block_device` (directly or via `dev_type`), all
specs, all classes — the complete list is 10 rules; the effective grants on the p9 node are:**

```
allow init           frp_block_device : chr_file { read setattr open }
allow init           dev_type         : blk_file { ioctl read getattr lock open }
allow system_server  frp_block_device : blk_file { ioctl read write getattr lock append open }
allow ueventd        dev_type         : blk_file { create setattr unlink }
allow domain         dev_type         : lnk_file { ioctl read getattr lock open }
allow init           dev_type         : dir { ...write... }        # /dev/block dir itself
allow init           dev_type         : lnk_file { create }
```

**Answer to the goal question — init-domain root CANNOT write the frp byte.**
`init` may open/read/ioctl (+setattr on the chr side) `frp_block_device`, and has
`write` on several *other* block types (`device`, `dm_device`, `metadata_block_device`,
`swap_block_device`, `userdata_block_device`, `tmpfs`), but the ONLY domain with
`write`/`append` on `frp_block_device:blk_file` is **system_server**. Nobody else
(vold, uncrypt, toolbox, fsck …) has any frp rule. `allow init dev_type : blk_file
{ioctl read getattr lock open}` deliberately omits write.

`block_device` (generic `/dev/block(/.*)?` label) `:blk_file` holders (read side noted where the write side is absent):
`init {read getattr setattr open}`, `vold {ioctl read write create getattr setattr lock
append unlink rename open}` (+matching auditallow), `uncrypt {write append open}`,
`fsck`, `blkid`, `blkid_untrusted`, `sgdisk`, `toolbox`, `install_recovery` (on its own
partition types), `system_server` — i.e. classic AOSP vold/fsck plumbing; none of it
reaches `frp_block_device`.

Consequence: the "init-domain root writes the last byte of /dev/block/by-name/persistent"
chain is **not available through any existing allow rule**. Reaching it requires either
(a) code execution in **system_server**, (b) a policy reload after modifying `sepolicy`
(see §2/§9 — blocked: `/sepolicy` lives in rootfs/ramfs, not dirtycow-able), or
(c) kernel-level (dirtycow is (c) but only against page-cache-backed files, not device
nodes). The one init-domain *block write* that exists from factory data is on the **misc**
partition — see §8/§9.

## 2. init domain power set

`init` has attribute `mlstrustedsubject` + `domain`. Highlights (full dump: 1,729 rules,
mostly the universal `relabelto` fan-out; `relabelto` lines omitted here):

**Property sets (the restarter question):** `allow init property_type : property_service set`
— `property_type` is an attribute with **41 members = every property type in the policy**:
`default_prop, system_prop, shell_prop, security_prop, restorecon_prop, logtool_prop,
ctl_default_prop, ctl_dumpstate_prop, ctl_*_prop, radio_prop, logd_prop, vold_prop, …`
plus `allow init system_radio_prop : set`. So init may set **any** property including
`selinux.reload_policy` (`security_prop`) and `selinux.restorecon_recursive`
(`restorecon_prop`), and any `ctl.*` (all `ctl_*` types are in `property_type`).
No domain can *deny* init anything on the property service.

**Filesystem:** `allow init fs_type : filesystem { mount unmount remount … }` and the
same on `unlabeled` (mount/unmount/remount anything); `dir` write on `rootfs`, `tmpfs`,
`dev_type`, `sdcard_internal`, `cgroup`, `proc`, `sysfs_*`, `debugfs`, `pstorefs`,
`selinuxfs`(!), `sepfs`, `binfmt_miscfs`, `usermodehelper`; `file` write on `device`,
`debugfs`, `proc`, `proc_net`, `proc_security`, `proc_sysrq`, `selinuxfs`, `sepfs`,
`sdcard_internal`, `usermodehelper`, `fscklogs`, `binfmt_miscfs`, `cgroup`, `init` (self).

**Block:** as §1 — `device`, `dm_device`, `metadata_block_device`, `swap_block_device`,
`tmpfs`, `userdata_block_device`(write-only rule) but **not** frp.

**Execute / transitions:** `init` holds `execute(+no_trans)/read/open` on
**`info_setting_exec`, `voucher_exec`, `logtoold_exec`, `dumpstate_exec`, `shell_exec`,
`grep_exec`, `sensors_config_exec`, `fw_switch_exec`, `wifi_init_exec`, `wifi_mac_exec`,
`wl_exec`** (execute_no_trans = runs *in init domain*), plus `execute` on ~50 daemon
exec types with `allow init <X> : process {transition siginh rlimitinh}` +
`type_transition` into each daemon domain (`dumpstate`, `zygote`, `vold`, `adbd`, …).
`init_exec` is its entrypoint. `allow init init : process {… setexec setfscreate setkeycreate
setsockcreate …}`; `allow init domain : process sigkill`.

**/data/security and /data/property:**
- `/data/security(/.*)?` → `security_file`: `allow init security_file : file {getattr
  ioctl lock open read}` + dir `{create getattr ioctl open read search setattr}` —
  init may **read** /data/security (mac_permissions.xml etc.), may create/replace it,
  but has **no `write`/`append`** on existing `security_file:file` (replacement =
  unlink+create via dir rights). Only **system_server** has real
  `security_file:file {append create … write}`.
- `/data/property(/.*)?` → `property_data_file`: **init only**, full
  `{append create getattr ioctl lock open read relabelfrom relabelto rename setattr
  unlink write}`. Nobody else can touch persistent-property files — consistent with the
  ground-truth dirtycow idea (init re-reads those files at boot; file owner/mode/nlink
  checks are satisfied by dirtycow writes into the page cache).

**Other:** `key {search setattr write}`; `security` class: only `compute_av/compute_create`
(**no `load_policy`, nobody holds it** — and `setenforce` is held by nobody either;
see §9 note on what that does/doesn't stop); `service_manager list` only.

## 3. shell domain full power set (current level)

`shell` attrs: `appdomain domain mlstrustedsubject netdomain`.

**Property service — the complete set allow list (answer: shell can NOT set `selinux.*`):**

```
allow shell ctl_dumpstate_prop : property_service set
allow shell debug_prop         : property_service set
allow shell powerctl_prop      : property_service set
allow shell shell_prop         : property_service set
```

- `selinux.reload_policy` / `selinux.` → `security_prop` — settable by **system_server only**
  (init via `property_type`). `selinux.restorecon_recursive` → `restorecon_prop` —
  **vold only**. shell: denied. This is consistent with the live observation that
  `logtool.*`/`persist.logtool.*` (`logtool_prop`) and `ctl.start` (`ctl.` → catch-all
  `ctl_default_prop`) don't stick: shell has neither type. Note `ctl.dumpstate` maps
  specially to `ctl_dumpstate_prop` which **is** settable by shell per policy — so if the
  live `ctl.dumpstate` rejection is SELinux, it is *not* this property-context check
  (worth one targeted adb check, §9 list). `default_prop` (catch-all incl. `atd.*`,
  `factory.product.device`, `ro.wifimac`) is settable by **init only**.

**File access by label (allow file; the important ones):**

```
factory_file        {getattr open read setattr write}     # /factory: shell READ+WRITE (SELinux level!)
security_file       {getattr}                             # /data/security: getattr only (no read)
properties_device   {getattr ioctl lock open read}         # /dev/__properties__
selinuxfs           {append getattr ioctl lock open read write}   # includes /sys/fs/senlinux/load (DAC root-only)
shell_data_file     {full incl. execute execute_no_trans}
sdcard_internal     {full}   sdcard_external {full}
shell / shell_tmpfs {full / execute read write}
apk_data_file       {execmod execute execute_no_trans getattr ioctl lock open read}
system_file         {execute execute_no_trans getattr ioctl lock open read}
system_data_file    {execmod execute execute_no_trans getattr open read}
debugfs, cgroup, proc, proc_net, proc_cpuinfo, qtaguid_proc(write), cache_file(full),
bootchart_data_file(full), data_sensors_file, wallpaper_file, radio_data_file{read write},
backup_data_file, cache_backup_file, themepack_exchange_file, …
```

**Execute transitions:** `shell_exec` (entrypoint+execute_no_trans — the adb shell),
`runas_exec` with `allow shell runas : process {rlimitinh siginh transition}` +
`type_transition`, and `execute_no_trans` on `toolbox_exec`, `grep_exec`, `logcat_exec`,
`dex2oat_exec`, `demoapp_file`, `apk_data_file`, `zygote_exec`, `oemfs`, `system_file`,
`system_data_file`. **Not** `dumpstate_exec` (shell cannot exec into dumpstate) and no
`*_exec` type transitions at all — shell only stays shell (or runas).

**Process:** self `{… ptrace fork setpgid setsched sigkill … execmem}`, `sigchld` to
adbd/debuggerd/init/zygote, `getattr` on `domain`; **no `dyntransition`** to anything.

**Binder/services:** `call transfer` to appdomain/binderservicedomain; `find` on ~120
service_manager services (incl. ASUS: `ISEP_service`, `DockObserver_service`,
`IProxyService_service`, `cameraproxy_service`, `cta_service`, `cws_service`,
`aware_service`, `securityfile_service`, `securitymanager_service`,
`persistent_data_block_service`, `registry_service`), `list` on servicemanager.

**Net:** full tcp/udp/rawip/packet/netlink_route sockets (`node_bind`, `name_bind`).

**Summary:** shell = essentially an app domain + **RW `factory_file`** + selinuxfs file
write + property sets limited to 4 types.

## 4. dumpstate domain

`dumpstate` attributes: `domain mlstrustedsubject netdomain`. Relevant access rules:

- **app_data_file: NO rules at all** — no read/open/search. The LogTool-script route
  (`/data/data/com.asus.LogTool/files/*.sh`, `app_data_file`) is not reachable from
  dumpstate, and com.asus.LogTool is not installed anyway (ground truth).
- **/data/property (`property_data_file`): NO rules.**
- **Block devices (`blk_file`): NO rules** (expected ✓).
- **`security_file`: dir{getattr search}, file{getattr}, lnk_file{getattr ioctl lock open
  read}** — cannot read /data/security contents.
- **kill:** `capability {chown dac_override fowner fsetid kill net_raw setgid setuid
  sys_admin sys_ptrace sys_resource}` + `capability2 syslog` + `process signal` on
  `appdomain, mediaserver, sdcardd, surfaceflinger, system_server, drmserver`.
- **dyntransition: none.** Only `allow dumpstate vdc : process {rlimitinh siginh transition}`
  + `type_transition dumpstate vdc_exec => vdc`, and a `dontaudit` wall on vdc.

**Property sets (important):**

```
allow dumpstate ctl_default_prop : property_service set   # ctl.* catch-all!
allow dumpstate logtool_prop     : property_service set
allow dumpstate system_prop      : property_service set
```

dumpstate may set `logtool.*`, `persist.logtool.*`, `persist.sys.*`/`persist.service.*`/
`persist.security.*` (all `system_prop`), and **any `ctl.*`** not matched by a specific
prefix (`ctl.start`/`ctl.stop`/`ctl.restart` land in `ctl_default_prop` → dumpstate can
start/stop arbitrary init services!). No `security_prop`/`restorecon_prop`.

**File:** full RW on `log_file`, `logtoold_data_file`, `cache_file`, `bluetooth_data_file`,
`anr_data_file`, `dumpstate`, `dumpstate_tmpfs`, `debugfs`, `cgroup`; read on `net_data_file`,
`apk_data_file`, `asec_public_file`, `properties_device`, `proc*`, `pstorefs`;
`lnk_file` full on `system_app_data_file`(!); entrypoints `dumpstate_exec`, `logcat_exec`;
execute_no_trans `logtoold_exec`, `procrank_exec`. Sockets: `dumpstate_socket`,
netlink_route, packet, rawip, tcp/udp full, `property_socket write`, `logd*`, `mdnsd_socket`.
service_manager `find` on ~120 services. `filesystem {config_file factory_file fs_type
log_file getattr}` (mount-label getattr only, **not** factory file access).
ioctl-opnum allows: sockets magic 0x54 nr {0x1,0x11,0x13,0x14,0x1b,0x51} (TCGETS/TIOCOUTQ/
TIOCGWINSZ/TIOCINQ?/TIOCGICOUNT-style tty ioctls) on unix sockets.

## 5. voucher_exec, info_setting_exec, factory_file, custom exec types

**file_contexts (the type names):**

```
/system/bin/info_setting   u:object_r:info_setting_exec:s0      # NOT init_exec
/system/bin/VerifyVouchers u:object_r:voucher_exec:s0
/factory(/.*)?             u:object_r:factory_file:s0
```

Both custom exec types have exactly **one** accessor:

```
allow init voucher_exec      : file { read getattr execute execute_no_trans open }
allow init info_setting_exec : file { read getattr execute execute_no_trans open }
```

No `type_transition` into any `voucher`/`info_setting` **domain** — those types are
`exec_type` only; the init.mofd_v1.rc services pin `seclabel u:r:init:s0`, so both run
**every boot as uid 0 in the init domain** (`info_setting`: class core, oneshot, always;
`VerifyVouchers`: class core, oneshot, disabled, `on property:sys.boot_completed=1`).
`logtoold_exec` is likewise init-only `execute execute_no_trans`.

**Who can read/write `factory_file` (shell can read — and write, per this set):**

```
init             dir{full} file{create getattr open read setattr unlink write} lnk{...}
shell            dir{getattr open read search write}  file{getattr open read setattr write}
system_server    dir{add_name search write}           file{create open read write}
toolbox          dir{full-ish}                        file{create getattr open read setattr write}
bluetooth        dir/file full
mmgr             dir/file full
recovery         dir/file full
wlan_prov        dir/file full-ish
sensors_config   dir{open read search write}           file{getattr open read setattr write}
vold             dir/file full
asus_init_shell  dir{getattr open read remove_name rmdir search setattr write}
mediaserver      dir{search-ish} file{getattr ioctl lock open read}
hostapd, wpa     file{open read}
system_app       file{getattr open read}
```

So an overwrite of `/factory/info` or `/factory/Voucher_enc.bin` is permitted for shell by
policy (DAC: `/factory` is mounted RW ext4 and `/factory/info` is 0777 root:root — plain
writes allowed by both layers for info; `Voucher_enc.bin` is 0600 system:system → dirtycow
for the write, plain `cat` not even possible… note `/factory/info` IS shell-readable as
verified live).

## 6. service_contexts / property_contexts (ASUS-relevant) and who may set them

**service_contexts (158 entries) — ASUS/Intel/vendor-relevant name → type, and who may
`add` (register) / `find` (lookup) that binder service:**

| service name | type | add (register) | find |
|---|---|---|---|
| `com.intel.security.service.ISEPService` | ISEP_service | system_app | shell, system_app, system_server … |
| `DockObserver` | DockObserver_service | — | shell, apps |
| `com.android.net.IProxyService` | IProxyService_service | — | shell |
| `media.camera.proxy` | cameraproxy_service | — | shell |
| `CTA_SERVICE` | cta_service | — | shell |
| `cws_service_manager` | cws_service | system_app, system_server | shell |
| `awareservice(2)` | aware_service | system_server | shell |
| `dts_hpx_service` | dtshpxservice_service | dtshpxservice | shell |
| `securityfile` | securityfile_service | **(no add rule!)** | shell, system_server |
| `security` | securitymanager_service | system_app | shell |
| `telephony.registry` | registry_service | — | shell |
| `persistent_data_block` | persistent_data_block_service | — | shell |
| `proxy-tunneling`, `ptproxy_usbreset` | radio_service | radio | shell |
| `system_server_service` | system_server_service | system_server | system_server |

There is **no** `dumpstate`/`logtool` binder service in service_contexts (grep confirms);
ASUS services are registered by `system_app`/`system_server`/vendor daemons only.

**Property label → who may `set` (complete map; `property_type` attribute = init covers all):**

```
security_prop       <- system_server            # selinux.*
restorecon_prop     <- vold                     # selinux.restorecon_recursive
logtool_prop        <- asus_init_shell dumpstate system_app system_server toolbox
ctl_default_prop    <- ap_log_srv dumpstate gpsd modem_class_main system_app system_server toolbox
ctl_dumpstate_prop  <- shell
ctl_bugreport_prop  <- system_app system_server
ctl_bootanim_prop   <- surfaceflinger;  ctl_fuse_prop <- vold;  ctl_mdnsd_prop <- netd
ctl_rildaemon_prop  <- modem_class_main radio toolbox;  ctl_dhcp_pan_prop <- bluetooth system_server
default_prop        <- (nobody but init)        # atd.*, factory.product.device, ro.wifimac, unmatched
system_prop         <- 13 domains (asus_init_shell dumpstate healthd intel_fw_props intel_prop
                         kernel mmgr netd rild system_app system_server toolbox vold …)
shell_prop          <- adbd shell;   debug_prop <- shell system_app system_server
powerctl_prop       <- adbd shell system_server uncrypt vold
system_radio_prop   <- asus_init_shell init radio rild system_app system_server
```

`seapp_contexts` is stock M (system_server/system_app/bluetooth/nfc/radio/shell/
isolated_app/untrusted_app/platform_app/smartcard) — nothing ASUS-specific.

## 7. zygote / system_server dyntransition

Confirmed in THIS policy:

```
allow zygote system_server : process { dyntransition getpgid setpgid }
allow zygote appdomain     : process { dyntransition getpgid setpgid }
```

`zygote → system_server` dyntransition exists ✓ and **zygote is the only domain with a
dyntransition into `system_server`** (complete dyntransition table audited: 95 rules, e.g.
init→{dumpstate,fsck,toolbox,mmgr,rild,slideshow,rfkill_bt,tzdatacheck,zygote,adbd,…},
adbd→shell, runas→{shell,radio,untrusted_app,platform_app,isolated_app,bluetooth,nfc,
shared_relro,mmgr_app,dnsmasq_script}, vold→{fsck*,blkid*,sgdisk,sdcardd}, netd→{hostapd,
dhcp,dnsmasq,clatd}, dumpstate→vdc, installd→dex2oat, kernel→init, mmgr→mmgr_app,
mtp→ppp, dnsmasq→dnsmasq_script). `shell → runas` dyntransition exists (shell→runas only).

Practical reading: to sit in system_server one must already be code-exec inside zygote's
fork path (i.e. an app_process compromise / zygote bug), or abuse
`type_transition … zygote_exec => zygote` (init only).

## 8. system.new.dat binary analysis (`/system/bin/info_setting`, `VerifyVouchers`, sweep)

Converted image: `system.img` root = `/system` (see the header note — not committed, regenerable).
Both binaries are 32-bit x86 PIE, stripped, bionic, gcc 4.9. Temporary `*.asm`
and `*.xref.asm` listings were generated with Capstone and a local `disxref.py`
helper. Those listings and the helper were not committed.

### 8.1 VerifyVouchers (init domain, root, every boot on `sys.boot_completed=1`)

Full logic (448-line binary):

1. `fopen("/factory/Voucher_enc.bin","rb")`; on failure: `property_set("atd.voucher.exist","0")`,
   `exit(0)`.
2. `atd.voucher.exist := "1"`; read a **16-bit big-endian checksum** (2×fgetc), then up to
   600 bytes payload.
3. XOR-decode payload with a **580-byte embedded key** (`idx = i % 580`; if a decoded byte
   is 0x00 the plaintext byte is kept instead — a NUL-avoiding encoding).
4. Compute the **plain byte sum** (SSE `paddd` chain) of the decoded buffer; `intact =
   (sum == header16)`.
5. `property_set("atd.voucher.intact", intact?"1":"0")` and
   `property_set("atd.voucher.ready",   intact?"1":"0")`. No exec, no file write, no block
   access, no crypto imports.

**Format is fully attacker-forgeable** (embedded key + byte-sum): dirtycow'ing
`/factory/Voucher_enc.bin` gives complete control of `atd.voucher.{exist,intact,ready}`.
These are unmatched → `default_prop` (init may set them; reads are unrestricted).
**Consumer sweep: nothing in /system (bin, xbin, vendor, framework, app, priv-app)
references `atd.voucher.*` at all** — dead feedback channel on the shipping device (live
check: `getprop | grep atd`). So this path is influence-only, not a privilege primitive.

### 8.2 info_setting (init domain, root, every boot)

The binary is the "ASUS NVM tool": a slot store of **3072 × 256-byte RSA-"encrypted" blobs**
(slot `i` at byte offset `i<<8`, first 768 KB = `0xc0000`) kept in **two places** —
native: `/dev/block/by-name/misc`, backup: `/factory/info`. Decryption is
`RSA_public_decrypt` with an **embedded PEM public key** (RSA-2048, PKCS#1 type-1 padding
implied), and the decrypted value must be exactly **128 bytes** (`SLOT_SIZE`).
Boot flow (user build):

1. Slot table (main): `0→ro.isn, 1→ro.serialno(default "unknown"), 2→ro.config.versatility,
   3→ro.config.CID, 4→ro.config.idcode, 0xe→ro.config.packingcode, 0xf→ro.config.datecode`.
2. For each slot: read native blob from **`/dev/block/by-name/misc`** at `idx<<8`
   (256 B), RSA_public_decrypt → must be 128 B. On **success**, the raw 256 B ciphertext
   is copied to the backup file: `write_to_backup` → `ensure_file("/factory/info")` then
   `copy_buf_idx` (`fopen "rb+"`, `fseek(idx<<8)`, `fwrite 256 B`, fsync). `ensure_file`
   **creates `/factory/info` missing with 768 KB of 0xFF and `chmod 0777`** — this is where
   the observed 0777 mode comes from.
3. On native read **failure** (and `ro.build.type != "eng"`): `get_backup_idx_value`:
   read+decrypt the same slot from **`/factory/info`**; on success it **"Fix index %d"s —
   copies the raw 256-byte backup ciphertext VERBATIM into `/dev/block/by-name/misc` at
   `idx<<8`** (`copy_buf_idx("/dev/block/by-name/misc", idx, blob)`), i.e. a root/init-domain
   **block-device write whose bytes come from /factory/info**; then the 128-byte value is
   used. On backup failure: give up, slot value = default.
4. `property_set(<ro.* name>, value)` per slot (init domain → any prop type).
5. If `ro.build.type == "eng"`: `property_set("factory.product.device","NoSetting")`;
   else log `No ENG build, skip set factory info`.

**Write path is compiled OUT of this user build** (verified: the strings
`asus_nvm_write`, `user`, `No support write function in user-build`, `Encrypt fail!`,
`Write backup fail`, `%s: write native/backup idx(%d) success`, `Error write size %d
(0<= write <= 128)`, `Create empty file fail!`, and the sysfs hardware-ID readers
(`/sys/module/intel_mid_sfi/parameters/{pcb_id,project_id,hardware_id}`,
`cpuinfo_max_freq`, `get CPU/PCB/PROJ/HW ID error`) have **zero code references** —
they are dead rodata; likewise `PEM_read_bio_RSAPrivateKey`/`RSA_private_encrypt` are
imported but have no PLT slot). So on WW-user the only writes are: backup-file refresh
(step 2) and the "Fix index" misc-partition write (step 3). No `exec*`, no `system()`,
no prop names derived from file content — values only.

### 8.3 /system sweep — every binary referencing `/factory` (and `persist.` prop setters)

`bin|xbin|vendor` (412 files) string sweep:

| binary | /factory use | notes |
|---|---|---|
| `info_setting` | `/factory/info` r/w | §8.2 |
| `VerifyVouchers` | `/factory/Voucher_enc.bin` read | §8.1 |
| `bd_prov` | `/factory/bt/bd_addr.conf`, `/factory/info` read | service: class core, root, oneshot, disabled, **`seclabel u:r:bluetooth:s0`** (init.bt.rc); copies BT addr to /config |
| `sensors_config` | `/factory/{ACCEL,ALS_P,COMPS,GYRO,PS_P}.conf`, `/factory/info` read | service: class main, root, oneshot, disabled but **`start sensors_config` in init.mofd_v1.rc data-stage ⇒ runs EVERY BOOT**, **`seclabel u:r:init:s0`** — init-domain root parses sensor calibration + /factory/info. No property_set import. |
| `WiFiMACtoProp` | `/factory/wifi/wifi_mac.txt` → `setprop ro.wifimac \`cat …\`` | shell script; `wifi_mac_exec`; init has `execute_no_trans` but script exec goes through `/system/bin/sh` (`shell_exec`) ⇒ domain **asus_init_shell** (logtool/system/system_radio props only — `ro.wifimac` is `default_prop`, so the setprop is policy-denied unless mapping differs; live check) |
| `FwSwitch` | writes `/factory/wifi/*` firmware blobs | `fw_switch_exec`; run by init? (service in init.wifi.rc) |
| `droidboot` | `/factory/.adbon`, `.readBtMac`, `.readWifiMac` marker dirs; `umount /factory` | bootloader-mode userspace, not normal boot |
| `crashlogd` | reads `/factory/userdata_footer` (+ `/logs/factory_sum`) | **not referenced by any init*.rc** and has no file_contexts entry — only `default.prop: persist.logtool.crashlogd.en=0`; presumably started by the (absent) LogTool APK. Reads many `persist.*` props |
| `vendor/lib/libWVStreamControlAPI_L1.so` | `/factory` (Widevine) | lib |

`persist.`-string binaries (mostly readers): `logt_bootup*`, `asus_mts`, `lpe_prober_record`,
`t2l_hit`, `wifi_driver_init`, `gpsd*`, `netd`, `vold`, `logd`, `mdnsd`, `wl`,
`sensorhubd`, `screenrecord`, `dumpstate` — the *boot scripts that set props from data*
are the LogTool ones (`logt_bootup`, `logt_bootup_mos`, class main, oneshot, **NOT
disabled ⇒ run every boot as root `seclabel u:r:dumpstate:s0`**); both exit early on user
builds (`logt_bootup.sh`: waits for `/data/data/com.asus.LogTool/files/logtool-executor.sh`
and `exit 0` when `ro.build.type=user` and it is absent), so on the shipping device they
are inert; their only writes are /cache/logtool/boot (`dmesg`) and /data/*log copies.
No `/factory` consumer sets props from parse data except `WiFiMACtoProp` (§8.3) and
`info_setting` (RSA-gated, §8.2). No consumer of `/factory/DeviceStatus.txt` or
`Voucher_enc` outside VerifyVouchers; `DeviceStatus.txt` is dead on the shipping system.

---

## 9. Historical chain assessment and query plan

### 9.1 Historical chain ratings

These ratings describe the earlier static hypotheses. They do not replace the
implemented zygote-child/Magisk sequence in the methodology.

**(A) dirtycow `/factory/info` → info_setting (init-domain root, every boot) — PARTIAL.**
What our bytes can do: (1) values for `ro.isn/ro.serialno/ro.config.*` only if we can forge
or replay **valid RSA-signed 256-byte blobs** (private key not present on the device; the
write path + `PEM_read_bio_RSAPrivateKey` are compiled out — but *replaying/shuffling
existing slots* works, since any valid blob decrypts at any idx: e.g. swap the CID and
serialno ciphertexts; and corrupting a native blob via any means triggers the self-heal
read of our backup). (2) the "Fix index" path writes **our 256 raw bytes into
/dev/block/by-name/misc at a slot offset ≤ 0xbff00** — but only after the blob passes
`RSA_public_decrypt(...)=128B`, i.e. only blobs we copied from the device itself.
**What it can NOT do:** reach `/dev/block/mmcblk0p9` (different partition), write
arbitrary bytes (RSA gate), exec anything, or set props of interesting types (ro.* only,
and only signed values). Rating: **low for privilege gain; medium for NVM/identity
tampering (serial/CID/etc. slot shuffle → props at next boot)**.

**(B) other `/factory` files read by root processes** — `sensors_config` (**init domain**,
every boot!) parses 5 plain-text calibration files + `/factory/info`; `WiFiMACtoProp`
(asus_init_shell) reads `wifi_mac.txt` into a setprop; `bd_prov` (bluetooth domain, on
demand) reads `bd_addr.conf`/`info`. None of these is a known primitive, but
**`sensors_config` parsing attacker-controlled text as init-domain root at every boot is
the best remaining memory-safety target** (a crash/overflow there is init-domain root).
`DeviceStatus.txt`/`userdata_footer` have no live consumer.

**(C) VerifyVouchers** — full control of `atd.voucher.*` (forgeable XOR+sum format), zero
consumers on this firmware. Dead end for privilege.

**(D) FRP access and the earlier policy-replacement hypothesis.** The reference
rows in section 1 grant `system_server` the relevant `frp_block_device` block
access; init's different character-device row does not grant that block write.
The final payload reached the required gid/uid and domain through zygote.

The earlier policy-replacement assessment assumed policy could only be loaded
from rootfs. The [init analysis](init.md), section 1a.3,
identifies a version/file-access gate for `/data/security/current`, so the
rootfs-only assumption is superseded. This does not establish a working way to
plant those files or complete a live reload. The reference grants init
`selinuxfs:file write`; no `security load_policy` grant was found in this report.
The running kernel's complete reload checks were not established by those rows.

The LogTool services additionally require script files and suitable access to
create and read them. Their registration alone did not establish persistence.
The final implementation used the logcat carrier and Magisk instead.

These static findings identify possible surfaces and permission limits. They
did not establish a direct `/factory` route to arbitrary FRP writes or a working
policy-replacement installation.

### 9.2 Historical read-only query plan

These are Android-shell queries for the stock-device research context. Expected
labels and values were hypotheses to check, rather than guarantees for every
firmware build.

1. `ls -lZ /factory /factory/info /factory/Voucher_enc.bin /factory/wifi /factory/bt`
   + `mount | grep factory` — confirm labels (`factory_file`) and the RW ext4 mount,
   file modes (0777 vs 0600).
2. Query each property separately, for example `getprop ro.build.type`.
   The original plan covered `ro.serialno`, `ro.isn`, `ro.config.CID`,
   `factory.product.device`, `ro.wifimac`, and `atd.voucher.*` (ro.wifimac:
   expected unset/denied, section 8.3; atd values: expected 1/1/1). Device identity
   values belong in private local notes, not a publication tree.
3. `ls -l /dev/block/by-name/misc /dev/block/mmcblk0p9` + `ls -lZ /dev/block/by-name/`
   — confirm symlink targets and labels (misc's label decides which allow covers the
   "Fix index" write; expected `block_device` or `device`).
4. `dmesg | grep -i avc; logcat -b events -d | grep -i avc` right after boot — look for
   `info_setting`/`sensors_config`/`VerifyVouchers` denials (esp. any avc on
   `blk_file:write` for misc, and `default_prop:set` for `ro.wifimac`).
5. `ps -Z` / `top -Z` during the first minute after boot (and `getprop init.svc.*`) —
   catch `info_setting`/`sensors_config` running as `u:r:init:s0` and the LogTool boot
   scripts as `u:r:dumpstate:s0`; `bd_prov` only appears if started, expected
   `u:r:bluetooth:s0`.
6. `cat /factory/info | busybox hexdump -C | head` — capture the 768KB FF file + the 256B
   slots at 0/0x100/0x200/0x300/0x400/0xe00/0xf00 (the 7 ro.* ciphertexts) — the corpus
   for replay/shuffle experiments and for offline RSA analysis of the embedded pubkey
   (already extracted: §8.2 pubkey PEM).
7. `getprop atd.voucher.ready` — query the current voucher verdict without
   changing the voucher file.
8. `ls /sys/fs/selinux/; ls -l /sys/fs/selinuxfs/load` + `getenforce` — confirm load-file
   mode (root-only) for the §9.1(D) policy-replacement note.
9. `ls /data/data/com.asus.LogTool` (expect absent) and `ls /data/logtool` (expect absent)
   — re-confirm the LogTool/dumpstate-script routes are inert on user build.

A separate historical proposal would have corrupted `Voucher_enc.bin` and
rebooted to observe the three voucher properties. That would change device
state; it is excluded from the read-only query plan and was not part of the
implemented unlock chain.

Some queries were later used during the recorded run; see
[methodology](../../methodology.md) for the resulting evidence and limits.
