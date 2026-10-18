# WW 5.5.1 droidboot: unlock and flash gates

Device context: ASUS ZenPad S 8.0 Z580CA (P01MA), Intel Moorefield, Android 6.0.1.
The analyzed WW ELF is `reference/ww-5.5.1/executables/droidboot`; the separately pulled device ELF
is the excluded target-derived comparison copy. The saved copies differ only in the 16-byte GNU
build-id note (section 8). This ELF comparison does not establish that their
complete boot images or SELinux policies match. See [artifacts](../../artifacts.md).

## Recorded implementation and evidence

The final implementation used Dirty COW to replace cached `logcat` and
`app_process32` contents. The bugreport carrier requested a zygote restart;
a forked child set gid/uid 1000 before changing to `u:r:system_server:s0`.
It opened the persistent partition and read the last byte as `0x01`
(`already1`); the record does not identify its first writer. See the
[methodology](../../methodology.md) for the mechanism, missing initial staging
record, and the archived v6 parent diagnostic-parser defect.

The reference firmware includes VRL/TXE verification paths and the `wait,verify`
fstab configuration. Static paths alone do not establish which signature checks
were enforced on the running device. A Magisk-patched boot successfully ran after
the standard unlock; that is the persistent-root path in the final implementation.

The proposals and probe plans later in this report are historical research.
They are not additional validated routes or fresh-device instructions.


Method: static analysis with objdump 2.42 and Python. Device observations are
quoted separately from the recorded run. Addresses are ELF vaddrs (PIE, load
base 0). Section layout:

- `.text` 0x24980–0x1441e6 (0x11f866)
- `.rodata` 0x144200–0x170e1c
- `.plt` 0x23d50–0x24960 (bionic imports)
- `.data.rel.ro` 0x1a3200 / 0x1ab940, `.data` 0x1ae000, `.bss` 0x1aea40

PGDO runtime observations are quoted from the recorded device probes.

Detailed reports cover [flash gates](droidboot/flash-gates.md),
[FRP and unlock state](droidboot/frp-and-unlock-state.md), and
[OEM handlers and boot flow](droidboot/oem-and-boot-flow.md).
The disassembly and indexes are in `tools/droidboot/`, including
`disassembly_index.py` (GOT base 0x1ADCEC; `A.dis/A.dump_func/A.xref_lines`),
the strings dump, and the extracted RSA public key `frp-verification-key.der`.

---

## 0. Binary inventory

Built as PIE with bionic (`/system/bin/linker`), i386 PIC convention: GOT base =
`_GLOBAL_OFFSET_TABLE_` = **0x1ADCEC** (`.got.plt`); every function does
`call <pc_thunk>; add $imm,%ebx`, string refs are `lea disp(%ebx)` → 0x1ADCEC+disp.
2,151 exported dynsym symbols (mostly OpenSSL + Intel CRYS crypto + a TEE/IFP layer);
droidboot's own fastboot logic is stripped/unexported — function addrs below are derived
from call-graph + string xrefs (toolkit in tools/droidboot/disassembly_index.py).

Key function map (derived; see child reports for full dumps):

| addr | role |
|---|---|
| 0x24BE0 | `main` |
| 0x28310 | fastboot loop wrapper (calls 0x2E5A0 transport loop) |
| 0x2E5A0 | transport setup/accept loop (adb-FFS / TCP:1234) |
| 0x2D300 | fastboot protocol command loop (min_state gate 0x2D620) |
| 0x2D8D0 | getvar dispatcher (`sofia_support` ⇒ override 0x1B01FC=1 @0x2D945) |
| 0x29B60 | oem dispatcher (map 0x1B67B8) |
| 0x29DE0 | `flashing` dispatcher (lock/unlock/get_unlock_ability) |
| 0x2A6C0 | `erase:` handler (state gate 0x2A741, whitelist 0x2A968, BLKSECDISCARD) |
| 0x2AB60 | `flash:` handler (special map 0x2ABCC, state gate 0x2AC03) |
| 0x31380 | `flashing unlock/lock` state-change handler (FRP gate 0x315CD) |
| 0x318B0 | `flashing get_unlock_ability` responder |
| 0x31190 | device-state UI confirm menu |
| 0x112BB0 | `flash sig` handler (FRP sig + erase persistent) |
| 0x11D830 | FRP signature verify engine (embedded RSA-2048 SPKI @0x1AE800) |
| 0x119F20 | `flash bootloader` $BLD/VRL bundle handler (TEE-verified) |
| 0x11E110 | image-check fn (SKU/hw-id gates; skipped when debricking flag ∈{1,2}) |
| 0x119360 / 0x1195D0 | oem/flash-special registration + init (0x1195D0 also calls the ops chooser) |
| 0x1114B0 / 0x111500 | `oem start_partitioning` / `oem stop_partitioning` |
| 0x1144D0 / 0x114770 | `oem backup_factory` / `oem restore_factory` |
| 0x37020 | `enable_end_user_mode` (factory-reset helper, §4 note) |
| 0x2CF00 / 0x2B090 / 0x2AF20 | registrars: fastboot commands / oem map 0x1B67B8 / flash-special map 0x1B679C |
| 0x120830 / 0x31C20 | device-state ops chooser (TEE security-info bit 0x20) / ops setter (writes 0x1AFF9C) |
| 0x120CC0/0x120B00 | misc-backed set_state/get_state (misc+0x1000, 3 bytes) |
| 0x129300/0x129460 | TEE "INTELAndVerBoApp" set/get state (vtable B) |
| 0x10C940 | `tee_policy_check` (exported) |
| 0x111E70 | `ifp_manuf_sts_bit_set` (exported; manufacturing bit — NOT the FRP verify) |
| 0x11D700 | manufacturing-status bit getter (used by flash-ifwi gates) |

**main = 0x24BE0** (from `_start` 0x2509E arg): freopen stdout→/dev/kmsg, log tag
"droidboot", banner " -- Droidboot %s for %s --" (version global 0x1B6760, "moorefield"),
copies "installer.cmd" name into global 0x1B5780, then 0x30F30 (build-type check,
`ro.build.asus.version`), 0x2B5A0 (command registration, below), 0x1195D0 (oem + flash-
special registration + device-state ops setup), battery gate (global 0x1B060C threshold →
`charger_run()`), sets `sys.usb.config=none`, then the fastboot loop; on exit checks
global 0x1B05FC==1 → `property_set("sys.partitioning", …)`.

**Fastboot command table** — registration fn 0x2cf00(name, handler, min_state) called from
0x2b5a0; entries `{next,name,name_len,handler,min_state}` in a list @0x1B6790; the
dispatch loop (0x2d300) fails any command with `state < min_state` ("command not allowed
in this device state"):

| cmd | handler | min_state |
|---|---|---|
| `oem` | 0x29B60 (dispatcher, §4) | 0 |
| `boot` | 0x29660 ("boot command stubbed on this platform!") | 2 |
| `reboot` | 0x29730 | 0 |
| `reboot-bootloader` | 0x29690 (sync; `android_reboot(RESTART2,"fastboot")`) | 0 |
| `erase:` | 0x2A6C0 | 0 |
| `flash:` | 0x2AB60 | 0 |
| `continue` | 0x29730 (same as reboot) | 0 |
| `flashing` | 0x29DE0 (§2) | 0 |

getvar dispatcher 0x2d8d0: published vars (list 0x1AFF80) + dynamic callback map
0x1B679C (getters for `update`,`system`,`data`,`APD`,`ADF`,`factory-reset`,`run-sddl`,
`print-fingerprint`,`get_build_version`,`enable_end_user_mode`,`enable_adb` — the SAME
map the flash: handler uses for special flash names, §3/§7.4). Whitelists from .data
arrays: **0x1AE020 = 12-name FLASH whitelist** {bootloader, boot, system, oem, vendor,
recovery, cache, data, userdata, config, logs, factory}; **0x1AE000 = 6-name ERASE
whitelist** {cache, data, userdata, system, vendor, oem}.
**`getvar sofia_support` ⇒ sets oem-gate override 0x1B01FC = 1 (see §2).**


---


## 1. `get_unlock_ability` flow end-to-end — SOLVED

Handler **0x318b0** (the fastboot responder; see §2 for its caller). Disassembly
`0x318b0–0x31bc0`:

```
318d6  lea "ro.frp.pst" → property_get("ro.frp.pst", buf, "")   @0x318f0
318f5  cmpb $0, buf[0]; je → 31ab8 "Failed to get property %s" → prints
        "The device can be unlocked."  (FAIL-OPEN if property unset/empty)
31908  open(buf, O_RDONLY)                    ; buf = value of ro.frp.pst
3192e  lseek(fd, -1, SEEK_END)                ; ← LAST BYTE of the device
3194b  tee_policy_check(0x69, 1)  @10c940     ; TEE policy gate #1 (see below)
         ret==0 → "Unlock authorization check bypassed by policy."
                  → "The device can be unlocked."   (ALLOW)
31963  tee_policy_check(0x6a, 1)
         ret==0xcab13001 → "No tee-policy defined yet. Allow as work-around"
                  → "The device can be unlocked."   (ALLOW)
         ret!=0 → "The device class does not permit to unlock it."  (DENY)
         ret==0 → read(fd, &b, 1)
319fd  close(fd)
31a05  cmpb $1, b                             ; ← the FRP byte
         b==1  → "The device can be unlocked."  (ALLOW)
         else  → "Unlock is disabled. To enable it, go in the Android
                  Developer Options menu and activate 'Enable OEM Unlock'."
```

- **The FRP "byte" is literally the LAST BYTE (offset size-1) of the device node named by
  property `ro.frp.pst`.** On this device `droidboot-ramdisk/default.prop:32`:
  `ro.frp.pst=/dev/block/by-name/persistent` → **last byte of the 1 MB `persistent`
  partition**. No FRP structure, no signature, no header parse in this read path —
  a single raw byte compared against **0x01**.
- The `ro.frp.pst` default passed to property_get is `""` (empty string at 0x144613), so an
  *unset property fails OPEN* ("The device can be unlocked.") — but on the shipped device
  the property IS set.
- `tee_policy_check(0x69/0x6a, 1)` (exported func @0x10c940, size 0x13b): 0x69/0x6a are TEE
  policy IDs (Intel "policy" applet). On a consumer PGDO device the TEE policy for these IDs
  is undefined → returns 0xCAB13001 ("no policy defined") → treated as **allow** (the
  "No tee-policy defined yet. Allow as work-around" string confirms this is deliberate).
  So effectively on stock devices the ONLY gate is the last byte of `persistent`.
- It does NOT parse any FRP signature structure here. The `FRP signature verify` strings
  belong to a different subsystem (see §5).

Live check (read-only): from normal Android (if `persistent` readable) —
`adb shell "dd if=/dev/block/by-name/persistent bs=1 skip=$(( $(blockdev --getsize64 /dev/block/by-name/persistent) - 1 )) count=1 2>/dev/null | od -An -tx1"`
→ currently `00` (matches "Unlock is disabled."). Flipping it to `01` is what every route
must achieve.

---


## 2. `flashing lock/unlock` handler — the UNLOCK gate — SOLVED

**Dispatch layer (0x2d300 = fastboot command loop):** commands are matched against the
list built by `fastboot_register(name, handler, min_state)` @0x2CF00 — entry layout
`{next, name, name_len, handler, min_state}`. For EVERY command the loop does
`get_device_state() @0x31150 → 0x31c80`; if `state < entry->min_state` →
**"command not allowed in this device state"** (0x2d8a4). Same check inside the oem
dispatcher (0x29c50, entry+4 = min_state) with an **override escape hatch**:

```
2d620  call 31150              ; get device state
2d625  cmp 0x10(%esi),%eax     ; entry->min_state
2d628  jb  2d8a4               ; state < min_state → FAIL "command not allowed..."
```
and in oem dispatcher:
```
29c50  call 31150
29c55  cmp 0x4(%edi),%eax      ; oem_entry->min_state
29c58  jae 29c68               ; state >= min_state → run
29c5a  mov 0x1214(%ebx),%eax   ; OVERRIDE GLOBAL 0x1B01FC
29c62  je  29cf5               ; if override==0 → "command not allowed in this device state"
```

**The override is set by `fastboot getvar sofia_support`** — handler 0x2d8d0
(`cmd_getvar`): if the queried var starts with the string `"sofia_support"` (Sofia =
Moorefield tablet platform codename), it executes `0x1B01FC = 1` (0x2d945). This persists
for the whole droidboot session. ⇒ **after one `fastboot getvar sofia_support`, all
min_state-gated oem commands (see §4 table) are callable regardless of device state.**
(0x2d945: `lea 0x1214(%ebx),%eax; movl $0x1,(%eax)` gated only by
`strncmp(var, "sofia_support", min(len,14))==0`.)

**`flashing` dispatcher (0x29DE0):** tokenizes the subcommand; special-cases
`get_unlock_ability` → 0x318b0 (§1); otherwise calls 0x317b0(subcmd, *state, *confirm):

| subcmd | state | notes |
|---|---|---|
| `unlock` | **2** | then 0x31380 (below) |
| `lock` | **0** | then 0x31380 (below) |
| other | ret −1 | silently ignored |

0x317b0 also reads **`ro.debuggable`**: if it equals "1" the *confirm byte is 0* (no UI
confirmation needed — ENG build path); on user builds confirm=1 → on-device
"Change device state" prompt (0x31190) is required.

**0x31380 = the state-change handler** ("AOSP Mark" style):

```
arg1 esi = requested device state, arg2 edi&0xff = already-confirmed flag
313b4  call 31c80                ; get current device state
313bb  if (esi == current)       → "Nothing to do." ret 0
313c1  if (esi == 2)             → 31428 FRP CHECK FIRST:
         property_get("ro.frp.pst") [empty → CONTINUE (fail-open)]
         open(); lseek(-1,SEEK_END); tee_policy_check(0x69,1)
            ==0 → "Unlock authorization check bypassed by policy." → CONTINUE
         tee_policy_check(0x6a,1)
            ==0xcab13001 → "No tee-policy defined yet. Allow as work-around" → CONTINUE
            !=0        → "The device class does not permit to unlock it." ret -1
            ==0        → read(fd,&b,1)
               b==1  → CONTINUE (permitted)
               b!=1  → "Unlock command is protected." /
                       "Go to Android OS to remove the protection" /
                       "Unlock not permitted"  ret -1
               read err → "Unlock command is protected." ret -1
313c6  call 31ce0(esi, confirmed)   ; UI confirm if needed (0x31190 "Yes: Change device state")
         !=0 → "couldn't get confirmation" ret -1
313e4  call 31c40(esi)              ; set device state
         !=0 → "Couldn't set device state" ret -1
313f1  call 31c80(); != esi → "Failed to set device state" ret -1
31400  call 2af00                   ; post-transition hook → 0x396e0 (saves state)
```

So `flashing unlock` = request state **2**; `flashing lock` = state **0**. The only hard
gate for unlock is the FRP byte (plus on-device UI confirm on user builds). *Fail-opens*:
empty property / open() / lseek() failure all CONTINUE toward the unlock.

State plumbing: 0x31c80/0x31c40/0x31cb0/0x31ce0 wrap an **ops vtable pointer at .bss
0x1AFF9C** (`{+0 set_state(state), +4 get_state(), +8 is_unlocked()-style, +0xc
confirm(state, flag)}`); NULL ops ⇒ get→2, set→-1, +8→1, confirm→-1. Registration:
**0x31C20** = `set_device_state_ops(ptr)`; called by **0x120830**, which calls exported
`tee_get_security_info_struct()` (TEE applet UUID `00 de fa 01 de fa 02 de fa 03 de fa
04 de fa ff` @0x16E4D2) and picks:
- security_info bit 0x20 **clear** → vtable **A @0x1AE93C** (misc-partition backed)
- bit 0x20 **set** → vtable **B @0x1AE94C** (TEE "AVB_change_device_state" backed)
(see §7; live check: `fastboot oem get-sec-info` is always allowed and prints this.)

---

## 3. The flash gate: per-partition static findings

**Front door `flash:` (0x2AB60), decision order:**
1. `misc` special-case: on legacy devices (op2==0) misc flags are saved before and
   restored after any misc flash (0x2ADC8→0x120D60 read, 0x2AC80→0x120D90 write).
2. `state = get_state()` (0x2ABC1); look up the partition name in the special-flash map
   0x1B679C (0x2ABCC):
   - **found →** log `asus_internal_unlock %d` (%d = the sofia_support override flag
     0x1B01FC) @0x2ABF0; gate `state >= min_state` (0x2ABFE) else sofia override
     (0x2AC03–0x2AC0B) else **"command not allowed in this device state"**; then call
     the special handler.
   - **not found → generic partition path (0x2ACE0):**
     - `state == 0 && !sofia` → **"Bootloader must not be locked" (0x2AEA3) FAIL** —
       i.e. **while locked, NO generic partition is flashable at all.**
     - whitelist `hashmapContainsKey(map 0x1B67A8, name)` (0x2ACF2) — the 12-name array
       @.data 0x1AE020: **bootloader, boot, system, oem, vendor, recovery, cache, data,
       userdata, config, logs, factory** — not in list → **"not allowed to flash this
       partition"** (0x2AE90).
     - volume lookup 0x258D0("/"+name) → device; sparse magic 0xED26FF3A → sparse writer
       0x306A0 else raw writer 0x30470; sync; no signature check in either writer.
3. `erase:` (0x2A6C0) mirror: while locked & !sofia, erase is allowed only for the
   6-name whitelist @0x1AE000 (**cache, data, userdata, system, vendor, oem**)
   (0x2A968–0x2A988), else **"bootloader must not be locked"**; erase = BLKGETSIZE64
   (0x80041272) then **BLKSECDISCARD (0x127D)** over {0, partition-size}.

**Per-partition verdict table:**

| fastboot target | locked (state 0) | unlocked / +sofia — internal checks | who verifies |
|---|---|---|---|
| `boot`, `recovery` (mapA, min 2, 0x11C7E0/0x11C850→0x11BBB0) | ❌ "command not allowed in this device state" | **no userspace signature check** — raw write after erasing the OSIP header (0x11AE40) | kernel/recovery verified downstream by the TXE/SBL VRL chain at boot (not by droidboot) |
| `system`/`data`/`APD`/`ADF`/`update` etc. (mapA, min 2) | ❌ same | `flash system` 0x2A070 raw/sparse write; `flash update` 0x29800 → writes /cache/update.zip + "--update_package" to /cache/recovery/command + reboot to recovery — **droidboot does NOT verify the zip** (recovery does, with its own keys) | dm-verity on /system (`wait,verify` fstab); OTA zip verified by recovery |
| generic whitelist names (cache, data, userdata, config, logs, factory, oem, vendor) | ❌ "Bootloader must not be locked" (0x2AEA3, before whitelist) | raw/sparse write, no checks | none in droidboot; /system dm-verity at mount |
| `fastboot` (the droidboot image; 0x11CD10→0x11D240) | ❌ | **$POSS/$MOSS/$ROSS phase-header check** (offset 0x280 of the image, or trailing 0x258-byte "$XXSS" via 0x11CFB0) — header presence only, no local RSA | TXE/SBL chain enforces the real signature at boot |
| `bootloader` ($BLD bundle; 0x119F20 + verifier 0x121E20) | ❌ | **full TEE-verified chain**: "BOOTLDR!" magic + "$BLD" VRL header (blob+0x80, 0x2D8 B) + "$ToC" module scan + per-module TEE RSA ($POS/$SSI/ITKN/MIPD/MIPN/UTKN/BOMTOKEN via 0x129D90/0x129590, verify-end 0x12A270); "invalid bootloader header !" on magic mismatch | all RSA inside the TEE (SEP, /dev/dx_sep_q1) |
| `ifwi` (0x11CC80) / `dnx` (0x11C720) | ❌ | `flash dnx` stages /tmp/__dnx.bin; `flash ifwi` needs it, BOM-token/SKU gate (0x11D700 + 0x1B68C4), IFWI ToC parse, FW **version** compare (major/minor downgrade abort @0x12AA00), writes /tmp/__ifwi.bin → sysfs `/sys/devices/ipc/intel_fw_update.0/{ifwi,dnx}` | kernel driver + TXE |
| `capsule` (0x11C780) | ❌ | mounts ESP vfat, writes **/ESP/BiosUpdate.fv** (+ flash_capsule_esp) | BIOS capsule chain |
| `splashscreen` +1..4 (0x11C8D0/0x11C910/0x11C950/0x11C990) | ❌ | raw write | **never read at boot by droidboot** (see §6) |
| `token` (0x121A40) | ✅ **min_state 0 — allowed LOCKED** | tee_token_write (TEE InvokeCommand 0x70C4) | TEE decides token validity |
| `token_umip` (0x11C660) | ✅ **min_state 0 — allowed LOCKED** | ifwi-ops hook: opens `/dev/block/mmcblk0bootN`, clears force_ro, mmap+write at +0x4000 (UMIP blob) | none on payload |
| `sig` (0x112BB0) | ❌ (min 2) | RSA-PKCS1(SHA256(ro.serialno)) vs embedded key → erase `persistent` | §5 |

**CASIGN:** no CASIGN strings/parse in droidboot — the Intel signed-image format here is
the "$BLD"/"$ToC"/module-name container verified inside the TEE; "casign" is the host
side tool. **No IFWI/$BLD/$POS/$SSI keys are present in droidboot.** The only key
material embedded is the FRP RSA-2048 SPKI (§5).

**Debricking flag 0x1B248C** (GOT+0x47A0): `flash debricking` (0x113930) writes the
`/cache/debricking` marker; it is validated at init/after-unlock (checker 0x35BF0 via
0x396E0 @0x39709, and the runtime "Force debricking : YES!" path @0x11E8CE→0x11E8EA
setting 2). With flag ∈ {1,2} droidboot-side checks relax — notably the SKU/hw-id gate
in image-check 0x11E110 (0x11E63E `flag-1 ≤ 1 → "Skip checking hw_sku"`; otherwise
"Project name and Hardware ID are not match" abort) and the related gates at
0x11EB73/0x11ECC2. It does **not** replace TEE-side verification of $BLD bundles. (The
separate logtool flag 0x1B0488 @0x2A72F only saves/restores /cache/logtool around cache
wipes.)

---


## 4. The `oem` command table + device-state gate — SOLVED (full table; per-handler
details in oem-and-boot-flow.md)

Dispatcher **0x29B60** (`fastboot oem <args>`): strips spaces, `strtok_r(" ")` into
argv[64]; looks argv[0] up in the **oem map @0x1B67B8** (name → `{handler@0,
min_state@4}`, registered by `oem_register` 0x2b090). Special cases before the map:
`system` → "OEM system command are not supported anymore"; `showtext` → prints the
argument via the OKAY path. Unknown → **"unknown OEM command"**.

Gate: `current_state = get_device_state()` (0x31150→0x31c80); if
`current_state < entry->min_state` → **"command not allowed in this device state"** —
unless the **session override global 0x1B01FC is non-zero** (set by
`fastboot getvar sofia_support`, see §2).

Complete table (32 registrations; `get_batt_info` registered twice, second is a no-op
key-collision). Highlights from the per-handler decode (OEM and boot-flow report): `backup_factory`
/`restore_factory`/`backup_config`/`restore_config` just set `sys.backup_*=backup|restore`
and wait for the droidboot-ramdisk init service to copy /factory or /config to /tmp;
`start_partitioning`/`stop_partitioning` only set `sys.partitioning`; `emmc_data_read`
streams raw /dev/block/mmcblk0 back to the host; `custom_boot` pokes the Intel UMIP;
`flash_all_start/end` prime the flash-all scratch flags (end also flashes IFWI/BOM_TOKEN
and, for eng builds, wipes data+cache); none of them changes the lock state.

| oem cmd | handler | min_state | meaning (verified in §7 where noted) |
|---|---|---|---|
| `adb_enable` | 0x113B50 | 2 | enable ADB in droidboot |
| `backup_config` | 0x114620 | 2 | back up config partition |
| `backup_factory` | 0x1144D0 | 2 | back up factory partition (state-gated; live probe hit this) |
| `restore_config` | 0x114390 | 2 | restore config |
| `restore_factory` | 0x114770 | 2 | restore factory |
| `custom_boot` | 0x113090 | 2 | boot a custom image |
| `dnx_timeout` | 0x1131E0 | 2 | set DNX timeout |
| `emmc_data_read` | 0x112CA0 | 2 | raw eMMC read |
| `emmc_resize` | 0x113DE0 | 2 | resize eMMC data |
| `erase_osip_header` | 0x11AE40 | 2 | erase OSIP header |
| `flash_all_start` | 0x11E9D0 | 2 | begin "flash all" session |
| `flash_all_end` | 0x11EA90 | 2 | end "flash all" session |
| `pos_logging` | 0x113CF0 | 2 | POS logging |
| `pre_sending` | 0x113850 | 2 | pre-send hook |
| `retrieve_partitions` | 0x1118B0 | 2 | rebuild partition table |
| `start_partitioning` | 0x1114B0 | 2 | partitioning mode |
| `stop_partitioning` | 0x111500 | 2 | end partitioning mode (state-gated; live probe hit this) |
| `start_update` | 0x118F10 | 2 | OTA update flow |
| `cancel-update` | 0x121200 | 0 | cancel pending OTA |
| `erase_token` | 0x112AC0 | 0 | erase TEE token |
| `remove-token` | 0x121AB0 | 0 | remove TEE token |
| `finalize-update` | 0x121240 | 0 | finalize OTA |
| `start-update` | 0x1211C0 | 0 | stage OTA |
| `get-fru` | 0x1213C0 | 0 | FRU info |
| `get-lifetime` | 0x121000 | 0 | lifetime data |
| `get-mfg-status` | 0x121CD0 | 0 | manufacturing status |
| `set-mfg-status` | 0x121D70 | 0 | set manufacturing status |
| `get-part-id` | 0x121970 | 0 | part id |
| `get-sec-info` | 0x121B90 | 0 | security info |
| `get-spid` | 0x121280 | 0 | SPID |
| `get_batt_info` | 0x112FD0 | 0 | battery info |

**Device states:** 0 = locked, 2 = unlocked (both proven in §2; value 1 is never used as
a state — §7.3). The *readable* state names for getvar: "unlocked" @0x1458A4 / "locked"
@0x1458AD.

There is **no `oem <cmd>` that switches device state directly**; state changes go only
through `flashing lock/unlock` (0x31380) — i.e. through the FRP byte. However the
`getvar sofia_support` override makes all min_state-gated commands (the whole
min_state=2 column above — including `stop_partitioning`, `backup_factory`,
`flash_all_*`, `custom_boot`, `emmc_*`) callable **while locked**, which is exactly the
"command not allowed in this device state" the live probe hit.

`cmd_oem_enable_end_user_mode` (@0x15DEA5, xref @0x37BD2 in fn 0x37020) is not an oem
subcommand — it's a *called function* (see §5/§7).

---


## 5. The FRP write side — SOLVED

**droidboot never writes the FRP byte.** Both users of `ro.frp.pst` (0x3142E in 0x31380,
0x318D6 in 0x318b0) only open+lseek+read. The byte is written from the **Android side**
("Enable OEM unlock" toggle); the only `persistent` reference in droidboot's code is the
erase path (below).

**`FRP signature verify pass/fail!` belongs to `fastboot flash sig`** — handler
0x112BB0 (special flash name `sig`, registered into map 0x1B679C via 0x2AF20, min_state
2 → needs unlocked state or the `getvar sofia_support` override):

```
112bc1  property_get("ro.serialno", buf@0x1B6680)
112c08  call 0x11d830(serial, serial_len, downloaded_data, data_len)
          ret!=0 → "FRP signature verify fail!" → FAIL (no erase)
          ret==0 → "FRP signature verify pass!"
112c3f  "Start to erase persistent partition!"
112c5d  call 0x2a6c0("persistent", 0, 0)     ; the ERASE handler (BLKSECDISCARD whole partition)
112c62  "The persistent partition has already been erased!"
        "Finish flashing sig!" → OKAY
```

**The verify engine 0x11D830** (also used for `pre-flash` @0x118CF0):
```
buf = calloc(1, data_len)
call 0x11d7f0(serial, serial_len, 2, sha_out)          ; hash (algo id 2) over serial||data
key = d2i_RSA_PUBKEY(NULL, &p, 294)                    ; embedded DER SPKI:
        length dword @.data 0x1AE7C0 = 0x126 (294)
        DER      @.data 0x1AE800
call 0x11d7a0(data, buf, serial, rsa)                  ; RSA_public_decrypt(sig)
memcmp(decrypted_tail + ret - 0x20, sha_out, 0x20)     ; last 32 bytes of the recovered
                                                       ; block == SHA-256(serial||data)
== 0 → PASS
```

**Key: RSA-2048, e=65537** (DER SPKI at 0x1AE800, extracted to
tools/droidboot/frp-verification-key.der). Forging `flash sig` payloads requires
the ASUS private key — **not feasible**; and even a successful `flash sig` only *erases*
persistent (byte → 0x00, still "Unlock is disabled."). So there is **no sign-then-flip
path inside droidboot**: the signing side lives in ASUS's provisioning tooling, not on
the device.

**Patch analysis for a self-serve unlock** (if droidboot itself can be patched, e.g. via
dirtycow of /system/bin/droidboot from Android; file offset == vaddr):

| # | addr | raw bytes | change | effect |
|---|---|---|---|---|
| P1 | 0x315D2 | `0f 84 ee fd ff ff` | → `e9 ef fd ff ff 90` (jmp 0x313C6 + nop) | `flashing unlock` skips the byte==1 gate entirely (branch at `cmpb $0x1,0x3f(%esp)` @0x315CD forced taken) |
| P4 | 0x2A749 | `0f 84 19 02 00 00` | → `e9 1a 02 00 00 90` (jmp 0x2A968 + nop) | erase: handler behaves as if the sofia override were set (skip the locked whitelist) |
| P5 | 0x2AC0B | `0f 84 de 01 00 00` | → `90`×6 | flash:-handler special-name gate always passes (the "command not allowed" je nopped) |

P1 is the minimal patch. After P1, `fastboot flashing unlock` proceeds to the UI
confirm (stock user build: press volume/power on the tablet) and then set_state(2) —
which writes **misc** (vtable A) or the TEE (vtable B). The `persistent` byte stays 0 —
harmless, since P1'd droidboot no longer reads it.

Other decoded items: `enable_end_user_mode` (0x37020) = the **factory-reset helper** —
writes `--wipe_data`/`--wipe_cache` into `/cache/recovery/command`, syncs, then
`android_reboot(0xDEAD0003, "recovery")`; it does NOT touch the FRP byte or the lock
state. `enable_adb` getter returns the runtime option flag; the `oem enable_adb` setter
(0x113B50, min_state 2) toggles droidboot's adbd. `oem erase_token` (0x112AC0,
min_state 0) → `erase_token_umip` hook — on this consumer build the MIA hook table
(0x1AE9A0) has NULL hooks → "%s is not implemented"; `flash token_umip` (0x11C660,
min_state 0) uses hook 0x12C330 only when the MIA factory struct is registered
(otherwise not implemented).

---


## 6. Boot-time image security (Q6) — what validates what

- **droidboot userspace verifies almost nothing at boot.** The boot path (`main`) does
  not read/verify boot/recovery/splash partitions; it reboots via
  `android_reboot(0xDEAD0003, reason)` and the **TXE/IFWI secure-boot chain** (VRL
  headers, keys fused in TEE) verifies the OS boot chain downstream. Unsigned boot
  images written raw (even with sofia+unlocked-ish paths) are rejected at the SBL/TXE
  layer, not by droidboot.
- **`/system`** is protected by **dm-verity** (`wait,verify` in fstab.mofd_v1; verity
  pubkey in the droidboot ramdisk `verity_key`) — a modified system image fails the
  verity tree at mount, so `flash system` is only useful with a re-signed (ASUS-key)
  image.
- **splashscreen partition is never read by droidboot at boot** — splash drawing in
  droidboot mode uses minui assets (/res/images/ in the ramdisk); the splash partitions
  are consumed by the SBL/IFWI stage before droidboot runs (and verified there, if at
  all, by the same fused-key chain).
- The only local-crypto checks in droidboot: the FRP `sig` (embedded RSA-2048, §5) and
  the `$POSS/$XXSS` phase-header *presence* checks for `flash fastboot`.
- `is_secure_boot_enabled` (exported @0x112720, TEE query) exists; used by the flash
  paths (0x11A200 call sites) to harden checks when secure boot is on.

---


## 7. Device-state machine, boot flow, reboot reasons

### 7.1 Ops vtables and state persistence — SOLVED (core)

Registration fn **0x120830** (called from the big init/oem-registration fn **0x1195D0**,
which `main` calls at 0x24CE2): `tee_get_security_info_struct(&info)`; on failure prints
"Failed to get security info" and leaves ops NULL; else:

- `testb $0x20, info+…` — **bit 0x20 clear → vtable A @0x1AE93C**:
  `{set_state=0x120CC0, get_state=0x120B00, slot8=0x1208F0(ret 0), confirm=0x120900}`
- **bit 0x20 set → vtable B @0x1AE94C**:
  `{set_state=0x120E50, get_state=0x120E00, slot8=0x120DC0(ret 2), confirm=0x120DD0}`
  B delegates to fns 0x129300 (set) / 0x129460 (get) which log
  "AVB_change_device_state returned error code 0x%X - state %d" (@0x14DACC) — i.e. the
  state lives in the **TEE applet (AVB)**, and `confirm` = the on-device UI prompt
  (0x31190).

**Vtable A (misc-backed) details:**
- `get_state` 0x120B00: buf[0]=**2 (unlocked) default**, then `read_misc_flags(&buf3)`
  @0x120980; returns buf[0]. Read = open(`misc` node via name lookup @0x11BF60),
  `lseek(fd, 0x1000)`, read 3 bytes = **"bootloader flags" at misc+0x1000..0x1002**.
  **Read failure ⇒ state 2 = unlocked (fail-open).**
- `set_state` 0x120CC0: state 0 → read flags, rewrite buf[0]=0 (`write_misc_flags`
  0x120B40 = same open/lseek(0x1000)/write(3)); state 2 → write buf[0]=2 and set
  global 0x1AE938=1; other values → return 1 (failure).
- `confirm` 0x120900: if requested state==2 → prints "Erasing...", **erases the
  `userdata` partition** (0x2B370) and formats /data (0x25CD0) — the standard
  unlock-wipe; returns 0. (Called before set_state in 0x31380.)

**Vtable B (TEE-backed) details:**
- `get_state` 0x120E00 / `set_state` 0x120E50 → 0x129460 / 0x129300: TEE session to
  applet **"INTELAndVerBoApp"** (Intel Android Verified Boot applet), get = TEE
  InvokeCommand **cmd 1**, set = **cmd 2**; set rejects states ∉ {0,2}
  (`and $0xfffffffd` → "Libavb: wrong device state (%d)"); error string
  "AVB_change_device_state returned error code 0x%X - state %d" (@0x14DACC).
  **On immediate TEE failure get_state returns 0 (locked) — fail-closed.**
- `slot8` 0x120DC0: constant 2 (TEE regime aux flag vs 0 on misc regime).
  `confirm` 0x120DD0 → 0x31190 (on-device UI prompt).

**Third regime:** if `tee_get_security_info_struct` itself fails, 0x120830 registers
**nothing** → accessors fall back to get=2 (fail-open) / set=−1 ("Couldn't set device
state").

Registration timing: `main` 0x24CE2 → oem-init 0x1195D0 → 0x119C87 → 0x120830 — the
ops are live **before any fastboot traffic**.

⇒ **Device state (locked/unlocked) = 3 bytes at offset 0x1000 of the `misc` partition
(1 MB)** when vtable A is active — independent of the FRP byte in `persistent`! Writing
those 3 bytes directly (0x1000: first byte = state: 0=locked, 2=unlocked) makes droidboot
boot "unlocked" with vtable A — no signature, no FRP check on the read path. If vtable B
is active, state lives in the TEE and misc is ignored. Which vtable is live on the PGDO
device must be confirmed (live: `fastboot oem get-sec-info`, always allowed).

### 7.2 Transport, main loop, and misc vars

**0x2E5A0** = fastboot transport/accept loop (called from the 0x28310 wrapper; sets up
listeners, then `0x2d300` per connection):
- registers more commands into the same list: `getvar:` → 0x2D8D0 (min_state 0),
  `download:` → 0x2F2D0 (min_state 0), **`emmc_write:` → 0x2C9F0 (min_state 2)**,
  publishes `version-bootloader` = version buffer (0x1B6760), `max-block-size` =
  computed `"%d"` (scratch size), and **`flash-all-depart` = constant string "1"**
  (@0x145254, value @0x144D6A) — i.e. **it is just a getvar advertisement, not a state
  flag** (Q7 answered).
- `property_set("sys.usb.config", "adb")`; if `debug.droidboot.adb == "enable"` opens
  `/dev/android_adb`, else falls back to **TCP listen on port 1234** (0x2EAA8,
  "Listening on TCP port %d" with 0x4d2) — droidboot speaks the fastboot protocol over
  adb-FFS (`/dev/usb-ffs/adb/ep0..2`, ep1=read fd 0x1AFF84, ep2=write fd 0x1AFF88) and
  also over TCP.
- per accepted connection: `0x2d300(cmd loop)`; loop exit conditions checked back in
  0x28310.

`reboot` (0x29730) prints "REBOOT..." and calls `android_reboot(0xDEAD0003,0,"fastboot")`;
`reboot-bootloader` (0x29690) syncs and reboots back into droidboot ("fastboot" reason).
A second, shadowed reboot-bootloader registration exists at 0x112960 (reason
"bootloader"); the first registration (0x29690) wins the list walk.

**Boot-mode reasons** (reboot-enum table @0x119DC0; handlers 0x11CD10, 0x11C720,
0x11C780, 0x11E360, 0x11DC00, 0x11C660, 0x112AC0): recovery / bootloader / dnx /
fastboot / poweroff / umip / token, all via `android_reboot(0xDEAD0003,0,<name>)`.
`fastboot boot` is stubbed; `continue` shares the reboot path. droidboot exits to
Android only via the `sys.partitioning=0` property trigger at main exit (global
0x1B67A0 == 1) — set when the droidboot ramdisk is booted with `droidboot.autopart=1`
(main also parses `droidboot.minbatt`, `droidboot.scratch`, `droidboot.mountpart`,
`droidboot.installer_usb`, `droidboot.disablefbootui` at 0x30C20).

**Battery gate:** if `droidboot.minbatt` > 0, `charger_run()` gates the fastboot loop;
level < threshold → `android_reboot(0xDEAD0002,0,0)` (back to charger/Android).

### 7.3 getvar state surface + state enum details

- `getvar device_state` getter **0x310D0** (published 0x31BF8): get_state()==0 →
  "locked", ==2 → "unlocked", **any other value → panic** (0x2FB00).
- `getvar unlocked` getter **0x31120** (published 0x31BEB): "no"/"yes" strings
  @0x1458B4/0x1458B7.
- State value 1 is never written or tested as a state — the enum is {0 locked, 2
  unlocked}.
- **No oem handler changes device state** (all 32 decoded; state changes only via
  `flashing lock/unlock`).

### 7.4 `flash <special-name>` handlers (map 0x1B679C, min_state 2, via registrar 0x2AF20)

The `flash:` handler looks the partition name up in a second map (0x1B679C — shared
with the dynamic-getvar callbacks) BEFORE the normal partition path. Registered
special names (sites 0x119414–0x1194E0, all min_state 2):

| name | handler | role |
|---|---|---|
| `debricking` | 0x113930 | sets debricking flag 0x1B248C = 2, mounts /cache, writes marker file `/cache/debricking` |
| `sig` | 0x112BB0 | **FRP-signature path**: property_get(`ro.serialno`) → verify engine 0x11D830 ("FRP signature verify pass/fail!") → on pass, erases the persistent partition (see §5) |
| `all` | 0x118D90 | flash-all driver |
| `pre-flash` | 0x118CF0 | pre-flash pass |
| `partition` | 0x115680 | format factory/spare/config per partition.tbl |
| `repart` | 0x114050 | GPT rewrite from /etc/partition.tbl |
| `media` | 0x114120 | media partition flow |

**Debricking flag 0x1B248C** (GOT+0x47A0) is read at 13 sites; when ∈ {1,2} the
flash-all/image-check code SKIPS its checks (e.g. 0x11E63E: `flag-1; cmp 1; jbe → skip
check` in image-check fn 0x11E110, "Start check Image-SKU..." path). It is also
initialized from 0x396E0 (the post-unlock hook) — i.e. after a real unlock the device
runs with debricking semantics (0x39709: `mov %eax,0x47a0(%ebx)` from call 0x35BF0).

### 7.5 UI confirm (0x31190)

Menu UI ("**** Unlock bootloader? ****" @0x145AE2 / lock-prompt twin), items
"Yes: Change device state" (0x1458BB) / "No: Cancel"; key loop 0x3ACD0 over
`/dev/input/event*` (epoll thread 0x10D940): 103/108 = up/down, 114/115 = vol
up/down, 116 = power/enter; -1 → "device state prompt timed out" (0x153C68);
confirmation on selection runs the userdata+cache wipe ("Userdata erase required,
this can take a while..." @0x5A064-region) then the state set. With
`ro.debuggable == "1"` (0x317B0) the confirm is skipped entirely.

### 7.6 startftm / hidden commands

- **No FTM / startftm** anywhere in this build (strings + asm: zero hits).
- `fastboot_register` has 12 call sites in two functions (0x2B5A0: oem, boot, reboot,
  reboot-bootloader, erase:, flash:, continue, flashing; 0x1195D0 tail: "token"-style
  oem entries + duplicate reboot-bootloader 0x112960 + "data" (min_state 2)).
- Full oem surface = the 32-entry table in §4. Full getvar surface = published list
  (0x1AFF80 list: product, kernel, partition-size, partition-type, device_state,
  unlocked, battery-voltage, max-block-size, flash-all-depart, version-bootloader,
  update/system/data/APD/ADF/factory-reset/run-sddl/print-fingerprint/
  get_build_version/enable_end_user_mode/enable_adb dynamic getters).
- `flash-all-depart` is **published as the constant string "1"** (0x2E7C0, value
  @0x144D6A) — it is an advertisement, not a runtime flag; the 0x112870 handler of the
  same name probes the OSIP "temp"/"boot-one-shot" boot flags and one-shot-boots a
  prepared image (`android_reboot(...,"bootoneshot")`).

---


## 8. PGDO build (the real device copy) — delta analysis

The target-derived comparison copy was pulled from /system/bin/droidboot via adb
(sha256 `cf9959182bca…4ba7aeb`) and is excluded from publication. **Byte-diff vs the WW copy: 16 bytes, all in the
GNU build-id note** (file 0x190–0x19F: WW `c866401f-8674-7380-adc6-a0fde9e8beb2` vs PGDO
`ee14c87f-503f-2360-c17e-8fdcde5f76b5`). Everything else — code, rodata, data — is
byte-identical, so **every address in §0–§7 transfers 1:1 to the PGDO binary.** The
"extra strings" reported (custom_boot, erase_token_umip, flash_all_engine.SDDL.path,
asus_internal_unlock) exist at identical offsets in BOTH binaries.

### 8.1 Live-vs-binary oem mismatch — SOLVED

`custom_boot` (and `dnx_timeout`) **are conditionally registered**: in the oem-init fn
(0x1195D0), after `property_get("ro.build.type", buf)` @0x11965B, the registration block
at 0x119D30–0x119D76 (dnx_timeout → 0x1131E0, custom_boot → 0x113090, both min_state 2)
is reached only via `jne 0x119D30` @0x119939, guarded by a 5-byte `repe cmpsb` of
`ro.build.type` against **"user"** (0x119808 `lea "user",%edi`; compare @0x119937):

```
if (strcmp(ro.build_type_value, "user") != 0) {   // ENG/userdebug builds only
    oem_register("dnx_timeout",  0x1131E0, 2);
    oem_register("custom_boot",  0x113090, 2);
}
```

⇒ on the production **user** build both are never registered → live
"unknown OEM command", although both strings sit in .rodata. That is the entire
live-vs-binary delta: all other oem names in §4's table are registered unconditionally.

### 8.2 `asus_internal_unlock %d` — not a command

Printed by the `flash:` handler @0x2ABF6 on EVERY special-name flash, `%d` = the
sofia_support override flag (0x1B01FC). It is a log line only — no handler, no
fastboot surface, does not bypass the FRP byte. (The string sits at .rodata 0x144D8A,
used only there.)

### 8.3 `flash sig` / `flash debricking` on PGDO — registered, min_state 2

Both are in the special-flash map 0x1B679C (registrar 0x2AF20): with the
`getvar sofia_support` override they are callable while locked.
- `flash sig` → 0x112BB0: RSA-2048/PKCS1 verify (embedded key @0x1AE800) of
  (ro.serialno ‖ payload); on pass **erases the whole `persistent` partition**
  (BLKSECDISCARD via 0x2A6C0). Bypasses nothing about the lock state; it wipes FRP data.
- `flash debricking` → 0x113930: writes the `/cache/debricking` marker; the flag
  0x1B248C (validated at init/after-unlock by 0x35BF0/0x396E0 and set @0x11E8EA)
  relaxes droidboot-side SKU/hw-id image checks (0x11E63E etc.). Does not touch TEE-side
  $BLD verification or the lock state.

### 8.4 erase_token_umip / erase_token / remove-token / set-mfg-status (+ the wedges)

| oem cmd | handler | min | behaviour |
|---|---|---|---|
| `erase_token` | 0x112AC0 | 0 | argc==1 → `erase_token_umip()` @0x11C5B0 → MIA hook table @0x1AE9A0 (consumer build: hooks NULL) → prints "erase_token_umip is not implemented", returns. **No TEE call → no wedge.** |
| `flash token_umip` | 0x11C660 | 0 | MIA hook 0x12C330 (only when the MIA factory struct is registered): opens `/dev/block/mmcblk0bootN`, clears force_ro, writes UMIP blob at +0x4000. |
| `remove-token <dgid>` | 0x121AB0 | 0 | parses base-10 datagroup id (0xffffffff → error return) → **`tee_token_remove` (0xFF570) → synchronous TEE InvokeCommand**. |
| `set-mfg-status` | 0x121D70 | 0 | **no argument handling at all** — directly calls `ifp_manuf_sts_bit_set` (0x111E70) → synchronous TEE InvokeCommand (IFP). |

**The wedges explained:** the fastboot transport loop (0x2D300, run from the
single-threaded accept loop 0x2E5A0) executes these handlers inline; each TEE call does
DX_CclibInit → TEEC_InitializeContext("/dev/dx_sep_q1") → TEEC_OpenSession →
TEEC_InvokeCommand with **no timeout**. If the TEE/secure-channel or RPMB path stalls
(e.g. after a prior TEE call left the session bad), the loop blocks and fastboot stops
answering — exactly the observed wedges after `oem remove-token` and bare/arg
`oem set-mfg-status`. Recovery: let the call time out device-side or reboot.

### 8.5 `flash_all_engine.SDDL.path`

Set by `enable_end_user_mode` (0x37020 @0x37512):
`property_set("flash_all_engine.SDDL.path", "/sdcard/<name>")`, then the demo-content
installer 0x37CA0 ("Installing demo content!!") mounts /sdcard and installs the payload
— a **retail-demo** plumbing path, not a security gate. It only tells the flash-all
engine where a demo package lives.

### 8.6 get-sec-info → which state vtable is live

`oem get-sec-info` (0x121B90) mallocs `tee_get_security_info_size()` bytes and prints
**the raw TEE-returned blob verbatim** (tee_get_security_info_printable @0x10C450 =
TEEC_InvokeCommand cmd 0x12; the text is composed inside the TEE — hence "RPMB key
type"/"SS key type" appear nowhere in the binary). The ops-vtable selector (0x120830)
tests **bit 0x20 of byte 28 (0-based) of that same struct** (`testb $0x20,0x38(%esp)`,
buf at 0x1C(%esp)). Since the struct's first bytes ARE the printed text, the live
output decides the vtable: take the captured `oem get-sec-info` text, index byte 28,
test bit 0x20 — set ⇒ **vtable B (TEE "INTELAndVerBoApp", fail-closed)**, clear ⇒
vtable A (misc+0x1000). The original report attempted to identify the active table using byte 28 of
printable get-sec-info output. No mapping from that text offset to the internal
`tee_get_security_info_struct` field was verified. The text alone therefore does
not establish the live vtable. The archived probe plan is retained below as a
record of the unvalidated test.

### 8.7 Writing eMMC while LOCKED (item 8) — full knob list

With **only** `fastboot getvar sofia_support` (session override 0x1B01FC=1), while the
device reports "locked":

| knob | handler | writes what | caveat |
|---|---|---|---|
| `fastboot erase <ANY partition>` (incl. **persistent**) | 0x2A6C0 | BLKSECDISCARD of the whole partition — the 6-name whitelist is skipped entirely when sofia≠0 (0x2A741–0x2A749) | `misc` is protected only on vtable-A devices (flags saved @0x120D60 before, restored @0x120D90 after); on vtable B misc wipes freely (state is TEE-side anyway). Erasing persistent zeroes the FRP byte (0x00) — still "disabled", but FRP data is gone. |
| `emmc_write:<size>` | 0x2C9F0 → pump 0x2C700 | streams `<size>` bytes from the host into **/dev/block/mmcblk0 from LBA 0** (no seek — whole-disk image writer) | to reach `misc`/`persistent` it must also overwrite everything before them (GPT, system…) — destructive, rebuildable only via fastboot afterwards. Not a surgical knob. |
| `flash repart` / `flash partition` / `flash media` / `oem emmc_resize` / `oem start_partitioning` | 0x114050/0x115680/0x114120/0x113DE0/0x1114B0 | GPT/partition.tbl rewrites, formats factory/spare/config | destructive to data partitions; cannot set the lock state |
| `oem erase_osip_header` | 0x11AE40 | wipes the OSIP boot-list header | brick-risk for boot selection, no lock effect |

**No knob writes `misc`+0x1000 = 0x02 or `persistent` last-byte = 0x01 while locked.**
The `flash:` whitelist (12 names) excludes misc/persistent; `erase` of misc self-restores
its flags on vtable A; emmc_write can only destroy-forward. The lock state on this
device is therefore reachable only via (a) `flashing unlock` (FRP byte, §2), (b) the
misc+0x1000 bytes from an OS-level writer (the historical Route A), or (c) a modified droidboot gate
(the historical Route B). Their limitations are described below.

---

## Historical probe plan (includes state-changing commands)

This plan is retained as research context, not a sequence to run. In particular,
`getvar sofia_support` sets a session override, and the OEM commands that follow
were proposed tests of that override. They are not read-only state queries.

```
fastboot getvar product
fastboot getvar kernel
fastboot getvar version-bootloader
fastboot getvar state
fastboot getvar unlocked
fastboot flashing get_unlock_ability
fastboot oem get-sec-info                        # capture FULL output text, keep every byte/newline
fastboot oem get-spid
fastboot oem get-part-id
fastboot oem get-lifetime
fastboot oem get-fru
fastboot oem get-mfg-status
fastboot oem get_batt_info
fastboot oem backup_factory                      # expect: command not allowed in this device state
fastboot getvar sofia_support                    # sets the session override (reverted by reboot)
fastboot oem backup_factory                      # expect: NO state error now (its own result/error)
fastboot oem stop_partitioning                   # same expectation as backup_factory
fastboot oem custom_boot                         # expect: unknown OEM command (user build, §8.1)
fastboot oem dnx_timeout                         # expect: unknown OEM command (user build, §8.1)
fastboot getvar enable_end_user_mode             # getvar getter — answers (dynamic map)
# archived byte-28 test: text-to-struct mapping unverified
python3 -c "import sys;t=open('secinfo.txt','rb').read();b=t[28];print(hex(b),'bit0x20=',bool(b&0x20),'-> vtable', 'B/TEE' if b&0x20 else 'A/misc')"
```

The proposed plan assumed one command per invocation in droidboot mode. The
`getvar sofia_support` override lasts only for that droidboot session.

---

## Historical route assessment

The recorded PGDO ELF comparison found only a build-id difference from the WW
ELF. That supports transferring ELF addresses, not assuming that whole boot
images, runtime policy, or enforcement match. The get-sec-info interpretation
suggested vtable B (TEE-backed state), but mapping printable text byte 28 to
the internal struct bit was not verified. The active table was not established
by that test; the alternatives below were proposals.

On the analyzed stock locked build, **fastboot alone cannot flip the FRP byte**.
Static analysis of this droidboot build shows:

1. The byte is only ever **read** (both `flashing get_unlock_ability` 0x318B0 and the
   unlock gate 0x31380 open `ro.frp.pst` O_RDONLY). Nothing in droidboot writes it;
   Android-side code must supply the allowed byte. The tested firmware lacked
   an OEM-unlocking switch.
2. The one "FRP" fastboot surface — `flash sig` — **verifies an ASUS RSA-2048 signature
   then erases the whole persistent partition** (byte → 0x00). It needs either unlocked
   state or the `getvar sofia_support` session override, and it *cannot* set byte=1
   (forging needs the ASUS private key; key embedded @0x1AE800 for verification only).
3. Every fastboot/oem/flash surface is state-gated; the state gates collapse with the
   undocumented **`fastboot getvar sofia_support`** (sets override 0x1B01FC=1 for the
   session) — but that only widens commands; it does **not** unlock or write FRP.
4. Bootloader lock *state* lives at **misc+0x1000 (3 bytes, first = state: 0/2)** when
   vtable A (TEE security-info bit 0x20 clear) is active, or inside the TEE
   ("INTELAndVerBoApp") when the bit is set. misc is NOT whitelisted for erase/flash
   while locked, and TEE state is not reachable from fastboot.

### Proposed routes and their limits

- **Route A: Android-side partition write.** The original proposal assumed a
  generic root shell could write the last persistent byte. DAC and SELinux both
  apply; shell uid 0 alone did not supply the needed `frp_block_device` grant.
  The final payload instead used gid/uid 1000 and the `system_server` domain.
- **Route B: droidboot binary patch.** The six-byte branch proposal at 0x315D2
  (`0f 84 ee fd ff ff` → `e9 ef fd ff ff 90`) is retained in the
  [FRP analysis](droidboot/frp-and-unlock-state.md#part-6--historical-patch-proposals-bytes-and-addresses).
  Replacing cached `/system/bin/droidboot` bytes and rebooting is not a
  bootloader installation: those cached changes disappear at reboot. No patched
  droidboot installation was validated. The five-byte cmpb-to-movb proposal has
  an additional condition-flag limitation described in that report.
- **Route C: session override.** `fastboot getvar sofia_support` changes a
  session-only gate and can widen the available commands. It neither sets the
  persistent allow byte nor proves an unlocked state. The commands it exposes
  may write device state.

### Historical pre-unlock read-only query expectations

Fastboot queries require droidboot mode; the Android commands require a running
Android system. The expected values describe the pre-unlock research context,
not the final rooted configuration.

| # | check (read-only) | validates | expect |
|---|---|---|---|
| 1 | `fastboot flashing get_unlock_ability` | FRP byte = 0 | "Unlock is disabled. To enable it, go in the Android Developer Options menu and activate 'Enable OEM Unlock'." |
| 2 | `fastboot getvar state` / `getvar unlocked` | state enum live | "locked" / "no" |
| 3 | `fastboot oem get-sec-info` | which ops vtable is active (TEE security bit 0x20 ⇒ TEE- or misc-backed state) | printable security info; text offset does not establish struct bit 0x20 |
| 4 | `fastboot oem get_batt_info`, `oem get-spid`, `oem get-part-id` | always-allowed oem surface | battery/data print |
| 5 | `fastboot getvar product`, `getvar kernel`, `getvar version-bootloader`, `getvar flash-all-depart`, `getvar max-block-size` | publish table | moorefield / "droidboot" / version / 1 / size |
| 6 | From Android (root): `dd` last byte of `/dev/block/by-name/persistent` → `od -An -tx1` | FRP byte value | `00` |
| 7 | From Android: `uname -r` | kernel identification; vendor backports can affect Dirty COW applicability | old Moorefield kernel; age alone does not establish vulnerability |
| 8 | `fastboot oem get-mfg-status` (read) | manufacturing/`ifp_manuf_sts` state | status string |


### Archived mutating probes

The original checklist also proposed `fastboot getvar sofia_support` followed
by `fastboot oem backup_factory` to test the override, and `fastboot erase factory`
to test an erase whitelist. These change state or can erase the named partition;
they are not part of the read-only queries or the implemented unlock sequence.
