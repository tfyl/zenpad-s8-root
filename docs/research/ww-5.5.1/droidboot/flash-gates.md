# Droidboot flash gates and image verification

Historical WW 5.5.1 static analysis. Current ELF: `reference/ww-5.5.1/executables/droidboot`.
See [artifacts](../../../artifacts.md) for provenance and
[methodology](../../../methodology.md) for the implemented chain. The commands
and proposed tests below are historical analysis, not a tested reproduction
sequence. Addresses and disassembly quotes are retained as evidence.

ASUS ZenPad S 8.0 Z580CA (P01MA) "droidboot", Intel Moorefield, Android 6.0.1, WW 5.5.1
Binary: stripped i386 PIE, bionic; GOT base **0x1ADCEC** (`lea disp(%ebx)` → 0x1ADCEC+disp,
valid in every function because each prologue does `call 251ac; add $imm,%ebx` → ebx=GOT).

Sections: §0 state model, §1 registries, §2 erase, §3 flash, §4 loader bundle, §5 per-partition
verdicts, §6 TEE verification, §7 the one local RSA key (FRP), §8 download, §9 splash/boot,
§10 answers, §11 open questions, §12 corrections. The analysis input is
`reference/ww-5.5.1/executables/droidboot`.

## 0. Device-state infrastructure (needed to read the gates)

ops vtable at *(0x1AFF9C), selected in 0x120830 from TEE security info
(`tee_get_security_info_struct` @0x10c690 into a 0x1c-byte struct; bit 0x20 of
struct+0x38 decides):

- **0x1AE93C "legacy" ops**: set_state=0x120cc0, get_state=0x120b00, op2=0x1208f0, confirm=0x120900
  - 0x120b00 = get_state: reads **3 bytes at misc@offset 0x1000** (0x120980: get dev by
    0x11bf60("misc") → open O_RDONLY → lseek 0x1000 → read 3 bytes) → returns (s8)byte[0].
    If the read fails, byte[0] keeps its pre-set default **2 = unlocked**.
  - 0x1208f0 = op2: `xor %eax,%eax; ret` — always 0 on this path.
- **0x1AE94C "secure/AVB" ops**: set=0x120e50→0x129300, get=0x120e00→0x129460
  (prints "AVB_change_device_state returned error code 0x%X - state %d"),
  op2=0x120dc0 (`mov $0x2,%eax; ret` — always 2), confirm=0x120dd0→0x31190.

So `0x31170` (wrapping vtable[2]) returns **2** on AVB-managed devices and **0** on legacy
misc-flag devices. get_state stays `0x31150`.

**misc-preservation side effect** (legacy path, op2==0):
- erase "misc" → 0x2a9a0 → 0x120d60 → 0x120980(&global 0x1B67CC): reads the 3 flag bytes into
  memory BEFORE wiping; after the wipe 0x2aa18 → 0x120d90 → 0x120b40(&0x1B67CC) writes them back.
- flash "misc" → same pair at 0x2adc8 (pre) / 0x2ac80 (post).
→ A locked state stored in misc@0x1000 survives both erase misc and flash misc.

## 1. Registries (built by 0x2b5a0 + platform-reg fn 0x119360)

hash fn 0x298630, eq fn 0x2997d0. Created in 0x2b5a0:

| slot | map | semantics |
|---|---|---|
| *(0x1B679C) | **mapA** | name → {u32 flash_fn; u32 min_state} — special flash registry |
| *(0x1B67B8) | mapB | name → {fn, min_state} — `fastboot oem <name>` dispatch |
| *(0x1B67A8) | mapC | generic **flash whitelist**, filled from .data array 0x1AE020 |
| *(0x1B6798) | mapD | **erase whitelist**, filled from .data array 0x1AE000 |
| *(0x1B67C4) | mapE | (unused at init) |

- 0x1AE020 (12 entries + NULL): bootloader, boot, system, oem, vendor, recovery, cache,
  data, userdata, config, logs, factory.
- 0x1AE000 (6 entries + NULL): cache, data, userdata, system, vendor, oem.
- command list (0x1AFF80) via fastboot_register 0x2cf00 — entry {next, name, len, handler, min_state}:
  erase:→0x2a6c0 (its own gate inside), flash:→0x2ab60, flashing→0x29de0 (min 0),
  continue→0x29730, reboot-bootloader→0x29690, boot→0x29660 (**min 2**), getvar:→0x2d8d0,
  download:→0x2f2d0 (min 2, registered by 0x2e5a0 with `fn=-0x17ea1c(%ebx)=0x2f2d0`),
  emmc_write:→0x2c9f0 (min 2), version-bootloader var, max-block-size var,
  flash-all-depart → "OKAY" stub.

### mapA (special flash names) — full table (extracted from 0x119360 + inline puts in 0x2b5a0)

| name | fn | min_state |
|---|---|---|
| update | 0x29800 (`flash update` = OTA apply) | 2 |
| system | 0x2A070 | 2 |
| data | 0x36780 | 2 |
| APD | 0x36800 | 2 |
| ADF | 0x36AF0 | 2 |
| factory-reset | 0x36D20 | 2 |
| run-sddl | 0x37390 | 2 |
| print-fingerprint | 0x37A80 | 2 |
| get_build_version | 0x37B00 | 2 |
| enable_end_user_mode | 0x37B90 | 2 |
| enable_adb | 0x37C70 | 2 |
| debricking | 0x113930 | 2 |
| sig | 0x112BB0 (FRP reset) | 2 |
| all | 0x118D90 | 2 |
| pre-flash | 0x118CF0 | 2 |
| partition | 0x115680 | 2 |
| repart | 0x114050 | 2 |
| media | 0x114120 | 2 |
| gpt | 0x112B40 | 2 |
| testos | 0x11CA50 | 2 |
| boot | 0x11C850 | 2 |
| recovery | 0x11C890 | 2 |
| bootloader | 0x119F20 | 2 |
| ESP | 0x11CA10 | 2 |
| silentlake | 0x11C9D0 | 2 |
| splashscreen | 0x11C8D0 | 2 |
| splashscreen1 | 0x11C8D0 | 2 |
| splashscreen2 | 0x11C910 | 2 |
| splashscreen3 | 0x11C950 | 2 |
| splashscreen4 | 0x11C990 | 2 |
| ifwi | 0x11CC80 | 2 |
| fastboot | 0x11CD10 (droidboot itself; POS/$POSS check) | 2 |
| dnx | 0x11C720 | 2 |
| capsule | 0x11C780 | 2 |
| ulpmc | 0x11E360 | 2 |
| esp_update | 0x11DC00 | 2 |
| **token_umip** | 0x11C660 (UMIP flash via ifwi-ops) | **0 — allowed unlocked AND locked** |
| **token** | 0x121A40 (tee_token_write → TEE InvokeCommand 0x70c4) | **0 — allowed unlocked AND locked** |

oem mapB (selected): erase_token→0x112AC0 (min 0, no args required — "oem_erase_token requires
no argument"), get_batt_info→0x112FD0 (0), get-spid (0), get-fru→0x1213C0, get-part-id→0x121970,
get-lifetime→0x121000, get-sec-info→0x121B90, get-mfg-status→0x121CD0, set-mfg-status→0x121D70,
start-update→0x1211C0, cancel-update→0x121200, finalize-update→0x121240, remove-token→0x121AB0
(all 0); backup_factory→0x1144D0, restore_factory→0x114770, backup_config→0x114620,
restore_config→0x114390, emmc_resize→0x113DE0, emmc_data_read→0x112CA0, pos_logging→0x113CF0,
adb_enable→0x113B50, pre_sending→0x113850, start_update→0x118F10, erase_osip_header→0x11AE40,
start_partitioning→0x1118B0, retrieve_partitions→0x112A00, stop_partitioning→0x111500,
get_system_info→0x113510 (min 2).
oem dispatcher: 0x29b60; unknown token → "unknown OEM command"; 0-min tokens (system/showtext…)
special-case at 0x29d08.

## 2. `erase:` handler 0x2a6c0

Registered min_state irrelevant (0): the handler enforces state itself.

```
2a6c0( part_name ):
  2a70f snprintf(buf, 0x32, "/%s", name)        ; also stores name for logging
  2a725 repz cmpsb "cache"(6)                    ; name == "cache"?
  2a732 je 2a9b0 → logtool: property logtool.pos.logging... + system("cp -r /cache/logtool /tmp/")
         (before wiping cache; restores after via 2aa28 "cp -r /tmp/logtool /cache/")
  2a738 call 0x31150 (get_state) → eax
  2a73f jne 2a74f                                ; state != 0 (UNLOCKED) → proceed
  2a741 mov 0x1214(%ebx),%eax                    ; = 0x1AEF00 sofia_support
  2a747 test; je 2a968                           ; if 0 → whitelist check
  2a74f call 0x31170 (op2)                        ; 2 on AVB, 0 legacy
  2a754 test; jne 2a76f (skip misc special); 2a758..2a769: name=="misc"? → 2a9a0 →
       0x120d60 (save flags)
  2a76f log "ERASE %s..."; name=="userdata"? → replace with "data" (2a8f0)
  2a7a0 snprintf("/%s", name); 2a7bb call 0x258d0(buf) ; mounted-volume lookup
       (je 2ab13 → "E:Unable to get device for %s")
  2a7ca open( part->dev (+8), 0x201 /*O_RDWR|O_SYNC*/, 0644 )
       (2aad0 "E:%s open failed" → bp=0xffed)
  2a7f0 ioctl(fd, 0x80041272 /*BLKGETSIZE64 (i386 size_t encoding)*/, &len64) ; fail → 2a910
       "E:Unable to get %s block device" / "Unable to get %s block device" (fd closed, FAILED)
  2a819 ioctl(fd, 0x127d /*BLKSECDISCARD*/, {start=0 @0x28, len=size @0x30})
       ; fail → 2aa90 "E:Unable to erase %s" → FAIL
       (so the locked-state-permitted erase = full-partition SECURE DISCARD)
  2a852 close; 2a85f "ERASE %s COMPLETE."
       + post: misc special (2aa18 write-back), logtool restore (2aa28)
  success calls 2e3f0 ("OKAY%s"-ish → "ERASE %s" string, "COMPLETE." tail at 2a8be).
  FAIL paths: 2a900 "unable to format"; 2a988 → "bootloader must not be locked".
```

Gate for LOCKED state:

```
2a968: hashmapContainsKey( *(0x1B6798) [mapD: 6-name erase whitelist], name )
2a982: jne 2a74f           ; whitelisted → proceed with the zero-out
2a988: "bootloader must not be locked" (0x144CD3, lowercase) → FAIL
```

| state / gate → who can erase | while LOCKED |
|---|---|
| via mapD (only) | cache, data, userdata, system, vendor, oem |
| via sofia_support flag (0x1AEF00) | any name in mapD OR **anything else that reaches the "not locked" branch** — i.e., sofia bypasses the whitelist too (2a741-2a749 skip it) |
| misc | NOT in mapD → locked erase misc = FAIL; unlocked only (with flag save/restore) |

Notes:
- the erase uses BLKGETSIZE64 (0x80041272; i386 size_t-sized request encoding, kernel writes the
  u64 size) then **BLKSECDISCARD (0x127d)** over {start=0, len=whole partition} — a secure
  discard, not a plain zero-out (my initial BLKZEROOUT guess was wrong; 0x127d vs 0x127f).
- the 0x80041272 ioctl failure path prints "E:Unable to get %s block device" /
  "Unable to get %s block device" @0x2a910-0x2a925.
- logtool: erase cache saves/restores /cache/logtool (before/after wiping) when global
  *(0x1B2488)=disp 0x479c (set by 0x35dc0, the logtool-position check called from 0x396e0)
  is 1 — NOT the debricking flag.

## 3. `flash:` handler 0x2ab60

```
2ab60 handler(name@0x80(esp), arg2, arg3):
  2ab91 call 0x31170 (op2)                       ; 2 AVB / 0 legacy
  2ab98 jne 2abaf                                 ; AVB device: skip misc special-case
  2ab9a cmp name, "misc" (5) → je 2adc8           ; legacy: misc → save flags first (0x120d60)
  2abaf log "FLASH %s..."
  2abc1 call 0x31150 (get_state) → edi
  2abcc hashmapGet(*(0x1B679C) [mapA], name) → esi (entry {fn, min_state})
  2abdc je 2ace0                                  ; name NOT in mapA → generic partition path
  2abe6..2abf9 log "asus_internal_unlock %d", 0x1AEF00(sofia_support) exit condition (always when mapA hit)
  2abfe cmp 0x4(%esi),%edi ; jae 2ac11           ; state >= entry.min_state → run entry.fn
  2ac03 edx = 0x1AEF00 (sofia); test; je 2adef    ; not allowed & no sofia → FAIL
  2adef FAIL "command not allowed in this device state" (fastboot_fail 0x2d110)
  2ac11 call *%esi (entry.fn)(arg2, arg3)
  2ac25 test → success: "FLASH COMPLETE!" + fastboot_okay(""); Error: "%s flash failed!"
              → "FLASH FAILED!" → "flash_cmds error!" → FAIL.
  generic path (2ace0):
  2ace0 test edi (state); jne 2acf2
  2ace4 mov 0x1AEF00,%eax ; test; je 2aea3        ; LOCKED & no sofia → FAIL
  2aea3 FAIL "Bootloader must not be locked" (0x144DC9, Title-case — only here; the lowercase
       "bootloader must not be locked" @0x144CD3 is the ERASE equivalent)
  2acf2 hashmapContainsKey(*(0x1B67A8) [mapC: 12-name whitelist], name)
  2ad08 je 2ae90 → FAIL "not allowed to flash this partition" (0x1531F8)
  2ad0e..2ad25 name=="userdata"? → replace with "data" (2ade0)
  2ad2b snprintf(buf, 0x32, "/%s", name)          ; fmt "/%s" @0x1443cf
  2ad4d call 0x258d0(buf) → partition struct     ; mounted-volume lookup, vol->dev@+8
       fail → 2aeb6 "unknown volume %s to flash!"
  2ad80 cmpl $0xed26ff3a,(payload)                ; SPARSE_HEADER_MAGIC
  2ad8a je 2ae08 → sparse image write (306a0) + log "sparse image data detected..."
  2ada2 call 0x30470(vol->dev, payload, len)      ; file_write to the BLOCK DEVICE
  2adb1 sync
  2ac29 "FLASH COMPLETE!"
```

Writers:
- 0x30470 = file_write(dst, src, len): if dst == "/data/fastboot.tmp" → rename(tmpfile,dst);
  else open(dst, O_CREAT|O_RDWR (0x42), 0600) + write loop (EINTR tolerant).
- 0x306a0 = sparse writer: open dst O_RDWR|O_CREAT, walk chunk table (types 0xCAC1 RAW /
  0xCAC2 FILL / 0xCAC3 DON'T_CARE / 0xCAC4 CRC32) writing 0x1000-byte pages.
- `flash system` path (0x2A070) additionally: if filename == "/data/fastboot.tmp" (0x13 bytes),
  fopen + fread first 0x1c bytes; magic 0xED26FF3A → 0x30050 (sparse-from-file with gzip support);
  else "try to flash gzip" → 0x2fb50 (decompress file → write). For in-memory blobs:
  gzip-in-mem → 0x1201d0 ("try to flash gzip by mem" + "Let's try again!!!" retry loop 3x).

Note the ordering: `FLASH %s...` is logged BEFORE the state gate; `asus_internal_unlock %d`
only shows up when the partition name matched an entry in mapA (the first 0x2abf0 lea), printed
with the CURRENT value of the sofia_support global (0 or 1). Thus on stock (-device locked, no
trick) every `flash <special-name>` prints `asus_internal_unlock 0` then fails.

## 4. `flash bootloader` (0x119F20) — "Invalid bootloader header !"

Special mapA entry, min_state=2. Decoded at min_state gate (0x2abfe) — needs unlocked/sofia:

```
119f3a cmpl $0xf,0x94(%esp) ; jbe 11a189   ; download size <= 15 → FAIL "dowloaded file size is incorrect !"
119f5b call 0x121db0                        ; VRL skip: blob[0x80]=="$BLD" → blob+=0x2d8 else "no VRL found"
119f6c cmp blob with "BOOTLDR!" (0x14EDCA, 8 bytes)
119f8a jne 11a1a1 → FAIL "invalid bootloader header !" (lowercase 0x14EDBA)
119f9e call 0x121e20(blob, len)             ; signature bundle check (-1 → 11a1e5
       "Bootloader image verification failure")
119fab..11a03c build magic table: "DROIDBT!" "DNX!!!!!" "IFWI!!!!" "SPLASHS!" "CAPSULE!" "ESP!!!!!"
       "SIL!!!!!" (+ names fastboot/ifwi/splashscreen/capsule/esp_update/silentlake for %s)
11a07e..151 for i in 7 magic: 0x119dc0(blob, len-0x2d8, magic, &out) — "searching for ifwi"→
   printf("flashing %s"); flash via 0x119e50(out, blob, len) (per-type flasher)
   "No valid %s image found" (11a131); if none of the 7 sub-images present →
   "Nothing to be flashed" (11a161); if only "nothing flashed" flag set (11a178) →
   "Bootloader version not supported" (11a1d1).
```

So **one blob = an OSIP-style bundle**: a "$BLD" VRL header block (0x2d8 bytes) followed by
sub-images keyed by magic (droidboot / dnx / ifwi / splash / capsule / ESP / silentlake), with
per-magic flashing. Verification (the $BLD VRL + per-module RSA) runs in 0x121e20 (§6).

## 5. Per-partition verdict table (LOCKED device = state 0, no sofia_support)

| fastboot target | state 0 | who enforces | signature gate while unlocked |
|---|---|---|---|
| boot / recovery / system / data / cache / userdata / oem / vendor / config / logs / factory (generic) | **FAIL "Bootloader must not be locked"** (@2aea3, before the whitelist!) | mapA miss + state 0 mapC reach | none — raw or sparse write after `snprintf("/%s")` + mounted-volume lookup (0x258d0); if not in whitelist → "not allowed to flash this partition" |
| boot (special name in mapA) | FAIL "command not allowed in this device state" (min_state 2) | mapA entry 0x11C850→0x11C7E0 | flash_image ops: rename "testos"→"boot", get partition dev by name (0x11de70), "Erase OSIP header" (0x11ae40) then 0x11bbb0(raw-partition write); **no userspace crypto check** |
| recovery / splashscreen / splashscreenN / testos / silentlake / ESP / ulpmc / esp_update | same (min 2) | mapA | same flash_image path (no local verify) |
| fastboot (droidboot img) | min 2 FAIL | 0x11CD10 → update_fastboot_image 0x11d240 (5 tries × write /tmp/verify.tmp + check "$POSS" phase header, else check_sign_key_main_v2 trailing-0x258 "$POSS") → no_signed_POS → check_sign_key fail | OSIP phase header presence (no local RSA); write via flash_image to "fastboot" partition |
| bootloader (multi-image bundle) | min 2 FAIL | 0x119F20 (§4) + 0x121e20 (§6) | **full chain**: $BLD VRL @0x80 (0x2d8 bytes) + per-module TEE RSA ("$POS"/"$SSI"/modules) via 0x129d90 + BOM_TOKEN 0x129590 |
| ifwi | min 2 FAIL | 0x11CC80 (+check_production_sku 0x11d700 gate, "no_flash_bom_token") | → ifwi-ops → 0x12b2b0: dnx must exist (/tmp/__dnx.bin — `flash dnx` must run first, 0x12b250), IFWI ToC parse (0x1305b0), version compare (0x12aa00: "IFWI FW Major version numbers (file=%02X current=%02X) don't match, Update aborted..."), writes /tmp/__ifwi.bin then update via **/sys/devices/ipc/intel_fw_update.0/ifwi|dnx** (kernel driver decides) |
| dnx | min 2 | 0x11C720 | writes data to **/tmp/__dnx.bin** (file_write 0x11bbb0) — no hardware write; only a staging file used by "flash ifwi" |
| capsule | min 2 | 0x11C780 → flash_capsule | ops[1]: ESP mount path 0x11da10: mkdir /ESP, mount vfat, write **/ESP/BiosUpdate.fv** (0x11bbb0) then flash_capsule_esp activation; or non-ESP variant 0x12b460 |
| token (BOM/MCP token written via TEE) | **min 0 → allowed LOCKED** | 0x121A40 → tee_token_write(0xff650: DX_CclibInit + TEEC_Init + TEEC_OpenSession + TEEC_InvokeCommand 0x70c4) — TEE decides | n/a (TEE does whatever validation) |
| token_umip | **min 0 → allowed LOCKED** | 0x11C660 → ifwi-ops t[5]=0x12c330 (GPT variant): open /dev/block/mmcblk0boot%d, clear force_ro, mmap 0x400000, memcpy at +0x4000 (modulus at "never shared") | none for third-party data validity; UMIP blob stores platform IDs |
| sig (FRP reset) | min 2 | 0x112BB0 | **RSA-PKCS1(SHA256(ro.serialno)) MUST verify vs embedded pubkey** → erase "persistent" partition via 0x2a6c0 |
| update (OTA) | min 2 | 0x29800 | writes downloaded(image) → /cache/update.zip via file_write, writes "--update_package=/cache/update.zip" to /cache/recovery/command, then android_reboot(0xDEAD0003, 0, "recovery") — droidboot itself does NOT verify the OTA zip |
| debricking / repart / media / etc. | min 2 | 0x113930 | checks /cache/debricking message ("Check debricking mesg OK!"), writes flag; other OTAs similar |
| misc (single cmd, not in mapA) | (after op2 check pass) min-none | generic path | legacy: flag save/restore around the write; state-0: FAIL "Bootloader must not be locked" (mapA-miss → 2ace0 test) |

## 6. TEE-verifier details

All the bundle verification in 0x121e20 goes through **TEEC/**sep** on /dev/dx_sep_q1**:

- 0x129590 = BOM-TOKEN verify, TEEC_InvokeCommand cmd 0xd, resident blob scan using
  parser 0x119dc0(blob, len, "BOMTOKEN", &img). err → "verify start returned 0x%x".
- 0x129d90 = per-module verify: DX_CclibInit → TEEC_InitializeContext("/dev/dx_sep_q1" @0xfe850)
  → TEEC_OpenSession (uuid from 0x16fe35) → for each chunk (TEEC_RegisterSharedMemory, ≤0xffff
  bytes) TEEC_InvokeCommand cmd 0x10; failure "img_verify_session_cmd %d failed. error(0x%x)".
  Formats: a) blob->0x80 == size and blob->0x88 == 0x202 → 1- or 2-chunk-table at
  blob+0x2d4/0x2e8 stride 0x2d8/0x2f4; b) blob[0] == 0x54484324 ("$CHT") inline chunk walk
  (stride 0x1c entries {off, size, kind}) used by the "$SSI"/"$POS"/"$BLD"/module variants
  (129e00..129e77).
- 0x12a270 = verify END (cmd 0x8/10). 12a271 = "verify end returned 0x%x" on error.

=> **No IFWI/$BLD/$POS/$SSI keys in droidboot.** All crypto (hash + RSA) for the bootloader
bundle path happens inside the TEE (TA on the SEP). droidboot only orchestrates it.

### What in-mapA "ifwi/dnx/capsule/splash etc." do
- flash dnx (0x11C720) → ops[1]=0x12b250: writes data → /tmp/__dnx.bin (file_write).
- flash ifwi (0x11CC80): check_production_sku(0x11d700) → if==1 && bom-token-control global
  *(0x1B68C4)==0 → set "no_flash_bom_token" + 0x11ca90(reason) = prints
  "E:%s: check_sign_key fail: no_flash_bom_token" and FAILs. Otherwise dispatch ops[0]:
  flash_ifwi impl: requires /tmp/__dnx.bin (i.e. `flash dnx` first), parse IFWI (0x13x)
  versions; write /tmp/__ifwi.bin; call 0x12aa00 ("/tmp/__ifwi.bin", reset=0) — sysfs driven
  IFWI update with FW-version checks (0x12aa44 → "update_ifwi_image: Coudn't extract FW
  version data from image" also update_ifwi_image @0x15ca…).
- flash capsule (0x11C780): write /ESP/BiosUpdate.fv on mounted vfat (mkdir "/ESP" 0777 +
  mount(...,"/ESP","vfat") at 0x11da41-9a) then flash_capsule_esp (0x11bbb0 + "flash_capsule_esp"
  log @0x11daf4) — or via FWUP variant (12b410), which checks the property "sys.mia.version".
- `flash boot/recovery/…` (0x11c7e0): rename "testos"→"boot" (buffer at 0x11dfa7 "testos"
  changed to "boot" via cmove semantics), get partition dev by name (0x11de70), **erase OSIP
  header first** (0x11ae40 prints "Erase OSIP header" and zeroes it), then 0x11bbb0(dev,
  data, size) — NO signature check of the payload inside droidboot (OSIP/SBL-bound phases
  are re-enforced downstream at next boot by SBL; droidboot itself does not verify them).
- flash fastboot (0x11CD10) — the ONLY per-module "signed" gate in userspace for THIS binary:
  5 tries: write payload to /tmp/verify.tmp (0x11bbb0), check 11cd80(name, file):
  fread 8 bytes at offset **0x280** of /tmp/verify.tmp; the 4/5th bytes must be "$POSS"/"$MOSS"/
  "$ROSS" matching the requested target ("POS/MOS/ROS" @0x14F272/0x14F287/0x14F28B …), then
  "PASS"/"Fail" — the "$POSS" phase (the compressed droidboot image) is what a signed release
  update contains.
- if those checks fail → check_sign_key_main_v2 (11cfb0): reads the LAST 0x258 bytes of the
  file (fseek end-0x258) for the same "$XXSS" match; if PASS → OK (write permitted? see 11d305).
  Fail on both → check_sign_key reason → FAIL.

## 7. The one place droidboot itself verifies RSA locally — `flash sig` (FRP reset) 0x112BB0

min_state=2. Uses OpenSSL (statically linked, exported):
```
112bfc: buf(0x80 bytes) = property_get("ro.serialno") ; len = __strlen_chk(buf, 0x80)
112c08: call 0x11d830(buf, len, ARG2_from_cmdseq, ARG3)
112c0d: ==0 → "FRP signature verify pass!" → erase "persistent" partition via erase-handler (0x2a6c0)
        → "Finish flashing sig!" 0 = ok.
112c11: !=0 → "FRP signature verify fail!" → 0 (fail).
```

### Verifier 0x11d830 (generic local RSA check)
```
11d830(data, len, sig, siglen):
  digest (32 bytes at 0x30(%esp)) = 0x11d7f0(data, len, mode=2)
      0x11d7f0 → 0x11d950(buf, len, ≥1) : mode 1 → SHA1@c9c30, mode 2 → SHA256 @ca4e0 (OpenSSL).
  rsa = d2i_RSA_PUBKEY(NULL, &pp, len_global@0x1AE7C0)   ; pp→ DER blob inline @0x1AE800
      failure → return -33.
  ret = 0x11d7a0(sig, siglen, buf, rsa, 1 /*RSA_PKCS1_PADDING*/) — wrapper around
      RSA_public_decrypt(sig, siglen, buf, rsa, RSA_PKCS1_PADDING); ret ≤ 0 → -1.
  memcmp(buf + ret - 0x20, digest, 0x20) == 0 → 0 (verified); nonzero → -1.
```
(The `sig` handler passes the flash-command's own payload signature area as
(`sig`, `siglen`) — in code, `mov 0x24(%esp),%edx; mov %edx,0xc(%esp)` /
`mov 0x20(%esp),%edx; mov %edx,0x8(%esp)` feed 0x11d830's arg3/arg4 from the flash
command's registered handler arguments; exact arg pairing is opaque at the source level but the
semantic is: signature satisfies RSA-PKCS1(SHA256(ro.serialno)) against the embedded key below.)

### The embedded FRP key — FOUND, static in .data 0x1AE800..0x1AE925
- the d2i_RSA_PUBKEY size argument comes from *(0x1AE7C0) = 0x126 (plain initialised .data,
  no relocation), while the DER bytes themselves are INLINE at 0x1AE800 (0x11d885's
  `lea 0xb14(%ebx),%eax` computes the address of the blob, not a pointer slot).
- DER bytes at 0x1AE800: `30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03 82 01 0f`
  SubjectPublicKeyInfo{rsaEncryption, BITSTRING{RSA mod/exp}}:
  - modulus 2048-bit (leading 00, 0x200 bytes):
    ```
    81cb78ec68577b81b71f829c2117ba5d6fe6ed00b04e89ea7735df8f317378
    b98f84d53712fe5cd00d8c3a472d8197b449adf022450b4d5985ab6a0d8068
    6ab7492b4865d3c2003cb66b50a1498532bcd56fa8bec4afae396efb6d2f79
    982bc9f72292562f104cf9b6f7f6c9a21424030aacd5279c88a85ab21d3fb0
    f1cd01a155c736e4c2238c7a8fcb90b6512ac4b55822d6f9ae1dcf3bcf6232
    8199fe19b5f5c90f4451493ffbe1b44ec5cc7994a17b82047c5c408569d664
    3fbe199e70b1c293e7085f59873ae031309af7ba922aefcea962c692cf8ecc
    fdf8887f5683c630903acb950c71df4ac418dd8993e3ac7afa3012d0edca21
    083692f19fb6ea6b
    ```
  - exponent 010001 = 65537.
This is the canonical "FRP unlock protection" key. If you possess the matching private key,
you can produce `flash sig <blob>` that passes and wipes the FRP gate ("persistent" partition).

## 8. download: handling (command `download:`, fn 0x2f2d0, registered by 0x2e5a0 with min_state=0)

- 0x2e5a0 = fastboot transport init: reads the "download scratch size" from the kernel
  cmdline (0x280f0 = parse MemFree), computes **scratch = min(2/3 free RAM, 0x20000000)**
  ("No sratch size specified in cmdline will use %u (minimum between 2/3 o..."), mallocs the
  scratch buffer, pointer stored at *(0x1B6794) (disp 0x8aa8), size stored at **0x126c(%ebx)
  = 0x1AEF58**. Also registers "getvar:"→0x2d8d0, "download:"→0x2f2d0 (both min **0**),
  "emmc_write:"→0x2c9f0 (min 2), "version-bootloader" and "max-block-size" getvars,
  "flash-all-depart" stub, then property "sys.usb.config"=... and the ADB pipe loop.
- 0x2f2d0 cmd_download(size_str):
  - size = strtoul(hex) from the command payload.
  - if size <= scratch (0x1AEF58) → receive into the in-RAM scratch.
  - else (file mode) → close any open tmpfile, 27620("/data/fastboot.tmp") = check mounted
    volume; 2f040: query /data free space ("/data available size: %d MB, file size= %d MB",
    ref 0x2f088 = lea -0x5a56c(%ebx))
    and require **free_MB >= size_MB + 0xC8 (200 MB) headroom**, else
    "FAIL: no enought DATA space, please free %d MB at least".
    Then open("/data/fastboot.tmp", 0x242 = O_RDWR|O_CREAT|O_TRUNC, 0644) → fd stored at
    0x36c(%ebx) = 0x1AE058; the file **is** the download target.
  - responds "DATA%08x" (12 chars, via __sprintf_chk %40), then reads the socket (fd 0x2298)
    in ≤ 0x100000-byte chunks writing to scratch/tmpfile until `received == requested`;
    "E:fastboot: cmd_download error only got %d bytes" → FAIL. Writing to the tmpfile uses
    a retry/errno-msg path ("write to tmpfile failed: ...").
- handlers consume either source:
  - "flash <special>" handlers receive (data, size) where data may literally be the string
    "/data/fastboot.tmp" (13 bytes) — 0x2A070 (`flash system`) special-cases that exact string,
    fopen()s the tmpfile, reads a 28-byte sparse header to decide whether to treat it as
    **sparse (0x30050)** or **gzip (0x2fb50, "try to flash gzip")**.
  - otherwise the buffer is written as-is via 0x30470/0x306a0 (file_write handles
    "/data/fastboot.tmp" by rename()ing it — that's what "flash <partition>" achieves when the
    downloaded blob points at the tmpfile path).
- `emmc_write:` (0x2c9f0, min 2) = the secondary write command used for writing raw data into
  a partition from the tmpfile/scratch (used by ASUS update tooling).

So max download = min(2/3 RAM, 512 MiB) in RAM, or unbounded (≤ /data free minus 200 MiB)
into **/data/fastboot.tmp**.

## 9. splashscreen / boot-time image verification

- The fastboot-screen UI is rendered via the minui module (strings "failed to mmap framebuffer",
  "/res/images/%s.png", "framebuffer: %d (%d x %d)", ADF device paths "/dev/adf%u") — droidboot's
  own art assets live in its RAMdisk, NOT in the splashscreen partition. Nothing at fastboot boot
  READS the splashscreen partition. (Only the flash-side "raw write to /ESP/BiosUpdate.fv" and
  IFWI-bundle "update...." touch /ESP/BIOS fat partition paths.)
- At NORMAL Android boot the splash is drawn by the kernel/first-stage init off
  `/dev/block/mmcblk0p43`-style splashscreen partition (4 MiB). That path is NOT droidboot code.
- Inside the droidboot binary the only splash-partition uses:
  - `flash splashscreen` / `splashscreen1..4` (§5) — raw write after "Erase OSIP header".
  - `update_ifwi_image`-driven `splash1_MOS_sign`/`splash2_POS_sign`/`splash3_COS_sign` /
    `splash4_sign` (0x11eeb0, 0x115f40, 0x1182c0): OTA applies require the *_sign companion
    version files; if flash of boot/recovery/droidboot is NOT signed (no_signed_MOS/ROS/POS)
    → check_sign_key fail: no allow update kernel/recovery/droidboot (all min_state=2).
  - bootloader-bundle verifier 0x121e20 verifies "SPLASHS!" module with "$SSI" via TEE
    (129d90) BEFORE flashing inside the bundle.
- Because droidboot actually only writes the partition and reboots, the decision "bad splash
  blocks boot or is just shown" is made SBL/kernel-side, not here; droidboot does NOT verify
  the running/normal boot splash at every fastboot boot.

- `flash update` (§5) writes /cache/update.zip + /cache/recovery/command and reboots
  into recovery — the entire update.zip signature verdict belongs to recovery, not droidboot.
- `flash debricking` (0x113930): writes /cache/debricking after checking that its own
  current content says "Check debricking mesg OK!"; the flag affects the OTA module
  ("Force debricking : YES!").

## 10. Command behavior by device state

1. **erase: allow-list while LOCKED** = mapD from 0x1AE000 = {cache, data, userdata, system,
   vendor, oem} (hashmapContainsKey at 0x2a968 against *(0x1B6798)); everything else →
   "bootloader must not be locked" (0x2a988, lowercase @0x144CD3). Title-case variant
   "Bootloader must not be locked" @0x2aea3 is the FLASH-side equivalent (same meaning).
   "not allowed to flash this partition" (@0x2ae90, string @0x1531F8) is the FLASH-side
   **whitelist miss** (mapC from 0x1AE020) — reached only when unlocked/sofia; for LOCKED
   devices flash is stopped EARLIER by "Bootloader must not be locked" (@0x2aea3).
   `asus_internal_unlock %d` (@0x2abf0, string @0x144D8A) prints the sofia_support global
   (0x1AEF00) whenever `flash <name>` hits a mapA-registered special handler — %d ∈ {0,1}.
   Same global doubles as the erase/特殊 oem escapes.
2. **`boot`/`recovery`/`fastboot` while locked**: FAIL (mapA min_state 2 ⇒
   "command not allowed in this device state"). While UNLOCKED they go through flash_image
   (boot/recovery) or update_fastboot_image (fastboot: $POSS phase header must match, else
   check_sign_key fail) — no OPENSSL crypto verify by droidboot itself for boot/recovery.
   `system`/`data`/`cache`/`factory`/`config`/`splashscreen`: locked = FAIL
   ("Bootloader must not be locked" for non-mapA names, "command not allowed…" for special
   names — note system/data ARE mapA entries so locked flash system/data gets the
   min_state error, NOT the generic "");
     unlocked = raw/sparse write to the block device (no extra checks, except the classic
   "not allowed to flash this partition" if the partition isn't whitelisted).
3. **IFWI/CAPSULE**: parsed/verified in the $BLD/"$ToC" module verifier 0x121e20 with all the
   RSA inside the TEE (§6 of this report); IFWI/outside-the-bundle `flash ifwi` uses the
   kernel `/sys/devices/ipc/intel_fw_update.0/{ifwi,dnx}` interface (no local RSA; version
   comparison only). **No CASIGN / .CASI strings and no unknown-$-headers** — the Intel
   signed-IFWI format is the "$BLD"/"$ToC"/module-names one; CASIGN is the Intel MCU
   "casign" tool's artifact on disk, not parsed in droidboot searching.
4. **splashscreen**: never read by droidboot at boot; flash-only (raw write, unlocked-only).
   Verified only when shipped inside a $BLD bundle ("$SSI" TEE verify).
5. **download:**: registered "download:" → 0x2f2d0, min_state **0** (allowed in ANY state —
   `movl $0x0,0x10(%eax)` at 0x2e6cf). Max size = scratch (min(2/3 freemem, 0x20000000)) or — if
   the requested image is larger — lands in **/data/fastboot.tmp** after the free-space check
   (payload_MB + 0xc8 MB). The data is either an in-RAM scratch or the tmpfile;
   handlers fetch it per name ("flash system" reads/special-cases "/data/fastboot.tmp"; the
   generic write path rename()s the tmpfile when the destination equals it).

## 11. Open questions / uncertainties

- 0x2c9f0 (`emmc_write:`) and the remaining 0x36xxx/0x37xxx handlers (APD/ADF/factory-reset/
  run-sddl/…) were only classified by registration/min_state, not fully decoded.
- The BAR-style global flag at *(0x1B68C4) ("bom-token-can-flash" toggle) was only observed in
  the flash_ifwi branch; its setter was not chased.
- 0x119e50 (per-bundle-type flasher) internals and the ESP/`silentlake`/`ulpmc`/`esp_update`
  special handlers were not fully explored; only their entry points are mapped.
- minui PNG assets ("/res/images/") supply fastboot's own screen; whether the splashscreen
  partition feeds those assets at run-time (unlikely — separate partition) was ruled out by
  absence of splash reads at command-loop speed, not by individual asset tracing.
- The 0x1AE020 whitelist contains 12 names; only these can be flashed unlocked without a
  mapA override. If production builds add names (e.g. "PSP", "MFG"), they'd come from a
  different build config, not this blob.
- `flash token` is allowed in LOCKED state (min_state=0!) and writes a TEE token via
  0xff650. The TEE (not droidboot) decides whether the token is valid — worth fuzzing.

### Raw proof lines (selected) — see §2/§3/§4 code dumps above for context

```
2a968: lea    0x8aac(%ebx),%eax ; hashmap ptr (mapD = 6-name erase whitelist)
2a982: jne    2a74f                      ; whitelisted → erase permitted
2a988: lea    -0x69019(%ebx),%eax ; "bootloader must not be locked"
2a9ae  (call  2d110 <fastboot_fail>)
--
2acf2: lea    0x8abc(%ebx),%eax ; hashmap ptr (mapC = 12-name flash whitelist)
2ad08: je     2ae90                       ; miss → msg "not allowed to flash this partition"
2ae90: lea    -0x5aaf4(%ebx),%eax
--
2abe6..2abf6: "asus_internal_unlock %d" (0x1AEF00 = sofia_support), then state>=min_state else FAIL
2adef: lea    -0x5adb8(%ebx),%eax ; "command not allowed in this device state"
2aea3: lea    -0x68f23(%ebx),%eax ; "Bootloader must not be locked"
--
119f71: lea    -0x5ef3b(%ebx),%edi ; "BOOTLDR!"
11a1a1: lea    -0x5ef32(%ebx),%eax ; "invalid bootloader header !"
11a1b9: lea    -0x5ef51(%ebx),%eax ; "invalid VRL header !"
11a1e5: lea    -0x53fac(%ebx),%eax ; "Bootloader image verification failure"
--
121dd2 … "$BLD"  compare (check blob+0x80)
122738: "could not find IFWI ToC"
12263e: "missing entry for %s"
12279f: "verify check returned for splashscreen 0x%x"
12253a / 12257c / 129590 / 129d90 / 12a270 — TEE verify chain (cmd 0xd / 0x10 / end)
--
112c08: call 11d830     ; FRP: RSA-PKCS1(SHA256(ro.serialno))
c5e20 (RSA_public_decrypt) ← e4f10 (d2i_RSA_PUBKEY) ← static DER key @0x1AE800 (2048-bit, e=65537)
```

## 12. Addendum — verified debricking flag and erase-ioctl corrections

- **Debricking flag global = *(0x1B248C)** (disp `0x47a0(%ebx)`). Two setters:
  - `0x39709` (fn 0x396e0, boot init): value = return of `0x35bf0`, the `/cache/debricking`
    message checker (exists → checks "Check debricking mesg OK!" → "Check debricking fail!";
    "E:Force debricking : YES!" flash path at 0x113943/"flash debricking" handler 0x113930).
  - `0x11e8ea` sets it to **2** directly, right after logging "Force debricking : YES!"
    (0x11e8ce) — the runtime path that turns it on when /cache/debricking says YES.
  **13 references total** (`mov/lea … 0x47a0(%ebx)`), 2 setters + 11 read sites:
  0x39709(s) 0x3975b 0x1139b4 0x114e19 0x115414 0x11646c 0x1180d4 0x118e69 0x119259
  **0x11e63e** 0x11e8e4(s) 0x11eb73 0x11ecc2 (the last two `cmpl $0x1` — flag==1 gates
  adjacent paths, e.g. 0x11eb7c/0x11eccb).
- **Skip semantics at 0x11e63e** (inside the image check 0x11e110):
  ```
  11e63e: lea    0x47a0(%ebx),%eax    ; debricking flag
  11e644: mov    (%eax),%eax
  11e646: sub    $0x1,%eax
  11e649: cmp    $0x1,%eax
  11e64c: jbe    11e8f0               ; unsigned (flag-1) <= 1  →  flag ∈ {1, 2} → SKIP
  11e652+  (flag == 0): property_get("ro.build.type"), "Start check Image-SKU... "
           → 0x1148b0 checks image-SKU vs device hw SKU
  11e8f0: "Skip checking hw_sku "        ; skipped path
  ```
  i.e. when the debricking flag is 1 or 2 the SKU gate is bypassed; otherwise a mismatching
  image yields "Invalid package" / "[Error] Project name and Hardware ID are not match"
  (0x11d4e0 hw-id compare at 0x11e838). Related skip messages in the same checker:
  "Image no SKU info -> skipped", "Image no OEM info -> skipped", "ENG-build -> skipped".
- **Erase ioctl correction (§2)**: first ioctl = `0x80041272` = BLKGETSIZE64 (the i386
  `size_t`-sized encode of `_IOR(0x12,114)`; kernel writes the full u64 → lo@0x20/hi@0x24);
  second ioctl = `0x127d` = **BLKSECDISCARD** with {u64 start=0, u64 len=partition size} —
  the permitted locked-state erase is a full-partition secure discard (BLKDISCARD would be
  0x1277, BLKZEROOUT 0x127f — neither matches the binary).
- mapA "all" = 0x118D90 dispatches sub-flashes through the same
  image-check 0x11e110 path; the debricking flag is what turns those SKU checks into skips
  on retail-bricked devices.

## Splash verification + boot-time checks (compact §; details in §6 + §9)

- **Splash verify at FLASH time only**: inside the bootloader-bundle verifier 0x121e20, the
  "SPLASHS!" sub-image is verified with 0x129d90("$SSI", splash_data+0x10, size, 0) — TEE
  (invoke cmd 0x10, /dev/dx_sep_q1); failure prints "verify check returned for splashscreen
  0x%x" (0x12279f) and aborts the whole bundle. This is the ONLY place splash content is
  checked in droidboot.
- **No boot-time splash/kernel verification in droidboot itself**: droidboot never reads the
  splashscreen partition to draw anything — its fastboot UI is minui assets from its own
  ramdisk ("/res/images/%s.png", framebuffer info strings, /dev/adf*. It only ever WRITES
  splashscreen (raw write via 0x258d0/0x30470 or flash_image 0x11df90) or reboots. The
  normal-Android-boot splash/kernel signature enforcement lives in SBL/TEE (TXE) downstream —
  not in this binary. Consequence: a bad splash does not block droidboot; whether it blocks
  the real OS boot is decided outside droidboot.
- **flash boot/recovery raw-write path**: mapA fns 0x11c850 ("boot") / 0x11c890 ("recovery") →
  0x11c7e0 dispatcher (ops table 0x12a460: OSIP table @0x1AE928 vs GPT table @0x1AEA08) →
  0x11df90 (OSIP impl): renames "testos"→"boot", resolves the partition dev by name
  (0x11de70), **erases the OSIP header first (0x11ae40, prints "Erase OSIP header")**, then
  writes the payload straight to the block device (0x11bbb0). NO signature check of the
  kernel/recovery payload in droidboot. flash fastboot (droidboot image) = 0x11cd10 →
  0x11d240 with the "$POSS" phase-header checks (0x11cd80 at file offset 0x280 / v2
  check_sign_key_main_v2 0x11cfb0 at end-0x258) before the same raw write.
- splashscreen handlers: 0x11c8d0 (splashscreen + splashscreen1), 0x11c910 (splashscreen2),
  0x11c950 (splashscreen3), 0x11c990 (splashscreen4) — all via 0x11c7e0, min_state=2.

## download: handling (compact §; full decode in §8)

- `download:` is a normally-REGISTERED command (open-coded in transport init 0x2e5a0):
  entry {len=9, name="download:", fn=0x2f2d0, min_state=0} at 0x2e6b0–0x2e6cf — **min_state 0,
  allowed in any device state**.
- handler 0x2f2d0: size = strtoul(hex) of the command tail; if ≤ scratch → stream into the
  in-RAM scratch (pointer *(0x1B6794) via disp 0x8aa8); scratch size stored at 0x126c(%ebx) =
  0x1AEF58, computed at init as **min(2/3 free RAM (0x30ac0 /proc/meminfo), 0x20000000)**
  (512 MiB cap) — logged as "No sratch size specified in cmdline will use %u ...".
  0x2e753 asprintf formats that size into a string (fmt @0x1443D3) for the getvar max-size
  response. Larger transfers → **/data/fastboot.tmp** (open 0x242=O_RDWR|O_CREAT|O_TRUNC,
  0644, fd in 0x1AE058) after the free-space check (0x2f040: "/data available size: %d MB,
  file size= %d MB", needs free ≥ size_MB + 0xC8(200) MB, else silently-fails with
  "FAIL: no enought DATA space, please free %d MB at least").
- Protocol: reply "DATA%08x", then read the transport in ≤0x100000 chunks until requested
  bytes received; short reply counts → "fastboot: cmd_download error only got %d bytes"/FAIL.
- Consumers: handlers take the buffer or the tmpfile path; "flash system" (0x2a070)
  special-cases the literal string "/data/fastboot.tmp" — fopen+28-byte header → sparse
  (0x30050) or gzip (0x2fb50, "try to flash gzip"), then unlink; in-memory payload → sparse
  0x306a0 / gzip-by-mem 0x1201d0 ("try to flash gzip by mem", 3 attempts "Let's try again!!");
  generic write path 0x30470 rename()s the tmpfile when asked to write to that same path.

## Per-partition verdict + open items (compact §; full table in §5, open list in §11)

| fastboot target | LOCKED (state 0) | UNLOCKED | verification on the payload |
|---|---|---|---|
| token_umip, token | **OK (min_state 0)** — UMIP/TEE-token write | OK | none locally (TEE writes) |
| any of the 6 erase-whitelist partitions via `erase:` | OK (BLKSECDISCARD) | OK | none |
| erase anything else | FAIL "bootloader must not be locked" | OK | none |
| boot, recovery, splashscreen*, testos, silentlake, ESP, ulpmc, esp_update, media, repart, partition, all, pre-flash, gpt, dnx, capsule, ifwi, fastboot, update, data, system, APD, ADF, debricking, sig, factory-reset, run-sddl, ... | FAIL "command not allowed in this device state" (mapA min_state 2) | OK | boot/recovery/splash*: none (OSIP header erased first); fastboot: $POSS phase header presence; bootloader: TEE $BLD/$SSI/$POS/module verifies; sig: RSA-PKCS1(SHA256(ro.serialno)) vs embedded key @0x1AE800; ifwi/dnx/capsule: FW-version checks + kernel fw_update driver |
| any other partition name | FAIL "Bootloader must not be locked" (2aea3) | whitelisted names (12, @0x1AE020) OK; others FAIL "not allowed to flash this partition" (2ae90) | raw or sparse write, no signature check |
| misc | FAIL (generic path) | OK with unlock-flag save/restore around it | none |

Open items (unchanged from §11): `emmc_write:` 0x2c9f0 not fully decoded; 0x36xxx/0x37xxx
handlers (APD/ADF/factory-reset/run-sddl/…) only classified; 0x119e50 per-bundle-type flasher
internals; setter of the bom-token toggle *(0x1B68C4); the debricking-flag's exact producer of
value 1 vs 2 (init 0x39709 from 0x35bf0 vs runtime set-2 0x11e8ea); kernel-side/splash boot
verdict for normal Android boot is outside this binary; the 0x1AE020 whitelist is per-build
configuration (prod builds could add/remove names).
