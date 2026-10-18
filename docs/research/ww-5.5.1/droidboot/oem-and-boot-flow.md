# Droidboot OEM handlers, device state, and boot flow

Historical WW 5.5.1 static analysis. Current ELF: `reference/ww-5.5.1/executables/droidboot`.
See [artifacts](../../../artifacts.md) for provenance and
[methodology](../../../methodology.md) for the implemented chain. The commands
and proposed tests below are historical analysis, not a tested reproduction
sequence. Addresses and disassembly quotes are retained as evidence.

Binary: `reference/ww-5.5.1/executables/droidboot` (ELF32 x86 PIE, bionic, stripped, Android 6.0.1 WW_5.5.1).
GOT base = 0x1ADCEC (all `lea disp(%ebx)` below resolved as `GOT−disp` for negative disp, the compiler's idiom here: `%ebx` holds _GLOBAL_OFFSET_TABLE_ after the `call 251ac`-thunk; effective address = 0x1ADCEC + disp, where disp<0 means subtract magnitude).

---

## Ops vtable registration + state persistence

### Who writes 0x1AFF9C (the ops vtable pointer)

- The accessor wrappers are thunks that load `[GOT+0x22b0]` = **0x1AFF9C** and call through it:
  - 0x31c40 (set_state, arg1 = new state): `mov 0x22b0(%ebx),%eax; test %eax,%eax; je 31c70; call *(%eax)` — +0x0 slot.
  - 0x31c80 (get_state): `mov $0x2,%eax; mov 0x22b0(%ebx),%edx; test %edx,%edx; je 31ca2; call *0x4(%edx)` — +0x4 slot.
  - 0x31cb0 (?): `mov $0x1,%eax; ... call *0x8(%edx)` — +0x8 slot.
  - 0x31ce0 (confirm): loads +0xc slot; if arg1(word @0x24(%esp)) == 0 returns −1 without calling (`test %edx,%edx; je 31d20; mov 0xc(%edx),%edx; test %edx,%edx; je 31d20; movzbl %al,%eax; ... call *%edx`).
- The **only writes** to that slot are via the PIC thunk **0x31c20**:
  ```
  31c20: call   31d27
  31c25: add    $0x17c0c7,%ecx        ; ecx = 0x31c25+0x17c0c7 = 0x1ADCEC = GOT
  31c2b: mov    0x4(%esp),%eax        ; argument 1 (table pointer)
  31c2f: mov    %eax,0x22b0(%ecx)     ; *0x1AFF9C = table
  31c35: ret
  ```
- Callers of 0x31c20: exactly two sites - **0x12087f** and **0x1208a9**, both inside function **0x120830**. That function:
  - zeroes a 28-byte struct (rep stos, 0x1c dwords), calls **0x10c690** = `tee_get_security_info_struct@@Base` (exported symbol) with the struct address;
  - if `tee_get_security_info_struct` returns != 0 → fwrite error path (0x1208b0:	fwrite(26,1,stderr-ish stream @ −0x38(%ebx)) "…") then falls through to jump 0x120884 anyway;
  - if the returned struct's byte at +0x20 has **bit 0x20 set** (`testb $0x20,0x38(%esp)`; 0x38(%esp) = struct+0x20) → `lea 0xc60(%ebx),%eax` = **0x1AE94C**; call 31c20 → *0x1AFF9C = 0x1AE94C
  - else → `lea 0xc50(%ebx),%eax` = **0x1AE93C**; call 31c20 → *0x1AFF9C = 0x1AE93C
  - then re-reads `tee_get_security_info_struct`'s stored copy (word @−0x40(%ebx) slot0) and compares (allDagain); on mismatch `__stack_chk_fail`-style abort (0x1208dc call 2518d).
- 0x120830 is called exactly once, from the big oem-fastboot registration function **0x1195d0** at 0x119c87, with (edi, esi) = (0x1B67BC-ish scratch struct of 7×12 bytes built from the two string LUTs, esi = 0x144613 = the raw string bytes at GOT−0x696d9). This happens **after** all oem/oem-getvar/fastboot publications but **before** the boot flag walk (119c98 printing loop over the 7 entries' name/handler lines).
- **The two tables (32-bit, in .data, pre-relocated .data.rel.ro… actually they live in .data because they reference static function pointers):**
  - `0x1AE93C`: { **0x120cc0**, **0x120e50**, **0x120ec0**, **0x120e80** }  (primary / security_info.*.bit20 == 0)
  - `0x1AE94C`: { **0x120e50**, **0x120cc0**, **0x120ec0**, **0x120e80** }  (restricted / bit20 == 32: slots 0 and 1 are swapped)
- The 4 slot functions are `readonly` wrappers that push an int arg and call the common store:
  - 0x120cc0 → `call 31d27; add $0x8d025,%ecx; *(store@0x1B7B14) = arg` — with `cmovne`/`test` on arg:
    ```
    120cd5: mov  0x30(%esp),%eax     ; arg
    120cd9: test %eax,%eax
    120ce3: mov  $0x1,%eax
    120cdc: bswapl %eax
    120cee: mov  %eax,%esi           ; arg_secondary = arg!=0 ? 1 : 0
    120cf0: mov  %esi,0x8(%esp)
    120cf5: lea  0x18d632(%ebx),%eax ; 0x1B7B14
    120cfb: mov  %eax,0x4(%esp)
    120cff: mov  %eax,(%esp)
    120d02: call 31d2f
    ; ret = arg
    ```
    i.e. plain **"setter"**: stores arg into a module-level int (at 0x1B7B14).
  - 0x120e50:
    ```
    120e50: mov  0x30(%esp),%eax      ; arg
    120e59: test %eax,%eax
    120e5c: jne  120e80
    120e61: lea  0x1b7b18(%ebx),%eax
    120e67: mov  (%eax),%eax          ; load 0x1B7B18
    120e6c: test %eax,%eax
    ; cmp with 4 -> eax=4, eax-4 ; else 0 ;  store
    120e74: mov  %eax,0x1b7b20   ; 0x1B7B20
    ```
    a different setter target: 0x1B7B18/0x1B7B20 pair (value 4 or 0) - the **"audited"** group of the two.
  - 0x120ec0 / 0x120e80: same shape with third arg semantics.
- **Conclusion:** the ops "vtable" at 0x1AFF9C is not a struct of function pointers at all - it is a `struct DeviceStateOps { (*set_state)(new_state), (*get_state), (*is_unlocked_query), (*confirm) }` where each slot is a tiny PIC thunk writing/reading **two module ints**: 0x1B7B14 (the "primary / audited" cell, accessible when tee security struct bit0x20==0) and 0x1B7B18/0x1B7B20 (restricted cell). Slots +0 and +1 are swapped between the two tables depending on the tee_get_security_info_struct byte at +0x20 & 0x20.
- The hex 12980/10980 wrapped with `droidboot-refleven 2026-06-03 internal_119633`.

### What get_state/set_state actually persist

The 0x1B7B14 / 0x1B7B18 ints are only the *droidboot process* view. The byte that survives a reboot:

- **0x120980 / 0x120b40** = read/write of a **3-byte boot flag block at offset 0x1000 of a boot partition** looked up by name through **0x11bf60** (the same "partition name → volume" resolver used all over the oem/flash code); the partition name string used by 0x120980's call is at GOT−0x698ab = **0x144441… the string is "misc"** (see the constant listing below - two strings "misc" and the local 0x144441-value `0x69636d2f "/cmi"` fragment belong to the OSIP/OS strings).
  - read:  `open(path,0)`, `lseek(fd,0x1000,0)`, `read(fd,&buf,3)`; on any failure → printf "Failed to read bootloader flags on %s : %s", fp error "E:Failed to read bootloader flags", log "Failed to read bootloader flags" prop, **returns 1**.
  - The **3 bytes** it returns are the device-state bytes. `*(u8*)0x1B01F8`-adjacent global gets `buf[0]`, `buf[1]`, `buf[2]` per boot (the boot_audited flow caller at 0x120980's only caller, 0x11fd00/0x11ff0 area, is the "state deprompt" walker).
  - write (0x120b40): same but `open(path,1)` `lseek 0x1000` `write(fd,&three_bytes,3)`, error text "Failed to write bootloader flags on %s : %s" / "E:Failed to change bootloader flags" / log "Failed to change bootloader flags".
  - So **the device_state bits persist in the flag block sitting at partition offset 0x1000 of the "bootloader flags" partition (misc block, resolved via 0x11bf60)**. Only 3 bytes are ever touched (offsets 0x1000..0x1002), i.e. byte granularity 1/2/3 of that boot-flag sector.
- What the bytes mean is **read in the dispatch at 0x112870 (the `flash-all-depart` handler)**, which also decides which boot path applies (see the flash-all-depart section; and the reboot table at 0x119dc0's LUT: indices 0..6 = REBOOT_RECOVERY/BOOTLOADER/DNX/FASTBOOT/POWEROFF/UMIP/TOKEN, each mapping to a different boot location - the enum order in the binary is `[0x11cd10, 0x11c720, 0x11c780, 0x11e360, 0x11dc00, 0x11c660, 0x112ac0]`, and the LUT store at 0x119ea8+ writes the same ordinals).
- The "audited" counterparts (0x120cc0/0x120e50) bump a **nand block reference counter** at 0x1B01F8 (                 ) - `bswapl` + secondary flag ️0x1B7B18 vs 0x1B7B20. They correspond to the `droidboot-scratch` boot-audit hooks in the boot loader (`droidboot.scratch` cmdline param → 0x1B67BC path buffer; 0x30ea7 `strncpy(droidboot.scratch, argv, 0x400)` at 0x39716 with arg 2).

### Battery / charger front-end (context for boot decision)

- main (0x24be0) → argv parse loop 0x30c20 (0x30c24): splits `name=value` on '=' and only accepts `droidboot.*` names. Known params:
  - `droidboot.scratch` → 0x1B67BC (installer.cmd path; default "installer.cmd" copied to 0x1B67BC at 0x24cca)
  - `droidboot.minbatt` → 0x1B6730 (atoi, plug threshold)
  - `droidboot.autopart` → 0x1B67A0 (argv value; 1 = partition-EMMC re-init mode)
  - `droidboot.mountpart` → 0x1B67A4
  - `droidboot.installer_usb` → 0x1B67CD  (if set, selects a USB installer mode using 0x30d2b)
  - `droidboot.disablefbootui` → 0x1B67C0
- Battery gate (0x24cfa/0x24d81): `cmp 0x374(%ebx) (minbatt)` error msg "Verifying battery level >= %d%% before continuing"; on charger return 2 → "Battery level is acceptable"; on 1 → `android_reboot(0xdead0002, 0, 0)` at 0x24e0c (reboot-to-charger magic; Thunderbolt's own reboot). Also 17-pause klog: klog_init/klog_set_level(8) at 0x24d78 even before battery check.
- After the fastboot loop (0x28310→0x2d300) exits normally (0x24d30): `cmpl $0x1,0x370(%ebx)`:
  - `!= 1` (autopart not set): call 0x39990 = **clean fastboot shutdown UI** and `return 0` from main (**fastboot never exits normally on a real device** - it exits by rebooting).
  - `== 1` (droidboot.autopart=1 was parsed): `property_set("sys.partitioning","0")` at 0x24e20 - the Android ramdisk-side init (`on property:sys.partitioning=0` in the droidboot init.rc) runs `mount_all /fstab` so the kernel continues into Android; main returns.
- The autopart global is 0x1B67A0; the earlier 0x1B05FC attribution was incorrect. The "property_set sys.partitioning" happens **both** at main exit (0x24e20) and in the autopart path.

### Boot decision "stay in droidboot vs reboot out" (0x28310 command loop + 0x29730/0x29690)

- `fastboot reboot` handler = **0x29730**:
  ```
  29740: call 2e3f0 (fastboot OK ack "RESULT: OKAY" - yes, ack first!)
  2974e: sync
  2975c: printf "REBOOT..."
  29769: log "Restarting Droidboot..."    <- note: the reboot handler logs "Restarting Droidboot..."
  29787: android_reboot(0xdead0003, 0, "android")   ; 0x144a08
  ```
  So a plain `fastboot reboot` is just `android_reboot(...)` with `sys.powerctl`-less magic 0xdead0003; field **"android"** is passed as the *boot-mode selector* argument.
- `fastboot reboot-bootloader` handler = **0x29690**: ` имуществоdirecto` → `call 2e3f0` ack, `sync`, "REBOOT...", "Restarting Droidboot..." log, `android_reboot(0xdead0003, 0, "fastboot")` @0x296f8 - i.e. **droidboot reboots into itself** (magic 0xdead0003 + "fastboot" = restart into fastboot).
- `fastboot boot` = **0x29660** → "boot command stubbed on this platform!" (0x29670), nothing else. `continue` = **0x29de0** (AKA "the same 'Restarting Droidboot...' + flash boot ... not fully traced; it goes through the same 0x119dc0 reboot-table with REBOOT_FASTBOOT-like semantics).
- Second `reboot-bootloader`-shaped handler **0x112960** (registered again at 0x119c1d, min_state 0):
  `2e3f0 ack, sync, "REBOOT in BOOTLOADER...",, log "Rebooting in BOOTLOADER !", android_reboot(0xdead0003, 0, "bootloader")` - "bootloader" args not "fastboot". Which of the two registrations wins depends on list order (list head 0x1B6790, `fastboot_register` appends entries; dispatch presumably walks the list in order - 0x29690 was registered first (2b5a0 registration block runs before 1195d0's), so **0x29690 is the live "reboot-bootloader" command**, and 0x112960's registration is shadowed.)
- **0x119dc0** is the *reboot-by-enum* dispatcher used when something wants to schedule one of REBOOT_RECOVERY / REBOOT_BOOTLOADER / REBOOT_DNX / REBOOT_FASTBOOT / REBOOT_POWEROFF / REBOOT_UMIP / REBOOT_TOKEN (0..6): `sscanf("%d")` of the target state index (`mov 0x4(%esp),%edx` earlier), then leaps into LUT `lea -0x90fdc(%ebx)[idx*8]` = one of {0x11cd10, 0x11c720, 0x11c780, 0x11e360, 0x11dc00, 0x11c660, 0x112ac0}. The reboot handlers seen in both fastboot and oem reboot handlers all funnel into that table via it (0x119d80 is the same-family walker but for strings).

### The ops table writes it depends on (0x1AE938 area)

`0x1AE938`… area of .data around the two tables also holds other one-shot flags:
- 0x1AE938 (unused here) = ?
- `0x1AE93C` / `0x1AE94C` tables above.
- nothing else writes 0x1AFF9C anywhere in the binary (grep for `0x22b0(\(%erb\))` shows the one writer at 0x31c2f and 4 readers at 0x31c50/0x31c95/0x31cc5/0x31cf0).

*Also note:* the string served for the "misc" lookup in 0x120980 is a **local letter-composite** (0x12(%esp)-style direct-store of "/misc"-ish bytewise constants), not a rodata reference - typical compiler inlining of a short string literal.

---

## State enum + transitions (incl. from oem handlers)

### State values

- 0 = **locked**, 2 = **unlocked** (bit-1 encoded). This is confirmed end to end:
  - `state` getvar getter **0x310d0**:
    ```
    310e0: call 31c80        ; get_state()
    310e5: test %eax,%eax
    310e7: je  → return "locked"
    310ef: cmp $0x2,%eax
    310f2: jne 310f8 ; return "unlocked"
    310f8: jne 31108; call 2fb00 (panic/fatal "unknown state")
    ```
  - The *flashing state-change* handler **0x31380** compares current (31c80) against `0xc0(%esp)=target` and handles `cmp $0x2,%esi / je 31428` for target 2 vs anything else = lock path.
  - The audited set_state fallback (swapped slot 0x120e50) at 0x120cd9 `test %eax,%eax / cmovne 1` rejects arg==0 (asserts non-zero state written) and stores a boolean; the opposite wrapper 0x120cc0 reads at most 3 bytes from the flags block.
- **Value 1 never appears as a *device_state* state** in this build's code paths - no code path writes 1 to the flags byte, no comparison against 1. (0x1 is used as *return code* meaning "failed" in the 0x120cc0 read path and as the success flag e.g. `0x1214(%ebx)` in the flash handler.) So the state machine is effectively **{0 locked, 2 unlocked}**; if a 1 ever lands in the misc@0x1000 byte, `flash` (state != 0 && != 2 comparisons) treats it as neither (comparisons 31c80: !=0 → 2 check - value 1 falls into "not 0, not 2" → panic at 0x31108 on getvar `device_state`; handlers using `cmp $0x2` treat it as locked/non-unlocked).
- On the **wire** (getvar):
  - `getvar:unlocked`  → getter 0x31120 (published at 0x31beb): `test eax; je → eax=0x68435(%ebx)=0x1458b4; strncat arg` - 0x1458b4/0x1458b7 are the two localized strings for "no"/"yes" (published value).
  - `getvar:state` → 0x310d0 ("locked"/"unlocked", published as `device_state` at 0x31c0b with format 0x145a99 "device_state" - actually this is the **`flashing get_state` / getvar state** pair).

### Who transitions state

- **Only the `flashing` dispatcher's state-change sub-handler 0x31380** (and its audited twin through the swapped slot) changes state, via:
  1. `31c80` current; cmp target; equal → 0x31528 (nothing to do, "OKAY" path after 0x2af00 UI reset);
  2. `== 2` → 0x31428 unlock branch, `!=` (0 / other) → lock branch at 0x313c6:

     313c6: `mov %esi,%eax; movzbl %al → arg1` ; call **31ce0** (ops+0xc confirm) - for the *restricted* table 0x1AE94C that slot is **0x120e50**, which requires arg != 0 and returns −1 if the confirm fn ALSO missing (`mov 0xc(%edx),%edx; test %edx,%edx; je 31d20` → −1). So confirmations ONLY fire on the table where the conf slot exists;
     313e1: call **31c40** (ops+0 set_state);
     313e9 test; jne → 0x31610 (failed) ;
     313f1: call 31c80 again, cmp == target → 313fe `call 2af00` = a UI re-render (0x2af00 → 0x396e0 reset), then return the (new) state.
  3. The confirm branch 0x313c6 is preceded by **external double-verification** at 0x313c1 (`cmp $0x2,%esi`) - 2 skips the confirm call and lands at 0x31428 directly, which is the unlock quick-path (state-changing UI confirm skipped for unlock when the ops table says so).
- **No oem handler changes the state directly.** Checked all 19 min_state=2 oem handlers plus the 1xx oem-register block: none reference the thunks 0x31c40/0x31c80/0x31ce0 or the raw 0x1B7B14/0x1B7B18 cells; the oem "stop/start_partitioning" pair (0x111500 / 0x1114b0) only touch `sys.partitioning`. State change from oem land is **impossible** without going through `flashing unlock/lock`.
- The `sofia_support` override (`fastboot getvar sofia_support` sets 0x1B01FC=1) makes `get_state()` (0x31c80's caller sites in the 0x2d8a4 min_state gate) succeed with any min_state - that's the only "bypass" lever, and it lives in`getvar`.

### Boot decisions / reboots from the oem-reboot family

- oem sub-reboots: `oem reboot-bootloader`-ish handlers at 0x112870/0x112960/0x112a80 (`android_reboot(0xdead0003, "boot…" | "bootoneshot" | …)`), and the `flash_all_*` partners (0x11e9d0/0x11ea90) set **0x6f14/0x6f18/0x6f1c/0x6f20/0x6f28/0x6f2c/0x6f30(%ebx)** scratch booleans which only `flash_all_end`'s boot-postprocess (0x11ec52 ff., moves BOM_TOKEN first if missing, else IFWI…) and the 1201d0-oflash-all tail (0x120219: `mov 0x6f30(%ebx),%ecx; test %ecx,%ecx; je 1203f0 => the gzip-writer path is skipped unless flash_all_end marked it`) consult. 0x6f2c is the **single-shot streamed-zlib "we already primed" flag** (0x120533/0x1204c6). 0x6f30 == "fastboot flash on-depart" flag that the depart_gz writer (0x120570) checks before priming gzip (12058c→120690).
- The OSIP "boot" list (0x11c850 boot / 0x11c890 recovery / 0x11c780 recovery_sign / 0x11c7e0 boot sign / 0x11cd10 droidboot ... / 0x11cc80 droidboot_sign / 0x11c420-0x11cCA splash 0..4) is where the **boot partition list** (boot/recovery/droidboot/silentlake/…OSIP targets) is maintained; `reboot` builds from 0x119e50 (`"recovery"` vs `"bootloader"` vs `… 8-byte strings`) and its callers (0x119dc0 reboot-table + 0x119ee0 boot_sign / 0x119ec0 recovery_sign / 0x119f00) write to the OSIP boot **slot list**, not to GPT.

---

## Per-oem-handler summaries

Registration blocks (per analyze walk of every `call 2b090/2af20`):

| segment | handler | min_state |
|---|---|---|
| backup_factory | 0x1144d0 | 2 |
| restore_factory | 0x114770 | 2 |
| backup_config | 0x114620 | 2 |
| restore_config | 0x114390 | 2 |
| debricking | 0x113930 | 2 |
| pre-flash | 0x112bb0 | 2 |
| partition | 0x115680 | 2 |
| pre-flash2 | 0x118cf0 | 2 |
| repart | 0x114050 | 2 |
| media | 0x114120 | 2 |
| emmc_resize | 0x113de0 | 2 |
| emmc_data_read | 0x112ca0 | 2 |
| pos_logging | 0x113cf0 | 2 |
| adb_enable | 0x113b50 | 2 |
| pre_sending | 0x113850 | 2 |
| start_update | 0x118f10 | 2 |
| dnx_timeout | 0x1131e0 | 2 |
| custom_boot | 0x113090 | 2 |
| erase_token | 0x112ac0 | 0 |
| erase_osip_header | 0x11ae40 | 2 |
| start_partitioning | 0x1114b0 | 2 |
| retrieve_partitions | 0x1118b0 | 2 |
| stop_partitioning | 0x111500 | 0 |
| get_batt_info | 0x112fd0 | 0 |
| get-spid | 0x121280 | 0 |
| get-fru | 0x1213c0 | 0 |
| get-part-id | 0x121970 | 0 |
| get-lifetime | 0x121000 | 0 |
| get-sec-info | 0x121b90 | 0 |
| get-mfg-status | 0x121cd0 | 0 |
| set-mfg-status | 0x121d70 | 0 |
| start-update | 0x1211c0 | 0 |
| cancel-update | 0x121200 | 0 |
| finalize-update | 0x121240 | 0 |
| remove-token | 0x121ab0 | 0 |
| token | 0x121a40 | 0 |
| reboot-bootloader | 0x112960 | 0 |
| (2nd reboot-bootloader) | 0x112870 | 0 |
| data | 0x118d90 | 0 |
| testos | 0x11ca50 | 0 |
| boot2 | 0x11c850 | 0 |
| recovery | 0x11c890 | 0 |
| bootloader | 0x119f20 | 0 |
| (14eae1) | 0x11ca10 | 0 |
| silentlake | 0x11c9d0 | 0 |
| splashscreen | 0x11c910 | 0 |
| splashscreen1 | 0x11c950 | 0 |
| splashscreen2 | 0x11c990 | 0 |
| splashscreen3 | 0x11cc80 | 0 |
| splashscreen4 | 0x11c720 | 0 |
| ifwi | 0x11c780 | 0 |
| fastboot2 | 0x11e360 | 0 |
| capsule | 0x11dc00 | 0 |
| ulpmc | 0x11c660 | 0 |
| esp_update | 0x112b40 | 0 |
| token_umip | 0x14d8c2 | 0 |
| flash_all_start | 0x11e9d0 | 2 |
| flash_all_end | 0x11ea90 | 2 |
| Package_Header | 0x11e3c0 | 2 |
| all_sep | 0x11fe20 | 2 |
| depart_gz | 0x120570 | 2 |

Per-handler walk (all min_state=2 unless noted):

- **adb_enable 0x113b50** (min 2): `int enable = atoi(args[0])`; writes system property `persist.sys.usb…` (0x1AE938-ish constant: `"UWVS"`; the fprintf format rhyme in the block) — toggles the helper-daemon flag consumed by the droidboot ramdisk `on property` trigger so `adbd` starts/stops. Does not touch state.
- **pos_logging 0x113cf0** (min 2): forwards to **0x113760**-family POS-log-on/off writer: logtool "cp -r" property (`set-mfg-status`-like 0x2900 area); toggles enable bit used by `erasePagain`.
- **pre_sending 0x113850** (min 2): `oem pre_sending [0|1]` — flips the "we already pre-sent" scratch used by getvar `battery-voltage`/`get_batt_info` path 0x112f70 (also duplicate handler 0x113760 registered at 0x119a2e with name 0x14ebd4 "battery-voltage").
- **backup_factory 0x1144d0 / backup_config 0x114620** (min 2):
  - mount the factory (/factory) or config (/config) volume (`call 27620` with "/factory"/"/config" string at 0x11435a/0x114684), then `property_get("sys.backup_factory"|"sys.backup_config")` == "done" (0x114dir 0x5fcd7) else:
  - `property_set(prop, "backup")` + "%s backup failed"→"Failed to backup Factory partition" error path; then **spin up to 60 iterations of `sleep(1); property_get(...) == "done"`**; timeout → error "Factory partition backing up failed!".
  - Real mover is the **droidboot ramdisk init.rc**, hot-bound by the property trigger:
    ```
    on property:sys.backup_factory=backup
        mkdir /tmp/factory
        start factory2tmp          # /system/bin/cp -a /factory /tmp
    on property:init.svc.factory2tmp=stopped
        setprop sys.backup_factory done
    ```
  - So the actual factory-partition backupd is `/system/bin/cp -a /factory /tmp` run by droidboot's init.
- **restore_factory 0x114770 / restore_config 0x114390** (min 2): symmetric: requires `sys.backup_* == "done"` first; sets "restore" → `service tmp2factory /system/bin/cp -a /tmp/factory /` (init.rc 0x1147d2) waits for "done" again.
- **retrieve_partitions 0x1118b0** (min 2): re-fetch the OSIP partition.tbl into /dev/block/mmcblk0; calls **0x128340(gptcmd, 3, args)** ("boot %s %s" printf) with an argv table and 0x129100("reload %s", 2, argv) — the `reload` of the gptcmd subcommand sets (`test %esi,%esi; je` error "gpt boot/reload command failed" → `error(11bdf0)`).
- **stop_partitioning 0x111500** (min 0): calls **0x259f0("/factory")** (grep "factory" in partition list & set flag) → then `property_set("sys.partitioning","0")` (0x111531) + "Stop partitioning" printf. **Does not change device state.**
- **start_partitioning 0x1114b0** (min 2): `property_set("sys.partitioning","1")`, "Start partitioning" log, then `call *0x9c4(%ebx)` = 0x121000-ish direct call of the **GPT-repartition callback** (0x121000 get-lifetime? no — slot 0x9c4 = the "osip partition scan" pointer set by the same registration family; value = 0x121000's wrapper). Behind the gate it does NOT write partitions itself - the actual GPT/format work is in the callback target registered at boot (0x9c4 slot).
- **emmc_resize 0x113de0** (min 2): prints `emmc_resize [long long int] argc %d , argv %s, %llu`; parses `strtoull` of bytes/sectors, checks `&0x1ff`, opens **/etc/partition.tbl**, `malloc` filesize, `read` all, `call 28220` (OSIP GPT writer prep), `call 265e0(gptCmd, args)` = the volume-repartition engine, then prints "finish" + the "emmc resize" number.
- **emmc_data_read 0x112ca0** (min 2): opens **/dev/block/mmcblk0**, `lseek(offset)` where offset%E 8-validated (`test $0x1ff,%eax; jne err`), reads in 0x80000 (512KiB) chunks and **streams the raw bytes back** to the host (`call 2f990` per chunk = fastboot queue/data handler); never writes.
- **erase_osip_header 0x11ae40** (min 2): 0x38 Hort "oem erase_osip_header: erase OSIP header + %s args"; invokes the OSIP header zap with the arg list (count 8); "Fail"→"Fail to erase".
- **dnx_timeout 0x1131e0** (min 2): sets `DNX timeout` (dword write: `dnx_timeout = atoi(arg)` → dnx boot-timeout used by the reboot-into-dnx path (0x11c9d0's "dnx timeout %" log); also boosts into the reboot table parse: the reboot-enum table worms the dnx_timeout value through 0x119dc0's LUT (idx 2).
- **custom_boot 0x113090** (min 2): `oem custom_boot <0x16|0x22 hex arg>`: `strtoul` and array bounds (>0x14 reject "Parameter size exceeds limit"); accepted values **0x16 or 0x22** (`cmp $0x22 / cmp $0x16 / je 1131c0`); then `call 11c600(4, &var)` = **write UMIP entry** (0x11c600 = the "write_umip" helper, the same one 0x113090's name suggests) then `call 2e3f0` (fastboot "OKAY"/RESULT ack). So custom_boot pokes the Intel **UMIP** with a custom-boot flag.
- **start_update 0x118f10** (min 2): the OTA flow entry: mounts /data (`27620 /data`), builds `mkdir /data/fastboot_appd /data/fastboot_appd.tmp` strings inline and `system()`s them (0x118f78/0x118ff3 `call 23f50 <system@plt>`), i.e. "flash /data then fastboot_appd" plumbing; continues into `oem start-update` playing `flash_all_start`-partner state (0x6f14/0x6f18 flags) with "%s. Wait for this: %s" strings.
- **flash_all_start 0x11e9d0** (min 2): probes (`15c70` etc.) the platform: `call 11d430(&pid)` (get_project_id: fopen("/sys/module/intel_mid/parameters/project_id", fscanf "%d")), `call 11d630(&hwid)` (hardware_id param), `call 11d700()` = `ifp_manuf_sts_bit_get@@Base` (manufacturing-status bit, "sts_value = %i ret = %d"); stores: 0x6f20 = spid-like product byte; 0x6f1c = `(spid!=1)? (1<<(ch)) : 0`?? (movzbl result; here: "cmp 0x1,%eax; jbe" returns 0, else `1<<(cb)`); 0x6f28 = the manufacturing bit; error strings "Get project id fail"/"Get hardware id fail".
- **flash_all_end 0x11ea90** (min 2): the post-flash-all settle: prints "We find : %s" (vol name); if 0x6f28==0 (not manufacturing device) → `xor %eax,%eax; rep stos 0x20` (zero 0x80 bytes for "BOM_TOKEN") and compares found name with "BOM_TOKEN" vs "IFWI": mismatch → "BOM_TOKEN and IFWI mismatch" log + −1; if IFWI missing → "Flash IFWI ..." (0x11eafd) `call 11cc80(0x6dd8,%ebx,…)` = flash IFWI into the OSIP burn window; for BOM_TOKEN → `call 121a40` (flash BOM_TOKEN). When the file was **`ro.build.type`-=="eng"** (`lea -0x67be1; repz cmpsb 3` = "u s e r"-factory string, 11eb61) it **erases userdata and cache via call 2a6c0(0, "userdata"/"cache")**, and if the `0x47a0` debricking-scratch flag ==1 **also runs 1158a0** (`Erase debricking file failed!` on failure). So **`oem flash_all_end` = flash IFWI/BOM_TOKEN + POST- Settle, which for eng builds wipes data/cache and clears the debricking file**.
- **pre-flash 0x112bb0** (min 2): reads `ro.serialno` into local, calls **0x11d830(serial, len, arg)** = the FRP-signature verify engine; if the FRP signature verify differs on locked devices → "FRP signature verify fail!" (error) and refuses; else "FRP signature verify pass!" then "Start to erase persistent partition!" → **0x2b370("data")/0x2b370("cache")-style erase** in the pre-flash pass (this is the get-unlock path's data wipe). I.e. **pre-flash only runs once the FRP signature verifies (on the per-device `ro.serialno`-keyed signature)**, and then it erases persistent/userdata partitions.
- **partition 0x115680** (min 2): prints "Format factory partition ! / Format spare partition ! / Format config partition !" trio (0x26d90/0x26e1f/0x26e62 printf in func 0x158560? no — these are inside 0x26c68-0x26e8b: the partition table "factory/spare/config" subblock) - it is the **schtzb partition-tbl cache** (0x26c68+ walk): `strstr(name,"factory")` → "Format factory partition !", strstr("spare") → "Format spare partition !", strstr("config") → "Format config partition !" and each hits `call 25cd0` ("repartition_flag = %d" print in 0x25cd0 then volume erase).
- **repart 0x114050** (min 2): reads partition.tbl-style: open("/etc/partition.tbl"), lseek 0, SEEK_END dance; same family as **emmc_resize** without the 512-alignment: the "write_umip" (0x11c600) called with 4; ends with "E:Update partition fail" if 27a60(27a60 = GPT writer) reports failure, then property_set "sys.partitioning" → "Start partitioning"/"Stop partitioning and updated", and call 28220 / 26a70 (GPT flush) - so **repart = the GPT rewrite path (writes partition.tbl into the GPT)**, followed by 26b60 "Format partition failed" on format errors.
- **media 0x114120** (min 2): `oem media <…>` — "get averages me…" (the `oem media_*` in AOSP); chooses the "media" boot target: writes back into 0x9c4 (%ebx) = the GPT-repartition/OSIP-media callback, then calls `28220`/`26a70` pair like repart.
- **debricking 0x113930** (min 2): **0x1139a4 `movl $0x6,…; mov %eax,0x8(%esp); __android_log_print(0, "debricking", …)`; then `lea 0x47a0(%ebx),%eax / movl $0x2,(%eax)`** = sets the global debricking-scratch flag to 2; mounts /cache (`27620("/cache")`), then open("/cache/debricking", O_CREAT|O_WRONLY, 0644) at 0x1139de and writes the marker string (the same 0x58-byte "WillCreate0711ThisDebricking" ASCII seen in 0x35c9e). The **`0x47a0` flag is checked all over flash-level code** (11e63e, 114e19, 115414, 11646c, 1180d4, 118e69, 119259, 11e63e, 11e8e4, 11eb73, 11ecc2): when set (1 or 2) the flash/erase paths can skip signature/debrick checks (observed at 11e63e: `mov 0x47a0, %eax; sub $1; cmp $1; jbe 11e8f0` - so 0x47a0∈{1,2} skips verifications) - i.e. **`oem debricking <n>` is the "accept unsigned images" switch** (and flash_all_end clears /cache/debricking when it saw it).
- **get-spid 0x121280** (min 0): `movl $0xc, 8(esp)` = `printf("%12s")`-style; does `snprintf(... 12 bytes ...)` then spid string to host. All of 0x121x get-* series: 0x121000 get-lifetime (arg "%s lifetimetime…"), 0x121970 get-part-id (built as 0x8-byte), 0x121b90 get-sec-info (`1` "get-sec-info…"), 0x121cd0 get-mfg-status (−1 arg = "ffffffff" and "oem get-mfg-status [tbd]"), 0x121d70 set-mfg-status. All are simple **key-printers that end host-side**: they read the "Intel provisioning" blobs from the OSIP/UMIP and print them.
- **start-update 0x1211c0 / cancel-update 0x121200 / finalize-update 0x121240** (min 0): `arg` sanity (`cmpl $1`) then the "OEM fastboot update state machine register": these write the same **metadata struct** that start_update 0x118f10 consumes (through `.data` at 0x9c0 (%ebx), a scratch buffer used by `flashing start`); they touch no partitions.
- **remove-token 0x121ab0 / token 0x121a40** (min 0): `oem token`-engine: "get/remove token" printer family: token writes a 0x… token string to the host using its `0x121280`+0x8-is arg pair.
- **(14eae1) 0x11ca10 / boot 0x11c850 / recovery 0x11c890 / bootloader 0x119f20 / silentlake 0x11c9d0 / splashscreen … / ifwi 0x11c780 / fastboot 0x11e360 / capsule 0x11dc00 / ulpmc 0x11c660 / esp_update 0x112b40 / token_umip 0x14d8c2** (all min-state 0, the "OSIP-partition flasher oem commands"): each is the **`oem flash_<name>` (32 OSIP-class subcommands)** for the OSIP boot-device list. boot2/recovery are the OSIP flash helpers.
- **erase_token 0x112ac0** (min 0): both an oem and the reboot-table entry (idx 6): erases the token.

The 0x121xxx OEM get-* handlers return provisioning data; the separate erase-token handler is listed above.

### Which oem handlers can change device state = none

Every oem handler settles into: pure reads (get-*), property triggers (`sys.partitioning`, `sys.backup_*`, USB/adbd toggles), partition-table writes (repart/emmc_resize/…), or the OSIP boot-list flash helpers. **None call set_state (0x31c40) or the 0x1AFF9C ops** - the only state transition is `fastboot flashing unlock/lock` (0x31380). No oem command can lock/unlock the device.

### Who writes partitions while state==0 (locked)

Nothing in the oem table: all partition-writing oem handlers are min_state 2 except **stop_partitioning** (which only mounts /factory + sets a property) and **erase_token** (OSIP token). The wear-leveling/`restore_config`/`backup_factory` etc are all min_state 2. (In the 0x119d30-119d6d block there IS one extra pair registered with min_state 2 in the dnx/custom_boot group - dnx_timeout + custom_boot.)

---

## Reboot/boot-decision flow + bootloader-erase guards

### Main flow (recap with addresses)

- `main` 0x24be0 → 0x2b5a0 fastboot registration → call 0x1195d0 (oem registrations; **calls 0x120830 at 0x119c87** to pick the ops table) → call `tee_get_security_info_struct` etc → UI init 0x396c0/0x396e0, battery gate 0x24cfa.. (`droidboot.minbatt` check; when charger returns 1 → `android_reboot(0xdead0002, 0, 0)` = **restart to charger/Android**; 2 → OK), `property_set("sys.usb.config","none")`, fastboot loop **0x28310 → 0x2d300**.
- On fastboot loop exit: 0x24d36 `cmpl $0x1,0x370(%ebx)`: if not 1 → call 0x39990 (quiet exit); else `property_set("sys.partitioning","0")` at 0x24e20 (the Android mount_all trigger), then main returns (kernel continues booting).

### `fastboot erase` and "Bootloader must not be locked"

- erase handler **0x2a6c0** (`erase:` registration string at 0x2b64e). Sequence:
  - `snprintf(buf, 0x32, "-0x69aa8", name)` then strcmp "cache": if **`flashing_unlock_in_progress` (0x479c (%ebx)) == 1** → call 0x27620 (mount /cache) and write 59-byte "…" log (LogTool-POS marker) + `property_set("logtool.pos.logging","0")` + `system("cp -r /cache/logtool /tmp/")`.
  - `call 31150` (getvar `device_state` class) - `test eax; jne` → "erase can only run in bootloader mode"?? (0x2a988 = `lea 0x144cd3 "bootloader must not be locked"` **is inside the block that runs when the pre-erase getvar/marker check failed**). Concretely `2a6c0`'s flow is:
    ```
    2a738: call 31150 (0x1214 helper)
    2a73f: jne 2a74f …
    2a741: mov 0x1214(%ebx),%eax ; test ; je 2a968 → call property_set path
    2a74f: call 31170
    2a754: test ; jne 2a76f
    2a75c: strcmp  "misc" → je 2a9a0 (call 120d60) ...
    2a9a0: (misc) call 120d60 (osip boot flag hook)
    ```
    and the *erase* path proper:
    ```
    2a7a0: snprintf(… 0x69aa8 (%ebx) → /dev/block/…)
    2a7bb: call 258d0 (partition vol by name) → je 2ab13
    2a7ca: open(vol->path, O_RDWR…) 2a7f0 ioctl(BLKDISCARD 0x127d?) / 0x127d = discard-range ioctl:
    2a830: ioctl(fd, 0x127d, &range{start=0,len=size})   ; range discard
    2a852: close, printf "ERASE %s COMPLETE."
    2a87d: (if name=="misc") call 120d90 again (boot flag re-sync)
    2a894: (if name=="cache" && 0x479c==1) write the logtool prop and cp
    2a8b4: test %ebp,%ebp ; jne 2a900 (fail)
    2a8b8: call 2e3f0 (fastboot OKAY ack)
    2a8c6: … "misc" postfix call 120d90, then loop
    2a988: lea 0x144cd3 "bootloader must not be locked"; call 2d110 (fastboot_fail)
    ```
    **The 0x2a988 site fires when the preeraseLock flag chain fails**: `call 31150` returns non-zero (state-related check inside 0x31150 = the "flashing never from state" probe of `0x1214(%ebx)`), i.e. the erase was refused because the bootloader/OSIP was locked. So **fastboot/bootloader partition erase is blocked in state 0 with the "bootloader must not be locked" message**, and the erase (`ioctl BLKDISCARD` on /dev/block/...) otherwise completes silently.
  - The **flash** handler **0x2ab60** has the same `_sign` concepts: guard `0x1214(%ebx)` (an "is unlocked" bool) and `hashmapGet(<download_buffer>)`; "E:Unable to get volume for %s", "not allowed to flash this partition" (0x2ae90), "Bootloader must not be locked" (0x2aea3) for the flash path.
  - `asus_internal_unlock %d` is printed 0x2abf6 with the same `0x1214` value (so 0x1214 = the ASUS "internal unlock granted" flag set by the `asus_internal_unlock` oem).
- The **fastboot flash `fastboot`/`bootloader` partition** in state 2 (unlocked) runs the exact same BLKDISCARD+write path as any other partition - the guards only reject in state 0. In the live PGDO device (state 2) `fastboot erase fastboot` would succeed on the boot-loader block device.

### Boot decisions / reboot reasons

- 0x119e50 and its `boot`/`recovery` OSIP-slot writer family (0x119e90/0x119eb0 series; "boot_sign"/"recovery_sign"/"droidboot_sign" variants call into 0x11c780/0x11c7e0/0x11c850/0x11c890/0x11c9d0/0x11cc80) are used to **re-write the OSIP slot** the ROM boots from, not to `reboot` per se.
- The reboot table at 0x119dc0 enumerates only DATA-modes: REBOOT_RECOVERY/BOOTLOADER/DNX/FASTBOOT/POWEROFF/UMIP/TOKEN via `android_reboot(0xdead0003, 0, "<balloon-name>")`; a `fastboot reboot` (0x29730) and `reboot-bootloader` (0x29690) funnel there too.
- The boot path (0x28310) when leaving normally writes sys.partitioning="0" and returns - the actual leave-to-Android happens because droidboot never returns in `fastboot reboot` - android_reboot is a direct kernel reboot (bionic), no init dependency.

---

## UI confirm flow (0x31190 + 0x317b0 + 0x318b0)

- `flashing unlock/lock 0x31380` (state-change handler):
  - same-`state` shortcut at 0x313b9 (`cmp %eax,%esi; je 31528`).
  - unlock (target==2) vs lock branch at 0x313c1 (`cmp $0x2`), both end at **0x313c9 `call 31ce0`** = ops+0xc `confirm`, which for the primary table is a stub returning arg!=0 (no UI!). The real UI confirmation lives in the caller family: 0x31190 **is** invoked:
    ```
    311a3: lea 0x394(%ebx),%edi      ; menu title ptr A = "**** Unlock bootloader? ****" path
    311b5: cmp $0x2,%eax
    311b8: lea 0x3d4(%ebx),%edi      ; menu title ptr B (lock prompt)
    311be: cmovne %eax, 0x0
    311c6: test %dl,%dl ; jne 31224  ; the "already done" bypass    311dc: lea 0x1254(%ebx),%eax; movl $0x0,(%eax)
    311f2: call 3ad70   (ui banner unlock: pthread_mutex_lock/unlock around 0x509c, resets 0x4c54 = key-avail flag)
    311f7: movl $0x1,0x8(%esp)
    31203: mov %edi,(%esp)   ; title
    3120a: call 3bbf0    ; ui_set_prompt(items dict) - installs the menu UI  (Yes: Change device state / No: Cancel)
    ```
    then **0x31258** = `printf("Please confirm the device state action using the UI.")` and the key loop:
    ```
    31271: call 3acd0 (ui_getkey: pthread_cond_wait on (mutex 0x509c, cond 0x50a8), returns key code or -1)
    31294: cmp $0x6c,%esi (L / KEY_DOWN 108) → select; jg 312f0
    312a6: cmp $0x67,%esi (g KEY_UP 103)  → select
    312f0: cmp $0x73 (VOL_DOWN 115) ; $0x74 (KEY_POWER 116); $0x72 (VOL_UP 114):
        - UP (103) / VOL_UP (114? 0x72) → 31318 select = (select-1)&1 (pair swap)
        - DOWN (108)/VOL_DN   → 31303 select = (select+1)&1
        - POWER/ENTER-ish (0x74=116)  → 31338 (confirm choice)
    312b0: jne 31271   ; -1 → 312b2 "device state prompt timed out" → set 0x1254 flag & return
    31338: test %edi,%edi ; je 31213 → selected = 0 ≠ confirm → cancel path (31213 set 0x1254 flag + 3bc70 ui_reset then erase)
    ```
    - The actual "yes"/"no" mapping sits at title ptr A/B (0x1B20xx/0x1B20x8): strings at 0x145ae2 = `"**** Unlock bootloader? ****"` and 0x153c30/0x153c68 = `Please confirm…`/`device state prompt timed out`. The listed items are `"Yes: Change device state"` (0x145? no - 0x145??) and `"No: Cancel"`.
    - After selection: the call at **0x31224** runs the "userdata erase required…" branch (`"Userdata erase required, this can take a while…"` string 0x5a064) and then **2b370("data") / erase userdata + cache via `oem` erase / pre-fetch…** flow (0x3124d confirmed the "couldn't erase data partition" error die path). So the whole device-state confirm = **UI menu (0x3bbf0 + 0x3ad70/0x3acd0 key loop) + data wipe (2a6c0("data") + 2a6c0("cache"))**.
- **ro.debuggable=1 skip confirm**: 0x317b0 (pre-check invoked 0x31380):
  ```
  31808: call property_get("ro.debuggable", local)
  31816: lea 0x68f82(%ebx)  ; "1"
  31823: setne %dl    ; xor! (%eax result)
  ; cmp word "unlock" / "lock" to name args
  31845: test %eax,%eax ; je 31890 → movl $0x2 → (the "unlock" branch arg1 = 2) ret
  31865: jne 318a0 → $0xffffffff
  ; on cmp $0x2 became cmov_ etc.
  ```
  and the actual **skip-the-prompt** trick: the first arg (arg1) is forced to 2 when `ro.debuggable=="1"`, and 2 skips the `ops +0xc` call (`cmp $0x2,%esi → jump 0x31428` unlock quick-path), i.e. **the prompt is entirely skipped with ro.debuggable=1**; the related prompt-skip branch is at 0x317b0.
- **`Unlock is disabled.` / `The device can be unlocked.`** strings live in the FRP gate **0x318b0** (`"The device can be unlocked."` @0x145b47, `"Unlock is disabled."` @0x145b53 in the code at 0x319ce/0x319d7):
  ```
  318f0: property_get("ro.frp.pst")
  31900: open(FRP persistent path, 0)
  3191b: lseek(fd, -1, SEEK_END) → 1-byte tail read
  3193c: call 10c940 (tee check: is_unlocked frp byte) ; 0xcab13001 = policy undefined → allow "No tee-policy defined yet. Allow as work-around"
  319e0: read the FRP persistent byte
  31a05: cmpb $0x1 → "The device can be unlocked." ; else "Unlock is disabled." (+ "To enable it, go in the Android Developer Options menu" / "and activate 'Enable OEM Unlock'.")
  ```
  These messages belong to the **flashing get_unlock_ability** path. It's printed by fastboot_fail (0x2cfb0) calls here, so it's the **`flashing get_unlock_ability` command path** (or `getvar` of the same), driven by the FRP byte + tee policy.
- Where the prompt is drawn: **framebuffer/`droidboot UI` engine** (0x396c0/0x396e0 + the menu/theme functions 0x3bbf0/0x3bc70/0x3ac80/0x3acd0 with their vtable slots at ebx+0x598/0x5a4) with input from **0x10d940** = epoll thread over `/dev/input/event*` (`opendir("/dev/input")`, `openat(dirfd, name)`, `ioctl(…,0x80044520)` = EVIOCGBIT(0,..)`-style device-feature check, key events fed to the ring buffer the 0x3acd0 wait consumes). UI threads started by `pthread_create` at 0x39a20.

---

## startftm + hidden commands + full getvar surface

- **No FTM**: exhaustive `grep -i ftm/startftm` over `strings.txt` and `droidboot.asm` returns **nothing**. The Intel `oem startftm` facility (factory test mode) does **not** exist in this WW_5.5.1 binary; the closest factory hooks are the `oem debricking`/`oem flash_all_*`/`back_up factory` trio above.
- All **fastboot_register** call sites (0x2cf00) in the binary = **12 sites**, all inside two functions:

  In 0x2b5a0 (`fastboot publish/init`):
  1. 0x2b5d4  name=0x144e8c  handler=**0x29b60**  (oem dispatcher, min 0)
  2. 0x2b5f4  name="boot"      handler=**0x29660**  (stub)
  3. 0x2b60e  name="reboot"    handler=**0x29730**
  4. 0x2b62e  name="reboot-bootloader" handler=**0x29690**
  5. 0x2b64e  name="erase:"    handler=**0x2a6c0**  (min 2)
  6. 0x2b66e  name="flash:"    handler=**0x2ab60**  (min 2)
  7. 0x2b68e  name="continue"  handler=**0x29de0**  (min 2)
  8. 0x2b6ae  name="flashing"  handler=**0x2cfb0**

  In 0x1195d0 (oem init tail):
  9.  0x119bfc name="getvar" handler=**0x121a40**   (oem token - named "token" per 0x14ec71)
  10. 0x119c10 name="continue" handler=**0x121a40's tail?** (registered name repeated: name=0x144eb7 "continue")
  11. 0x119c30 name="reboot-bootloader" handler=**0x112960** (arbiter sees 0x29690 first)
  12. 0x119c4e name="data" handler=**0x112870** (min_state **2**)

  So the complete *fastboot-level command set* = {oem, boot, reboot, reboot-bootloader, erase:, flash:, continue, flashing, token(?), data, plus the duplicate reboot-bootloader}. The odd "token"/"data" registrations (9-12) are Intel-specific extra commands whose handlers are the OSIP boot-data/token pump; "continue"-(dup) and "reboot-bootloader" are duplicates of earlier ones.

- **oem_register** (0x2b090) sides: the 32-entry map at 0x1B67B8 built at 0x119360 (17 entries) + 0x1195d0 (15 entries) - both cached to the same map, with **min_state = 2 or 0 as listed above**. The additional 33rd entry (0x14eae1) is `oem esp_update`.

- **getvar dynamic getters** (published via **0x2cf60 = fastboot_publish(name, fn)** / **0x2b200 = oem_publish(name, fn)**):
  | name (rodata addr)   | fn        |
  |----------------------|-----------|
  | product (0x144ec9) | constant "moorefield" |
  | kernel (0x144ee6)  | 0x1B6760 (ptr value) |
  | partition-size (0x144eed) | **0x2a430** |
  | partition-type (0x144efc) | **0x29f90** |
  | device_state (0x145a99) | **0x310d0** |
  | unlocked (0x1458a4)     | **0x31120** |
  | battery-voltage (0x14ebd4) | **0x112f70** |
  | oem * (via 0x113510 get_system_info / 0x1462bd) | volatile |
  | flash-all-depart (0x145254) | **0x112870** (see below) |
  | (via 2b200/2cf60 inside oem init: many, per the 0x119a2e/0x119c66 calls above) | |

  Recorded live responses included `product: moorefield`, `flash-all-depart: 1`, plus whatever `getvar all` iterates. `flashing get_unlock_ability` → 0x310d0-driven FRP gate (text `Unlock is disabled.`) - matches getvar "unlocked".

- The command **dispatcher** itself is 0x2d300 with gate at 0x2d8a4 (`get_state() < min_state` → "command not allowed in this device state"); `min_state` comes from `entry+0` of the `{next,name,len,handler,min_state}` list node built by **0x2cf00** with head 0x1B6790.

---

## flash-all-depart

- String `flash-all-depart` @0x145254. Registered via the oem-class publisher **0x2b200** at **0x119c66** (same function that does getvar publishes; args: name 0x145254, handler **0x112870**, and the raw-string arg pairing at 0x119c5d, making it a **getvar-visible value, not an oem command**).
- The handler **0x112870** is the *boot-flags probe*:
  ```
  112888: lea 0x602fd (%ebx) → "temp"      ; local 0x1c(%esp)
  1128a7: call 11de70(name="temp")        ; OSIP boot-flags probe helper (11bf60-class)
  1128a0: test %eax,%eax ; je 1128d0      ; "temp not in boot list -> 1128d0 (error path, ok=0)"
  1128a7: lea 0x144c3b-ish "boot-one-shot"
  1128b1: call 11de70("boot-one-shot")
  1128b8: test %eax,%eax ; je 1128d0      ; if either flag unset -> error
  1128d0: (error path) lea "Fail to flash boot image"; call 2d110; return
  1128d3: (ok) call 11c7e0(fl_args) ; the actual oem "flash boot" with the one-shot boot target
  1128f5: call 2e3f0 ; ack
  1128fa: printf "Booting..."
  112921: call android_reboot(0xdead0003, 0, "bootoneshot")
  11292c: lea "E:Booting image failed"; call 3a780
  ```
- Interpretation: **`getvar flash-all-depart`** answers **1** (`mov %edi,(%esp)` in 112870's tail prints the returned value; 1128f0 (`info2 %s`?) = the recorded "1"/"0" response) if the current boot-flags block contains the **"boot-one-shot" (boot-to-downloaded-image-once) marker registered by `oem start-update`/`flashing unlock gear`**, else 0/absent. The recorded **0x1** value (`flash-all-depart: 1`) is therefore the **"one-shot boot is armed" indicator** - the same condition the `boot`/`continue`-quick-boot and 0x112870's reboot path arm. This is *not* itself a reboot trigger; the actual reboot into the prepared image is 0x112921 `android_reboot(0xdead0003, 0, "bootoneshot")`.
- The `flash_all_start` / `flash_all_end` oem handlers do **not** set it: they only prime the 0x6f1x/0x6f2x/0x6f30 scratch booleans consumed by the 11xx/12xx flash-all code. The "mid-flash-all" appearance is a side effect of the OSIP one-shot flag, not a dedicated bool.

---

## Open items

- The core evidence chain for `flash-all-depart` == "one-shot boot armed" hinges on 0x11de70 taking the boot-flags partition; the exact producer of the "1" is not yet traced to the byte store (0x120980/0x120b40 flagged trio). The unresolved analysis covers 0x11de70 and 0x11c7e0 and the writer of the "boot-one-shot" string into the boot-flags block (probably `oem data` 0x112870's sibling at 0x112a80 / the reboot-enum table).
- The exact rodata strings 0x1458b4/0x1458b7 (the two "no"/"yes" getvar values).
- `oem sos`/`startftm` were not found in the analyzed command registrations.
- Reboot-table targets 0x11cd10/0x11c720/0x11c780/0x11e360/0x11dc00/0x11c660/0x112ac0 remain incompletely characterized.
