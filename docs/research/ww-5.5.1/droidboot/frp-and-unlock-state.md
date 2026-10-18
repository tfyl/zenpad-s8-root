# Droidboot FRP and unlock state

Historical WW 5.5.1 static analysis. Current ELF: `reference/ww-5.5.1/executables/droidboot`.
See [artifacts](../../../artifacts.md) for provenance and
[methodology](../../../methodology.md) for the implemented chain. The final
implementation used an Android-side payload and stock droidboot unlock; the
binary patches below remain untested proposals. Addresses and disassembly
quotes are retained as static evidence.

All cited `.text` addresses use vaddr==fileoff in the first LOAD segment
(file offset/vaddr 0, file size 0x1a21c0).

**Headlines**: the FRP sig pub key is a static **ASUS 2048-bit RSA** in .data.rel.ro
@0x1AE800 (see Addendum 10 + frp-verification-key.der); the unlock gate reads 1 byte at the
END of /persistent, opens it **O_RDONLY**; no writer exists for that byte inside
droidboot. Part 6 retains proposed patch bytes, including the six-byte branch
rewrite at 0x315d2; it is not a tested installation route.

## Part 1 — Who WRITES the persistent partition (FRP write side)

### The definitive finding

**Nothing in droidboot WRITES byte 1 to /persistent.** The full proof chain
(the device-state vtable is registered; see Addendum 11):

1. `oem erase_token` handler 0x112ac0 (min_state=0) → `erase_token_umip` @0x11c5b0
   → factory 0x12a4b0: with `sys.mia.version` **empty/missing** (consumer WW) it
   returns table **0x1AE9A0**, whose slots +0x14/+0x18 (flash_token_umip /
   erase_token_umip hooks) are **NULL** → "not implemented" and **-1**; droidboot
   writes nothing. (With the prop set — merchant builds — table **0x1AE9E0**
   supplies real hooks at +0x00=0x12d480, +0x04=0x12d470, +0x08=0, +0x0c=0x12bdc0,
   +0x10=0x12bb50, **+0x14=0x12c330, +0x18=0x12cb30**, +0x1c=0x12c780, +0x20=0x12cee0,
   +0x24=0x12d290, +0x28=0x12a950.)
2. `fastboot flash gpt` handler 0x112b40 (min_state=2): never opens the
   persistent partition — `write_flash` @0x2f990 and `tee_token_write` @0x111550 only.
3. `fastboot flash sig` handler 0x112bb0 (min_state=2) — the only erase path:
   @0x112c44-0x112c5d calls `0x2a6c0("persistent", 0, 0)` (BLKX ioctl erase chain),
   not a byte write.
4. `flashing unlock` handler 0x31380: opens /persistent **O_RDONLY** (0x31463),
   lseek-to-end, reads **1** byte at 0x315b7, compares at 0x315cd. The device
   state that the unlock persists goes through the ops vtable
   (set_state → **3-byte "bootloader flags" at offset 0x1000 of the misc
   partition**, via 0x120CC0/0x120B40 — consumer path — or the TEE
   "INTELAndVerBoApp" applet, merchant path). /persistent itself is never
   written by droidboot on this path.
5. The Android side (Settings → "OEM unlocking") is the byte=1 writer, outside
   droidboot.

**The unlock-state store (corrected):** droidboot writes state 2 = `movb $0x2`
into the 3-byte misc bootloader-flags block at +0x1000 (set_state 0x120CC0 →
write 0x120B40), and marks the RAM flag `movb $0x1,0xc4c(%ebx)` = 0x1AE938.
`fastboot oem lock` (state 0) writes 0 the same way. The BLKX ioctl pair at
0x2a4e8/0x2b420 (0x80041272 BLKROGET-class + 0x127d) inside the OSIP-writer
0x2a430 remains the classic `fastboot flash bootloader` raw-write path — not the
FRP-byte flip.

## Reboot banner vs FRP write

0x2af00 → 0x396e0 is droidboot restart / entry into the interactive menu; the
banner bytes at 0x1b2490 area (0x39709) are for the UI — NOT a write to /persistent.

## `flashing unlock` — the 0x31380 body, full walk (byte-verified)

```
3138f: mov    0xc0(%esp),%esi   ; arg1 = requested state
3139c: mov    0xc4(%esp),%edi   ; arg2
313b4: call   31c80             ; get_state()   (ops[1])
313b9: cmp    %eax,%esi         ; requested == current?
313bb: je     31528             ; "Nothing to do."
313c1: cmp    $0x2,%esi         ; requested == 2 (unlock)?
313c4: je     31428             ; → FRP gate first (below)
; ---- requested != 2 (e.g. lock): ----
313c6: call   31ce0             ; confirm(state)  = ops[3] ; (arg1=esi, arg2=movzbl arg2)
313d7: test   %eax,%eax
313d9: jne    31588             ; "couldn't get confirmation"
313e1: call   31c40             ; set_state(state) = ops[0]   ← writes misc bootloader flags
313e9: test   %eax,%eax
313eb: jne    31610             ; "Couldn't set device state"
313f1: call   31c80             ; get_state() again
313f6: cmp    %esi,%eax
313f8: jne    31550             ; "E:Failed to set device state"
31400: call   2af00             ; banner + restart droidboot menu
; ---- requested == 2 (unlock): the FRP gate ----
31428: lea    "ro.frp.pst"      ; property_get (0x145900)
3144b: call   property_get
31454: cmpb   $0x0,0x40(%esp)   ; value empty → error path 0x31688
3145f: movl   $0x0,0x4(%esp)    ; flags = O_RDONLY
3146e: call   open
31497: call   lseek(fd,-1,SEEK_END)
314b4/314cc: call tee_policy_check(0x69/'1') / (0x6a/'1')   ; 0xcab13001 = "no policy" → allow
31508: "Unlock authorization check bypassed by policy."
315a0/315b7: read 1 byte into 0x3f(%esp)
315cd: cmpb   $0x1,0x3f(%esp)   ; byte==1 → permitted
315d2: je     313c6             ; → confirm(2) → set_state(2) → verify → restart
315d8: "Unlock command is protected." / "Go to Android OS to remove the protection"
315f9: "Unlock not permitted"
```

So the persisted unlock store is the **ops set_state** (misc/TEE, see
Addendum 11); the /persistent byte is only ever **read** here.

## Q5.1 — `FRP signature verify pass/fail!`

The strings are referenced only from **0x112BB0** — the `fastboot flash sig` handler
(registration site 0x119423: `key "sig"` → {0x112bb0, min_state=2} via registrar
0x2af20 into hashmap @0x1B679C). `ifp_manuf_sts_bit_set` @0x111e70 is an unrelated
exported TEE helper.

**who calls 0x111e70** (ifp_manuf_sts_bit_set): 0x37020 inside enable_end_user_mode
(@0x37c00) and set-mfg-status (0x121d70 @0x121d80). NOT the FRP verifier.

**Full decode of the FRP verify wrapper 0x112bb0** (prologue `push esi; push ebx; call
251ac; add $0x9b135,%ebx` — GOT 0x1ADCEC):
```
112bb0: push esi; push ebx
112bc1: lea "ro.serialno"      ; payload needs a hash over it
112bc7: lea 0x8994(%ebx),%esi   ; buffer, .data.rel.ro (0x1B6674+...) for serialno
112bdc: call property_get
112be1: movl $0x80,0x4(%esp)    ; __strlen_chk limit
112bec: call __strlen_chk       ; eax = len(serialno)
112c08: call 11d830(serialno, slen, payload_from_flash, siglen)
112c11: fail: "FRP signature verify fail!"
112c28: ok:   "FRP signature verify pass!"
112c36: "Start to erase persistent partition!"
112c5d: call 0x2a6c0("persistent", 0, 0)
112c70: "Finish flashing sig!"
```

**0x11d830 — the crypto core** (as verified above):
```
11d830: push %ebp/%edi/%esi/%ebx; add $0x904b3,%ebx
11d843:  esi = 0x7c(%esp) = arg4 = sig_pay_len (0x80 for `flash sig`)
11d852:  call calloc(1, arg4)         ; recovered-message buffer → %edi
11d861:  eax = 0x70(%esp) = arg1 = serialno ptr
11d880:  call 11d7f0(serialno, slen, 2, hashout@0x36(%esp)) ; hash routine (mode 2 = SHA256) — hashout = ebp
        ; NOTE: the 0x80-byte calloc buffer is filled by RSA_public_decrypt below,
        ;       NOT by hashing; the arg-counts at 11d880/11d7a0 differ.
11d885:  lea 0xb14(%ebx),%eax   ; &GOT slot holding DER pubkey-aligned field → slot used as in/out ptr
11d89f:  lea 0xad4(%ebx),%eax   ; file off 0x1AD5C0 — the second parameter slot
11d8aa:  call d2i_RSA_PUBKEY
11d8c8:  call 11d7a0(payload, payload_len, 0x80, rsa)  ; RSA_public_decrypt(payload, len, buf, rsa, PKCS1)
11d8e5:  sub $0x20,%esi          ; compare last 32 bytes of decrypted vs hashout
11d8f9:  call memcmp(last32, hashout, 32)  ; 0x11d7f0 = hash(data,len,2=SHA256,out)
```
Net: `ok = (RSA_public_decrypt(serialno_signed_blob).bytes[-32:] == SHA256(serialno))`;
0x11d7a0 = the thin wrapper: `RSA_public_decrypt(flen=warg2, from=warg1,
out=warg3, rsa=warg4, padding=1=RSA_PKCS1_PADDING)`; the
`.data` slot layout at 0x1AE800 holds the DER-encoded pubkey blob read by
`d2i_RSA_PUBKEY` (matching the extracted frp-verification-key.der, see Addendum 10).

## Q5.2 — set_state / set_unlock_ability write path — WHO STORES THE STATE? (corrected)

- **Registration is live**: writer fn **0x31C20** (`mov %eax,0x22b0(%ecx)` —
  %ecx-based, which is why an ebx-pattern scan missed it; full disassembly and the
  registration function 0x120830 are quoted in Addendum 11).
  Depending on `tee_get_security_info_struct` byte info+0x1c, bit 0x20:
  - **bit clear (consumer)**: vtable **0x1AE93C** = {set=0x120CC0, get=0x120B00,
    aux=0x1208F0, confirm=0x120900} — **misc-backed**.
  - **bit set (merchant/AVB)**: vtable **0x1AE94C** = {set=0x120E50, get=0x120E00,
    aux=0x120DC0, confirm=0x120DD0} — **TEE-backet via "INTELAndVerBoApp"**.
- **set_state(state) = ops[0]** is called directly by 0x31380's unlock/lock flow
  (@0x313e1). The consumer implementation 0x120CC0:
  - reads the 3-byte bootloader-flags block from **misc @0x1000** (0x120980),
  - `movb $0x0` (lock) or **`movb $0x2`** (unlock) into buf[0],
  - write 3 bytes back via **0x120B40** (`open(O_WRONLY)`, `lseek 0x1000`,
    `write 3`),
  - on unlock success also `movb $0x1,0xc4c(%ebx)` → RAM flag **0x1AE938**.
- **confirm(state) = ops[3]** at 0x313c6 — misc path 0x120900: on state==2 it
  **erases the userdata partition (0x2b370) and formats /data (0x25cd0)**;
  TEE path 0x120DD0 → the shared 0x31190 confirm/erase flow (the "Yes: Change
  device state" / "Userdata erase required…" UI).
- **get_state = ops[1] 0x120B00 FAILS OPEN**: the pre-seed `movb $0x2,0x1d(%esp)`
  stands whenever the misc read (0x120980) fails — device unreadable ⇒ 2.
- **The /persistent FRP byte is never flipped by droidboot** — it is opened
  O_RDONLY and only read. Byte=1 is written by Android (Settings → "OEM
  unlocking"); erase happens only in `flash sig` (0x112c5d → 0x2a6c0).

Practical consequence for the unlock plan: after bypassing the FRP gate (P1/P2
patch), `flashing unlock` stores state 2 in **misc**, so the unlock persists
across reboots. If the misc write fails, set_state returns 0xff → 0x31380 prints
"Couldn't set device state" — the write is **verified** by the follow-up
get_state() call at 0x313f1.

## Q5.3 — what `asus_internal_unlock %d` is (flash dispatcher 0x2ab60)

`%d` = `mov 0x1214(%ebx),%ecx @0x2abe6` = **the sofia_support flag 0x1AEF00**, the
dev QA/dev-mode bypass key. In flash-dispatcher (0x2ab60, invoked for
`fastboot flash <partition>`):
```
2abbc: call 31150           ; get device state (0=locked,2=unlocked)
2abca: mov %eax,%edi        ; edi = state
2abd7: call hashmapGet      ; oem cmd table: anchors at GOT+0x8ab0 → 0x1B679C
2abf6: lea -0x68f62(%ebx)   ; "asus_internal_unlock %d" (0x144d8a)
2abf9: call 3a780           ; log INFO with ecx=flag 0x1AEF00
2abfe: cmp 0x4(%esi),%edi   ; cmp cmd.min_state, state
2ac1c: mov 0x1c(%esp),%eax
2ac23: call *(%esi)          ; the oem command's handler
```
So the bypass is: if `getvar sofia_support` ran (flag=1), the `min_state` check
(state < cmd.min_state) is allowed to be violated: specifically at 0x2ac03
`mov 0x1214(%ebx),%edx; test %edx,%edx; je 2adef` → FAIL if state<min_state
and flag==0; if flag!=0 → continue. Same bypass in oem raw cmds at 0x29c5a
in 0x29b60's loop, on `0x1214(%ebx)` (0x1AEF00).

**The only writer of 0x1AEF00** = `fastboot getvar sofia_support` in getvar handler
0x2d8d0 at 0x2d94b (`movl $0x1,(%eax)` — inline lea 0x1214(%ebx)).
`flash` dispatcher handlers find the command table via hashmapGet(GOT+0x8ab0
struct @0x1B679C); `erase`, `boot`, etc. all flow through this same table.
`asus_internal_unlock %d` prints the dev-flag but opens **no partition**; the byte=1
unlock write path never comes from it.


## Q5.4 — `enable_end_user_mode` (0x37020) & the `enable_adb` getter

Decode (assembler-proved principles, all same/derived regs):

```
37036: mov -0x40(%ebx),%edi     ; -- GOT-ish frame
3704c: call 3a760               ; eax = dev_state_flag[idx] — wait: takes imm in (%esp):
       (3a760: add $0x173587,%ecx; mov (%esp),%eax; lea (%eax,%eax,2),%eax;
        mov 0x5e0(%ecx,%eax,8),%eax)        ; reads ctrl-flag-table idx from ROM
                                  ; the index arg is 0x1 (FUSER_TABLE mode 1) then 0x0
3706f-3707c: movl $0x1,(%esp); lea "/cache"; call sleep(1); 
37081: lea "Factory reseting..."; call 3a780  ; INFO
3708f: lea "%s-", ... 27620 mount("/cache")
370d0: je 3715e  → access("/cache/recovery", F_OK) or mkdir(+0309)
3717c: open("/cache/recovery/command", O_WRONLY|O_CREAT, 0644)
                       ; then write(0x1cd bytes):
       pattern:   "__wipe data" (0x69772d2d = "--"), then "__reboot|"
       (0x645f6572 = "--re", 0x6164 = "data")  → string looked up:
       analyzing the const-string load (0x37092-0x370c2): writes 24-byte
       buffer with the literal `--wipe_data\n--wipe_cache\n` (matches
       bytes 69772d2d-645f6572-0617461-69772d2d-635f6572-65686361 0x0a)
371d0: sync(); 371d5 "Rebooting to factory reset."
37217: property_set("sys.powerctl"?? — NO: it's the reboot-style
        **android_reboot(0xdead0003 = ANDROID_RB_RESTART2, "recovery")**
37228: call android_reboot — 0x240a0 = wunderbar — no property-set here;
        no charbuf is written to any partition.
```
34 bytes of `__wipe data`/`__wipe/ cache` are typed INTO the literal at
0x3708f..0x370c9, and every write happens to **/cache/recovery/command**
(= the AOSP recovery-wipe indicator): after reboot the recovery wipes CACHE part
but droidboot has no induced write on persistent.

**Who calls it**: `oem enable_end_user_mode <...>` reaches 0x37020 from 0x2b5a0's
initializer lines 0x2bc3d (`lea "enable_end_user_mode"`, strdup) and 0x2bc7d
(`mov -0x17615c(%ebx),%edx; movl $0x2,0x4(%eax)` — that's `(*key).fn 0x37020`
with min_state = **2**, so it runs only when `state==2 → get_state()=2`.
**With a `getvar sofia_support` first, the check again passes (0x1AEF00=1).**

The getter `enable_end_user_mode` is registered in 0x2b5a0 @0x2bc3d together with
the handler (reached by raw `fastboot oem enable_end_user_mode`).

**enable_adb**: setter (same cmd 0x113b50, dynsym-not-exported, `oem enable_adb <v>`,
min_state=2) enacts **restricted** — but the `enable_adb` GETTER is the
option-table one (0x2bc9e: lea "enable_adb", strdup; 0x2bcda: `mov -0x17607c(%ebx),%edx`
= a func ptr; min_state=2) that returns the runtime option flag 0x1AEF94
(`droidboot.scratch` was parsed into 0x1AFF94 at 0x30ac0's option parser).
A direct `fastboot oem enable_adb` therefore requires state==2 == unlocked; the
`$droidboot.scratch` route is loader-commandline-only (via kernel cmdline/property
at init).


## Q5.5 — tee_token/ifp layer, erase_token, remove-token (fully decoded)

### `oem erase_token` (0x112ac0, min_state=0)

```
112ad1: cmpl $0x1,0x20(%esp)    ; argc == 1 (no oem args) else "oem_erase_token requires no argument"
112ad8: call 11c5b0              ; erase_token_umip()
112ae1: jne 112b00              ; rc != 0 -> "Fail erase_token_umip" (2d110), return rc
112ae3: lea "/etc/..."; 112aec: call 2e3f0   ; OKAY echo
```

`erase_token_umip` (0x11c5b0) — resolves a hook table then dispatches:
```
11c5c0: call 12a4b0              ; sys.mia.version gated factory (see below)
11c5c5: mov %eax,0x6adc(%ebx)    ; cache @0x1B47C8 (GOT+0x6adc)
11c5cb: test %eax,%eax
11c5cf: mov 0x18(%eax),%eax      ; hook = ops[+0x18]
11c5d6: call *%eax               ; token-erase hook, no args
11c5e0: lea "erase_token_umip"   ; fallback: "%s is not implemented" via 11bdf0; -1
```

`flash_token_umip` (0x11c660) — write-ish consumer: `ops[+0x14](payload, payload_len)`.

### Token/UMIP factory 0x12a4b0 (sys.mia.version gated) — CORRECTED plumbing

```
12a4b0: call 12b3b0            ; returns al = (property_get("sys.mia.version") len == 0)
12a4c5: test %al,%al
12a4c7: je 12a4d8
      ; len==0 (prop missing/empty — CONSUMER):
12a4c9: lea 0xcb4(%ebx),%eax   ; = 0x1AE9A0
12a4cf: ret                    ; → A-table
      ; prop non-empty (MIA/merchant build):
12a4d8: call 12d4c0            ; setg on the same prop (len > 0) → 1
12a4df: lea 0xcf4(%ebx),%eax   ; = 0x1AE9E0
12a4ec: cmove $0,%eax          ; if len not > 0 → 0
12a4ef: ret                    ; → B-table
```

Tables read back from the file:

```
A-table @0x1AE9A0 (consumer): {+0x00=0x12b2b0, +0x04=0x12b250, +0x08=0x12afb0,
                               +0x0c..+0x28 = ALL ZERO}
B-table @0x1AE9E0 (MIA set):  {+0x00=0x12d480, +0x04=0x12d470, +0x08=0,
                               +0x0c=0x12bdc0, +0x10=0x12bb50, +0x14=0x12c330,
                               +0x18=0x12cb30, +0x1c=0x12c780, +0x20=0x12cee0,
                               +0x24=0x12d290, +0x28=0x12a950}
```

Consumers index **+0x14** = `flash_token_umip` (0x11c660: `mov 0x14(%eax),%eax;
call *%eax(payload, len)`) and **+0x18** = `erase_token_umip` (0x11c5b0:
`mov 0x18(%eax),%eax; call *%eax`).

- Consumer (prop missing): both slots are **NULL** in 0x1AE9A0 →
  `"%s is not implemented"` + return -1. `oem erase_token` prints
  "Fail erase_token_umip" → nothing written. **(Conclusion unchanged;
  earlier wrong plumbing/addresses in this file superseded.)**
- MIA build: real hooks 0x12c330 / 0x12cb30 present.
- Result is cached at `mov %eax,0x6adc(%ebx)` = **0x1B47C8** (first use only).

(The separate flash-image factory **0x12a460** — used by `fastboot flash
boot/recovery` via 0x11c7e0 — returns table **0x1AE928**
{+0x00=0x11df90, +0x04=0x11e1e0, +0x08=0x11de50, +0x0c=0x11de60, +0x10=1};
 second branch checks magic `0x24534f24` ("$OS$") via 0x12a550 and otherwise
returns 0. Adjacent in .data, distinct from the token factory above.)

### `oem remove-token <id>` (0x121ab0, min_state=0)

```
121ac2: cmpl $0x2,0x30(%esp)      ; argc must be 2
121ae8: mov 0x4(%eax),%edi        ; arg[1] = datagroup_id string
121afb: strtoul(..., base 10, &endptr)   ; parse
121b26: cmp $0xffffffff,%edx      ; reject -1 (fail)
121b38: mov %edx,(%esp)
121b3b: call ff570                ; tee_token_remove (datagroup_id, 0)
121b42: test %esi,%esi            ; returns rc
```

### `fastboot flash token <file>` (0x121a40, min_state=0)

```
121a50: args: 0x30(%esp)=payload, 0x34(%esp)=len
121a67: call ff650                ; tee_token_write(payload, len, 0)
121a76: movl $0x1,(0x6ad8(%ebx))  ; mark a .bss @0x1B47C4 (token-loaded flag)
```
Error string: `tee_token_write() call failed, return=0x%x`.

### tee_token_* — device/storage

All `tee_token_*` go to the **TEE "PROVISIONING" op**, i.e. via
`TEEC_InitializeContext / TEEC_OpenSession("PROVISIONING") / TEEC_InvokeCommand(0x70c3)
/ TEEC_CloseSession / TEEC_FinalizeContext` at 0xff360. The *actual blob key* is a
0x133c-byte (4924) RAM-side structure from 0x1017c0 (`calloc(4924)`), an "entry
area + DATA magic at +0x320 + SUBG-token tags" handshake structure (decoded in
Addendum 6).
**No tee_token_* call ever opens a real /dev/block/mmcblk* OR /persistent node.**

### `ifp_oem_spec_data_prog` (0x111ab0) / `_read` (0x111bf0)

```
     (prog):  0x5c(%esp)=1, 0x5d(%esp)=1, 0x60=arg0, 0x6c=arg1 → PROVISIONING cmd 1
     (read):  0x5c(%esp)=1, 0x5d(%esp)=2, 0x60=arg0 →            PROVISIONING cmd 2
```
Same TEE-to-TEE oracle; result is 0x6d-0x70-byte handshake, not device I/O.

### tee_policy_check (0x10c940) — the FRP-gate policy checker

Full disasm shows:
```
10c980: movl $0x0,(%esp)
10c98f: call TEEC_InitializeContext(NULL, ctx)
10c9c8: lea -0x3f81a(%ebx)        ; "OSPROV" / PROVISIONING opts (session TA)
10ca56: movb $0x3,0x5c(%esp)      ; op=3 (POLICY CHECK)
10ca63: mov %esi,0x64(%esp)       ; the byte-pair arg 0x69 / 0x6a = policy id
10ca67: call TEEC_InvokeCommand   ; 0x15 = command
```
`failure == 0xcab13001` = "no policy" — the WW consumer device without MIA. A
**0-return** means the check passed (unlock allowed). Prop-arg `0x69` and `0x6a`
are the 1-byte flags. This is the tee policy — no direct flash I/O.

# Part 6 — historical patch proposals (bytes and addresses)

## P1 — proposed branch rewrite at 0x315d2

These bytes were read from the ELF; none of the proposals was device-validated.
A cached `/system/bin/droidboot` replacement does not survive reboot and does not
establish a modified bootloader image. P1 changes the branch target condition;
P2/P3's proposed `movb` is not established as equivalent because it does not set
the condition flags consumed by the following `je`.

Objdump bytes in the binary (start-address=0x315c0):
```
   315c5: 89 04 24              mov    %eax,(%esp)     ; fd arg to close
   315c8: e8 13 28 ff ff        call   23de0 <close@plt>
   315cd: 80 7c 24 3f 01        cmpb   $0x1,0x3f(%esp) ; the byte==1 check
   315d2: 0f 84 ee fd ff ff     je     313c6           ; -> unlocked
   315d8: 8d 83 31 7d f9 ff     lea    -0x682cf(%ebx),%eax  ; "Unlock command is protected."
   315de: bf                    .byte 0xbf
```

- Primary (P1): replace 6 bytes at **0x315d2..0x315d8**:
  `0f 84 ee fd ff ff` (je 0x313c6) → `e9 ef fd ff ff 90` (jmp 0x313c6 + nop).
  Verified: rel32 = 0x313c6 - 0x315d7 = -0x211 = `ef fd ff ff`. The old je's
  own rel32 (`ee fd ff ff` = -0x212) was relative to end-of-je (0x315d8), so
  both hit the same target 0x313c6. In the proposed P1 instruction stream,
  execution reaches that target regardless of the FRP byte. This describes
  the local branch effect, not a verified complete unlock.

- Fragment in objdump notation, exact:
```
   (before)
   315cd:   80 7c 24 3f 01        cmpb   $0x1,0x3f(%esp)
   315d2:   0f 84 ee fd ff ff     je     313c6 <inflateReset@plt+0xca76>
   (after)
   315cd:   80 7c 24 3f 01        cmpb   $0x1,0x3f(%esp)   ; unchanged (6 bytes preserved)
   315d2:   e9 ef fd ff ff        jmp    313c6
   315d7:   90                    nop
```

## P2 — archived proposal to replace cmpb with movb

Raw (binary confirmed):
```
   315a0: c7 44 24 08 01 00 00    movl $0x1,0x8(%esp)   ; count for read()
   315a8: 8d 44 24 3f             lea  0x3f(%esp),%eax
   315ac: 89 44 24 04             mov  %eax,0x4(%esp)   ; buf = 0x3f(%esp)
   315b0: 8b 44 24 28             mov  0x28(%esp),%eax
   315b4: 89 04 24                mov  %eax,(%esp)      ; fd
   315b7: e8 b4 2a ff ff          call read@plt
   315bc: 83 f8 ff                cmp  $0xffffffff,%eax
   315bf: 74 73                   je   31634             ; read-failed path
   315c1: 8b 44 24 28             mov  0x28(%esp),%eax
   315c5: 89 04 24                mov  %eax,(%esp)
   315c8: e8 13 28 ff ff          call close@plt
   315cd: 80 7c 24 3f 01          cmpb $0x1,0x3f(%esp)   ; the FRP byte
   315d2: 0f 84 ee fd ff ff       je   313c6
```

Minimal P2 (5-byte overwrite at 0x315cd using identical-length instruction):
`80 7c 24 3f 01  (cmpb  $0x1,0x3f(%esp))`  ->  `c6 44 24 3f 01  (movb  $0x1,0x3f(%esp))`
This proposed rewrite stores 1 into the stack byte but does not set flags.
The earlier claim that the following `je` would therefore always be taken was
unsupported. The bytes are retained as a historical proposal, not an alternative
to P1 with established behavior. The preceding read and error checks remain.

## P3 — duplicate of the unvalidated P2 proposal
```
   315cd: 80 7c 24 3f 01        cmpb   $0x1,0x3f(%esp)   ; make this ALWAYS true
```
The archived proposal used `c6 44 24 3f 01` (`movb $0x1,0x3f(%esp)`) at
0x315cd. The condition-flag limitation described under P2 applies equally here.

## Where the bytes come from (byte-verified raw dump)

From the actual ELF:
```
   315c5: 89 04 24
   315c8: e8 13 28 ff ff        call close@plt
   315cd: 80 7c 24 3f 01        cmpb $0x1,0x3f(%esp)   ; FRP byte cmp
   315d2: 0f 84 ee fd ff ff     je   313c6
   315d8: 8d 83 31 7d f9 ff     lea -0x682cf(%ebx),%eax  ; "Unlock command is protected."
```
(the `80 7c 24 3f 01` = `cmp $0x1, 0x3f(%esp)`; patching to
`c6 44 24 3f 01 mov $0x1,0x3f(%esp)` gives the same 5 bytes and same
instruction length — hence byte-perfect paths.)
# TL;DR summary (the five Q5 answers in one page) — corrected edition

1. **FRP verify function 0x111e70** is an IFP/TEE helper (`ifp_manuf_sts_bit_set`,
   exported), NOT the sig verifier. The strings "FRP signature verify pass!/fail!"
   live in `fastboot flash sig` handler **0x112bb0** (registered via 0x2af20 in
   hashmap @0x1B679C, min_state=2): get "ro.serialno" → SHA256 via 0x11d950
   → verify via 0x11d830 (`d2i_RSA_PUBKEY`, embedded **ASUS 2048-bit RSA pubkey**
   in .data at 0x1AE800, `RSA_public_decrypt` PKCS1) → the last 32 bytes of the
   decrypted blob must equal SHA256(ro.serialno) →
   **erase the whole persistent partition** via 0x2a6c0("persistent", 0, 0).
   Used to factory-reset the FRP partition after a re-provisioned (RMA) device;
   NOT a per-byte unlock check.

2. **FRP write path (corrected)** — **NOBODY flips the /persistent byte to 1
   inside droidboot** (opened O_RDONLY; the allowed byte must be supplied
   by Android-side code). What `flashing unlock` actually persists is the **device-state ops
   vtable store**: registration writer **0x31C20** (`mov %eax,0x22b0(%ecx)`,
   selected from vtable **0x1AE93C** misc-backed {set=0x120CC0, get=0x120B00,
   aux=0x1208F0, confirm=0x120900} or **0x1AE94C** TEE-backed {set=0x120E50,
   get=0x120E00, aux=0x120DC0, confirm=0x120DD0} by `tee_get_security_info`
   byte info+0x1c bit 0x20, registered by 0x120830 ← oem registrar 0x1195d0 ←
   main 0x24ce2). Consumer path: state = **3-byte bootloader-flags at misc
   partition offset 0x1000**; set_state(2)=`movb $0x2,buf[0]` + write; unlock
   also sets RAM flag **0x1AE938=1**; get_state **fails open** (returns 2) if
   misc is unreadable (pre-seed at 0x120b23); confirm(2) **erases userdata**
   (0x2b370 + format /data via 0x25cd0).

3. **asus_internal_unlock %d @0x2abf0** prints the 0x1AEF00 value (*sofia_support*
   bypass flag, single writer @0x2d94b in getvar handler 0x2d8d0). Bypasses the
   min_state gate in the flash/oem/erase dispatchers. No partition flash and no
   /persistent write.

4. **enable_end_user_mode (min_state=2)** = wipe-and-restart via /cache/recovery/
   command ("--wipe_data\n--wipe_cache\n"), then android_reboot(0xdead0003,
   "recovery") — the factory-reset hook, not an unlock write. `enable_adb`
   getter is the **option-table only** entry (droidboot cmdline `droidboot.scratch`
   → 0x1AFF94), NOT a fastboot command.

5. **tee_token/ifp layer** — tee_token_write 0xff650 (`flash token`, min_state=0),
   tee_token_remove 0xff570 (`oem remove-token <id>`, min_state=0),
   tee_token_read 0x1015f0, tee_token_unprotected_write 0x1018d0 (0x133c-byte
   RAM blob, "DATA" magic @+0x320, SUBG 9-dword entries) — all go through the
   **TEE "PROVISIONING" session** (TEEC_InvokeCommand 0x70c3 = 28867). No direct
   MMC writes. The UMIP hooks (`erase_token_umip`/`flash_token_umip`) are factory
   0x12a4b0-selected: **0x1AE9A0 (consumer, prop missing → hooks NULL → "not
   implemented")** vs **0x1AE9E0 (MIA/merchant → hooks 0x12cb30/0x12c330)**.
   ⇒ An arbitrary 1-byte write of 0x01 at the end of /persistent **is** honored by
   the unlock gate (the read at 0x315b7 is the sole check, tee policy "no policy"
   allows on consumer).

6. **Patch analysis:** P1 proposes making the branch at 0x315d2
   unconditional. P2/P3 propose a same-length `cmpb`-to-`movb` rewrite at 0x315cd,
   but `movb` does not set the condition flags used by `je`. Byte lengths alone
   do not establish equivalent behavior. The static state-store flow is described
   separately; no patched bootloader installation was validated.

## Addendum 4 — Final walk-through table (byte-exact flash registration table)

The complete set of fastboot command registrations, with their min_state
(gate-level) and 0x1AEF00 (sofia_support) override behavior. All from
decoded map anchors 0x1B679C (flash-style) and 0x1B67B8 (oem-style):

| cmd/pattern | handler | min_state | owner |
|---|---|---|---|
| `erase_token` | 0x112ac0 | 0 | MIA-hook-erased; **not** the FRP erase |
| `token_umip` (flash) | 0x11c660 | 0 | uses 0x12a4b0 factory → MIA |
| `token` (flash) | 0x121a40 | 0 | tee_token_write (payload, len, 0) |
| `remove-token` | 0x121ab0 | 0 | tee_token_remove(id, 0) |
| `gpt` (flash) | 0x112b40 | 2 | tee_token_write + partition write |
| `sig` (flash) | 0x112bb0 | 2 | RSA sig verify + erase persistent |
| all | 0x118d90 | 2 | flash-all chain |
| `sig` chain | 0x112c44-2a6c0 | 2 | **erase("persistent")** full-wipe |
| `flashing unlock/lock` state Dispatcher | 0x31380 | 2 | reads FRP byte, never writes |

Sofia-support flag 0x1AEF00, single writer = `fastboot getvar sofia_support`
@0x2d94b; multiple readers: 0x2a741 (erase), 0x29c5a (oem raw cmds), 0x2abe6,
0x2ac03, 0x2ace4 (flash dispatchers), 0x2d945 (getvar). It bypasses min_state
gates only (does not touch the FRP byte).


---

### Addendum 4b — device-state vtable correction entered into the table

| vtable | index/type | consumer (bit 0x20 clear) | merchant (bit 0x20 set) |
|---|---|---|---|
| 0x1AE93C / 0x1AE94C | [0] set_state | 0x120CC0 (misc write) | 0x120E50 (TEE, {0,2} only) |
| | [1] get_state | 0x120B00 (misc read, **fail-open 2**) | 0x120E00 (TEE read) |
| | [2] aux-get | 0x1208F0 (→ 0) | 0x120DC0 (→ 2) |
| | [3] confirm | 0x120900 (wipe userdata) | 0x120DD0 (→ 0x31190 shared) |

Writer: 0x31C20 via %ecx-pc-thunk; registrar 0x120830 (tee_get_security_info_struct
→ bit 0x20 of info+0x1c); called once at init from oem registrar 0x1195d0 @0x119c87,
itself invoked from main init @0x24ce2 (after the command maps at 0x2b5a0).

# Addendum 5 — Q5.4 disassembly refresh (working copy dump)

The exact decode of the wipe string built inside enable_end_user_mode:
```
37092:  movl $0x69772d2d,0x1c(%esp)   ; "--wi"    (bytes 2d 2d 77 69)
3709a:  movl $0x645f6570,0x20(%esp)   ; "pe_d"
370a2:  movl $0xa617461,0x24(%esp)    ; "ata\x0a"  (3 bytes + NUL = wipedata\n\0)
370aa:  movl $0x69772d2d,0x28(%esp)   ; "--wi"
370b2:  movl $0x635f6570,0x2c(%esp)   ; "pe_c"
370ba:  movl $0x65686361,0x30(%esp)   ; "ache"
370c2:  movw  $0xa,0x34(%esp)         ; "\n\0"
        == the literal: "--wipe_data\n--wipe_cache\n"
370c9:  call 27620            ; mount("/cache", ...)
37195:  call open             ; open("/cache/recovery/command", O_WRONLY|O_CREAT, 0644)
371c3:  call write            ; writes the structbuffer, 0x200 bytes
371d0:  call sync
37228:  call android_reboot   ; 0xdead0003 ANDROID_RB_RESTART2 with arg "recovery"
```
There's no property_set in this flow (the 'sys.powerctl' path is absent); reboot
takes the android_reboot syscall route. The 0x1c(%esp)..0x34(%esp) stack area
holds 0x18 + 2 bytes which is 0x1a total = the wipe-data command string.


---

# Addendum 6 — verify claim "0x133c-byte token storage blob" context (0x1017c0)

The 0x1017c0 (`tee_token_unprotected_start`-family) allocates:

```
1017e0: movl $0x1,0x4(%esp)
1017e8: movl $0x133c,(%esp)         ; calloc(1, 0x133c) = 4924 bytes
1017ef: call calloc
1017f4: mov %eax,(%esi)             ; ret struct {0 = blob ptr}
1017f8: movl $0x33c,0x4(%esi)       ; [1] = 0x33c
1017ff: movl $0x133c,0x8(%esi)      ; [2] = 0x133c
101808: mov 0x28(%esp),%edx         ; capacity arg
10180c: movl $0x41544144,0x320(%eax); magic 0x41544144 = "DATA" at offset 0x320
101816: movl $0x1f,0x324(%eax)      ; dwords at +0x324 = 0x1f
101820: movl $0x7,0x328(%eax)       ; dwords at +0x328 = 0x7
10182a: movw $0xcf,0x316(%eax)      ; u16 field at +0x316 = 0x00cf
101833: mov %edx,0x334(%eax)        ; capacity at +0x334
```
Layout of the unprotected-token blob:
```
+0x000..0x316: entries area (each entry = 9 dwords = 0x24 "SUBG"-magic block per entry),
+0x316: u16 last_idx/blocks_used = 0x00cf,
+0x320: magic "DATA",
+0x324: dwords (?) = 0x1f,
+0x328: dwords (?) = 0x7,
+0x334: capacity dwords arg.
```
`tee_token_unprotected_write` at 0x1018d0 walks a linked list of 9-dword entries
(each = 0x20-0x24 bytes) with magic `0x47425553 ("SUBG"` = bytes [0x53,0x55,0x42,0x47] =
"S", "U", "B", "G" = the tag "SBUG"). It's a handshake structure backed by the TEE.

The token blob is fully RAM-side in this build; the tee-persisted blob (for real token
storage) never occurs in the FRP path.

---

# Addendum 7 — functional-flow replay (corrected edition)

## Static unlock flow and the missing Android-side writer

1. Android-side code must supply the allowed last byte. The tested firmware
   lacked an OEM-unlocking switch. The final v6 payload confirmed access and
   `already1`; the first writer was not isolated. Droidboot only reads the byte.
2. `fastboot getvar sofia_support` (optional, only for the min_state bypass):
   sets 0x1AEF00 = 1 (0x2d94b), which makes the flash/oem/erase dispatchers skip
   the state>=min_state requirement (0x29c5a / 0x2a741 / 0x2ac03 etc.).
3. `fastboot flashing unlock` → 0x31380:
   - get_state() (ops[1], >= consumer misc ops 0x120B00) returns 0x00 → locked;
   - requested==2 → FRP gate: /persistent last byte == 1 → permitted;
   - confirm(2) → ops[3]: consumer 0x120900 erases userdata + formats /data
     (TEE-registered builds take the shared 0x31190 flow instead);
   - set_state(2) → ops[0]: 0x120CC0 reads 3 bootloader-flag bytes from misc@0x1000,
     forces buf[0]=0x02, writes 3 bytes back (0x120B40), sets RAM flag 0x1AE938=1;
   - get_state() verify == 2 → 0x2af00 banner → stays in bootloader unlocked.
4. If the misc write fails, set_state returns 0xff → "Couldn't set device state"
   → unlock DOES NOT persist (verified by the get_state check at 0x313f1).

The three storage tiers are therefore: /persistent (FRP allow byte, Android-owned),
misc bootloader-flags at +0x1000 (lock state 0/2, droidboot-owned via ops vtable),
and TEE "INTELAndVerBoApp" (merchant alternative storage tier selected by
tee_get_security_info bit 0x20).

## The "enable_end_user_mode" verdict (unchanged)

**It does NOT alter the FRP-protected state.** It is the *factory-reset* helper:
writes /cache/recovery/command then reboots to the recovery bootloader; nothing
else. Both handlers `enable_adb` and `enable_end_user_mode` sit behind
min_state=2 = requires the bootloader ALREADY unlocked (sofia_support can walk
through the gate for a QA engineer).

Byte-verified proof (objdump of the actual binary):
```
   31463: c7 44 24 04 00 00 00  movl $0x0,0x4(%esp)   ; flags = 0 (O_RDONLY)
   3146e: e8 2d 29 ff ff        call open@plt          ; open(path, O_RDONLY)
```


# Addendum 8 — caller chain from fastboot command to 0x112bb0 (full walk)

```
    (fastboot client)
        flash sig  →  droidboot USB protocol loop 0x2d300  ("fastboot got command:")
                       → download: (0x2cf00 registar) then
                       → flash command parser (0x2ab60 "FLASH %s..." dispatcher)
                          2ab85: stage via *edb, hashmapGet(0x1B679C,"sig") {0x112bb0, srv=2}
                          2abf6: asus_internal_unlock print (bypass flag check)
                          2abfe: cmp min_state=2, get_state()
                          2ac23: call *(handler)  = 0x112bb0
                                 112bc1  property_get("ro.serialno")
                                 112c08  call 0x11d830 (RSA sig verify, key GOT+0xb14,
                                                        SHA256(serialno), last-32B match)
                                 112c28  "FRP signature verify pass!" / "fail!"
                                 112c5d  call 0x2a6c0("persistent", 0, 0)  → erase
                                 112c70  "Finish flashing sig!"  + 2e3f0 (OKAY)
```

Reachable ONLY when get_state()==2, i.e. unlocked (min_state=2 for "sig") — the
`sofia_support` bypass (0x1AEF00=1) can short-circuit this.

`oem erase_token` (`0x112ac0`, min_state=0) does NOT reach 0x2a6c0/erase-persistent:
it goes to the `erase_token_umip` hook, which (on consumer WW build without MIA)
prints "%s is not implemented" and returns -1.

---

# Addendum 9 — sig RSA verify key details + op-super edge (Q5.1 crypto deep-dive)

Hardware root key details (from the decoded 0x11d830):

- `0x11d830` is called with 4 args by 0x112bb0 @0x112c08:
  `(serialno_ptr, serialno_len, payload_ptr, payload_len=0x80)`.
- 0x11d830 calls `calloc(1, arg4)` (0x11d852) → temp buffer back to edi,
  then `0x11d7a0(payload_ptr, payload_len, buf(calloc), rsa)` — a thin wrapper
  that calls `RSA_public_decrypt(flen=payload_len, from=payload, to=buf,
  rsa, padding=RSA_PKCS1_PADDING)` @0xc5e20.
  Verify target: decrypted bytes [len-32 .. len] == SHA256(ro.serialno).
- The RSA key source: `d2i_RSA_PUBKEY` @0xe4f10 from a DER blob at
  `*GOT+0xb14` (vaddr 0x1AE800 — .data.rel.ro). Its length is read from a
  companion GOT slot.
- `EVP_cleanup`, `CRYPTO_cleanup_all_ex_data`, `ERR_remove_thread_state` — the
  OpenSSL static layer is linked in.

So the shipped build uses: ASUS root RSA pub key (statically embedded in
*.data.rel.ro at 0x1ae800*) + PKCS1 v1.5 decrypt of a 128-byte sig file whose last
32 bytes must equal SHA256(ro.serialno). If the "sig" payload decrypts cleanly,
droidboot ERASES the persistent partition wholesale. The byte IS NOT WRITTEN back.

Patch address sanity: 0x315d2 lies inside LOAD0 (`0..0x1a21c0 R E`), so for this
.a file the vaddr == file-offset. On a device whose droidboot is loaded at its
ELF-text base (PIE, with ASLR in droidboot mode), any dirtycow-style write has to
target the *file* itself (the /system/bin/droidboot blob) — offsets above are
then literal file offsets and also literal vaddrs within the running image.

---

# Addendum 10 — the extracted FRP public key (crypto key material — Q5.1 answer)

The DER pubkey blob at `(GOT+0xb14) → 0x1AE800` was extracted (file: frp-verification-key.der,
294 bytes) and decoded:

```
$ openssl rsa -pubin -inform DER -in frp-verification-key.der -text -noout
Public-Key: (2048 bit)
Modulus:
    00:81:cb:78:ec:68:57:7b:81:b7:1f:82:9c:21:17:
    ba:5d:6f:e6:ed:00:b0:4e:89:ea:77:35:df:8f:31:
    ... (further 2048-bit modulus bytes)
$ openssl rsa -pubin -inform DER -in frp-verification-key.der -modulus -noout
Modulus=81CB78EC68577B81B71F829C2117BA5D6FE6ED00B04E89EA7735DF8F317378B98F84D53712FE5CD00D8C3A472D8197B449ADF022450B4D5985AB6A0D80686AB7492B4865D3C2003CB66B50A1498532BCD56FA8BEC4AFAE396EFB6D2F79982BC9F72292562F104CF9B6F7F6C9A21424030AACD5279C88A85AB21D3FB0F1CD01A155C736E4C2238C7A8FCB90B6512AC4B55822D6F9AE1DCF3BCF62328199FE19B5F5C90F4451493FFBE1B44EC5CC7994A17B82047C5C408569D6643FBE199E70B1C293E7085F59873AE031309AF7BA922AEFCEA962C692CF8ECCFDF8887F5683C630903ACB950C71DF4AC418DD8993E3AC7AFA3012D0EDCA21083692F19FB6EA6B
```

So the FRP "sig" payload verification is a **2048-bit RSA** (Public key, exponent
from openssl output likely 0x10001 = 65537, standard e). The sig file (`fastboot
flash sig`) is a payload PKCS1-signed with the ASUS master RSA-2048 private key
(not in droidboot), computed over `(payload || SHA256(ro.serialno))`; the verify
routine validates the last 32 bytes = SHA256(serialno).

This answers "what key material verifies the signature: a static ASUS 2048-bit RSA
pubkey embedded in droidboot's .data.rel.ro at 0x1AE800".


---

# Addendum 11 — verified vtable registration and state persistence

The earlier "ops vtable registration not found" claim was wrong. The writer is
**0x31C20**, using `%ecx` (pc-thunk); an ebx-only pattern scan missed it.
The disassembly establishes the following:

1. **0x31C20 — confirmed exactly as stated** (`call 31d27; add $0x17c0c7,%ecx;
   mov 0x4(%esp),%eax; mov %eax,0x22b0(%ecx); ret` — thunk returns its own return
   address in %ecx: 0x31c25 + 0x17c0c7 = 0x1ADCEC = GOT ⇒ store at 0x1AFF9C).
   All earlier "no writer / never registered" language in this file is superseded.

2. **Registrar 0x120830 — confirmed** (only caller; sites 0x12087f / 0x1208a9):
   `tee_get_security_info_struct` (exported, 0x10C690) with a 0x70-byte struct,
   then `testb $0x20,0x38(%esp)` (byte info+0x1c). Bit **clear** → `lea 0xc50(%ebx)`
   = **0x1AE93C**; bit **set** → `lea 0xc60(%ebx)` = **0x1AE94C** → `call 31c20`
   If **tee_get_security_info_struct
   itself fails**, the function prints "Failed to get security info" and returns —
   in that case **no vtable is registered** and the accessor defaults apply
   (get 2 via `mov $0x2,%eax` @0x31c90, aux 1, set returns -1) — i.e. also fail-open.

3. **Vtables — read back from the file and confirmed:**
   - **0x1AE93C** {set=0x120CC0, get=0x120B00, aux=0x1208F0 (`xor %eax,%eax;ret`),
     confirm=0x120900} — MISC-backed.
   - **0x1AE94C** {set=0x120E50, get=0x120E00, aux=0x120DC0 (`mov $0x2,%eax;ret`),
     confirm=0x120DD0} — TEE-backed ("INTELAndVerBoApp" applet, InvokeCommand
     cmd 1 = read / cmd 2 = write; error strings "AVB_change_device_state returned
     error code 0x%X - state %d", "avb_process_cmd failed. error(0x%x)",
     "Libavb: wrong device state (%d)" — the set wrapper rejects any state outside
     {0,2} via `and $0xfffffffd`).

4. **MISC path — fully confirmed and extended:**
   - read **0x120980**: `11bf60("misc")` name→path (mallocs 0x400, writes
     `"/dev"` `"/blo"` `"ck/b"` constants → "/dev/block/by-name/misc"-style path),
     `open(O_RDONLY)`, `lseek(fd, 0x1000, SEEK_SET)`, `read(fd, buf, 3)` —
     3-byte "bootloader flags" (**error strings**: "Failed to read bootloader
     flags on %s : %s", "Failed to seek on %s, 0x1000 bytes : %s",
     "E:Failed to read bootloader flags").
   - **get_state 0x120B00 fails open**: buf pre-seeded
     with `movb $0x2` @0x120b23; 0x120980 never stores into the buffer, only the
     successful `read` fills it, so on any failure the pre-seeded 2 is returned.
   - **set_state 0x120CC0**: state 0 → read, `movb $0x0`, write; state 2 → read,
     **`movb $0x2`**, write (0x120B40: `open(O_WRONLY)`, `lseek 0x1000`,
     `write 3`); unlock path also `movb $0x1,0xc4c(%ebx)` → **0x1AE938**; other
     states → return 1; failures → 0xff. Write-error strings:
     "Failed to write bootloader flags on %s : %s",
     "E:Failed to change bootloader flags".
   - **confirm 0x120900**: only acts on state 2 → "Erasing..." → erase
     `userdata` (2b370) + mount/format `/data` (25cd0) — "Format failed." /
     "Erase Failed."

5. **Registration timing**: 0x120830 is called from
   **0x119c87** inside oem-registrar **0x1195d0**, which runs from main/init at
   **0x24ce2** (right after the command-map setup 0x2b5a0). So the vtable is
   registered before any fastboot traffic.

6. **Static conclusion:** /persistent is opened O_RDONLY; droidboot does not
   write its unlock-allowed byte. Unlock state is stored through the selected
   misc/TEE ops table. `flash sig` is the full-partition erase path. P1 and P2/P3
   bytes are listed above, with P2/P3's condition-flag limitation noted.

---

# Addendum 12 — consolidated findings

- **FRP verify fn 0x112BB0 (structure/key/callers)** — COMPLETE (Section Q5.1 +
  Addendum 9/10): registration site 0x119423 (key "sig", min_state=2, map 0x1B679C);
  structure = SHA256(ro.serialno) compared to last 32 bytes of an
  RSA-PKCS1 2048-bit `RSA_public_decrypt`; key = static ASUS pubkey at **0x1AE800**
  (frp-verification-key.der, 294-byte DER Blob); caller chain = `fastboot flash sig` →
  dispatcher 0x2ab60 → hashmap("sig") → 0x112bb0.
- **Persistent-byte write path** — COMPLETE (Section Q5.2 + Part 1): /persistent is
  never written by droidboot (O_RDONLY byte read @0x315b7 as sole arithmetic gate;
  full-partition *erase* only in `flash sig` via 0x2a6c0). The unlock state itself
  is persisted via the ops-vtable set_state → misc bootloader-flags @0x1000
  (consumer) or the INTELAndVerBoApp TEE applet (merchant, tee_get_security_info
  bit 0x20). The byte must be supplied from Android-side code; the tested firmware had no
  OEM-unlocking switch, and the first writer was not isolated.
- **asus_internal_unlock** — COMPLETE (Section Q5.3): %d = the 0x1AEF00
  sofia_support gate flag; per-flash info print; no partition write.
- **enable_end_user_mode / enable_adb** — COMPLETE (Section Q5.4 + Addendum 5).
- **tee_token/ifp reachability** — COMPLETE (Section Q5.5, Addendum 6);
  token ifp storage = 0x133c-byte RAM blob; erase_token/remove-token min_state=0 but
  no-ops fail on consumer MIA gate; nothing writes /persistent.
- **Historical patch proposals** (Part 6): P1 = six-byte je-to-jmp rewrite
  at 0x315d2 (`0f 84 ee fd ff ff` → `e9 ef fd ff ff 90`). P2/P3 = five-byte
  cmpb-to-movb proposal at 0x315cd (`80 7c 24 3f 01` → `c6 44 24 3f 01`), with
  the condition-flag limitation noted above. Address sanity was checked against
  ELF program headers (LOAD0 vaddr==fileoffset). Separately, the static unlock
  flow calls `set_state(2)` and verifies the result at 0x313f1; misc-write failure
  returns 0xff ("Couldn't set device state"). These facts do not establish a
  tested patched bootloader installation.
