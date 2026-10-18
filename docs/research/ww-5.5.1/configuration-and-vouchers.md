# ASUS ZenPad S 8.0 (P01MA) — `info_setting` + `VerifyVouchers` full disassembly analysis

Static findings cite disassembly evidence; runtime conclusions and speculation are labelled.

> Historical WW 5.5.1 research. Bundled boot and policy files came from the WW OTA,
> not a capture of the original PGDO boot. The completed tablet run and later
> evidence limits are in [methodology](../../methodology.md) and
> [artifacts](../../artifacts.md).

Scope: static offline analysis of `reference/ww-5.5.1/executables/info_setting` (20,988 B) and
`reference/ww-5.5.1/executables/VerifyVouchers` (9,644 B), both stripped **32-bit x86** PIE ELFs,
`seclabel u:r:init:s0`, class core oneshot. Runtime file-mode observations are distinguished from
static binary analysis.

Method: objdump -d/-s, string tables, manual call-flow reconstruction. Every claim below says how it was
verified (immediate constants read from the disassembly, .rodata dumps, PLT cross-refs).

**ISA correction (verified via `file`):** both binaries are **32-bit Intel x86 PIE**
(`ELF 32-bit LSB shared object, Intel 80386, interpreter /system/bin/linker`) — not ARM.
Consistent with the tablet's Intel Atom (Moorefield) SoC. All addresses below are x86 ELF VAs.

Sections:
1. File metadata + PLT inventory
2. `/factory/info` parse flow (magic/size/order, RSA call args, slots, index→prop map)
3. `misc` flows (read vs write, user-build gate, offsets)
4. Private-key path
5. Fix/backup write path and its integrity checks
6. VerifyVouchers
7. exec/dlopen check
8. Property-name constant table with .rodata offsets
9. Bottom line for the unlock project

---

## 1. File metadata + PLT inventory (verified: `file`, `readelf`)

Both binaries: `ELF 32-bit LSB shared object (PIE), Intel 80386, interpreter /system/bin/linker`,
stripped, bionic-linked (LIBC versioned symbols). x86 is correct for this tablet (Intel Atom
"Moorefield" SoC family).

### info_setting — imports and which are live

`.dynsym` lists 33 imports, but the **`.rel.plt` JUMP_SLOT relocations decide what is actually called**:

| import | PLT slot | status |
|---|---|---|
| `property_set` | 0x7a0 | live |
| `property_get` | 0x7c0 | live |
| `__android_log_print` | 0x7b0 | live |
| `BIO_new_mem_buf` | 0x7d0 | live |
| `PEM_read_bio_RSA_PUBKEY` | 0x7e0 | **live** |
| `RSA_public_decrypt` | 0x7f0 | **live** |
| `BIO_free` / `RSA_free` | 0x800/0x810 | live |
| `fopen/fwrite/fileno/fsync/fclose/chmod/fseek/fread/access/memset/strlen/__strlen_chk/__errno/strerror` | 0x820–0x8e0 | live |
| `PEM_read_bio_RSAPrivateKey` | — | **dead import: no relocation, no PLT slot, never called** |
| `RSA_private_encrypt` | — | **dead import, never called** |
| `open` / `read` / `close` | — | dead imports (all block I/O is stdio) |
| `__memcpy_chk` | — | dead import (memcpy is inlined) |

**Conclusion 1:** despite linking `PEM_read_bio_RSAPrivateKey` and `RSA_private_encrypt`, this
binary *never signs and never loads a private key at runtime*. The only crypto is
`RSA_public_decrypt` with the embedded public key. (The dead imports pair with dead strings —
see §4.)

There are **no `execve`/`execl`/`system`/`popen`/`dlopen`/`fork` imports at all** — verified by
walking the full `.dynsym` (list above is complete). Confirmed again per-binary in §7.

---

## 2. `/factory/info` parse flow — VERIFIED against disassembly

### 2.1 Function map (all addresses are VAs in the PIE)

| VA | role |
|---|---|
| 0x8f0 | `main` |
| 0xb00 | register/read/set one prop (called 7× from main) |
| 0xbf0 | build-type check (`ro.build.type`) + `factory.product.device` |
| 0xcb0 | RSA verify helper (BIO/PEM/RSA_public_decrypt) |
| 0xda0 | ensure `/factory/info` exists (768 KiB of 0xFF, mode 0777) |
| 0xf30 | raw slot write: `fseek(file, idx<<8, SEEK_SET)`, `fwrite(buf,1,0x100)` |
| 0x1050 | write backup slot into `/factory/info` (+ create file) |
| 0x10c0 | write slot into `/dev/block/by-name/misc` ("Fix") |
| 0x1140 | verified slot read from an arbitrary path |
| 0x1360 | read `/factory/info` slot; on success fix misc |
| 0x1420 | read `/dev/block/by-name/misc` slot; on success sync backup |
| 0x14c0 | `asus_nvm_read(idx,out)`: native+backup with fallback, logs |

### 2.2 Slot layout and sizes (verified from immediates)

- **SLOT_SIZE = 0x100 (256 bytes).** Every read/write does `fseek(f, idx*0x100, SEEK_SET)` and
  moves exactly `0x100` bytes (immediates `shl $0x8` + `movl $0x100` at 0x11a8/0x11b8 for reads
  and 0xf71/0xf85 for writes).
- **Expected RSA_public_decrypt return = 0x80 (128).** `cmp $0x80,%eax; jne fail` at 0x1205.
  On mismatch: log `"Decrypt lenght %d != SLOT_SIZE"` (0x1b70) and fail.
- Max valid index = **0xbff (3071)** — `cmpl $0xbff,idx; ja fail` at 0x14dd, error string
  `"%s: Index number '%d' is invalid! (Out of index)"` (0x1bb8).
  **0xC0000 bytes = 786,432 bytes = 768 KiB = 3,072 slots × 256 bytes.**
  This is the size info_setting creates at 0xda0, filled with 0xFF.
- **There is no magic value, no header, no file-size sanity check.** The first check on a slot is
  the RSA verify itself. The only pre-checks are: file opens, `fread` returns exactly 0x100, and
  index ≤ 0xbff.

### 2.3 The RSA call — exact arguments (verified: stack pushes at 0xd10–0xd37)

`RSA_public_decrypt(flen, from, to, rsa, padding)` is called at **0xd37** with:

- arg1 `flen` = caller-provided. 0xcb0 has exactly one call site (0x11fc, inside 0x1140), which
  hardcodes `movl $0x100,0x4(%esp)` at 0x11e5 → **flen is always 0x100 (256)**.
- arg2 `from` = the raw 256-byte slot,
- arg3 `to` = a stack buffer,
- arg4 `rsa` = the `PEM_read_bio_RSA_PUBKEY` result,
- **arg5 `padding` = a 32-bit word loaded from writable `.data` at `0x4204`**
  (`lea 0x274(%ebx),%edx; mov (%edx),%edx; mov %edx,0x10(%esp)` at 0xd10–0xd20).

`.data[0x4204]` = **`01 00 00 00` = RSA_PKCS1_PADDING (1)** — verified by direct byte dump.
**It is NOT RSA_NO_PADDING (3).**

So the slot is a standard **RSASSA-PKCS1-v1_5 style block**: `00 01 FF…FF 00 ‖ 128-byte message`,
2048-bit key (256-byte modulus). `RSA_public_decrypt` validates the v1.5 structure itself and
returns the recovered message length; info_setting requires it to be exactly 128.

**Malleability assessment (speculation-labeled, but the constraints are verified):**
with PKCS1 v1.5 *encrypt-format* verification there is no NO_PADDING-style "any 256 bytes are the
plaintext" malleability. Forging a slot that passes requires the RSA private key (or a
~2^-2030-style lucky block). The realistic weakness is not the padding — it is that:

- **the signature is not bound to the slot index or to any file path.** A 256-byte block that
  verifies in slot X verifies identically when copied to slot Y of either file (the plaintext
  just becomes that prop's value). Cross-slot replay inside `/factory/info` (which is 0777 and
  adb-shell-writable on the live device) is therefore trivial *content-wise* — the only gate for
  the backup path is that the native (misc) read must fail first (see §5).

### 2.4 Boot flow — exact order (verified call graph)

```
main (0x8f0), runs as root in init domain at every boot (oneshot):
  for (idx, name, default) in 7 registered pairs (see §8):
      0xb00:  ret = 0x14c0(idx, buf)                  // full read w/ fallback
              if ret == 0: property_set(name, buf)    // verified plaintext, 128B
              else:        property_set(name, default) // "" (empty), or "unknown" for ro.serialno
              if idx <= 4: log "ASUS_NVM: Write %s = %s\n" (tag INFO_SETTING:)
  0xbf0: property_get("ro.build.type", buf, "")       // default is the EMPTY string at 0x1778
         if buf == "eng" (3-byte cmpsb vs 0x184a + strlen==3):
              property_set("factory.product.device", "NoSetting")
         else: log "No ENG build, skip set factory info"
  return 0
```

0x14c0 (`asus_nvm_read`, tag `ASUS_NVM_TOOL: `):

```
asus_nvm_read(idx, out):
  if idx > 0xbff: log "Out of index"; return -1
  ret = 0x1420(out, idx)                       // native read = /dev/block/by-name/misc
  if ret == 0:
      log "%s: read native idx(%d) success" ("asus_nvm_read", idx)
      memcpy(out, plaintext, 0x80); return 0   // NOTE: also synced backup (see §5)
  log "%s: Index'%d' Can't get data, try to read backup data ..."   // ← BUGGY CALL, see below
  property_get("ro.build.type", buf, "")
  if buf == "eng":                             // ENG builds SKIP the backup entirely
      log "%s: Can not read index(%d) form native nvm! ENG! no try to read backup"
      return -1
  ret = 0x1360(out, idx)                       // backup read = /factory/info (+fix, §5)
  if ret == 0:
      log "%s: read backup idx(%d) success"; memcpy(out, plaintext, 0x80); return 0
  log "%s: fail to read backup data, give up!" ("get_backup_idx_value", idx)
  return -1
```

**Answer to "does it set ANY prop before the RSA check": NO.** All `property_set` calls happen
in 0xb00 only after 0x14c0 returns, i.e. after either (a) a slot passed RSA_public_decrypt with
exactly 128 bytes recovered, or (b) both reads failed and the prop gets the literal default
(`""` for 6 of 7 props, `unknown` for `ro.serialno`). No intermediate or unverified value
is ever put in a property. Garbage in `/factory/info` can therefore never become a prop value —
it can only (a) shift the boot to defaults, or (b) crash the process (next paragraph).

**Verified defect (crash):** on native-read failure the log call at **0x15ed** is built with
varargs `(%esp+0xc)=idx, (%esp+0x10)=idx` (0x1521 stale + 0x15ca) for the format
`"%s: Index'%d' Can't get data, try to read backup data ..."` — `%s` receives the *integer index*
as a `char*` (value 0…0xbff → unmapped page). The backup-read success log (0x166f) and the
ENG abort log (0x1743) have the same (idx, idx) shape; only the native-success log (0x1531)
passes the proper `"asus_nvm_read"` string. Consequence: **whenever the misc slot read fails and
the process reaches that log line, `info_setting` takes SIGSEGV in vsnprintf and the oneshot dies
before any property_set for that index.** (Speculation on exact libc behavior is minimal — the
vararg setup is verified byte-for-byte; the SEGV itself depends on vsnprintf dereferencing, which
is certain for bionic's log formatter.)
---

## 3. `misc` flows — every fopen of `/dev/block/by-name/misc` (verified: all call sites)

The path string sits once in .rodata at `0x198e`. Exactly two code paths use it:

| site | chain | mode | direction |
|---|---|---|---|
| 0x1463 → 0x1140@0x1187 | `asus_nvm_read` → 0x1420 → 0x1140 | `"r"` (0x19b6) | **READ** (native slot read) |
| 0x1106 → 0xf30@0xf53 | 0x1360 → 0x10c0 ("Fix") → 0xf30 | `"rb+"` (0x1919) | **WRITE** (slot repair) |

Both do `fseek(f, idx*0x100, SEEK_SET)` + transfer exactly 0x100 bytes + `fsync(fileno(f))`
(write path). There are no other opens of `misc`; raw `open/read/close` are dead imports.

### Can the misc WRITE run in a user build? — YES (verified control flow)

The gate is **inverted from what the strings suggest**. The string
`"%s: No support write function in user-build"` (0x1cd4) and `"asus_nvm_write"` (0x1d71) and
`"user"` (0x19d1) are **dead** — referenced by no code (verified by scanning every `lea`/`mov`/
`push` operand in the disassembly). The write-gating logic that survived compilation is the
`ro.build.type == "eng"` check inside `asus_nvm_read` (0x15f2–0x173b), and it guards the
*backup-read* branch, not the write:

- **user build:** native misc read fail → backup `/factory/info` read → on success
  → **0x10c0 writes the 256-byte slot into misc at `idx*0x100`** (logs `Fix index %d`,
  on failure `Fix idx %d fail`). No user-build gate exists on this path.
- **eng build:** native read fail → **returns -1 before any backup read or write**
  (`"ENG! no try to read backup"`).

### What is written, when, where

- **Bytes:** the raw 256-byte *ciphertext* slot exactly as read from `/factory/info` (the same
  buffer that just passed `RSA_public_decrypt`), NOT the 128-byte plaintext.
- **Offset:** `idx * 0x100` into `/dev/block/by-name/misc`, SEEK_SET. Boot-time indices are only
  the 7 registered ones → offsets **0x000, 0x100, 0x200, 0x300, 0x400, 0xE00, 0xF00**.
- **When:** at every boot, for each of the 7 indices whose misc slot fails to verify, provided
  the same index in `/factory/info` verifies.
- Slots 0–3 (0x000–0x3FF) overlay the standard Android `bootloader_message` (BCB: `command[32]`
  at 0x0, `status[32]` at 0x20, `recovery[768]` at 0x40 — public misc layout; device-specific
  partition size not inspected here). So an init-domain-root process *can* rewrite BCB-range
  bytes at boot — but the bytes it writes are constrained to a block that
  `RSA_public_decrypt(PKCS1)` accepts with the ASUS key (see §5 for why this is not a forge).

**Attack-value assessment (analysis, not device-verified):** to make this path fire you must
first make the *native* slot fail verification, i.e. corrupt `/misc` — which requires the very
root write you are trying to obtain, or pre-existing damage. And the bytes written are limited
to genuine signed 256-byte blocks already present in `/factory/info` (which the shell can
copy around freely, since the file is 0777). So info_setting is **not** a shell→init-BCB
privilege escalation by itself; its real exposure is the *index-unbound signature* (§5), which
lets signed NVM values be replayed into whichever property/index you choose once you can
influence either file. (Speculation beyond this is labeled in §5.)

**Practical caveat: the §2.4 vararg bug sits on this path.** The buggy `(idx, idx)` log at
0x15ed executes *before* the eng-check and the backup read. If bionic's log formatter faults on
`%s = (char*)idx` (as expected), then **on any device where a misc slot read fails, info_setting
dies at that log line and the backup read (0x164f) and the misc fix-write (0x10c0) are never
reached.** The whole §5(b) repair path would then be dead in practice. This needs one live test
(or a local replication of Android 6.0's `__android_log_print` path) to settle; the disassembly
facts themselves are verified.

---

## 4. Private key — dead in this binary (verified)

- `PEM_read_bio_RSAPrivateKey` and `RSA_private_encrypt` are imports **without** `.rel.plt`
  relocations — the binary contains no call to them (a call would need a PLT slot).
- The string `"Failed to read Private Key"` (0x1898) is referenced by no code.
- There is **no private-key path constant** anywhere in .rodata (full string table enumerated,
  §8); the only file paths are `/factory/info`, `/dev/block/by-name/misc`, and the four
  `/sys/...` strings which are *also* dead in this build (see below).
- The embedded PEM (`.data` 0x4040–0x4203, 451 bytes incl. trailing NUL at 0x4203) is the
  **public** key:

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzNyWRUKRdJ53QCpOxlYR
sWhMPu2SXQmg6iZxRZB4m4YgVIW7acI87Oj3GR59XFk/k6UKWMk1nw8k/eGZBYAB
LEatpOeG7pKcyHChzNyp5HIo1ssl7sklgBX3AnX2Agzo1qhuR+kJCNO2WIMv4Y6L
LO3MCT82wo19C7DVQxgrCG/ECDoxYCSAHWyo1bLdpXr0OjGeLAY1qwjO5pr+b8pS
x0tBEMJFOoVVIH0XDQuhWwfMzb2JYLiNDu9SqgHaikVUy5acpisTMXtmp78RHehd
3q0r0mNhLhrBNfNOdZH8G3M3Y7dOehuk7A5/1750aBjD1AV16yp033d/gT/oGSqM
MQIDAQAB
-----END PUBLIC KEY-----

(RSA-2048, exponent 65537 — verified by decoding the embedded DER:
SubjectPublicKeyInfo/rsaEncryption, modulus
`00ccdc96454291749e77402a4ec65611b1684c3eed925d09a0ea26714590789b86205485bb69c23cece8f7191e7d
5c593f93a50a58c9359f0f24fde1990580012c46ada4e786ee929cc870a1ccdca9e47228d6cb25eec9258015f702
75f6020ce8d6a86e47e90908d3b658832fe18e8b2cedcc093f36c28d7d0bb0d543182b086fc4083a316024801d6c
a8d5b2dda57af43a319e2c0635ab08cee69afe6fca52c74b4110c2453a8555207d170d0ba15b07cccdbd8960b88d
0eef52aa01da8a4554cb969ca62b13317b66a7bf111de85ddead2bd263612e1ac135f34e7591fc1b733763b74e7a
1ba4ec0e7fd7be746818c3d40575eb2a74df777f813fe8192a8c31`. Both binaries built with
`GCC: (GNU) 4.9 20140827 (prerel)` (+4.8 residue in .comment) — stock Android NDK.)

- `RSA_public_decrypt` is called only at 0xd37, only with this key.
- **Conclusion 4:** in this shipped binary the private key is unreachable: no file read, no
  PEM-private parser call, no `RSA_private_encrypt` call. The dead imports + dead strings
  (`"user"`, `"Encrypt fail! result:%d\n"`, `"%s: idx %d write fail"`,
  `"%s: write native idx(%d) success"`, `"asus_nvm_write"`,
  `"%s: No support write function in user-build"`, `"%s: Error write size %d (0<= write <= 128)"`,
  `"%s: write backup idx(%d) success"`, `"Failed to read Private Key"`) are the residue of an
  ENG/`#ifdef` signing+write path that was compiled out of the USER build. (Compiled-out
  interpretation: standard inference from dead imports+strings; the alternative — that a private
  key exists but is only used by another binary — is speculation.)
- Also unreferenced: the four `/sys/module/intel_mid_sfi/parameters/{pcb_id,project_id,
  hardware_id}` + `cpuinfo_max_freq` strings and `get CPU/PCB/PROJ/HW ID error` strings — the
  SoC-info-to-NVM provisioning code is compiled out too.
- 40 bytes of unreferenced data sit at `.data` 0x4000–0x4027
  (`40 41 34 36 25 49 29 02 0c 1c 15 09 03 00 03 02 65 64 4f 10 19 0a 00 19 0b 0b 4c 45 04 1d
  08 05 00 40 04 47 7d 4a 05 02`), followed by 24 zero bytes. No code reads them.
  *Speculation:* leftover of the compiled-out path (sized like a SHA-1 + something, or a small
  obfuscated blob); no evidence either way.

---

## 5. The fix path — what it writes and what gates it (verified)

Two repair flows exist, both inside the boot read path, both in **user** builds:

**(a) native → backup sync (0x1420 → 0x1050).** After a *successful* verified read of misc slot
idx, the raw 256-byte ciphertext is written to `/factory/info` at `idx*0x100` (`"rb+"`, fsync).
If `/factory/info` does not exist, 0xda0 first creates it: 786,432 bytes of 0xFF
(`memset(buf,0xFF,0xC0000)`, `"w+"`, fwrite, fsync) and — **on every invocation, even when the
file already existed — `chmod(path, 0777)`** (0xe63–0xe6e, immediate `$0x1ff`).
This explains the on-device observation that `/factory/info` is 0777 root:root.

**(b) backup → native fix (0x1360 → 0x10c0).** When the native misc read fails and the build is
not eng, the `/factory/info` slot is read (verified, §2), then its raw 256-byte ciphertext is
written into misc at `idx*0x100` (`"rb+"`, fsync), logging `Fix index %d` /
`Fix idx %d fail`. **Same §2.4 crash caveat as §3 applies:** the buggy log at 0x15ed runs before
this branch, so on a real fault the fix-write never executes.

**Integrity gating of the fix content:** the SAME `RSA_public_decrypt` path (0x1140 → 0xcb0)
gates the backup slot; there is **no CRC, no size check, no secondary weaker check**. The fix
only ever copies a block that already passed full verification. So "the backup slots are weakly
checked" is false — but the scheme has a different structural weakness:

**The signature is not bound to the index or the file.** `RSA_public_decrypt` sees only the
256-byte block; the index exists solely as the `fseek` offset chosen by the caller. Any verified
block from anywhere in the 3072-slot `/factory/info` file (or from misc, if readable) can be
copied to any slot position of either file and will verify. `/factory/info` is 0777 and
shell-writable on the live device, so replay *into* `/factory/info` is trivial; the remaining
hurdle for making the tool *consume* a replayed slot is making the corresponding misc slot fail
first (root required) — or natural misc damage. On the property side the reward would be
controlling `ro.serialno` / `ro.isn` / `ro.config.*` with any signed 128-byte message found in
the file. (What signed messages exist in `/factory/info` beyond the 7 in-use slots is a
device-side question — static analysis cannot enumerate them;
labeled speculation.)

**Fix-write in user builds inside the boot read path: YES** for both directions ((a)
unconditionally after every successful native read of the 7 indices; (b) when native fails and
backup verifies). ENG builds do (a) only.

---

## 6. VerifyVouchers — complete protocol (verified)

Single worker (0x680) called from `main` (0x550); imports are only
`fopen/fread/fgetc/fclose/malloc/exit/property_set/__android_log_print` (all live via
`.rel.plt`; **no crypto, no open/read/close, no writes of any kind**).

```
check():
  buf[600] on stack (0x96 dwords zeroed @ ebp-0x274)
  f = fopen("/factory/Voucher_enc.bin", "rb")            // 0xA87, mode "rb" @0xA84
  if (!f):
      log("set property atd.voucher.exist: %d\n", 0)     // fmt @0xad8, tag = NULL
      property_set("atd.voucher.exist", "0")
      exit(0)                                            // oneshot ends quietly
  log("set property atd.voucher.exist: %d\n", 1)
  property_set("atd.voucher.exist", "1")                 // exist = "1" on mere open success
  hdr  = (fgetc(f) & 0xff) << 8 | (fgetc(f) & 0xff)      // big-endian 16-bit checksum field
  n    = fread(buf, 1, 0x258 /*600*/, f)                 // payload, max 600 bytes
  out = malloc(n + 1)                                    // called before the n==0 test; 1-byte leak if n==0
  if (n == 0) { fclose(f); ok = (hdr == 0); goto verdict; }
  for i in 0..n-1:                                        // XOR "decryption"
      k = key[i % 580]                                   // key = .rodata 0xb40, 580 bytes
      d = buf[i] ^ k
      out[i] = d ? d : buf[i]                            // zero result → keep ciphertext byte
  fclose(f)
  sum = Σ out[i]  (32-bit; SSE 16-byte-block accumulate + scalar tail, exact sum of n bytes)
verdict:
  ok = (hdr == sum)                                      // cmp @0x974, sete
  log("set property atd.voucher.intact: %d\n", ok)       // fmt @0xafc
  if ok:  property_set("atd.voucher.intact", "1"); property_set("atd.voucher.ready", "1")
  else:   property_set("atd.voucher.intact", "0"); property_set("atd.voucher.ready", "0")
```

- **File format** (`/factory/Voucher_enc.bin`): `[u16be checksum][≤600 XOR-"encrypted" bytes]`.
  Checksum = plain 32-bit **sum of the decrypted bytes**, compared against the 16-bit header —
  so any payload whose byte-sum ≥ 65536 can never validate, and there is **no keyed MAC**: the
  "integrity" is a 16-bit additive checksum and the cipher is XOR with a **static embedded key**
  (`.rodata` 0xb40–0xd83, 580 bytes, fully recoverable from the binary; the key exhibits strong
  self-similarity — 265/325 bytes match under a 255-byte shift — suggesting a generated/
  periodic key, exact generator not identified: labeled speculation). Both header and payload
  are attacker-choosable → **the intact/ready verdict is forgeable by anyone who can write the
  file.** (DAC says the file is 0600 system:system, so on the live device shell cannot write it;
  that is the only thing standing between shell and a forged verdict.)
- **Corner case (verified):** the n==0 branch (taken iff the file is ≤ 2 bytes, i.e. fread got
  nothing past the header) runs at 0xa09/0xa12 → `ok = (hdr == 0)`. Checking the EOF arithmetic:
  a 0-byte file gives `hdr = 0xFFFFFEFF` and a 1-byte file gives `(b0<<8)-1`, both ≠ 0 → fail.
  **Exactly a 2-byte file `00 00` yields `hdr == sum == 0` → `exist=1, intact=1, ready=1`.**
- **Property values:** always the strings `"0"` (0xa80) / `"1"` (0xa82) — verified at
  0x719/0x9b5/0x9c9/0xa00/0x9c9.
- **Ordering vs info_setting:** VerifyVouchers is triggered by `on property:sys.boot_completed=1`
  (per the init rc, disabled by default), so it always runs **after** info_setting's boot-time
  work. There is no shared file and no shared property; the two never interact.
- **Anything else opened/written:** nothing — one fopen, no other I/O; `exit(0)` on missing file.

**Assessment:** VerifyVouchers is factory/ATD plumbing. Its props (`atd.voucher.*`) feed the
Automated Test infrastructure; they do not gate unlock. Its verdict rests on an unkeyed 16-bit additive checksum + static XOR key.

---

## 7. exec behavior (verified: complete `.dynsym` × `.rel.plt` walk for both binaries)

- **info_setting:** imports = the 33 symbols listed in §1. No `execve`/`execl*`/`system`/
  `popen`/`fork`/`posix_spawn`/`dlopen`/`dlsym`. No `socket`/`connect`. Nothing is executed;
  the only outbound actions are property_set + file I/O + log.
- **VerifyVouchers:** imports = 13 symbols (§6). Same conclusion; `exit` is its only "action"
  beyond props/log.
- Both binaries' `.init_array`/`.preinit_array` contain the standard bionic
  `__libc_init`/atexit/stack-guard plumbing only (verified: the arrays at 0x3e44–0x3e54 /
  0x2e88–0x2e98 hold pointers to the small crt stubs disassembled at 0xa3a/0xa4e/0xa88 and
  0x5c2/0x5d6/0x610 respectively — no hidden constructors).

**Conclusion 7: neither binary executes anything.**

---

## 8. Property-name constant table (verified: .rodata VAs, all `lea(%ebx)` sites)

### info_setting — live (set or read) properties

| .rodata VA | string | role | set when |
|---|---|---|---|
| 0x1779 | `ro.isn` | prop for NVM slot **0** (default `""`) | 0xb00 (7 calls, 0x913–0x9c4) |
| 0x1788 | `ro.serialno` | prop for NVM slot **1** (default `"unknown"` @0x1780) | 0xb00 |
| 0x1794 | `ro.config.versatility` | slot **2** (default `""`) | 0xb00 |
| 0x17aa | `ro.config.CID` | slot **3** (default `""`) | 0xb00 |
| 0x17b8 | `ro.config.idcode` | slot **4** (default `""`) | 0xb00 |
| 0x17c9 | `ro.config.packingcode` | slot **14** (0xe) (default `""`) | 0xb00 |
| 0x17df | `ro.config.datecode` | slot **15** (0xf) (default `""`) | 0xb00 |
| 0x183c | `ro.build.type` | read by 0xbf0 and 0x14c0 (user/eng gates) | — |
| 0x1858 | `factory.product.device` | set to `"NoSetting"` @0x184e on **eng** builds only | 0xbf0 |

Slot→property mapping is deterministic: value = the 128-byte RSA-verified plaintext, used as a
C string (`property_set` copies up to the first NUL).

### info_setting — log/format constants (for cross-reading logs)

| VA | string |
|---|---|
| 0x1750 | `ASUS_NVM: Write %s = %s\n` (fmt, tag INFO_SETTING: @0x1769) |
| 0x1888 | `ASUS_NVM_TOOL: ` (tag) |
| 0x1964 / 0x198e | `/factory/info` / `/dev/block/by-name/misc` |
| 0x1b4c | `No ENG build, skip set factory info` |
| 0x1b70 | `Decrypt lenght %d != SLOT_SIZE` |
| 0x1bb8 / 0x1bec / 0x1c28 / 0x1c70 / 0x1b90 / 0x1c94 / 0x1cb4 | read-path messages (§2.4) |
| 0x1981 / 0x19a6 / 0x1972 | `Fix index %d` / `Fix idx %d fail` / `%s: copy fail\n` |
| 0x18e0 / 0x18fe / 0x191d / 0x1932 / 0x194a | file-creation/sync error messages |
| 0x1d80 / 0x1d8e / 0x1da3 / 0x1db3 | `asus_nvm_read` / `get_backup_idx_value` / `write_to_backup` / `copy_buf_idx` (the `%s` function-name args) |

### VerifyVouchers

| VA | string | role |
|---|---|---|
| 0xaa0 | `atd.voucher.exist` | `"1"` if fopen succeeded, else `"0"` + exit(0) |
| 0xab2 | `atd.voucher.intact` | `"1"` iff hdr == Σ decrypted bytes |
| 0xac5 | `atd.voucher.ready` | same condition as intact (always equal) |
| 0xad8 / 0xafc | `set property atd.voucher.exist: %d\n` / `set property atd.voucher.intact: %d\n` | log fmts (tag NULL) |
| 0xa80 / 0xa82 | `0` / `1` | the only values ever set |
| 0xb40–0xd83 | 580-byte XOR key | static, embedded, extractable |

---

## 9. Relevance to the implemented unlock

1. **ro.serialno / ro.isn / ro.config.* are RSA-2048 PKCS1-v1.5 signed values living on
   `/misc` (native) with a shell-writable mirror on `/factory/info` (backup, 0777).** Without
   the private key you cannot mint new values; with a shell-writable `/factory/info` you can
   *replay* any already-signed block into any slot. **But consuming a replayed slot requires the
   native misc read to fail first, and the §2.4 vararg bug sits between those two events** —
   if bionic's `%s` on a tiny integer faults (expected), the oneshot SIGSEGVs before the backup
   read ever runs, making both the property-fallback path and the misc fix-write unreachable in
   practice on any misc-damaged boot. Open question for the live device; everything else here is
   verified from the binaries. Note the same crash also fires on the *legit* fallback path —
   i.e. a device with naturally blank misc slots would already be showing
   `init: process 'info_setting' killed by signal 11` at every boot (testable observation).
2. **BCB control via the fix path is not a practical shell→init escalation**: trigger requires
   root, content requires a valid ASUS signature, offsets are the 7 fixed slot offsets, and —
   per (1) — the path may not even execute past the buggy log on a native-fail boot.
3. **VerifyVouchers is cosmetic** (unkeyed 16-bit additive checksum + static embedded XOR key);
   verdict forgeable by anyone who can write `/factory/Voucher_enc.bin`, which DAC (0600
   system:system) currently prevents for shell. Its props are ATD test flags, not unlock gates.
4. **No private key, no signing, no exec in either binary.** The only root-writable surfaces at
   boot are: misc slots 0/1/2/3/4/14/15 (via fix path, §5b), `/factory/info` (create + chmod
   0777 + slot sync, §5a), and the seven properties themselves.
5. **For the dirtycow/root goal specifically:** info_setting does not provide a root primitive,
   but it (a) maintains `/factory/info` at 0777 at every boot — a guaranteed shell-writable,
   init-verified data mirror that survives factory resets only as long as misc does, and (b)
   demonstrates the NVM trust model (per-slot PKCS1 signatures, index-unbound).
   Those signatures govern info_setting's NVM slots, not the separate FRP byte
   accessed by the final payload. Two research questions remain: enumerate
   which of the 3072 `/factory/info` slots actually contain verifying blocks (device-side), and
   settle the log-crash question (live or emulated bionic).
