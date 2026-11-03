# TSRA PKCS#11 module

A standalone **PKCS#11 (Cryptoki) v3.1** module for the TSRA. It links the
native C API (`tsra.h`, generated from `api/native`) the same way
`plugins/ossl_prov` does.

## Status: digests, AES keys and ciphers, host objects

Unimplemented PKCS#11 entry points return `CKR_FUNCTION_NOT_SUPPORTED` (after
`C_Initialize`; before it every entry point other than `C_Initialize` and the
function-list / interface queries reports `CKR_CRYPTOKI_NOT_INITIALIZED`, as
the spec requires). Implemented so far:

- **Library / slots / sessions** — `C_Initialize`, `C_GetInfo`, slot/token/
  mechanism enumeration (real TSRA partitions become slots), sessions and the
  login state machine, and the `C_GetInterface` "PKCS 11" interface.
  `C_GetMechanismList` reports only the ten mechanisms below, and
  `C_GetTokenInfo` the real session counts (at most 256 sessions).
- **`C_Login`**: runs the TSRA provisioning ceremony and opens one device
  session for the token. Provisioning is done lazily: login opens a device
  session and provisions the partition only if the device reports it is not
  yet provisioned (provisioning is one-shot per power cycle; a session is the
  repeatable per-login primitive). Login state is per token, so every PKCS#11
  session of the slot shares that one device session. It closes at
  `C_Logout`, when the slot's last session closes, and at `C_Finalize`.
- **Host objects** — `C_CreateObject` / `C_DestroyObject` / `C_GetAttributeValue`
  / `C_SetAttributeValue` / `C_GetObjectSize` / `C_FindObjects*` against the
  host object store: in memory, or token objects in files with
  `TSRA_PKCS11_PERSIST` (see Configuration). `C_SetAttributeValue` changes
  only the attributes PKCS#11 marks modifiable for the object's class (label,
  ID, dates, usage flags), and applies a template all-or-nothing; on keys
  `CKA_SENSITIVE` can only become TRUE and `CKA_EXTRACTABLE` only FALSE.
  `C_GetObjectSize` reports the bytes of the attribute values plus the masked
  key body. `C_CopyObject` is not implemented.
  A session object is destroyed when the session that created it closes;
  token objects outlive it. (`C_Logout` does not yet destroy private session
  objects — it only hides them until the next login.)
- **`C_Digest*` (SHA-1/256/384/512)** — host-side digests (one-shot and
  multi-part); every other digest mechanism returns `CKR_MECHANISM_INVALID`.
- **`C_GenerateKey` (`CKM_AES_KEY_GEN`, `CKM_AES_XTS_KEY_GEN`)** — generates a
  key on the device and stores its **masked blob** (the TSRA key's only
  durable form) as the object's key body. The device has three disjoint AES key
  kinds, so the template picks one, and the key records it as
  `CKA_ALLOWED_MECHANISMS`:

  | Mechanism and template | Key | `CKA_KEY_TYPE` | `CKA_VALUE_LEN` |
  |---|---|---|---|
  | `CKM_AES_KEY_GEN` | AES for `CKM_AES_CBC` / `_CBC_PAD` | `CKK_AES` | 16, 24, 32 |
  | `CKM_AES_KEY_GEN` + `CKA_ALLOWED_MECHANISMS = { CKM_AES_GCM }` | AES-GCM | `CKK_AES` | 32 |
  | `CKM_AES_XTS_KEY_GEN` | AES-XTS | `CKK_AES_XTS` | 64 |

  PKCS#11 has no GCM key-generation mechanism, hence the allowed-mechanism
  list; a list mixing families (GCM with CBC) is refused. A caller's narrower
  list (`{ CKM_AES_CBC }`) is kept and enforced. Generated keys are always
  sensitive, unextractable and local — a template asking otherwise is rejected
  (note: OpenSC `pkcs11-tool --keygen` needs its `--sensitive` flag for this
  reason).
- **`C_Encrypt` / `C_Decrypt` one-shot (`CKM_AES_CBC`, `CKM_AES_CBC_PAD`,
  `CKM_AES_GCM`, `CKM_AES_XTS`)** — each `C_EncryptInit`/`C_DecryptInit`
  unmasks the stored blob into a fresh session-scoped device key that lives
  exactly as long as the operation; a key serves only its own family. Input and
  output may be the same buffer; the binding stages the input whenever the two
  ranges overlap, because the native API cannot hold a read and a write slice
  over the same bytes.
  - GCM takes `CK_GCM_PARAMS` with a 12-byte IV and a 128-bit tag only (the
    device supports no other sizes) and optional AAD. The tag is appended to
    the ciphertext. A failed tag check currently reports
    `CKR_FUNCTION_FAILED`: the SDK delivers it as a generic device-command
    failure that the module cannot tell apart from a device fault.
  - XTS takes the 16-byte tweak (little-endian sector number, below 2^64 - 1:
    see Deviations) and encrypts the whole message as one data unit, which
    the device caps at 8 KiB: a message must be a non-zero multiple of 16
    bytes up to 8192.

- **Multi-part `C_EncryptUpdate` / `C_EncryptFinal` and `C_DecryptUpdate` /
  `C_DecryptFinal` (the same four mechanisms)**: the one-shot lifetime rules
  apply, and one operation cannot mix one-shot and multi-part calls
  (`CKR_OPERATION_ACTIVE`). The result always equals the one-shot result.
  - CBC and CBC-PAD run through the SDK's stream context. It holds back the
    last full block until the final call, even without padding, so an
    update's output trails its input by up to one block (the spec allows
    that). A sizing probe on an update reports an upper bound, because the
    SDK's own sizing call would already consume the data.
  - GCM and XTS buffer the parts and run the one-shot operation at the final
    call. The device has no incremental GCM or XTS, the SDK's GCM decrypt
    needs the tag before the data, and a PKCS#11 XTS operation is one data
    unit. So their updates return no output, a GCM decrypt releases no
    plaintext before the tag is checked, and the one-shot size limits apply to
    the sum of the parts.
  - The OpenSSL provider works around the same SDK constraints
    (`plugins/ossl_prov/src/tsra_ossl_cipher.c`).

  The other key-backed mechanisms (RSA/ECDSA, wrap/unwrap, derive) are not
  implemented yet.
- **Ending an operation**: `C_DigestInit`, `C_EncryptInit` and
  `C_DecryptInit` with a NULL mechanism end the session's active operation of
  their kind (and return `CKR_OK` when there is none), and `C_SessionCancel`
  ends the operations its flags name.

## Deviations from PKCS#11

- **No random-number generator.** The device offers the host none, so the
  token does not set `CKF_RNG`, and `C_GenerateRandom` and `C_SeedRandom`
  return `CKR_RANDOM_NO_RNG`.
- **An AES-GCM key is a key kind of its own.** The device keeps CBC, GCM and
  XTS keys apart, so a key serves only its own family (table above). A GCM key
  is requested with `CKA_ALLOWED_MECHANISMS = { CKM_AES_GCM }` at generation;
  with OpenSC: `pkcs11-tool --keygen --key-type aes:32 --sensitive
  --allowed-mechanisms AES-GCM`. A key generated without that list is a CBC
  key, and `CKM_AES_GCM` on it returns `CKR_KEY_FUNCTION_NOT_PERMITTED`. In
  PKCS#11 an AES key without the attribute serves every AES mechanism.
- **GCM IV uniqueness is the caller's duty.** The caller supplies the 12-byte
  IV in `CK_GCM_PARAMS`, and neither the module nor the device checks that an
  IV is never reused with the same key. The message-based API, in which a
  token can generate the IVs, is not implemented.
- **XTS tweaks are 64-bit.** The tweak, read as a little-endian 128-bit
  integer, must be below 2^64 - 1: its upper 8 bytes zero and its lower 8 not
  all 0xFF, so the device can advance it past the data unit. Any other tweak
  returns `CKR_MECHANISM_PARAM_INVALID`, where PKCS#11 allows any 16 bytes.

## Layering

| Layer | Files | Responsibility |
|---|---|---|
| C ABI | `tsra_pkcs11_dispatch.c` | `CK_FUNCTION_LIST` + `_3_0` + the "PKCS 11" interface |
| Framework | `tsra_pkcs11_module.c`, `tsra_pkcs11_slot.c`, `tsra_pkcs11_session.c`, `tsra_pkcs11_mech.c` | init, slots, sessions, login, operation state machine; the mechanism table is a device-free unit of its own |
| Host crypto | `tsra_pkcs11_digest.c` | self-contained SHA-1/256/384/512 (PKCS#11 digests must work in public sessions; the SDK digest needs a login) |
| Object store | `tsra_pkcs11_objstore.h`, `tsra_pkcs11_objstore_mem.c` | host-side objects behind a vtable seam; the in-memory backend |
| File store | `tsra_pkcs11_objstore_file.c`, `tsra_pkcs11_store_record.c`, `tsra_pkcs11_store_io.c` | the persistent backend for token objects (session objects stay in memory): one record file per object, the record codec, and the crash-safe, owner-only filesystem primitives with a cross-process lock |
| Object policy | `tsra_pkcs11_attr_policy.c` | which attributes `C_SetAttributeValue` may change, per class; a device-free unit of its own |
| Key operations | `tsra_pkcs11_crypt.c`, `tsra_pkcs11_template.c` | key-backed entry points: operation state and the masked-blob store/unmask flow (CK_RV only); the keygen template validation, key-family choice and cipher mechanism policy are a device-free unit of their own |
| HSM binding | `tsra_pkcs11_hsm.c`, `tsra_pkcs11_key.c`, `tsra_pkcs11_status.c`, `tsra_pkcs11_config.c` | the only code that calls `tsra_*` and maps `tsra_status` → `CK_RV` |
| Not implemented | `tsra_pkcs11_stubs.c` (generated) | everything else → `CKR_FUNCTION_NOT_SUPPORTED` |

The object store is the emulation layer PKCS#11 requires and the device does not
provide (no persistent, attribute-templated, searchable key store). It is fronted
by the `tsra_pkcs11_objstore` vtable, so the in-memory and the file backend
serve the same callers.

## Build

```sh
# Against the simulator / mock DDI (no physical device):
cargo build -p tsra_pkcs11 --features mock
# -> target/debug/tsra_pkcs11.so

# Standalone (no device linked) framework smoke build:
gcc -shared -fPIC -Iinclude/pkcs11-v3.1 src/*.c -o tsra_pkcs11.so -lpthread
```

`build.rs` drives CMake, which imports `tsra_api_native` via Corrosion and
generates `tsra.h` with cbindgen.

`include/pkcs11-v3.1/` holds the OASIS PKCS #11 v3.1 headers, vendored
unmodified under their own copyright; see the `NOTICE` file there. The
copyright check skips that directory.

## Configuration

Credentials are read from the environment (`TSRA_PKCS11_ID` /
`TSRA_PKCS11_PIN`, each 32 hex characters); simulator defaults are used when
unset. Set `TSRA_PKCS11_DEBUG=1` for stderr tracing.

Token objects live in memory and end with the process unless
`TSRA_PKCS11_PERSIST=1` (or `true`) selects the file store. It keeps them
under `TSRA_PKCS11_STORE_DIR` (default `/var/lib/tsra/pkcs11`; a `file:`
prefix is accepted), one subdirectory per slot. The module creates a missing
directory with mode 0700 (its parent must exist) and refuses an existing one
that is not a directory the calling user owns with mode 0700, so
`C_Initialize` fails. A `TSRA_PKCS11_STORE_DIR` that is empty, contains `..`
or is longer than 4095 bytes makes `C_Initialize` return `CKR_ARGUMENTS_BAD`,
with or without `TSRA_PKCS11_PERSIST`, instead of falling back to the
default.

## Testing

`tests/run_validation.sh` builds the module and drives it with OpenSC
`pkcs11-tool` (interactive smoke). Pure host logic has device-free unit tests
that link the translation unit directly: `tests/digest_kat_test.c` (NIST
vectors), the object-store harnesses, and `tests/aes_template_test.c` (the
complete CK_RV matrix of the keygen template validation and defaults, the
key-family choice and cipher mechanism policy, CK_GCM_PARAMS decoding, the
GCM/XTS output-length plan and the status maps; built with UBSan, so the
misaligned templates and parameter blocks it feeds the decoders are real
checks), `tests/attr_policy_test.c` (every `C_SetAttributeValue` verdict,
per object class), `tests/mech_table_test.c` (the mechanism table against
the dispatch arms, in both directions) and `tests/config_test.c` (the
environment configuration). `integration-tests/cpp/` is the functional suite
(GoogleTest, same shape as the OpenSSL provider's): it `dlopen`s the built
module and drives the real Cryptoki ABI: keygen including the GCM/XTS key
families, one-shot CBC, GCM and XTS round trips, the two-call sizing
discipline, the operation state machine and init precedence, an init path
for every advertised mechanism, attribute changes and object sizes, and the
store configuration at `C_Initialize`. So it needs the mock- or
hardware-backed build (see the CMakeLists.txt header for
the build/run recipe; `TSRA_PKCS11_MODULE` points it at a module,
`TSRA_PKCS11_TEST_PIN` overrides the simulator PIN). `tests/pkcs11test/` is
the conformance gate: it builds Google's PKCS#11 conformance program at a
pinned revision and requires every test on its include-list to pass, which is
how spec behaviour is kept from regressing as pieces land (the list grows with
them — see the README there). The CI workflow
(`.github/workflows/pkcs11.yml`) runs all of these on pushes/PRs to the
staging branch: the unit harnesses under UBSan and under ASan
(`tests/build_units.sh`), and the functional suite on the memory store, on the
file store (`TSRA_PKCS11_PERSIST=1`) and against an ASan build of the module.
`tests/HARDWARE.md` lists what only a device can show, and how to run the same
suites on one.
