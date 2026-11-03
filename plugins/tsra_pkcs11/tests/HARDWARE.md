# Hardware checklist

Every module test runs against the mock device. Some behaviour is decided by
the firmware and cannot be shown on the mock: credential checks, retry limits,
provisioning races, capacities, power-cycle survival, firmware crypto paths.
This file lists those items with the result expected on hardware, so a run on
a device is a run, not a design session.

## Running the suites on hardware

The test binaries are the same as in CI. Everything the run needs comes from
the environment:

| Variable | Meaning |
|---|---|
| `TSRA_PKCS11_HW=1` | The module drives a real device. Cases named `*_hw` run; mock-only cases skip. |
| `TSRA_PKCS11_MODULE` | Path of the hardware-backed `tsra_pkcs11.so`. |
| `TSRA_PKCS11_TEST_PIN` | The user PIN of the partition (default: the simulator's `1234`). |
| `TSRA_PKCS11_PERSIST=1`, `TSRA_PKCS11_STORE_DIR` | The file object store, in a directory that does not exist yet. |

```sh
export TSRA_PKCS11_HW=1 TSRA_PKCS11_MODULE=/path/to/tsra_pkcs11.so TSRA_PKCS11_TEST_PIN=...
ctest --test-dir <gtest-build-dir> --output-on-failure --output-junit gtest-mem.xml
TSRA_PKCS11_PERSIST=1 TSRA_PKCS11_STORE_DIR="$PWD/store" \
    ctest --test-dir <gtest-build-dir> --output-on-failure --output-junit gtest-file.xml
plugins/tsra_pkcs11/tests/pkcs11test/run.sh "$TSRA_PKCS11_MODULE" "$PWD/pkcs11test"
```

The GoogleTest results land in the JUnit files, the pkcs11test log in
`<work-dir>/run.log`. Any difference from the mock result is a finding, not a
reason to change the include-list.

In the GoogleTest suite a hardware-only case is named `*_hw` and starts with
`HW_ONLY("why")`; it is skipped with that reason unless `TSRA_PKCS11_HW=1`. A
case that pins a mock-only model starts with `MOCK_ONLY("why")` and is skipped
on hardware (`integration-tests/cpp/utils/module.hpp`).

## Checklist

Record the firmware version and the platform before anything else, for every
run. Each item says what to do, what to expect, which cases cover it today,
and the result of the last hardware run.

### H-a Firmware, platform and key survival

- Run: generate AES keys, encrypt with CBC, GCM and XTS, `C_Logout`,
  `C_Login`, encrypt again.
- Expect: the same ciphertexts after the login. Round trips only, until keys
  can be imported for known-answer tests. Firmware older than the key
  generation enablement fails at key generation.
- Cases: `key_survival.*`, `aes_cbc.logout_tears_down_the_active_operation`
  (skipped while B1 is open: the key blob dies with the device session at
  `C_Logout`).
- Result: not run yet.

### H-b Provisioning through C_Login on a fresh partition

- Run: the first `C_Login` on a partition nobody has provisioned.
- Expect: `CKR_OK`. The caller endorsement the module builds at run time (a
  fresh P-384 key from host libcrypto) passes the device's PKA check; the
  simulator checks it in software only.
- Result: not run yet.

### H-c Provisioning race

- Run: two processes perform the first `C_Login` at the same time. Then kill
  a process between the BK3 initialisation and the credential setup.
- Expect: one process wins; the other gets "BK3 already initialised" (-41)
  and a clean `CK_RV` from `C_Login`. After the kill, record whether every
  later `C_Login` fails until a power cycle.
- Result: not run yet.

### H-d Second process on a provisioned partition

- Run: a second process logs in with the same PIN, another PIN and an empty
  PIN, and uses a token key the first process created.
- Expect: the same PIN logs in; another PIN fails with `CKR_FUNCTION_FAILED`
  (not `CKR_PIN_INCORRECT` until the SDK names the status); the token key
  works in the second process. The mock cannot show the last part: it
  provisions every process afresh.
- Cases: `persist.a_second_process_sees_the_token_object` (the object, not
  the key).
- Result: not run yet.

### H-e Power cycle and NSSR

- Run: create token keys, power-cycle the device (and separately reset it
  with NSSR), log in, use the keys.
- Expect: fails today, with the keys unusable (-26), until the module
  replays the backup masking key and the owner backup key at
  re-provisioning. With both replayed and the same endorsement key the keys
  come back; with a fresh endorsement key they do not.
- Result: not run yet.

### H-f First login wins

- Run: after power-on, log in from an arbitrary local process with an
  arbitrary PIN; try wrong PINs repeatedly; check the device node's
  permissions; after a reset, log in with any PIN once the backup keys are
  replayed.
- Expect: the first `C_Login` sets the credential, so the device node's
  permissions are the trust boundary. Record whether the device limits failed
  attempts (the simulator does not), and whether the first login after a
  reset takes over the old keys with any PIN.
- Result: not run yet.

### H-g Partition after the last file descriptor closes

- Run: provision, close every handle to the device, open it again, log in.
- Expect: unknown; record whether the partition stays provisioned.
- Result: not run yet.

### H-h Capacity across processes

- Run: start processes that log in and hold their session until `C_Login`
  refuses; end one; log in again. Fill the key table the same way.
- Expect: a clean `CK_RV` at the limit and a successful login after one
  holder ends. No fixed number: firmware and mock differ.
- Result: not run yet.

### H-i Killed processes

- Run: create token keys, `kill -9` the process, repeat.
- Expect: record whether device key entries stay until a partition reset.
- Result: not run yet.

### H-j Fork

- Run: fork a child from a process with an open device session; use the
  session in the parent afterwards.
- Expect: the parent's device session is unharmed; the child starts fresh.
- Result: not run yet.

### H-k Firmware crypto paths

- Run: an over-long ECDSA digest on the PKA, the XTS key container, GCM keys
  unwrapped over MBOR, a 16-byte XTS tweak against an 8-byte little-endian
  sector number.
- Expect: the same results as on the mock and the host references.
- Result: not run yet.

### H-l RSA decryption timing

- Run: time RSA decryption of valid and invalid PKCS#1 v1.5 and OAEP
  ciphertexts (Bleichenbacher, Manger). Optional before general availability.
- Expect: no timing difference an attacker can use.
- Result: not run yet.

### H-m External tools

- Run: pkcs11-check against an externally provisioned token; pkcs11-provider
  TLS with a token EC key; `p11perftest -n`.
- Expect: the same verdicts as on the mock.
- Result: not run yet.
