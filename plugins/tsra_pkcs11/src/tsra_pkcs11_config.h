// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "tsra_pkcs11_compat.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define P11_CREDS_ID_LEN 16
#define P11_CREDS_PIN_LEN 16
#define P11_OBK_LEN 48

/* Environment variables consulted by tsra_pkcs11_config_load(). */
#define TSRA_PKCS11_ENV_ID "TSRA_PKCS11_ID"
#define TSRA_PKCS11_ENV_PIN "TSRA_PKCS11_PIN"

/* Persistent host object store: opt-in file backend rooted at a store directory.
 * The backend is enabled by TSRA_PKCS11_PERSIST and rooted at
 * TSRA_PKCS11_STORE_DIR, defaulting to a dedicated directory when unset. */
#define TSRA_PKCS11_STORE_DIR_LEN 4096
#define TSRA_PKCS11_ENV_STORE_DIR "TSRA_PKCS11_STORE_DIR"
#define TSRA_PKCS11_ENV_PERSIST "TSRA_PKCS11_PERSIST"
#define TSRA_PKCS11_DEFAULT_STORE_DIR "/var/lib/tsra/pkcs11"

/*
 * Provisioning inputs the module supplies to the TSRA ceremony, plus the host
 * object-store settings. The partition identifier and owner backup key are
 * operator/token-install configuration; the per-login PIN comes from C_Login,
 * and `default_pin` is only the fallback used when a caller logs in without one.
 */
typedef struct
{
    CK_BYTE id[P11_CREDS_ID_LEN];
    CK_BYTE obk[P11_OBK_LEN];
    CK_BYTE default_pin[P11_CREDS_PIN_LEN];
    char store_dir[TSRA_PKCS11_STORE_DIR_LEN]; /* persistent object-store root */
    bool store_persist;                        /* select the file backend over in-memory */
} tsra_pkcs11_config;

/*
 * Populate `cfg`. Credentials are taken from the environment only
 * (TSRA_PKCS11_ID / TSRA_PKCS11_PIN, each 32 hex chars = 16 bytes); mock
 * defaults are used for anything unset or malformed so the module is usable out
 * of the box against the simulator. The store directory is
 * TSRA_PKCS11_STORE_DIR with an optional "file:" prefix, or
 * TSRA_PKCS11_DEFAULT_STORE_DIR when the variable is unset. Returns
 * CKR_ARGUMENTS_BAD when the variable is set but empty, contains "..", or does
 * not fit store_dir: a bad setting fails closed instead of falling back to the
 * default. The caller clears `cfg` on either outcome.
 */
CK_RV tsra_pkcs11_config_load(tsra_pkcs11_config *cfg);

/*
 * Wipe `cfg` (credential id, OBK, and PIN bytes). Callers must clear a loaded
 * config as soon as it is no longer needed, on success and error paths alike;
 * the wipe is not elided for stack objects about to leave scope.
 */
void tsra_pkcs11_config_clear(tsra_pkcs11_config *cfg);

#ifdef __cplusplus
}
#endif
