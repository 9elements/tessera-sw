// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "tsra_pkcs11_config.h"
#include "tsra_pkcs11_wipe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Staging bound for hex_decode; must cover the largest tsra_pkcs11_config field
 * (P11_OBK_LEN). */
#define P11_HEX_DECODE_MAX 64

/* Decode exactly `bytes` bytes from a 2*bytes hex string. Returns 0 on success,
 * -1 if the string is the wrong length or contains a non-hex character. `out` is
 * written only on full success (via a local staging buffer), so a malformed
 * value leaves the caller's default in place rather than a half-decoded mix. */
static int hex_decode(const char *hex, CK_BYTE *out, size_t bytes)
{
    CK_BYTE tmp[P11_HEX_DECODE_MAX];
    int rc = -1;
    /* strnlen bounds the scan to the expected length, so a string missing its
     * terminator within bytes * 2 + 1 chars is rejected rather than run past. */
    if (hex == NULL || out == NULL || bytes > sizeof(tmp) ||
        strnlen(hex, bytes * 2 + 1) != bytes * 2)
    {
        return -1;
    }
    for (size_t i = 0; i < bytes; i++)
    {
        char ch = hex[i * 2];
        char cl = hex[i * 2 + 1];
        int hi = (ch >= '0' && ch <= '9')   ? ch - '0'
                 : (ch >= 'a' && ch <= 'f') ? ch - 'a' + 10
                 : (ch >= 'A' && ch <= 'F') ? ch - 'A' + 10
                                            : -1;
        int lo = (cl >= '0' && cl <= '9')   ? cl - '0'
                 : (cl >= 'a' && cl <= 'f') ? cl - 'a' + 10
                 : (cl >= 'A' && cl <= 'F') ? cl - 'A' + 10
                                            : -1;
        if (hi < 0 || lo < 0)
        {
            goto cleanup;
        }
        tmp[i] = (CK_BYTE)((hi << 4) | lo);
    }
    memcpy(out, tmp, bytes);
    rc = 0;

cleanup:
    tsra_pkcs11_wipe(tmp, sizeof(tmp)); /* it staged credential bytes */
    return rc;
}

/* Return `path` advanced past a leading "file:" scheme, mirroring the provider's
 * handling of path values; returns the original pointer when the prefix is
 * absent (NULL passes through unchanged). */
static const char *strip_file_prefix(const char *path)
{
    static const char FILE_PREFIX[] = "file:";
    if ((path != NULL) && (strncmp(path, FILE_PREFIX, sizeof(FILE_PREFIX) - 1) == 0))
    {
        return path + (sizeof(FILE_PREFIX) - 1);
    }
    return path;
}

/* Reject an empty path or any ".." component so the store directory cannot be
 * pointed outside its intended location — the same rule the provider applies to
 * its resiliency storage dir. */
static bool path_is_safe(const char *path)
{
    return (path != NULL) && (path[0] != '\0') && (strstr(path, "..") == NULL);
}

/* Populate `cfg` from the environment: mock-friendly credential defaults, then
 * the env-var overrides, then the object-store settings (see the contract on
 * the declaration in tsra_pkcs11_config.h). */
CK_RV tsra_pkcs11_config_load(tsra_pkcs11_config *cfg)
{
    if (cfg == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    memset(cfg, 0, sizeof(*cfg));
    /* Simulator defaults: any non-zero id/pin is accepted, OBK is any 48 bytes. */
    memset(cfg->id, 0x01, sizeof(cfg->id));
    memset(cfg->default_pin, 0x02, sizeof(cfg->default_pin));
    memset(cfg->obk, 0xA5, sizeof(cfg->obk));

    (void)hex_decode(getenv(TSRA_PKCS11_ENV_ID), cfg->id, sizeof(cfg->id));
    (void)hex_decode(getenv(TSRA_PKCS11_ENV_PIN), cfg->default_pin, sizeof(cfg->default_pin));

    const char *env = getenv(TSRA_PKCS11_ENV_STORE_DIR);
    const char *dir = (env != NULL) ? strip_file_prefix(env) : TSRA_PKCS11_DEFAULT_STORE_DIR;
    if (!path_is_safe(dir))
    {
        return CKR_ARGUMENTS_BAD;
    }
    int written = snprintf(cfg->store_dir, sizeof(cfg->store_dir), "%s", dir);
    if ((written < 0) || ((size_t)written >= sizeof(cfg->store_dir)))
    {
        return CKR_ARGUMENTS_BAD; /* a truncated path would name another directory */
    }

    const char *persist = getenv(TSRA_PKCS11_ENV_PERSIST);
    cfg->store_persist =
        (persist != NULL) && ((strcmp(persist, "1") == 0) || (strcasecmp(persist, "true") == 0));
    return CKR_OK;
}

void tsra_pkcs11_config_clear(tsra_pkcs11_config *cfg)
{
    tsra_pkcs11_wipe(cfg, sizeof(*cfg)); /* NULL-safe */
}
