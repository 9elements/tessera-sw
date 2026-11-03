// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Unit test for the environment configuration (src/tsra_pkcs11_config.c),
 * driven through tsra_pkcs11_config_load with setenv. No device, no libcrypto:
 *
 *   gcc -I ../include/pkcs11-v3.1 -I ../src config_test.c \
 *       ../src/tsra_pkcs11_config.c -o config_test && ./config_test
 *
 * Covers the credential hex decoding (malformed values keep the default), the
 * "file:" prefix, the store directory failing closed (empty, "..", overlong)
 * while an unset variable takes the default, the persist switch, and the wipe.
 */

#define _DEFAULT_SOURCE

#include "tsra_pkcs11_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail = 0;
static int g_checks = 0;

#define CHECK(cond, msg)                                                                           \
    do                                                                                             \
    {                                                                                              \
        g_checks++;                                                                                \
        if (cond)                                                                                  \
        {                                                                                          \
            printf("  ok   : %s\n", (msg));                                                        \
        }                                                                                          \
        else                                                                                       \
        {                                                                                          \
            printf("  FAIL : %s\n", (msg));                                                        \
            g_fail = 1;                                                                            \
        }                                                                                          \
    } while (0)

/* The simulator defaults tsra_pkcs11_config_load starts from. */
#define DEFAULT_ID_BYTE 0x01
#define DEFAULT_PIN_BYTE 0x02

static bool all_bytes(const CK_BYTE *p, size_t n, CK_BYTE v)
{
    for (size_t i = 0; i < n; i++)
    {
        if (p[i] != v)
        {
            return false;
        }
    }
    return true;
}

/* Load with TSRA_PKCS11_STORE_DIR set to `dir` (unset for NULL). */
static CK_RV load_with_dir(const char *dir, tsra_pkcs11_config *cfg)
{
    if (dir == NULL)
    {
        unsetenv(TSRA_PKCS11_ENV_STORE_DIR);
    }
    else
    {
        setenv(TSRA_PKCS11_ENV_STORE_DIR, dir, 1);
    }
    return tsra_pkcs11_config_load(cfg);
}

static void test_store_dir(void)
{
    printf("== store directory ==\n");
    tsra_pkcs11_config cfg;
    CHECK(
        (load_with_dir(NULL, &cfg) == CKR_OK) &&
            (strcmp(cfg.store_dir, TSRA_PKCS11_DEFAULT_STORE_DIR) == 0),
        "unset -> the default directory"
    );
    CHECK(
        (load_with_dir("/srv/p11", &cfg) == CKR_OK) && (strcmp(cfg.store_dir, "/srv/p11") == 0),
        "a plain path is taken as is"
    );
    CHECK(
        (load_with_dir("file:/srv/p11", &cfg) == CKR_OK) &&
            (strcmp(cfg.store_dir, "/srv/p11") == 0),
        "a file: prefix is stripped"
    );
    CHECK(load_with_dir("", &cfg) == CKR_ARGUMENTS_BAD, "empty -> CKR_ARGUMENTS_BAD");
    CHECK(
        load_with_dir("file:", &cfg) == CKR_ARGUMENTS_BAD,
        "empty after file: -> CKR_ARGUMENTS_BAD"
    );
    CHECK(load_with_dir("/srv/../etc", &cfg) == CKR_ARGUMENTS_BAD, "'..' -> CKR_ARGUMENTS_BAD");
    CHECK(
        load_with_dir("file:../p11", &cfg) == CKR_ARGUMENTS_BAD,
        "'..' after file: -> CKR_ARGUMENTS_BAD"
    );

    /* The longest path that fits store_dir, and one byte more. */
    static char path[TSRA_PKCS11_STORE_DIR_LEN + 1];
    memset(path, 'a', TSRA_PKCS11_STORE_DIR_LEN - 1);
    path[0] = '/';
    path[TSRA_PKCS11_STORE_DIR_LEN - 1] = '\0';
    CHECK(
        (load_with_dir(path, &cfg) == CKR_OK) && (strcmp(cfg.store_dir, path) == 0),
        "the longest path that fits is taken"
    );
    path[TSRA_PKCS11_STORE_DIR_LEN - 1] = 'a';
    path[TSRA_PKCS11_STORE_DIR_LEN] = '\0';
    CHECK(load_with_dir(path, &cfg) == CKR_ARGUMENTS_BAD, "one byte longer -> CKR_ARGUMENTS_BAD");
    unsetenv(TSRA_PKCS11_ENV_STORE_DIR);
    tsra_pkcs11_config_clear(&cfg);
}

static void test_persist(void)
{
    printf("== persist switch ==\n");
    tsra_pkcs11_config cfg;
    static const struct
    {
        const char *value; /* NULL: unset */
        bool persist;
    } rows[] = {
        { NULL, false }, { "1", true }, { "true", true }, { "TRUE", true },
        { "0", false },  { "", false }, { "yes", false },
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++)
    {
        if (rows[i].value == NULL)
        {
            unsetenv(TSRA_PKCS11_ENV_PERSIST);
        }
        else
        {
            setenv(TSRA_PKCS11_ENV_PERSIST, rows[i].value, 1);
        }
        char msg[80];
        snprintf(
            msg,
            sizeof(msg),
            "%s=%s -> %s",
            TSRA_PKCS11_ENV_PERSIST,
            (rows[i].value != NULL) ? rows[i].value : "(unset)",
            rows[i].persist ? "file store" : "memory store"
        );
        CHECK(
            (tsra_pkcs11_config_load(&cfg) == CKR_OK) && (cfg.store_persist == rows[i].persist),
            msg
        );
    }
    unsetenv(TSRA_PKCS11_ENV_PERSIST);
    tsra_pkcs11_config_clear(&cfg);
}

static void test_credentials(void)
{
    printf("== credentials ==\n");
    tsra_pkcs11_config cfg;
    unsetenv(TSRA_PKCS11_ENV_ID);
    unsetenv(TSRA_PKCS11_ENV_PIN);
    CHECK(
        (tsra_pkcs11_config_load(&cfg) == CKR_OK) &&
            all_bytes(cfg.id, sizeof(cfg.id), DEFAULT_ID_BYTE) &&
            all_bytes(cfg.default_pin, sizeof(cfg.default_pin), DEFAULT_PIN_BYTE),
        "unset -> the simulator defaults"
    );

    setenv(TSRA_PKCS11_ENV_ID, "000102030405060708090a0B0c0D0e0F", 1);
    setenv(TSRA_PKCS11_ENV_PIN, "ffffffffffffffffffffffffffffffff", 1);
    bool counting = true;
    CHECK(tsra_pkcs11_config_load(&cfg) == CKR_OK, "valid hex loads");
    for (size_t i = 0; i < sizeof(cfg.id); i++)
    {
        counting = counting && (cfg.id[i] == i);
    }
    CHECK(counting, "the id decodes, either hex case");
    CHECK(all_bytes(cfg.default_pin, sizeof(cfg.default_pin), 0xFF), "the PIN decodes");

    static const struct
    {
        const char *hex;
        const char *name;
    } bad[] = {
        { "000102030405060708090a0b0c0d0e0", "odd length (31)" },
        { "000102030405060708090a0b0c0d0e0f00", "overlong (34)" },
        { "000102030405060708090a0b0c0d0eXY", "a non-hex digit" },
        { "", "empty" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
    {
        setenv(TSRA_PKCS11_ENV_ID, bad[i].hex, 1);
        char msg[80];
        snprintf(msg, sizeof(msg), "id %s -> the default is kept", bad[i].name);
        CHECK(
            (tsra_pkcs11_config_load(&cfg) == CKR_OK) &&
                all_bytes(cfg.id, sizeof(cfg.id), DEFAULT_ID_BYTE),
            msg
        );
    }
    unsetenv(TSRA_PKCS11_ENV_ID);
    unsetenv(TSRA_PKCS11_ENV_PIN);

    tsra_pkcs11_config_clear(&cfg);
    CHECK(all_bytes((const CK_BYTE *)&cfg, sizeof(cfg), 0), "config_clear zeroes the whole config");
    tsra_pkcs11_config_clear(NULL);
    CHECK(tsra_pkcs11_config_load(NULL) == CKR_ARGUMENTS_BAD, "NULL config -> CKR_ARGUMENTS_BAD");
}

int main(void)
{
    test_store_dir();
    test_persist();
    test_credentials();
    printf(
        g_fail ? "\nconfig_test: FAILED (%d checks)\n" : "\nconfig_test: all %d checks passed\n",
        g_checks
    );
    return g_fail;
}
