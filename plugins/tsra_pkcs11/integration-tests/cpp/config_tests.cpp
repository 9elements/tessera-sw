// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file config_tests.cpp
///
/// The store configuration as C_Initialize sees it: a bad
/// TSRA_PKCS11_STORE_DIR fails closed instead of falling back to the default
/// directory, and a store directory others can access is refused. Each case
/// finalizes the module, initializes it under its own environment and leaves
/// it initialized again under the original one.

#include <cstdlib>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include "tsra_pkcs11_config.h"
#include "utils/module.hpp"

class config : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        ASSERT_NE(p11(), nullptr) << "module not loaded";
        dir_ = saved(TSRA_PKCS11_ENV_STORE_DIR);
        persist_ = saved(TSRA_PKCS11_ENV_PERSIST);
        ASSERT_CKR_OK(p11()->C_Finalize(nullptr));
    }

    void TearDown() override
    {
        (void)p11()->C_Finalize(nullptr);
        restore(TSRA_PKCS11_ENV_STORE_DIR, dir_);
        restore(TSRA_PKCS11_ENV_PERSIST, persist_);
        EXPECT_CKR_OK(p11()->C_Initialize(nullptr));
    }

    /// C_Initialize under the given store settings.
    static CK_RV init_with(const char *dir, const char *persist)
    {
        setenv(TSRA_PKCS11_ENV_STORE_DIR, dir, 1);
        setenv(TSRA_PKCS11_ENV_PERSIST, persist, 1);
        return p11()->C_Initialize(nullptr);
    }

  private:
    static std::optional<std::string> saved(const char *name)
    {
        const char *v = std::getenv(name);
        return (v != nullptr) ? std::optional<std::string>(v) : std::nullopt;
    }

    static void restore(const char *name, const std::optional<std::string> &value)
    {
        if (value)
        {
            setenv(name, value->c_str(), 1);
        }
        else
        {
            unsetenv(name);
        }
    }

    std::optional<std::string> dir_;
    std::optional<std::string> persist_;
};

TEST_F(config, unsafe_store_dir_fails_initialize)
{
    const std::string overlong = "/" + std::string(TSRA_PKCS11_STORE_DIR_LEN, 'a');
    for (const char *dir : { "", "file:", "/tmp/../tmp", overlong.c_str() })
    {
        SCOPED_TRACE(
            ::testing::Message() << "store dir '" << std::string(dir).substr(0, 16) << "'"
        );
        // The memory store does not use the directory; a bad setting still fails.
        EXPECT_CKR(CKR_ARGUMENTS_BAD, init_with(dir, "0"));
        EXPECT_CKR(CKR_ARGUMENTS_BAD, init_with(dir, "1"));
        EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, p11()->C_Finalize(nullptr))
            << "the failed C_Initialize left the module uninitialized";
    }
}

TEST_F(config, store_dir_others_can_access_is_refused)
{
    const char *tmp = std::getenv("TMPDIR");
    std::string tmpl = std::string((tmp != nullptr) && (*tmp != '\0') ? tmp : "/tmp") +
                       "/tsra_pkcs11_config_test.XXXXXX";
    ASSERT_NE(nullptr, mkdtemp(tmpl.data()));
    const std::string dir = tmpl;

    ASSERT_EQ(0, chmod(dir.c_str(), 0775));
    EXPECT_NE(CKR_OK, init_with(dir.c_str(), "1")) << "a group-writable store dir is refused";
    EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, p11()->C_Finalize(nullptr));

    ASSERT_EQ(0, chmod(dir.c_str(), 0700));
    EXPECT_CKR_OK(init_with(dir.c_str(), "1")) << "the same directory at 0700 is accepted";
    EXPECT_CKR_OK(p11()->C_Finalize(nullptr));
    EXPECT_EQ(0, rmdir(dir.c_str())) << "initialization alone writes nothing into the store";
}
