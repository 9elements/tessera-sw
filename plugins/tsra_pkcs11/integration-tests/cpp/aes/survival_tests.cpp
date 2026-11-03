// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file survival_tests.cpp
///
/// Keys outlive the events PKCS#11 says they outlive, proven by use: a
/// SurvivingKey (utils/surviving_key.hpp) encrypts the same message to the
/// same ciphertext before and after each event.

#include <gtest/gtest.h>
#include <utility>

#include "utils/aes_helpers.hpp"
#include "utils/module.hpp"
#include "utils/surviving_key.hpp"

class key_survival : public UserSession
{
};

TEST_F(key_survival, every_key_family_gives_c0_again_when_nothing_happened)
{
    // The positive control for every survival case: with no event in between,
    // the check passes for each key family.
    CK_OBJECT_HANDLE cbc = 0;
    CK_OBJECT_HANDLE gcm = 0;
    CK_OBJECT_HANDLE xts = 0;
    ASSERT_CKR_OK(gen_aes_key(s_, 32, CK_TRUE, CK_TRUE, "survival-cbc", &cbc));
    ASSERT_CKR_OK(gen_gcm_key(s_, "survival-gcm", &gcm));
    ASSERT_CKR_OK(gen_xts_key(s_, "survival-xts", &xts));
    for (auto [key, mech] : { std::pair{ cbc, CKM_AES_CBC },
                              std::pair{ gcm, CKM_AES_GCM },
                              std::pair{ xts, CKM_AES_XTS } })
    {
        SCOPED_TRACE(mech);
        SurvivingKey survivor(s_, key, mech);
        ASSERT_NO_FATAL_FAILURE(survivor.record());
        ASSERT_NO_FATAL_FAILURE(survivor.check("nothing"));
    }
}
