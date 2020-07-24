// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using PasswordManagerAccess.Kaspersky;
using Xunit;

namespace PasswordManagerAccess.Test.Kaspersky
{
    public class UtilTest
    {
        [Fact]
        public void DeriveMasterPasswordAuthKey_returns_derived_key()
        {
            var key = Util.DeriveMasterPasswordAuthKey(
                "206a9e27-f96a-44d5-ac0d-84efe4f1835a",
                "Password123!",
                new DatabaseInfo(2, 1500, "39b56347c16c94c36553fd74a7cd2cb1".DecodeHex()));

            Assert.Equal(
                "d6602e5364ffa30389d9bab817919919ed417aabce1723ebc554099a34375253fee450daa7b0d9959672398c79cde5736d020c73db661f12da6c2ede7c747e2c".DecodeHex(),
                key);
        }

        [Fact]
        public void DeriveEncryptionKey_returns_derived_key()
        {
            var key = Util.DeriveEncryptionKey(
                "Password123!",
                new DatabaseInfo(2, 1500, "39b56347c16c94c36553fd74a7cd2cb1".DecodeHex()));

            Assert.Equal("d8f2bfe4980d90e3d402844e5332859ecbda531ab24962d2fdad4d39ad98d2f9".DecodeHex(),
                         key);
        }
    }
}
