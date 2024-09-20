// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using PasswordManagerAccess.OpVault;
using Xunit;

namespace PasswordManagerAccess.Test.OpVault
{
    public class UtilTest
    {
        [Fact]
        public void DeriveKek_returns_key()
        {
            var expected = new KeyMac("a7HZUoTh0E9I7LCTF3AHDRQXGEbcnQuUMv6Vcvv7e13IOFMfmCJORzuf" + "hnDVeB4cDrxnTsPFYMTvpHboE8MPGg==");
            var kek = Util.DeriveKek("password".ToBytes(), "pzJ5y/CiCeU8Sbo8+k4/zg==".Decode64(), 40000);

            Assert.Equal(expected.Key, kek.Key);
            Assert.Equal(expected.MacKey, kek.MacKey);
        }

        [Fact]
        public void DecryptAes_returns_plaintext_without_padding()
        {
            // Generated with Ruby/openssl
            var plaintext = Util.DecryptAes("yNVOKI5bgIJ0lPdVszvlEQ==".Decode64(), "iviviviviviviviv".ToBytes(), TestKey);

            Assert.Equal("decrypted data!!".ToBytes(), plaintext);
        }

        //
        // Data
        //

        private static readonly KeyMac TestKey = new KeyMac("key!key!key!key!key!key!key!key!saltsaltsaltsaltsaltsaltsaltsalt".ToBytes());
    }
}
