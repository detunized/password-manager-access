// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.OpVault;
using Xunit;

namespace PasswordManagerAccess.Test.OpVault
{
    public class KeyMacTest
    {
        [Fact]
        public void KeyMac_created_from_bytes()
        {
            var key = new KeyMac(Buffer.Decode64());

            Assert.Equal(Key.Decode64(), key.Key);
            Assert.Equal(MacKey.Decode64(), key.MacKey);
        }

        [Fact]
        public void KeyMac_created_from_base64()
        {
            var key = new KeyMac(Buffer);

            Assert.Equal(Key.Decode64(), key.Key);
            Assert.Equal(MacKey.Decode64(), key.MacKey);
        }

        //
        // Data
        //

        private const string Buffer = "a7HZUoTh0E9I7LCTF3AHDRQXGEbcnQuUMv6Vcvv7e13IOFMfmCJORzuf" +
                                      "hnDVeB4cDrxnTsPFYMTvpHboE8MPGg==";
        private const string Key = "a7HZUoTh0E9I7LCTF3AHDRQXGEbcnQuUMv6Vcvv7e10=";
        private const string MacKey = "yDhTH5giTkc7n4Zw1XgeHA68Z07DxWDE76R26BPDDxo=";
    }
}
