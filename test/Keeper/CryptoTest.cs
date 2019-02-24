// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Keeper.Test
{
    public class CryptoTest
    {
        [Fact]
        public void HashPassword_returns_hashed_password()
        {
            var hash = Crypto.HashPassword("password", "saltsaltsaltsalt".ToBytes(), 100);
            Assert.Equal("bWbRG1iqy6UG9WIFz8igJa5ItR65ujAFWexQt2ka3Y4=".Decode64(), hash);
        }

        [Fact]
        public void DecryptVaultKey_returns_decrypted_key()
        {
            const string encodedKey = "AQGGoIqGPWs+EgWNoz6PKXNpDGHJdPVMb6ourk88DSspxlgOmZmtNiXQpVrOUFUBhtox" +
                                      "/mRgS8ySKbVwPEYKjNqvVvapkatzZJFyuULrePNocBgRtnbKs5QNreLgUrXsbx9aMg==";
            const string password = "J7wSAB&NgP!Xuo7jdSAu4KSwmcj7YZi1soHvuurd&5YBm3Y5QV!oNCi7%@xVoDZ*";
            var key = Crypto.DecryptVaultKey(encodedKey.Decode64(), password);

            Assert.Equal("AN21ZRN0e4Oy4J7+YdsAMxeCacvE2kOsRRSqDiaitqk=".Decode64(), key);
        }
    }
}
