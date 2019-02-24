// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Xunit;

namespace PasswordManagerAccess.Common.Test
{
    public class CryptoTest
    {
        //
        // PBKDF2
        //
        // Since we're not implementing the algorithm anymore, it doesn't make since
        // to have an exhaustive test suite. Just to see that we're calling the .NET
        // functions correctly.

        [Fact]
        public void Pbkdf2Sha1_returns_correct_result()
        {
            var derived = Crypto.Pbkdf2Sha1("password", "saltsalt".ToBytes(), 13, 32);
            Assert.Equal("Uyh7Yhywug6MOvQr33lUKcwxFx/bFNLViotFCggREnc=".Decode64(), derived);
        }

        [Fact]
        public void Generate_sha_256_returns_correct_result()
        {
            var derived = Crypto.Pbkdf2Sha256("password", "saltsalt".ToBytes(), 13, 32);
            Assert.Equal("vJEouk0ert2NexzPxbIn09X1I34luPYBn2IKmJQu66s=".Decode64(), derived);
        }

        [Fact]
        public void Generate_sha_512_returns_correct_result()
        {
            var derived = Crypto.Pbkdf2Sha512("password", "saltsalt".ToBytes(), 13, 32);
            Assert.Equal("zpWyQNRZlkwRdVOkHlemEWCjT8P8js2m6sYqcakt+ns=".Decode64(), derived);
        }
    }
}
