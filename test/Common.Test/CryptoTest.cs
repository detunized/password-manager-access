// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Xunit;

namespace PasswordManagerAccess.Common.Test
{
    public class CryptoTest
    {
        //
        // SHA-256
        //

        [Fact]
        public void Sha256_string_returns_hashed_message()
        {
            var sha = Crypto.Sha256("message");
            Assert.Equal("q1MKE+RZFJgrefm34/uplM/R8/si9xzqGvvwK0YMbR0=".Decode64(), sha);
        }

        [Fact]
        public void Sha256_bytes_returns_hashed_message()
        {
            var sha = Crypto.Sha256("message".ToBytes());
            Assert.Equal("q1MKE+RZFJgrefm34/uplM/R8/si9xzqGvvwK0YMbR0=".Decode64(), sha);
        }

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
        public void Pbkdf2Sha256_returns_correct_result()
        {
            var derived = Crypto.Pbkdf2Sha256("password", "saltsalt".ToBytes(), 13, 32);
            Assert.Equal("vJEouk0ert2NexzPxbIn09X1I34luPYBn2IKmJQu66s=".Decode64(), derived);
        }

        [Fact]
        public void Pbkdf2Sha512_returns_correct_result()
        {
            var derived = Crypto.Pbkdf2Sha512("password", "saltsalt".ToBytes(), 13, 32);
            Assert.Equal("zpWyQNRZlkwRdVOkHlemEWCjT8P8js2m6sYqcakt+ns=".Decode64(), derived);
        }

        //
        // AES
        //

        [Fact]
        public void DecryptAes256_decrypts_ciphertext()
        {
            var plaintext = Crypto.DecryptAes256("TZ1+if9ofqRKTatyUaOnfudletslMJ/RZyUwJuR/+aI=".Decode64(),
                                                 "YFuiAVZgOD2K+s6y8yaMOw==".Decode64(),
                                                 "OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=".Decode64());
            Assert.Equal("All your base are belong to us".ToBytes(), plaintext);
        }
    }
}
