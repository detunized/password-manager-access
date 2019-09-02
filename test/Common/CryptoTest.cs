// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test.Common
{
    public class CryptoTest
    {
        //
        // SHA-1
        //

        [Fact]
        public void Sha1_string_returns_hashed_message()
        {
            var sha = Crypto.Sha1("message");
            Assert.Equal("b5ua881ui4pzws3O03/p9ZIm4n0=".Decode64(), sha);
        }

        [Fact]
        public void Sha1_bytes_returns_hashed_message()
        {
            var sha = Crypto.Sha1("message".ToBytes());
            Assert.Equal("b5ua881ui4pzws3O03/p9ZIm4n0=".Decode64(), sha);
        }

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
        // SHA-512
        //

        [Fact]
        public void Sha512_string_returns_hashed_message()
        {
            var sha = Crypto.Sha512("message");
            Assert.Equal(
                "+Nr1ejNHzE1rnVdbMf5gd+LLSH9gqWIzwIy0edvzFTjMkV7G1IvbqpbdwaFttPT5bzcnbPyzUQuCRiQXcNWVLA==".Decode64(),
                sha);
        }

        [Fact]
        public void Sha512_bytes_returns_hashed_message()
        {
            var sha = Crypto.Sha512("message".ToBytes());
            Assert.Equal(
                "+Nr1ejNHzE1rnVdbMf5gd+LLSH9gqWIzwIy0edvzFTjMkV7G1IvbqpbdwaFttPT5bzcnbPyzUQuCRiQXcNWVLA==".Decode64(),
                sha);
        }

        //
        // HMAC-SHA-256
        //

        [Fact]
        public void HmacSha256_string_returns_mac()
        {
            var mac = Crypto.HmacSha256("message".ToBytes(), "key".ToBytes());
            Assert.Equal("6e9ef29b75fffc5b7abae527d58fdadb2fe42e7219011976917343065f58ed4a".DecodeHex(), mac);
        }

        //
        // PBKDF2
        //
        // We're not implementing the algorithm in Crypto and it doesn't make sense to have
        // an exhaustive test suite here. PBKDF2 is tested elsewhere. We just need to check
        // that we're calling the functions correctly.

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
        public void DecryptAes256Cbc_decrypts_ciphertext()
        {
            var plaintext = Crypto.DecryptAes256Cbc("TZ1+if9ofqRKTatyUaOnfudletslMJ/RZyUwJuR/+aI=".Decode64(),
                                                    "YFuiAVZgOD2K+s6y8yaMOw==".Decode64(),
                                                    "OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=".Decode64());
            Assert.Equal("All your base are belong to us".ToBytes(), plaintext);
        }

        [Fact]
        public void DecryptAes256CbcNoPadding_decrypts_ciphertext()
        {
            var plaintext = Crypto.DecryptAes256CbcNoPadding("TZ1+if9ofqRKTatyUaOnfono97F1Jjr+jVBAKgu/dq8=".Decode64(),
                                                             "YFuiAVZgOD2K+s6y8yaMOw==".Decode64(),
                                                             "OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=".Decode64());
            Assert.Equal("All your base are belong to us!!".ToBytes(), plaintext);
        }
    }
}
