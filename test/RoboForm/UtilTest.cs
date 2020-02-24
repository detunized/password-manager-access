// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Security.Cryptography;
using PasswordManagerAccess.RoboForm;
using Xunit;

namespace PasswordManagerAccess.Test.RoboForm
{
    public class UtilTest
    {
        [Fact]
        public void RandomDeviceId_starts_with_B()
        {
            for (var i = 0; i < 10; ++i)
                Assert.StartsWith("B", Util.RandomDeviceId());
        }

        [Fact]
        public void RandomDeviceId_has_correct_length()
        {
            for (var i = 0; i < 10; ++i)
                Assert.Equal(33, Util.RandomDeviceId().Length);
        }

        [Fact]
        public void ComputeClientKey_returns_key()
        {
            // Generated with the original JavaScript code
            Assert.Equal("8sbDhSTLwbl0FhiHAxFxGUQvQwcr4JIbpExO64+Jj8o=".Decode64(),
                         Util.ComputeClientKey(TestData.Password, TestData.AuthInfo));
        }

        [Fact]
        public void Md5_returns_hashed_message()
        {
            // Generated with OpenSSL (just a smoke test, we're not implementing MD5 here)
            // $ echo -n message | openssl dgst -md5 -binary | openssl base64
            Assert.Equal("eOcxAn2P1Q7WQjQLfJpjsw==".Decode64(), Util.Md5("message".ToBytes()));
        }

        [Fact]
        public void DecryptAes256_returns_plaintext_without_padding()
        {
            // Generated with Ruby/openssl
            Assert.Equal("decrypted data!!".ToBytes(),
                         Util.DecryptAes256("XOUQiNfzQHLMHYJzo8jvaw==".Decode64(),
                                            "this is a very secure password!!".ToBytes(),
                                            "iviviviviviviviv".ToBytes(),
                                            PaddingMode.None));
        }

        [Fact]
        public void DecryptAes256_returns_ciphertext_with_padding()
        {
            // Generated with Ruby/openssl
            Assert.Equal("decrypted data!".ToBytes(),
                         Util.DecryptAes256("snfIB8VWKBn7p869FXAfrw==".Decode64(),
                                            "this is a very secure password!!".ToBytes(),
                                            "iviviviviviviviv".ToBytes(),
                                            PaddingMode.PKCS7));
        }

        [Fact]
        public void HashPassword_returns_hashed_password()
        {
            // TODO: Generate a test case with MD5

            // Generated with the original JavaScript code
            Assert.Equal("b+rd7TUt65+hdE7+lHCBPPWHjxbq6qs0y7zufYfqHto=".Decode64(),
                         Util.HashPassword(TestData.Password, TestData.AuthInfo));
        }
    }
}
