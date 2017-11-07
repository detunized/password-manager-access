// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace RoboForm.Test
{
    [TestFixture]
    class CryptoTest
    {
        [Test]
        public void ComputeClientKey_returns_key()
        {
            // Generated with the original JavaScript code
            Assert.That(Crypto.ComputeClientKey(Password, AuthInfo),
                        Is.EqualTo("8sbDhSTLwbl0FhiHAxFxGUQvQwcr4JIbpExO64+Jj8o=".Decode64()));
        }

        [Test]
        public void HashPassword_returns_hashed_password()
        {
            // Generated with the original JavaScript code
            Assert.That(Crypto.HashPassword(Password, AuthInfo),
                        Is.EqualTo("b+rd7TUt65+hdE7+lHCBPPWHjxbq6qs0y7zufYfqHto=".Decode64()));
        }

        [Test]
        public void Md5_returns_hashed_message()
        {
            // From https://www.nist.gov/itl/ssd/software-quality-group/nsrl-test-data
            Assert.That(Crypto.Md5("abc".ToBytes()),
                        Is.EqualTo("kAFQmDzST7DWlj99KOF/cg==".Decode64()));
        }

        [Test]
        public void Sha256_returns_hashed_message()
        {
            // Generated with OpenSSL (just a smoke test, we're not implementing SHA here)
            // $ echo -n message | openssl dgst -sha256 -binary | openssl base64
            Assert.That(Crypto.Sha256("message".ToBytes()),
                        Is.EqualTo("q1MKE+RZFJgrefm34/uplM/R8/si9xzqGvvwK0YMbR0=".Decode64()));
        }

        [Test]
        public void Hmac_returns_hashed_message()
        {
            // Generated with OpenSSL (just a smoke test, we're not implementing HMAC here)
            // $ echo -n message | openssl dgst -sha256 -binary -hmac "salt" | openssl base64
            Assert.That(Crypto.Hmac("salt".ToBytes(), "message".ToBytes()),
                        Is.EqualTo("3b8WZhUCYErLcNYqWWvzwomOHB0vZS6seUq4xfkSSd0=".Decode64()));
        }

        //
        // Data
        //

        private const string Password = "h74@aB$SCt9dTBQ3%rmAVN3oOmtGLt58Nix7!3z%vUO4Ni07rfjutHRbhJ9!SkOk";

        // TODO: Generate a test case with MD5
        private static readonly Client.AuthInfo AuthInfo =
            new Client.AuthInfo(sid: "",
                                data: "",
                                nonce: "",
                                salt: "A+Ft8UM674OZOOjUjXCdbw==".Decode64(),
                                iterationCount: 4096,
                                isMd5: false);
    }
}
