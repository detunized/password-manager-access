// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using NUnit.Framework;

namespace LastPass.Test
{
    [TestFixture]
    class EncryptedStringTest
    {
        [Test]
        public void EncryptedString_Encrypted_set()
        {
            var bytes = "DEADBEEF".DecodeHex();
            var encryptedString = new EncryptedString(bytes);
            Assert.AreEqual(bytes, encryptedString.Encrypted);
        }

        [Test]
        [ExpectedException(typeof(InvalidOperationException), ExpectedMessage = "The field has not been decrypted yet")]
        public void EncryptedString_Decrypted_throws()
        {
            var bytes = "DEADBEEF".DecodeHex();
            var encryptedString = new EncryptedString(bytes);
            var decrypted = encryptedString.Decrypted;
        }

        [Test]
        public void EncryptedString_Decrypt_sets_Decrypted_and_returns()
        {
            var encrypted = "IcokDWmjOkKtLpZehWKL6666Uj6fNXPpX6lLWlou+1Lrwb+D3ymP6BAwd6C0TB3hSA==".Decode64();
            var decrypted = "All your base are belong to us";
            var key = "OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=".Decode64();

            var encryptedString = new EncryptedString(encrypted);
            var decryptedReturned = encryptedString.Decrypt(key);

            Assert.AreEqual(decrypted, decryptedReturned);
            Assert.AreEqual(decrypted, encryptedString.Decrypted);
            Assert.AreEqual(decrypted, (string)encryptedString);
        }
    }
}
