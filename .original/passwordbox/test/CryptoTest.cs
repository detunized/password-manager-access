// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace PasswordBox.Test
{
    [TestFixture]
    class CryptoTest
    {
        [Test]
        public void Decrypt_returns_correct_result()
        {
            // TODO: Add real data
            var decrypted = Crypto.Decrypt("", "");
            Assert.AreEqual("", decrypted);
        }

        [Test]
        public void Decrypt_returns_empty_on_empty_input()
        {
            var decrypted = Crypto.Decrypt("", "");
            Assert.AreEqual("", decrypted);
        }
    }
}
