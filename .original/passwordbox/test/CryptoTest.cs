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
            var decrypted = Crypto.Decrypt("", "");
            Assert.AreEqual("", decrypted);
        }
    }
}
