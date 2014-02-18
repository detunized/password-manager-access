// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace LastPass.Test
{
    [TestFixture]
    class BlobTest
    {
        private static readonly byte[] Bytes = "TFBBVgAAAAMxMjJQUkVNAAAACjE0MTQ5".Decode64();
        private const int IterationCount = 500;
        private const string Username = "postlass@gmail.com";
        private const string Password = "pl1234567890";
        private static readonly byte[] EncryptionKey = "OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=".Decode64();

        [Test]
        public void Blob_properties_are_set()
        {
            var blob = new Blob(Bytes, IterationCount);
            Assert.AreEqual(Bytes, blob.Bytes);
            Assert.AreEqual(IterationCount, blob.KeyIterationCount);
        }

        [Test]
        public void Blob_MakeEncryptionKey()
        {
            var key = new Blob(Bytes, IterationCount).MakeEncryptionKey(Username, Password);
            Assert.AreEqual(EncryptionKey, key);
        }
    }
}
