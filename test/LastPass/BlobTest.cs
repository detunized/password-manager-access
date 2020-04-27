// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.LastPass;
using Xunit;

namespace PasswordManagerAccess.Test.LastPass
{
    public class BlobTest
    {
        private static readonly byte[] Bytes = "TFBBVgAAAAMxMjJQUkVNAAAACjE0MTQ5".Decode64();
        private const int IterationCount = 500;
        private const string EncryptedPrivateKey = "DEADBEEF";
        private const string Username = "postlass@gmail.com";
        private const string Password = "pl1234567890";
        private static readonly byte[] EncryptionKey = "OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=".Decode64();

        [Fact]
        public void Blob_properties_are_set()
        {
            var blob = new Blob(Bytes, IterationCount, EncryptedPrivateKey);
            Assert.Equal(Bytes, blob.Bytes);
            Assert.Equal(IterationCount, blob.KeyIterationCount);
            Assert.Equal(EncryptedPrivateKey, blob.EncryptedPrivateKey);
        }

        [Fact]
        public void Blob_MakeEncryptionKey()
        {
            var key = new Blob(Bytes, IterationCount, EncryptedPrivateKey)
                .MakeEncryptionKey(Username, Password);
            Assert.Equal(EncryptionKey, key);
        }
    }
}
