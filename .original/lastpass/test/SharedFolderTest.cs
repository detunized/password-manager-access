// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace LastPass.Test
{
    [TestFixture]
    class SharedFolderTest
    {
        [Test]
        public void SharedFolder_properties_are_set()
        {
            var id = "1234567890";
            var name = "name";

            var folder = new SharedFolder(id, name, TestData.EncryptionKey);
            Assert.AreEqual(id, folder.Id);
            Assert.AreEqual(name, folder.Name);
            Assert.AreEqual(TestData.EncryptionKey, folder.EncryptionKey);
        }
    }
}
