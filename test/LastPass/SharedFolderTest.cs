// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using PasswordManagerAccess.LastPass;
using Xunit;

namespace PasswordManagerAccess.Test.LastPass
{
    public class SharedFolderTest
    {
        [Fact]
        public void SharedFolder_properties_are_set()
        {
            var id = "1234567890";
            var name = "name";
            var key = "blah".ToBytes();

            var folder = new SharedFolder(id, name, key);

            Assert.Equal(id, folder.Id);
            Assert.Equal(name, folder.Name);
            Assert.Equal(key, folder.EncryptionKey);
        }
    }
}
