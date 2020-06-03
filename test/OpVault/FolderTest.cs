// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.OpVault;
using Xunit;

namespace PasswordManagerAccess.Test.OpVault
{
    public class FolderTest
    {
        [Fact]
        public void Folder_properties_are_set()
        {
            var id = "id";
            var name = "name";

            var folder = new Folder(id, name);

            Assert.Equal(id, folder.Id);
            Assert.Equal(name, folder.Name);
        }
    }
}
