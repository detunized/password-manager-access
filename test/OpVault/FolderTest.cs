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
            Assert.Same(Folder.None, folder.Parent);
        }

        [Fact]
        public void Null_or_unset_parent_is_reference_equal_to_None()
        {
            var folder = new Folder("", "");
            Assert.Same(Folder.None, folder.Parent);

            folder.Parent = null;
            Assert.Same(Folder.None, folder.Parent);
        }

        [Fact]
        public void Parent_of_None_is_None()
        {
            Assert.Same(Folder.None, Folder.None.Parent);
        }
    }
}
