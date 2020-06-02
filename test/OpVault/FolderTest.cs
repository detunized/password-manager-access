// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace PasswordManagerAccess.Test.OpVault
{
    [TestFixture]
    public class FolderTest
    {
        [Test]
        public void Folder_properties_are_set()
        {
            var id = "id";
            var name = "name";

            var folder = new Folder(id, name);

            Assert.That(folder.Id, Is.EqualTo(id));
            Assert.That(folder.Name, Is.EqualTo(name));
        }
    }
}
