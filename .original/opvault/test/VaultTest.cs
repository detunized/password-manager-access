// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace OPVault.Test
{
    [TestFixture]
    public class VaultTest
    {
        [Test]
        public void MakeFilename_makes_path_inside_vault()
        {
            var filename = Vault.MakeFilename("path/to/test.opvault", "profile.js");
            Assert.That(filename, Is.EqualTo("path\\to\\test.opvault\\default\\profile.js"));
        }

        [Test]
        public void MakeFilename_ignores_extra_slash()
        {
            var filename = Vault.MakeFilename("path/to/test.opvault/", "profile.js");
            Assert.That(filename, Is.EqualTo("path\\to\\test.opvault\\default\\profile.js"));
        }

        [Test]
        public void MakeFilename_keeps_drive_letter()
        {
            var filename = Vault.MakeFilename("c:/path/to/test.opvault", "profile.js");
            Assert.That(filename, Is.EqualTo("c:\\path\\to\\test.opvault\\default\\profile.js"));
        }

        [Test]
        public void NormalizeSlashes_converts_forward_to_back_slashes()
        {
            // TODO: Test on non Windows based platforms
            var normalized = Vault.NormalizeSlashes("/path/to\\a/file/");
            Assert.That(normalized, Is.EqualTo("\\path\\to\\a\\file\\"));
        }
    }
}
