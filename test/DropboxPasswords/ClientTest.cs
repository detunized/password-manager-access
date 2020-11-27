// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json;
using PasswordManagerAccess.Common;
using Xunit;
using PasswordManagerAccess.DropboxPasswords;
using R = PasswordManagerAccess.DropboxPasswords.Response;

namespace PasswordManagerAccess.Test.DropboxPasswords
{
    public class ClientTest: TestBase
    {
        [Fact]
        public void OpenVault_returns_accounts()
        {
            var flow = new RestFlow()
                .Post(GetFixture("account-info"))
                .Post(GetFixture("features"))
                .Post(GetFixture("root-folder"))
                .Post(GetFixture("entry-keyset"))
                .Post(GetFixture("entry-vault"));

            var accounts = Client.OpenVault("token", UtilTest.RecoveryWords, flow);

            Assert.Equal(2, accounts.Length);

            var a0 = accounts[0];
            Assert.Equal("7793c55f-6a21-40f5-bb1c-fd175e2515f0", a0.Id);
            Assert.Equal("Facebook", a0.Name);
            Assert.Equal("mark", a0.Username);
            Assert.Equal("yo-yo-yo-yo", a0.Password);
            Assert.Equal("https://facebook.com", a0.Url);
            Assert.Equal("Hey-ya!", a0.Note);
            Assert.Equal("My passwords", a0.Folder);

            var a1 = accounts[1];
            Assert.Equal("df1a3eb0-522a-4acb-a0e6-071fcf295f79", a1.Id);
            Assert.Equal("Google", a1.Name);
            Assert.Equal("blah@gmail.com", a1.Username);
            Assert.Equal("123", a1.Password);
            Assert.Equal("https://https://accounts.google.com/ServiceLogin", a1.Url);
            Assert.Equal("", a1.Note);
            Assert.Equal("My passwords", a1.Folder);
        }

        [Fact]
        public void FindAndDecryptAllKeysets_returns_only_keysets()
        {
            var entries = JsonConvert.DeserializeObject<R.EncryptedEntry[]>(GetFixture("entries"));
            var keysets = Client.FindAndDecryptAllKeysets(entries, MasterKey);

            Assert.Single(keysets);
        }

        //
        // Data
        //

        // TODO: Share with UtilTest
        private static readonly byte[] MasterKey =
            "4a0a046a2d4e2ee312c550a54fe96b573133e0d5b34f09b985c2b02876b98e6f".DecodeHex();
    }
}
