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

            Assert.Empty(accounts);
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
