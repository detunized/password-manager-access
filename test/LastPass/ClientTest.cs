// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Linq;
using PasswordManagerAccess.LastPass;
using Xunit;

namespace PasswordManagerAccess.Test.LastPass
{
    public class ClientTest
    {
        // TODO: Figure out how to test this!
        //       All methods require username/password which I don't want to expose here.
        //       Actually, I'm pretty sure the password is lost and the whole test blob
        //       needs to be regenerated.
        //       Currently all the vault tests that deal with decryption are disabled.

        [Fact]
        public void Create_returns_vault_with_correct_accounts()
        {
            var accounts = Client.ParseVault(new Blob(TestData.Blob, 1, TestData.EncryptedPrivateKey),
                                             TestData.EncryptionKey);

            Assert.Equal(TestData.Accounts.Length, accounts.Length);
            Assert.Equal(TestData.Accounts.Select(i => i.Id), accounts.Select(i => i.Id));
            Assert.Equal(TestData.Accounts.Select(i => i.Url), accounts.Select(i => i.Url));
        }

        [Fact]
        public void ParseVault_throws_on_truncated_blob()
        {
            var tests = new[] {1, 2, 3, 4, 5, 10, 100, 1000};
            foreach (var i in tests)
            {
                var e = Assert.Throws<ParseException>(
                    () => Client.ParseVault(new Blob(TestData.Blob.Take(TestData.Blob.Length - i).ToArray(), 1, ""),
                                            new byte[16]));
                Assert.Equal(ParseException.FailureReason.CorruptedBlob, e.Reason);
                Assert.Equal("Blob is truncated", e.Message);
            }
        }
    }
}
