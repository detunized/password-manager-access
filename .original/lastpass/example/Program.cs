using System;
using LastPass;

namespace Example
{
    class Program
    {
        static void Main(string[] args)
        {
            var username = "username";
            var password = "password";
            var session = Fetcher.Login(username, password);
            var blob = Fetcher.Fetch(session);
            var vault = Vault.Create(blob);

            for (var i = 0; i < vault.EncryptedAccounts.Length; ++i)
            {
                var account = vault.DecryptAccount(vault.EncryptedAccounts[i], username, password);
                Console.WriteLine("{0}: {1} {2} {3} {4}", i, account.Name, account.Username, account.Password, account.Url);
            }
        }
    }
}
