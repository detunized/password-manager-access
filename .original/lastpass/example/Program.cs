using System;
using LastPass;

namespace Example
{
    class Program
    {
        static void Main(string[] args)
        {
            var session = Fetcher.Login("username", "password");
            var blob = Fetcher.Fetch(session);
            var vault = Vault.Create(blob);

            for (var i = 0; i < vault.EncryptedAccounts.Length; ++i)
            {
                var account = vault.EncryptedAccounts[i];
                Console.WriteLine("{0}: {1}", i, account.Url);
            }
        }
    }
}
