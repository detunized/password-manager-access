using System;
using System.IO;
using System.Text;
using LastPass;

namespace Example
{
    class Program
    {
        static void Main(string[] args)
        {
            // Read LastPass credentials from a file
            // The file should contain 2 lines: username and password.
            // See credentials.txt.example for an example.
            var credentials = File.ReadAllLines("../../credentials.txt");
            var username = credentials[0];
            var password = credentials[1];

            // Fetch and create the vault from LastPass
            var vault = Vault.Create(username, password);

            // Compute the encryption key only once (could be slow)
            var key = vault.MakeKey(username, password);

            // Dump all the accounts
            for (var i = 0; i < vault.EncryptedAccounts.Length; ++i)
            {
                var account = vault.DecryptAccount(vault.EncryptedAccounts[i], key);
                Console.WriteLine("{0}: {1} {2} {3} {4} {5}",
                                  i + 1,
                                  account.Id,
                                  account.Name,
                                  account.Username,
                                  account.Password,
                                  account.Url);
            }
        }
    }
}
