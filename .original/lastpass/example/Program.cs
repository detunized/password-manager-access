using System;
using System.IO;
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

            // Decrypt all accounts
            vault.DecryptAllAccounts(EncryptedAccount.Field.Name |
                                     EncryptedAccount.Field.Username |
                                     EncryptedAccount.Field.Password |
                                     EncryptedAccount.Field.Group,
                                     username,
                                     password);

            // Dump all the accounts
            for (var i = 0; i < vault.EncryptedAccounts.Length; ++i)
            {
                var account = vault.EncryptedAccounts[i];
                Console.WriteLine("{0}: {1} {2} {3} {4} {5} {6}",
                                  i + 1,
                                  account.Id,
                                  account.Name,
                                  account.Username,
                                  account.Password,
                                  account.Url,
                                  account.Group);
            }
        }
    }
}
