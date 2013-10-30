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
            Vault vault = null;
            try
            {
                // Frist try basic authentication
                vault = Vault.Create(username, password);
            }
            catch (LoginException e)
            {
                if (e.Reason == LoginException.FailureReason.LastPassGoogleAuthenticatorRequired)
                {
                    // Request Google Authenticator code
                    Console.Write("Enter Google Authenticator code: ");
                    var code = Console.ReadLine();

                    // Now try with GAuth code
                    vault = Vault.Create(username, password, code);
                }
                else
                {
                    throw;
                }
            }

            // Decrypt all accounts
            vault.DecryptAllAccounts(Account.Field.Name |
                                     Account.Field.Username |
                                     Account.Field.Password |
                                     Account.Field.Group,
                                     username,
                                     password);

            // Dump all the accounts
            for (var i = 0; i < vault.Accounts.Length; ++i)
            {
                var account = vault.Accounts[i];

                // Need explicit converstion to string.
                // String.Format doesn't do that for EncryptedString.
                Console.WriteLine("{0}: {1} {2} {3} {4} {5} {6}",
                                  i + 1,
                                  account.Id,
                                  (string)account.Name,
                                  (string)account.Username,
                                  (string)account.Password,
                                  account.Url,
                                  (string)account.Group);
            }
        }
    }
}
