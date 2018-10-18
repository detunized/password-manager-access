// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using OnePassword;

namespace Example
{
    public class Program
    {
        public static void Main(string[] args)
        {
            // Read 1Password credentials from a file
            // The file should contain 5 lines:
            //   - username
            //   - password
            //   - account key
            //   - client UUID
            //   - API domain (my.1password.com, my.1password.eu or my.1password.ca)
            // See credentials.txt.example for an example.
            var credentials = File.ReadAllLines("../../credentials.txt");
            var username = credentials[0];
            var password = credentials[1];
            var accountKey = credentials[2];
            var uuid = credentials[3];
            var domain = credentials[4];

            try
            {
                DumpAllVaults(username, password, accountKey, uuid, domain);
            }
            catch (ClientException e)
            {
                Console.WriteLine("Error: {0} (Reason: {1})", e.Message, e.Reason);
            }
        }

        private static void DumpAllVaults(string username,
                                          string password,
                                          string accountKey,
                                          string uuid,
                                          string domain)
        {
            var vaults = Client.OpenAllVaults(username, password, accountKey, uuid, domain);

            foreach (var vault in vaults)
            {
                Console.WriteLine("{0}: '{1}', '{2}':", vault.Id, vault.Name, vault.Description);
                for (int i = 0; i < vault.Accounts.Length; ++i)
                {
                    var account = vault.Accounts[i];
                    Console.WriteLine("  {0}:\n" +
                                      "          id: {1}\n" +
                                      "        name: {2}\n" +
                                      "    username: {3}\n" +
                                      "    password: {4}\n" +
                                      "         url: {5}\n" +
                                      "        note: {6}\n",
                                      i + 1,
                                      account.Id,
                                      account.Name,
                                      account.Username,
                                      account.Password,
                                      account.Url,
                                      account.Note);
                }
            }
        }
    }
}
