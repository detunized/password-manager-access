// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.Example.Common;
using PasswordManagerAccess.LastPass;

namespace PasswordManagerAccess.Example.LastPass
{
    public static class Program
    {
        // Very simple text based user interface that demonstrates how to respond to
        // to Vault UI requests.
        private class TextUi: Ui
        {
            public override string ProvideSecondFactorPassword(SecondFactorMethod method)
            {
                return GetAnswer(string.Format("Please enter {0} code", method));
            }

            public override void AskToApproveOutOfBand(OutOfBandMethod method)
            {
                Console.WriteLine("Please approve out-of-band via {0}", method);
            }

            private static string GetAnswer(string prompt)
            {
                Console.WriteLine(prompt);
                Console.Write("> ");
                var input = Console.ReadLine();

                return input == null ? "" : input.Trim();
            }
        }

        public static void Main(string[] args)
        {
            var config = Util.ReadConfig();

            try
            {
                // Fetch and create the vault from LastPass
                var vault = Vault.Open(config["username"],
                                       config["password"],
                                       new ClientInfo(Platform.Desktop,
                                                      config["device-id"],
                                                      config["client-description"],
                                                      false),
                                       new TextUi());

                // Dump all the accounts
                for (var i = 0; i < vault.Accounts.Length; ++i)
                {
                    var account = vault.Accounts[i];
                    Console.WriteLine("{0}:\n" +
                                      "        id: {1}\n" +
                                      "      name: {2}\n" +
                                      "  username: {3}\n" +
                                      "  password: {4}\n" +
                                      "       url: {5}\n" +
                                      "     group: {6}\n",
                                      i + 1,
                                      account.Id,
                                      account.Name,
                                      account.Username,
                                      account.Password,
                                      account.Url,
                                      account.Group);
                }
            }
            catch (LoginException e)
            {
                Console.WriteLine("Something went wrong: {0}", e);
            }
        }
    }
}
