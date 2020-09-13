// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Example.Common;
using PasswordManagerAccess.ZohoVault;
using PasswordManagerAccess.ZohoVault.Ui;

namespace PasswordManagerAccess.Example.ZohoVault
{
    class TextUi: BaseUi, IUi
    {
        public Passcode ProvideGoogleAuthPasscode()
        {
            return ProvideOtpPasscode("Google Authenticator");
        }

        //
        // Private
        //

        private static Passcode ProvideOtpPasscode(string method)
        {
            var answer = GetAnswer($"Please enter {method} code {PressEnterToCancel}");
            return answer == "" ? Passcode.Cancel : new Passcode(answer, GetRememberMe());
        }
    }

    static class Program
    {
        static void Main(string[] args)
        {
            var config = Util.ReadConfig();
            try
            {
                // Open the remote vault
                var vault = Vault.Open(config["username"],
                                       config["password"],
                                       config["passphrase"],
                                       new TextUi(),
                                       new PlainStorage());

                // Print the decrypted accounts
                for (int i = 0; i < vault.Accounts.Length; ++i)
                {
                    var account = vault.Accounts[i];

                    Console.WriteLine("{0}:\n" +
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
            catch (BaseException e)
            {
                Util.PrintException(e);
            }
        }
    }
}
