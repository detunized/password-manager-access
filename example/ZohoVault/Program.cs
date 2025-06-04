// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Example.Common;
using PasswordManagerAccess.ZohoVault;
using PasswordManagerAccess.ZohoVault.Ui;

namespace PasswordManagerAccess.Example.ZohoVault
{
    class TextUi : BaseUi, IUi
    {
        private readonly string _totpSecret;

        public TextUi(string totpSecret)
        {
            _totpSecret = totpSecret;
        }

        public Passcode ProvideGoogleAuthPasscode()
        {
            if (string.IsNullOrEmpty(_totpSecret))
                return ProvideOtpPasscode("Google Authenticator");

            var totp = Util.CalculateGoogleAuthTotp(_totpSecret);
            Console.WriteLine($"Auto-generated TOTP: {totp}");
            Console.WriteLine("Remember this device: no");

            return new Passcode(totp, false);
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
            string totpSecret;
            config.TryGetValue("google-auth-totp-secret", out totpSecret);

            var credentials = new Credentials(username: config["username"], password: config["password"], passphrase: config["passphrase"]);
            var settings = new Settings { KeepSession = true };
            var ui = new TextUi(totpSecret);
            var storage = new PlainStorage();

            Session session = null;
            try
            {
                // Stage 1: LogIn
                session = Client.LogIn(credentials, settings, ui, storage);

                // Stage 2: Download Vault
                var vault = Client.DownloadVault(session, credentials.Passphrase);

                // Print the decrypted accounts
                for (var i = 0; i < vault.Accounts.Length; ++i)
                {
                    var account = vault.Accounts[i];

                    Console.WriteLine(
                        "{0}:\n"
                            + "          id: {1}\n"
                            + "        name: {2}\n"
                            + "    username: {3}\n"
                            + "    password: {4}\n"
                            + "         url: {5}\n"
                            + "        note: {6}\n",
                        i + 1,
                        account.Id,
                        account.Name,
                        account.Username,
                        account.Password,
                        account.Url,
                        account.Note
                    );
                }
            }
            catch (BaseException e)
            {
                Util.PrintException(e);
            }
            finally
            {
                // Stage 3: LogOut
                if (session != null)
                {
                    Client.LogOut(session);
                }
            }
        }
    }
}
