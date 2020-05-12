// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Example.Common;
using PasswordManagerAccess.LastPass;
using PasswordManagerAccess.LastPass.Ui;

namespace PasswordManagerAccess.Example.LastPass
{
    public static class Program
    {
        // Very simple text based user interface that demonstrates how to respond to
        // to Vault UI requests.
        private class TextUi: IUi
        {
            public Passcode ProvideGoogleAuthPasscode()
            {
                return ProvideOtpPasscode("Google Authenticator");
            }

            public Passcode ProvideMicrosoftAuthPasscode()
            {
                return ProvideOtpPasscode("Microsoft Authenticator");
            }

            public Passcode ProvideYubikeyPasscode()
            {
                return ProvideOtpPasscode("Yubikey");
            }

            public OufOfBandAction AskToApproveOutOfBand(OutOfBandMethod method)
            {
                Console.WriteLine($"Please approve out-of-band via {method}");
                if (GetAnswer("press ENTER to continue or 'c' to cancel").ToLower() == "c")
                    return OufOfBandAction.Cancel;

                return GetRememberMe() ? OufOfBandAction.ContinueAndRememberMe : OufOfBandAction.Continue;
            }

            private static Passcode ProvideOtpPasscode(string method)
            {
                var answer = GetAnswer($"Please enter {method} code {ToCancel}");
                return answer == "" ? Passcode.Cancel : new Passcode(answer, GetRememberMe());
            }

            private static string GetAnswer(string prompt)
            {
                Console.WriteLine(prompt);
                Console.Write("> ");
                var input = Console.ReadLine();

                return input == null ? "" : input.Trim();
            }

            private static bool GetRememberMe()
            {
                var remember = GetAnswer("Remember this device?").ToLower();
                return remember == "y" || remember == "yes";
            }

            private const string ToCancel = "or just press ENTER to cancel";
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
                                                      config["client-description"]),
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
                                      "      path: {6}\n",
                                      i + 1,
                                      account.Id,
                                      account.Name,
                                      account.Username,
                                      account.Password,
                                      account.Url,
                                      account.Path);
                }
            }
            catch (BaseException e)
            {
                Console.WriteLine("Something went wrong: {0}", e);
            }
        }
    }
}
