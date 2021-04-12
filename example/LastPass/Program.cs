// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Threading.Tasks;
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
        private class TextUi: DuoUi, IUi
        {
            public async Task<OtpResult> ProvideGoogleAuthPasscode()
            {
                return await ProvideOtpPasscode("Google Authenticator");
            }

            public async Task<OtpResult> ProvideMicrosoftAuthPasscode()
            {
                return await ProvideOtpPasscode("Microsoft Authenticator");
            }

            public async Task<OtpResult> ProvideYubikeyPasscode()
            {
                return await ProvideOtpPasscode("Yubikey");
            }

            public async Task<OobResult> ApproveLastPassAuth()
            {
                return await ApproveOutOfBand("LastPass Authenticator");
            }

            public async Task<OobResult> ApproveDuo()
            {
                return await ApproveOutOfBand("Duo Security");
            }

            //
            // Private
            //

            private static async Task<OtpResult> ProvideOtpPasscode(string method)
            {
                var answer = await GetAnswerAsync($"Please enter {method} code {PressEnterToCancel}");
                return answer == "" ? OtpResult.Cancel : new OtpResult(answer, await GetRememberMeAsync());
            }

            private static async Task<OobResult> ApproveOutOfBand(string method)
            {
                Console.WriteLine($"> Please approve out-of-band via {method} and press ENTER");
                var answer = await GetAnswerAsync($"Or enter the {method} passcode from the app or 'c' to cancel");

                if (answer.ToLower() == "c")
                    return OobResult.Cancel;

                var rememberMe = await GetRememberMeAsync();
                return answer.Length == 0
                    ? OobResult.WaitForApproval(rememberMe)
                    : OobResult.ContinueWithPasscode(answer, rememberMe);
            }
        }

        public static void Main(string[] args)
        {
            Task.Run(() => MainAsync(args)).GetAwaiter().GetResult();
        }

        public static async Task MainAsync(string[] args)
        {
            var config = Util.ReadConfig();

            try
            {
                // Fetch and create the vault from LastPass
                var vault = await Vault.Open(config["username"],
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
                Util.PrintException(e);
            }
        }
    }
}
