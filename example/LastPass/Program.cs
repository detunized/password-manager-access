// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Threading;
using System.Threading.Tasks;
using OneOf;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Example.Common;
using PasswordManagerAccess.LastPass;
using PasswordManagerAccess.LastPass.Ui;

namespace PasswordManagerAccess.Example.LastPass
{
    public static class Program
    {
        // Very simple text based user interface that demonstrates how to respond to Vault UI requests.
        private class TextUi : DuoAsyncUi, IAsyncUi
        {
            public Task<OneOf<Otp, MfaMethod, Cancelled>> ProvideGoogleAuthPasscode(MfaMethod[] methods, CancellationToken cancellationToken) =>
                ProvideOtpPasscode("Google Authenticator", methods, cancellationToken);

            public Task<OneOf<Otp, MfaMethod, Cancelled>> ProvideMicrosoftAuthPasscode(MfaMethod[] methods, CancellationToken cancellationToken) =>
                ProvideOtpPasscode("Microsoft Authenticator", methods, cancellationToken);

            public Task<OneOf<Otp, MfaMethod, Cancelled>> ProvideYubikeyPasscode(MfaMethod[] methods, CancellationToken cancellationToken) =>
                ProvideOtpPasscode("Yubikey", methods, cancellationToken);

            public Task<OneOf<Otp, WaitForOutOfBand, MfaMethod, Cancelled>> ApproveLastPassAuth(
                MfaMethod[] methods,
                CancellationToken cancellationToken
            ) => ApproveOutOfBand("LastPass Authenticator", methods, cancellationToken);

            public Task<OneOf<Otp, WaitForOutOfBand, MfaMethod, Cancelled>> ApproveDuo(MfaMethod[] methods, CancellationToken cancellationToken) =>
                ApproveOutOfBand("Duo Security", methods, cancellationToken);

            //
            // Private
            //

            private static async Task<OneOf<Otp, MfaMethod, Cancelled>> ProvideOtpPasscode(
                string method,
                MfaMethod[] methods,
                CancellationToken cancellationToken
            )
            {
                var prompt = $"> Please enter {method} code {PressEnterToCancel}" + BuildMfaPrompt(methods);

                var answer = await GetAnswer(prompt, cancellationToken);
                return answer switch
                {
                    "" => new Cancelled(""),
                    var s when s.EndsWith('!') => methods[int.Parse(s.Substring(0, s.Length - 1)) - 1],
                    _ => new Otp(answer, await GetRememberMe(cancellationToken)),
                };
            }

            private static async Task<OneOf<Otp, WaitForOutOfBand, MfaMethod, Cancelled>> ApproveOutOfBand(
                string method,
                MfaMethod[] methods,
                CancellationToken cancellationToken
            )
            {
                Console.WriteLine($"> Please approve out-of-band via {method} and press ENTER");
                var answer = await GetAnswer(
                    $"Or enter the {method} passcode from the app or 'c' to cancel" + BuildMfaPrompt(methods),
                    cancellationToken
                );

                return answer switch
                {
                    "c" or "C" => new Cancelled(""),
                    var s when s.EndsWith('!') => methods[int.Parse(s.Substring(0, s.Length - 1)) - 1],
                    "" => new WaitForOutOfBand(await GetRememberMe(cancellationToken)),
                    _ => new Otp(answer, await GetRememberMe(cancellationToken)),
                };
            }

            private static string BuildMfaPrompt(MfaMethod[] methods)
            {
                if (methods.Length == 0)
                    return "";

                var prompt = $" or selected a diffrent MFA method by entering the number followed by !:\n";
                for (var i = 0; i < methods.Length; i++)
                    prompt += $"{i + 1}. {methods[i]}\n";

                return prompt;
            }
        }

        public static async Task Main(string[] args)
        {
            var config = Util.ReadConfig();

            try
            {
                // Fetch and create the vault from LastPass
                var vault = await Vault.Open(
                    config["username"],
                    config["password"],
                    new ClientInfo(Platform.Desktop, config["client-id"], config["client-description"]),
                    new TextUi(),
                    new ParserOptions
                    {
                        // Set to true to parse "server" secure notes
                        ParseSecureNotesToAccount = false,
                        LoggingEnabled = true,
                    },
                    null,
                    CancellationToken.None
                );

                // Dump all the accounts
                for (var i = 0; i < vault.Accounts.Length; ++i)
                {
                    var account = vault.Accounts[i];
                    Console.WriteLine(
                        "{0}:\n"
                            + "        id: {1}\n"
                            + "      name: {2}\n"
                            + "  username: {3}\n"
                            + "  password: {4}\n"
                            + "       url: {5}\n"
                            + "      path: {6}\n"
                            + "     notes: {7}\n"
                            + "      totp: {8}\n"
                            + "  favorite: {9}\n"
                            + "    shared: {10}\n",
                        i + 1,
                        account.Id,
                        account.Name,
                        account.Username,
                        account.Password,
                        account.Url,
                        account.Path,
                        account.Notes,
                        account.Totp,
                        account.IsFavorite,
                        account.IsShared
                    );
                }
            }
            catch (BaseException e)
            {
                Util.PrintException(e);
            }
        }
    }
}
