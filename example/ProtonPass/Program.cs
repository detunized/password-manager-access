// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using OpenQA.Selenium;
using OpenQA.Selenium.Chrome;
using OpenQA.Selenium.Support.UI;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Example.Common;
using PasswordManagerAccess.ProtonPass;

namespace PasswordManagerAccess.Example.ProtonPass
{
    public static class Program
    {
        private class AsyncTextUi(string extraPassword) : BaseUi, IAsyncUi
        {
            struct JsMessage
            {
                [JsonProperty("type")]
                public string Type { get; set; }

                [JsonProperty("payload")]
                public JsMessagePayload Payload { get; set; }
            }

            struct JsMessagePayload
            {
                [JsonProperty("type")]
                public string Type { get; set; }

                [JsonProperty("token")]
                public string Token { get; set; }
            }

            public async Task<IAsyncUi.CaptchaResult> SolveCaptcha(string url, string humanVerificationToken, CancellationToken cancellationToken)
            {
                Console.WriteLine($"Please solve the captcha at {url} and press ENTER");

                using (IWebDriver driver = new ChromeDriver())
                {
                    driver.Navigate().GoToUrl(url);

                    new WebDriverWait(driver, TimeSpan.FromSeconds(30)).Until(d =>
                        ((IJavaScriptExecutor)d).ExecuteScript("return document.readyState").Equals("complete")
                    );

                    // JavaScript to inject to intercept postMessage calls and fetch the messages later
                    var vm = (IJavaScriptExecutor)driver;
                    vm.ExecuteScript(
                        @"
                        window.receivedMessages = window.parent.receivedMessages = [];
                        window.postMessage = window.parent.postMessage = function (m) {
                            window.receivedMessages.push(m);
                        }
                    "
                    );

                    const int captchaVerificationTimeoutSec = 60;
                    const int checkEveryMs = 250;

                    // Wait for 60 seconds, checking for messages every 250ms
                    for (var i = 0; i < captchaVerificationTimeoutSec * 1000 / checkEveryMs; i++)
                    {
                        var r =
                            vm.ExecuteScript(
                                @"
                            return (function () {
                                try {
                                    return JSON.stringify(window.receivedMessages);
                                } catch (e) {
                                    return JSON.stringify({error: e.toString()});
                                }
                            })();
                        "
                            ) as string;

                        if (r != null && r.Contains("HUMAN_VERIFICATION_SUCCESS"))
                        {
                            // The returned string is an array of JSON encoded messages, one of them is the success message.
                            // deserialize the array and find the success message
                            var messages = JsonConvert.DeserializeObject<string[]>(r);
                            foreach (var message in messages)
                            {
                                // Parse the message and check if it's the success message
                                try
                                {
                                    var parsed = JsonConvert.DeserializeObject<JsMessage>(message);
                                    if (parsed.Type == "HUMAN_VERIFICATION_SUCCESS" && !string.IsNullOrEmpty(parsed.Payload.Token))
                                    {
                                        Console.WriteLine("Captcha solved!");
                                        return new IAsyncUi.CaptchaResult(true, parsed.Payload.Token);
                                    }
                                }
                                catch (JsonException)
                                {
                                    // Ignore
                                }
                            }

                            // We should not really get here. Something must be wrong with our code or the message structure.
                            Console.WriteLine("Captcha seems to be solved, but the result could not be parsed!");
                            return new IAsyncUi.CaptchaResult(false, "");
                        }

                        await Task.Delay(checkEveryMs, cancellationToken).ConfigureAwait(false);
                    }

                    Console.WriteLine("Timed out!");
                }

                return new IAsyncUi.CaptchaResult(false, "");
            }

            public Task<IAsyncUi.PasscodeResult> ProvideExtraPassword(int attempt, CancellationToken cancellationToken)
            {
                if (!string.IsNullOrEmpty(extraPassword))
                    return Task.FromResult(new IAsyncUi.PasscodeResult(extraPassword));

                return Task.FromResult(new IAsyncUi.PasscodeResult(GetAnswer($"Enter the extra password {PressEnterToCancel}")));
            }

            public Task<IAsyncUi.PasscodeResult> ProvideGoogleAuthPasscode(int attempt, CancellationToken cancellationToken)
            {
                return Task.FromResult(new IAsyncUi.PasscodeResult(GetAnswer($"Enter the Google Authenticator passcode {PressEnterToCancel}")));
            }
        }

        private static void DumpVaults(Vault[] vaults)
        {
            foreach (var vault in vaults)
                DumpVault(vault);
        }

        private static void DumpVaultInfos(VaultInfo[] vaultInfos)
        {
            foreach (var info in vaultInfos)
                DumpVaultInfo(info);
        }

        private static void DumpVault(Vault vault)
        {
            DumpVaultInfo(vault.Info);
            DumpAccounts(vault.Accounts);
        }

        private static void DumpVaultInfo(VaultInfo info)
        {
            Console.WriteLine(
                """
                      Vault: {0}
                Description: {1}
                         ID: {2}
                """,
                info.Name,
                info.Description,
                info.Id
            );
        }

        private static void DumpAccounts(Account[] accounts)
        {
            for (var i = 0; i < accounts.Length; ++i)
            {
                var account = accounts[i];
                DumpAccount($"{i + 1}", account);
            }
        }

        private static void DumpAccount(string prefix, Account account)
        {
            Console.WriteLine(
                $"""
                {prefix}:
                          id: {account.Id}
                        name: {account.Name}
                       email: {account.Email}
                    username: {account.Username}
                    password: {account.Password}
                        totp: {account.Totp}
                        note: {account.Note}
                        urls: ({account.Urls.Length})
                """
            );

            for (var j = 0; j < account.Urls.Length; ++j)
                Console.WriteLine($"           {j + 1}: {account.Urls[j]}");
        }

        private enum DemoMode
        {
            SingleItem,
            SingleVault,
            AllVaultsOneByOneByInfo,
            AllVaultsOneByOneById,
            AllVaults,
            AllVaultsSingleShot,
        }

        private static readonly DemoMode Mode = DemoMode.SingleItem;

        public static async Task Main(string[] args)
        {
            var config = Util.ReadConfig();
            var extraPassword = config.GetValueOrDefault("extra-password", "");

            try
            {
                var cts = new CancellationTokenSource();

                // This is the original method of opening Proton Pass vaults. It does everything in one go. There's no session object to deal with.
                // This method is convenient for downloading all vaults in one shot. To download individual items or individual vaults, or do it
                // multiple times, check one of the other ways demonstrated below.
                if (Mode == DemoMode.AllVaultsSingleShot)
                {
                    var allVaults = await Client
                        .OpenAll(config["username"], config["password"], new AsyncTextUi(extraPassword), new AsyncPlainStorage(), cts.Token)
                        .ConfigureAwait(false);
                    DumpVaults(allVaults);

                    return;
                }

                Session session = null;

                try
                {
                    session = await Client
                        .LogIn(config["username"], config["password"], new AsyncTextUi(extraPassword), new AsyncPlainStorage(), cts.Token)
                        .ConfigureAwait(false);

                    // Any of the operations below could be done multiple times on same session. Remember to call Client.LogOut when done.

                    switch (Mode)
                    {
                        case DemoMode.SingleItem:
                            {
                                // Use your own vault and item IDs.
                                var maybeAccount = await Client.GetItem(
                                    "TsQKDDVRzzAm2FnkEjUMXZbo6qDa2gndi88rMEghRZfRYRnzezXbxO3Vhr9ihh-4_dP9Ikrp3ssTlReX4zI2ow==",
                                    "DyIGqZSxf42a3n2qlfGpqVfiPHvoWM56DuoJW5mShsGxOxD32jEp_S3MLIS9jihx2-edhoNKzA3q5e-q4QvitQ==",
                                    session,
                                    cts.Token
                                );

                                maybeAccount.Switch(
                                    account => DumpAccount("Account", account),
                                    noItem => Console.WriteLine($"NoItem: {noItem}"),
                                    noVault => Console.WriteLine($"NoVault: {noVault}")
                                );
                            }

                            break;
                        case DemoMode.SingleVault:
                            {
                                // Use your own vault ID.
                                var maybeVault = await Client
                                    .DownloadVault(
                                        "TsQKDDVRzzAm2FnkEjUMXZbo6qDa2gndi88rMEghRZfRYRnzezXbxO3Vhr9ihh-4_dP9Ikrp3ssTlReX4zI2ow==",
                                        session,
                                        cts.Token
                                    )
                                    .ConfigureAwait(false);

                                maybeVault.Switch(DumpVault, noVault => Console.WriteLine($"NoVault: {noVault}"));
                            }
                            break;
                        case DemoMode.AllVaultsOneByOneByInfo:
                            {
                                var vaultInfos = await Client.ListAllVaults(session, cts.Token).ConfigureAwait(false);
                                DumpVaultInfos(vaultInfos);

                                foreach (var vaultInfo in vaultInfos)
                                {
                                    var vault = await Client.DownloadVault(vaultInfo, session, cts.Token).ConfigureAwait(false);
                                    DumpVault(vault);
                                }
                            }
                            break;
                        case DemoMode.AllVaultsOneByOneById:
                            {
                                var vaultInfos = await Client.ListAllVaults(session, cts.Token).ConfigureAwait(false);
                                DumpVaultInfos(vaultInfos);

                                foreach (var vaultInfo in vaultInfos)
                                {
                                    var maybeVault = await Client.DownloadVault(vaultInfo.Id, session, cts.Token).ConfigureAwait(false);
                                    maybeVault.Switch(DumpVault, noVault => Console.WriteLine($"NoVault: {noVault}"));
                                }
                            }
                            break;
                        case DemoMode.AllVaults:
                            {
                                var vaults = await Client.DownloadAllVaults(session, cts.Token).ConfigureAwait(false);
                                DumpVaults(vaults);
                            }
                            break;
                    }
                }
                finally
                {
                    if (session != null)
                        await Client.LogOut(session, cts.Token).ConfigureAwait(false);
                }
            }
            catch (BaseException e)
            {
                Util.PrintException(e);
            }
        }
    }
}
