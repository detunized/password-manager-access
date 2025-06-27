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

        private static void DumpVault(Vault vault)
        {
            Console.WriteLine(
                "Vault: {0}\n" + "Description: {1}\n" + "ID: {2}\n" + "Accounts: ({3})\n",
                vault.Info.Name,
                vault.Info.Description,
                vault.Info.Id,
                vault.Accounts.Length
            );

            for (var i = 0; i < vault.Accounts.Length; ++i)
            {
                var account = vault.Accounts[i];

                Console.WriteLine(
                    "\n"
                        + "{0}:\n"
                        + "          id: {1}\n"
                        + "        name: {2}\n"
                        + "       email: {3}\n"
                        + "    username: {4}\n"
                        + "    password: {5}\n"
                        + "        totp: {6}\n"
                        + "        note: {7}\n"
                        + "        urls: ({8})",
                    i + 1,
                    account.Id,
                    account.Name,
                    account.Email,
                    account.Username,
                    account.Password,
                    account.Totp,
                    account.Note,
                    account.Urls.Length
                );

                for (var j = 0; j < account.Urls.Length; ++j)
                    Console.WriteLine("           {0}: {1}", j + 1, account.Urls[j]);
            }
        }

        public static async Task Main(string[] args)
        {
            var config = Util.ReadConfig();
            var extraPassword = config.GetValueOrDefault("extra-password", "");

            try
            {
                // Uncomment the following line to use the old way of opening vaults.
                // This is not recommended as it does not support the new Proton Pass features.
                // var vaults = await Client
                //     .OpenAll(config["username"], config["password"], new AsyncTextUi(extraPassword), new AsyncPlainStorage())
                //     .ConfigureAwait(false);
                // DumpVaults(vaults);

                var cts = new CancellationTokenSource();
                Session session = null;

                try
                {
                    session = await Client
                        .LogIn(config["username"], config["password"], new AsyncTextUi(extraPassword), new AsyncPlainStorage(), cts.Token)
                        .ConfigureAwait(false);

                    var vaults = await Client.DownloadAllVaults(session, cts.Token).ConfigureAwait(false);
                    DumpVaults(vaults);
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
