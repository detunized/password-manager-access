// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Example.Common;
using PasswordManagerAccess.ProtonPass;

using OpenQA.Selenium;
using OpenQA.Selenium.Chrome;
using OpenQA.Selenium.Support.UI;

namespace PasswordManagerAccess.Example.ProtonPass
{
    public static class Program
    {
        private class AsyncTextUi : IAsyncUi
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

            public async Task<IAsyncUi.Result> SolveCaptcha(string url, string humanVerificationToken, CancellationToken cancellationToken)
            {
                Console.WriteLine($"Please solve the captcha at {url} and press ENTER");

                using (IWebDriver driver = new ChromeDriver())
                {
                    driver.Navigate().GoToUrl(url);

                    new WebDriverWait(driver, TimeSpan.FromSeconds(30)).Until(
                        d => ((IJavaScriptExecutor)d).ExecuteScript("return document.readyState").Equals("complete"));

                    // JavaScript to inject to intercept postMessage calls and fetch the messages later
                    var vm = (IJavaScriptExecutor)driver;
                    vm.ExecuteScript(@"
                        window.receivedMessages = window.parent.receivedMessages = [];
                        window.postMessage = window.parent.postMessage = function (m) {
                            window.receivedMessages.push(m);
                        }
                    ");

                    const int captchaVerificationTimeoutSec = 60;
                    const int checkEveryMs = 250;

                    // Wait for 60 seconds, checking for messages every 250ms
                    for (var i = 0; i < captchaVerificationTimeoutSec * 1000 / checkEveryMs; i++)
                    {
                        var r = vm.ExecuteScript(@"
                            return (function () {
                                try {
                                    return JSON.stringify(window.receivedMessages);
                                } catch (e) {
                                    return JSON.stringify({error: e.toString()});
                                }
                            })();
                        ") as string;

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
                                        return new IAsyncUi.Result { Solved = true, Token = parsed.Payload.Token } ;
                                    }
                                }
                                catch (JsonException)
                                {
                                    // Ignore
                                }
                            }

                            // We should not really get here. Something must be wrong with our code or the message structure.
                            Console.WriteLine("Captcha seems to be solved, but the result could not be parsed!");
                            return new IAsyncUi.Result { Solved = false };
                        }

                        await Task.Delay(checkEveryMs, cancellationToken).ConfigureAwait(false);
                    }

                    Console.WriteLine("Timed out!");
                }

                return new IAsyncUi.Result { Solved = false };
            }
        }

        public static void Main(string[] args)
        {
            var config = Util.ReadConfig();

            try
            {
                var vault = Vault.Open(config["username"],
                                       config["password"],
                                       new AsyncTextUi(),
                                       new AsyncPlainStorage()).GetAwaiter().GetResult();

                Console.WriteLine("Vault: {0}\n" +
                                  "Description: {1}\n" +
                                  "Accounts: ({2})\n",
                                  vault.Name,
                                  vault.Description,
                                  vault.Accounts.Length);

                for (var i = 0; i < vault.Accounts.Length; ++i)
                {
                    var account = vault.Accounts[i];

                    Console.WriteLine("\n" +
                                      "{0}:\n" +
                                      "          id: {1}\n" +
                                      "        name: {2}\n" +
                                      "       email: {3}\n" +
                                      "    username: {4}\n" +
                                      "    password: {5}\n" +
                                      "        totp: {6}\n" +
                                      "        note: {7}\n" +
                                      "        urls: ({8})",
                                      i + 1,
                                      account.Id,
                                      account.Name,
                                      account.Email,
                                      account.Username,
                                      account.Password,
                                      account.Totp,
                                      account.Note,
                                      account.Urls.Length);

                    for (var j = 0; j < account.Urls.Length; ++j)
                        Console.WriteLine("           {0}: {1}", j + 1, account.Urls[j]);
                }

            }
            catch (BaseException e)
            {
                Util.PrintException(e);
            }
        }
    }
}
