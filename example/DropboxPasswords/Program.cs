// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Example.Common;
using PasswordManagerAccess.DropboxPasswords;
using PuppeteerSharp;
using System.Runtime.InteropServices;

namespace PasswordManagerAccess.Example.DropboxPasswords
{
    public static class Program
    {
        internal class TextUi : IUi
        {
            public string PerformOAuthLogin(string url, string redirectUrl)
            {
                // Detect the Chrome installation path.
                // Note that this will not work for all installations. This code here is purely to demonstrate how
                // this might be implemented. The real application should launch the browser in a more robust way.
                var chromePath = "";
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    chromePath = @"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe";
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                    chromePath = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                    chromePath = "/usr/bin/google-chrome";
                else
                    throw new InvalidOperationException("Unsupported platform");

                return Task.Run(async () =>
                {
                    using (var browser = await Puppeteer.LaunchAsync(new LaunchOptions
                           {
                               ExecutablePath = chromePath,
                               Headless = false
                           }))
                    using (var page = await browser.NewPageAsync())
                    {
                        Util.WriteLine($"Opening in browser: {url}", ConsoleColor.Green);
                        await page.GoToAsync(url);

                        // Wait for redirect
                        var tcs = new TaskCompletionSource<string>();
                        page.Response += (sender, e) =>
                        {
                            if (e.Response.Url.StartsWith(redirectUrl))
                                tcs.SetResult(e.Response.Url);
                        };

                        // TODO: Detect the situation when the redirect doesn't happen.
                        var redirectedTo = await tcs.Task;
                        Util.WriteLine($"Redirected to: {redirectedTo}", ConsoleColor.Yellow);

                        await browser.CloseAsync();
                        return redirectedTo;
                    }
                }).GetAwaiter().GetResult();
            }

            public void WillSendEnrollRequest()
            {
                Util.WriteLine(
                    "Sending the enrollment request. Please open your browser extension to receive the notification. And press ENTER when done.",
                    ConsoleColor.Green);
                Console.ReadLine();
            }

            public void EnrollRequestSent(string[] deviceNames)
            {
                Util.WriteLine("Please approve the enrollment request that has been sent to the following devices:",
                               ConsoleColor.Green);

                foreach (var name in deviceNames)
                    Util.WriteLine($"  - {name}", ConsoleColor.Yellow);
            }

            public IUi.Action AskForNextAction()
            {
                while (true)
                {
                    Util.WriteLine("You need to approve the enrollment on one of your devices. Please choose:",
                                   ConsoleColor.Green);
                    Util.WriteLine("  1. Keep waiting", ConsoleColor.Yellow);
                    Util.WriteLine("  2. Resend the request", ConsoleColor.Yellow);
                    Util.WriteLine("  3. Cancel", ConsoleColor.Yellow);

                    int choice;
                    switch (int.TryParse(Console.ReadLine(), out choice) ? choice : 0)
                    {
                    case 1:
                        return IUi.Action.KeepWaiting;
                    case 2:
                        return IUi.Action.ResendRequest;
                    case 3:
                        return IUi.Action.Cancel;
                    default:
                        Util.WriteLine("Huh?", ConsoleColor.Red);
                        break;
                    }
                }
            }
        }

        static void Main(string[] args)
        {
            var config = Util.ReadConfig();

            try
            {
                // The device is required. The first time it should be generated using
                // Vault.GenerateRandomDeviceId and stored for later reuse. It's not a
                // good idea to generate a new device ID on every run.
                var deviceId = config.ContainsKey("device-id") ? config["device-id"] : "";
                if (string.IsNullOrEmpty(deviceId))
                {
                    deviceId = Vault.GenerateRandomDeviceId();
                    Console.WriteLine($"Your newly generated device ID is {deviceId}. " +
                                      "Store it and use it for subsequent runs.");
                }

                // The recovery words are optional. It's possible to use the recovery words instead a full device
                // enrollment with an approval on another enrolled device. In this case the master key is not
                // saved to the secure storage. Instead it's derived from the recovery words every time the vault
                // is opened.
                var words = Array.Empty<string>();
                if (config.ContainsKey("recovery-words"))
                {
                    words = config["recovery-words"].Split(' ');
                    if (words.Length != 12)
                    {
                        Console.WriteLine("Exactly 12 words separated by a single space should be provided.\n" +
                                          "See config.yaml.example for reference.");
                        return;
                    }
                }

                var clientInfo = new ClientInfo(config["device-id"], "PMA Dropbox Passwords Example");

                var vault = words.Length > 0
                    ? Vault.Open(clientInfo, words, new TextUi(), new PlainStorage())
                    : Vault.Open(clientInfo, new TextUi(), new PlainStorage());

                var accounts = vault.Accounts;
                for (var i = 0; i < accounts.Length; ++i)
                {
                    var account = accounts[i];
                    Console.WriteLine("  - {0}: {1} {2} {3} {4} {5} {6} {7}",
                                      i + 1,
                                      account.Id,
                                      account.Name,
                                      account.Username,
                                      account.Password,
                                      account.Url,
                                      account.Note,
                                      account.Folder);

                }
            }
            catch (BaseException e)
            {
                Util.PrintException(e);
            }
        }
    }
}
