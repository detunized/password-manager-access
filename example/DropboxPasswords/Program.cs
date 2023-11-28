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
        }

        static void Main(string[] args)
        {
            var config = Util.ReadConfig();

            try
            {
                var words = config["recovery-words"].Split(' ');
                if (words.Length != 12)
                {
                    Console.WriteLine("Exactly 12 words separated by a single space should be provided.\n" +
                                      "See config.yaml.example for reference.");
                    return;
                }

                var accounts = Vault.Open(config["device-id"], new TextUi(), new PlainStorage()).Accounts;
                //var accounts = Vault.Open("", words).Accounts;
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
