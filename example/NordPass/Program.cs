// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Net.WebSockets;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Example.Common;
using PasswordManagerAccess.NordPass;

namespace PasswordManagerAccess.Example.NordPass;

static class Program
{
    class BrowserUi : IAsyncUi
    {
        public async Task<string?> AuthorizeOAuth(string url, CancellationToken cancellationToken)
        {
            Console.WriteLine("Opening browser for Nord Account login...");

            // Launch Chrome as a normal process with remote debugging enabled.
            // This avoids Cloudflare bot detection that blocks Selenium/WebDriver.
            const int debugPort = 9223;
            var userDataDir = Path.Combine(Path.GetTempPath(), "nordpass-chrome-debug");
            var chromeArgs = $"--remote-debugging-port={debugPort} --user-data-dir=\"{userDataDir}\" \"{url}\"";

            var chromePath = FindChromePath();
            if (chromePath == null)
            {
                Console.WriteLine("Could not find Chrome. Please install Google Chrome.");
                return null;
            }

            var process = Process.Start(
                new ProcessStartInfo
                {
                    FileName = chromePath,
                    Arguments = chromeArgs,
                    UseShellExecute = false,
                    RedirectStandardError = true,
                }
            );

            if (process == null)
            {
                Console.WriteLine("Failed to start Chrome.");
                return null;
            }

            try
            {
                Console.WriteLine("Please enter your Nord Account password in the browser window.");

                // Wait for Chrome to start and get the WebSocket debug URL for the tab
                using var http = new HttpClient();
                string? wsUrl = null;
                for (var i = 0; i < 30; i++)
                {
                    try
                    {
                        var json = await http.GetStringAsync($"http://localhost:{debugPort}/json", cancellationToken).ConfigureAwait(false);
                        var tabs = JsonSerializer.Deserialize<JsonElement[]>(json);
                        if (tabs is { Length: > 0 })
                        {
                            wsUrl = tabs[0].GetProperty("webSocketDebuggerUrl").GetString();
                            break;
                        }
                    }
                    catch (HttpRequestException) { }
                    await Task.Delay(500, cancellationToken).ConfigureAwait(false);
                }

                if (wsUrl == null)
                {
                    Console.WriteLine("Failed to connect to Chrome debug protocol.");
                    return null;
                }

                // Connect via WebSocket and listen for every navigation event
                using var ws = new ClientWebSocket();
                await ws.ConnectAsync(new Uri(wsUrl), cancellationToken).ConfigureAwait(false);

                // Enable page events
                var enableCmd = JsonSerializer.SerializeToUtf8Bytes(new { id = 1, method = "Page.enable" });
                await ws.SendAsync(enableCmd, WebSocketMessageType.Text, true, cancellationToken).ConfigureAwait(false);

                var buffer = new byte[64 * 1024];
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(TimeSpan.FromSeconds(120));

                while (!cts.Token.IsCancellationRequested)
                {
                    var result = await ws.ReceiveAsync(buffer, cts.Token).ConfigureAwait(false);
                    var message = JsonSerializer.Deserialize<JsonElement>(buffer.AsSpan(0, result.Count));

                    var method = message.TryGetProperty("method", out var m) ? m.GetString() : null;
                    if (method != "Page.frameNavigated")
                        continue;

                    var frameUrl = message.GetProperty("params").GetProperty("frame").GetProperty("url").GetString() ?? "";
                    if (!frameUrl.Contains("app.nordpass.com") || !frameUrl.Contains("verify_token="))
                        continue;

                    var uri = new Uri(frameUrl);
                    var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
                    var token = query["verify_token"];

                    if (!string.IsNullOrEmpty(token))
                    {
                        Console.WriteLine("Got verify token from browser redirect.");
                        return token;
                    }
                }

                Console.WriteLine("Timed out waiting for authentication.");
                return null;
            }
            finally
            {
                try
                {
                    process.Kill();
                }
                catch
                {
                    // Already exited
                }
            }
        }

        private static string FindChromePath()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                return "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return @"C:\Program Files\Google\Chrome\Application\chrome.exe";
            return "google-chrome";
        }
    }

    static async Task Main(string[] args)
    {
        var config = Util.ReadConfig();

        try
        {
            var cts = new CancellationTokenSource();
            var vault = await Client
                .OpenVault(config["username"], config["master-password"], new BrowserUi(), new PlainStorage(), cts.Token)
                .ConfigureAwait(false);

            for (var i = 0; i < vault.Accounts.Length; ++i)
            {
                var a = vault.Accounts[i];
                Console.WriteLine(
                    "{0}:\n"
                        + "          id: {1}\n"
                        + "        name: {2}\n"
                        + "    username: {3}\n"
                        + "    password: {4}\n"
                        + "         url: {5}\n"
                        + "        note: {6}\n"
                        + "      folder: {7}\n",
                    i + 1,
                    a.Id,
                    a.Name,
                    a.Username,
                    a.Password,
                    a.Url,
                    a.Note,
                    a.Folder
                );
            }
        }
        catch (BaseException e)
        {
            Util.PrintException(e);
        }
    }
}
