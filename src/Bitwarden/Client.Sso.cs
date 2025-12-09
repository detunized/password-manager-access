// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Bitwarden.Ui;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Bitwarden;

public static partial class Client
{
    public static async Task<Session> LogInSso(ClientInfoSso clientInfo, string baseUrl, IAsyncUi ui, CancellationToken cancellationToken)
    {
        var transport = new RestTransport();
        try
        {
            return await LogInSso(clientInfo, baseUrl, ui, transport, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception)
        {
            transport.Dispose();
            throw;
        }
    }

    //
    // Internal
    //

    internal static async Task<Session> LogInSso(
        ClientInfoSso clientInfo,
        string baseUrl,
        IAsyncUi ui,
        IRestTransport transport,
        CancellationToken cancellationToken
    )
    {
        var ssoResult = await LoginWithIdentityProvider(clientInfo, baseUrl, ui, cancellationToken);

        // From this point on it's a regular login sequence with some extra parameters
        return await LogInGeneric(
                AppName,
                clientInfo.DeviceId,
                clientInfo.Password,
                baseUrl,
                new Dictionary<string, string>
                {
                    ["grant_type"] = "authorization_code",
                    ["code"] = ssoResult.Code,
                    ["code_verifier"] = ssoResult.CodeVerifier,
                    ["redirect_uri"] = ssoResult.RedirectUrl,
                },
                transport,
                cancellationToken
            )
            .ConfigureAwait(false);
    }

    internal record SsoLoginResult(string Code, string CodeVerifier, string RedirectUrl);

    internal static async Task<SsoLoginResult> LoginWithIdentityProvider(
        ClientInfoSso clientInfo,
        string baseUrl,
        IAsyncUi ui,
        CancellationToken cancellationToken
    )
    {
        using var server = StartLocalServer();
        var redirectUrl = server.Url;

        var state = Util.GenerateRandomString(64);
        var codeVerifier = Util.GenerateRandomString(64);
        var codeVerifierHash = Crypto.Sha256(codeVerifier);
        var challenge = codeVerifierHash.ToUrlSafeBase64NoPadding();

        // Make SSO provider login URL
        // CLI SSO URL:
        // https://vault.bitwarden.com/#/sso?
        //    clientId=cli
        //    redirectUri=http://localhost:8065
        //    state=ynrPYu6j6GiGaA4Qlmq0GYlVHRwXB8hTGfzOxlqERfwGD6aSzLgXNrpNcN8wNEK5
        //    codeChallenge=Rhlqz8Cvi7Ysrg_e0C0hMV7c2UldAqG8KVqVNdSf2hg
        //    identifier=organization

        var ssoLoginUrl =
            $"{baseUrl.TrimEnd('/')}/#/sso?clientId={AppName}&redirectUri={server.Url.EncodeUriData()}&state={state}&codeChallenge={challenge}";

        if (!clientInfo.Organization.IsNullOrEmpty())
            ssoLoginUrl += $"&identifier={clientInfo.Organization.EncodeUriData()}";

        // Start both tasks, but don't await them yet
        var redirectTask = WaitForSsoRedirect(server, cancellationToken);

        // We need a linked cancellation token so that we can cancel browser operation
        // when we get a redirect
        var browserCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var browserTask = ui.PerformSsoLogin(ssoLoginUrl, browserCts.Token);

        // This should return quickly and not wait for the user to complete the login
        var success = false;
        try
        {
            await Task.WhenAny(redirectTask, browserTask).ConfigureAwait(false);

            // Check if user canceled
            if (browserTask.IsCompleted && browserTask.Result is { } canceled)
                throw new CanceledSsoLoginException($"SSO login canceled: {canceled.Reason}");

            // Otherwise we should get a hit on our local server with a redirect
            // TODO: Should we add a timeout?
            var redirectedTo = await redirectTask.ConfigureAwait(false);

            var serverState = Url.ExtractAndDecodeQueryParameter(redirectedTo, "state");
            if (serverState.IsNullOrEmpty())
                throw new InternalErrorException("Missing SSO state returned");

            // State is returned in a form "<state>_identifier=<orgId>"
            var serverStateParts = serverState.Split("_identifier=");
            if (serverStateParts.Length != 2)
                throw new InternalErrorException($"Invalid SSO state returned: '{serverState}'");

            if (serverStateParts[0] != state)
                throw new InternalErrorException("Invalid SSO state returned");

            var code = Url.ExtractAndDecodeQueryParameter(redirectedTo, "code");
            if (code.IsNullOrEmpty())
                throw new InternalErrorException("Missing SSO code returned");

            success = true;

            return new SsoLoginResult(code, codeVerifier, redirectUrl);
        }
        finally
        {
            // Cancel browser operation if still running
            if (!browserTask.IsCompleted)
                await browserCts.CancelAsync();

            await ui.CloseBrowser(success, cancellationToken).ConfigureAwait(false);
        }
    }

    internal record LocalServer(HttpListener Listener, string Url) : IDisposable
    {
        public void Dispose()
        {
            Listener.Stop();
            Listener.Close();
        }
    }

    internal static LocalServer StartLocalServer()
    {
        foreach (var host in LocalHosts)
        {
            for (var port = 8065; port < 8075; port++)
            {
                try
                {
                    var url = $"http://{host}:{port}";
                    var listener = new HttpListener();
                    listener.Prefixes.Add($"{url}/");
                    listener.Start();

                    return new LocalServer(listener, url);
                }
                catch (HttpListenerException)
                {
                    // Host/port combination is in use, try the next one
                }
            }
        }

        throw new InternalErrorException("Failed to start a local HTTP server on any of the available ports");
    }

    internal static async Task<string> WaitForSsoRedirect(LocalServer server, CancellationToken cancellationToken)
    {
        // TODO: Should we check if this is the expected redirect and not some other random request?

        // Wait for incoming request
        var context = await server.Listener.GetContextAsync().ConfigureAwait(false);

        // Grab the URL. It should contain the code and state parameters returned by the server.
        var url = context.Request.Url?.ToString() ?? "";

        // Respond with a simple HTML page
        using var response = context.Response;
        var buffer = "<html><body><h1>You can close this window now and return to the application</h1></body></html>".ToBytes();
        response.ContentLength64 = buffer.Length;
        await using var output = response.OutputStream;
        await output.WriteAsync(buffer, cancellationToken);

        // Done
        return url;
    }

    //
    // Private
    //

    private static readonly string[] LocalHosts = ["localhost", "127.0.0.1", "[::1]"];
}
