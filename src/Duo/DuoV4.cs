// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using HtmlAgilityPack;
using OneOf;
using PasswordManagerAccess.Common;
using R = PasswordManagerAccess.Duo.ResponseV4;

namespace PasswordManagerAccess.Duo
{
    internal static class DuoV4
    {
        public static DuoResult Authenticate(string authUrl, IDuoUi ui, IRestTransport transport, ISimpleLogger logger = null)
        {
            return AuthenticateAsync(authUrl, [], new DuoUiToAsyncUiAdapter(ui), transport, logger, CancellationToken.None)
                .GetAwaiter()
                .GetResult()
                .AsT0;
        }

        public static async Task<OneOf<DuoResult, MfaMethod, DuoCancelled>> AuthenticateAsync(
            string authUrl,
            MfaMethod[] otherMethods,
            IDuoAsyncUi ui,
            IRestTransport transport,
            ISimpleLogger logger,
            CancellationToken cancellationToken
        )
        {
            var rest = new RestClient(transport, logger: logger);

            // 1. First get the main page
            var (html, url, cookies) = await GetMainHtml(authUrl, rest, cancellationToken).ConfigureAwait(false);

            // 2. Detect a redirect to V1
            if (url.Contains("/frame/frameless/v3/auth"))
                return DuoResult.RedirectToV1;

            // 3. The main page contains the form that we need to POST to
            string host;
            (host, cookies) = await SubmitSystemProperties(html, url, cookies, rest, cancellationToken).ConfigureAwait(false);

            // 4. Get `sid`
            var sessionId = ExtractSessionId(url);

            // 5. Extract `xsrf` token. It's used in some requests.
            var xsrf = ExtractXsrf(html);

            // 6. New rest with the API host
            var apiRest = new RestClient(
                transport,
                $"https://{host}/frame/v4/",
                defaultHeaders: new Dictionary<string, string> { ["X-Xsrftoken"] = xsrf },
                defaultCookies: cookies,
                logger: logger
            );

            // 7. Get available devices and their methods
            var devices = await GetDevices(sessionId, apiRest, cancellationToken).ConfigureAwait(false);

            // There should be at least one device to continue
            if (devices.Length == 0)
                throw Util.MakeInvalidResponseError("no devices are registered for authentication");

            while (true)
            {
                // Ask the user to choose what to do
                var factorResult = await ui.ChooseDuoFactor(devices, otherMethods, cancellationToken).ConfigureAwait(false);

                switch (factorResult.Value)
                {
                    case MfaMethod mfa:
                        return mfa;
                    case DuoCancelled cancelled:
                        return cancelled;
                }

                var choice = factorResult.AsT0;

                // SMS is a special case: it doesn't submit any codes, it rather tells the server to send a new code
                // to the phone via SMS.
                if (choice.Factor == DuoFactor.SendPasscodesBySms)
                {
                    _ = await SubmitFactor(sessionId, choice, "", apiRest, cancellationToken).ConfigureAwait(false);
                    choice = choice with { Factor = DuoFactor.Passcode };
                }

                // Ask for the passcode
                var passcode = "";
                if (choice.Factor == DuoFactor.Passcode)
                {
                    var passcodeResult = await ui.ProvideDuoPasscode(choice.Device, cancellationToken).ConfigureAwait(false);
                    switch (passcodeResult.Value)
                    {
                        case DuoPasscode p:
                            passcode = p.Passcode;
                            break;
                        case DuoCancelled cancelled:
                            return cancelled;
                    }
                }

                var maybeResult = await SubmitFactorAndWaitForResult(sessionId, xsrf, choice, passcode, ui, apiRest, cancellationToken)
                    .ConfigureAwait(false);

                // Flow error like an incorrect passcode. The UI has been updated with the error. Keep going.
                if (maybeResult == null)
                    continue;

                // All good
                var result = maybeResult.Value;
                return new DuoResult($"{result.Code}:{result.State}", "", choice.RememberMe);
            }
        }

        //
        // Internal
        //

        internal record struct MainHtml(HtmlDocument Html, string RedirectUrl, Dictionary<string, string> Cookies);

        internal static async Task<MainHtml> GetMainHtml(string authUrl, RestClient rest, CancellationToken cancellationToken)
        {
            var response = await rest.GetAsync(authUrl, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessful)
                throw Util.MakeSpecializedError(response);

            return new MainHtml(Util.Parse(response.Content), response.RequestUri.AbsoluteUri, response.Cookies);
        }

        internal record struct HostCookies(string Host, Dictionary<string, string> Cookies);

        internal static async Task<HostCookies> SubmitSystemProperties(
            HtmlDocument html,
            string url,
            Dictionary<string, string> cookies,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            // Find the main form
            var form = html.DocumentNode.SelectSingleNode("//form[@id='plugin_form']");
            if (form == null)
                throw Util.MakeInvalidResponseError("Duo HTML: the main form is not found");

            // Assign the known values. There are might be others defaulted to "". We're going to ignore them as long
            // as it doesn't break the process.
            var properties = new Dictionary<string, object>();
            foreach (var input in form.SelectNodes("./input"))
            {
                var name = input.GetAttributeValue("name", "");
                if (name.IsNullOrEmpty())
                    continue;

                var value = input.GetAttributeValue("value", "");
                if (value.IsNullOrEmpty())
                    value = KnownSystemProperties.GetOrDefault(name, "");

                properties[name] = value;
            }

            var response = await rest.PostFormAsync(url, properties, [], cookies, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessful)
                throw Util.MakeSpecializedError(response);

            return new HostCookies(response.RequestUri.Host, response.Cookies);
        }

        internal static string ExtractSessionId(string url)
        {
            return Url.ExtractQueryParameter(url, "sid") ?? throw Util.MakeInvalidResponseError("failed to find the session ID parameter in the URL");
        }

        internal static string ExtractXsrf(HtmlDocument html)
        {
            var xsrf = html.DocumentNode.SelectSingleNode("//form[@id='plugin_form']/input[@name='_xsrf']")?.GetAttributeValue("value", "");

            if (xsrf.IsNullOrEmpty())
                throw Util.MakeInvalidResponseError("failed to find the 'xsrf' token");

            return xsrf;
        }

        internal static async Task<DuoDevice[]> GetDevices(string sessionId, RestClient rest, CancellationToken cancellationToken)
        {
            var response = await rest.GetAsync<Response.Envelope<R.Data>>(
                    $"auth/prompt/data?post_auth_action=OIDC_EXIT&sid={sessionId}",
                    cancellationToken
                )
                .ConfigureAwait(false);

            if (!response.IsSuccessful)
                throw Util.MakeSpecializedError(response);

            return ParseDeviceData(response.Data.Payload);
        }

        internal static DuoDevice[] ParseDeviceData(R.Data data)
        {
            if (data.Phones == null)
                return [];

            return data.Phones.Select(x => new DuoDevice(x.Id, x.Name, GetDeviceFactors(x.Key, data.Methods))).ToArray();
        }

        internal static DuoFactor[] GetDeviceFactors(string key, R.Method[] methods)
        {
            return methods
                .Where(x => x.DeviceKey == key || x.DeviceKey.IsNullOrEmpty())
                .Where(x => StringToFactor.ContainsKey(x.Factor))
                .Select(x => StringToFactor[x.Factor])
                .ToArray();
        }

        internal static async Task<string> SubmitFactor(
            string sid,
            DuoChoice choice,
            string passcode,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            var parameters = new Dictionary<string, object>
            {
                ["sid"] = sid,
                ["device"] = choice.Device.Id,
                ["factor"] = Util.GetFactorParameterValue(choice.Factor),
                ["postAuthDestination"] = "OIDC_EXIT",
            };

            if (!passcode.IsNullOrEmpty())
                parameters["passcode"] = passcode;

            var response = await Util.PostForm<Response.SubmitFactor>("prompt", parameters, rest, cancellationToken).ConfigureAwait(false);
            return response.TransactionId ?? "";
        }

        internal record struct CodeState(string Code, string State);

        // Returns null when a recoverable flow error (like incorrect code or time out) happened
        // TODO: Don't return null, use something more obvious
        internal static async Task<CodeState?> SubmitFactorAndWaitForResult(
            string sid,
            string xsrf,
            DuoChoice choice,
            string passcode,
            IDuoAsyncUi ui,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            var txid = await SubmitFactor(sid, choice, passcode, rest, cancellationToken).ConfigureAwait(false);
            if (txid.IsNullOrEmpty())
                throw Util.MakeInvalidResponseError("transaction ID (txid) is expected but wasn't found");

            if (!await PollForResultUrl(sid, txid, ui, rest, cancellationToken).ConfigureAwait(false))
                return null;

            return FetchResult(sid, txid, xsrf, choice, rest);
        }

        internal static async Task<bool> PollForResultUrl(
            string sid,
            string txid,
            IDuoAsyncUi ui,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            const int maxPollAttempts = 100;

            // Normally it wouldn't poll nearly as many times. Just a few at most. It either bails on error or
            // returns the result. This number here just to prevent an infinite loop, which is never a good idea.
            for (var i = 0; i < maxPollAttempts; i += 1)
            {
                var response = await Util.PostForm<R.Status>(
                        "status",
                        new Dictionary<string, object> { ["sid"] = sid, ["txid"] = txid },
                        new Dictionary<string, string>
                        {
                            ["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/112.0",
                            ["Accept"] = "*/*",
                            ["Accept-Language"] = "en-US,en;q=0.5",
                            ["Accept-Encoding"] = "gzip, deflate, br",
                            // TODO: Fix host
                            ["Referer"] = $"https://api-005dde75.duosecurity.com/frame/v4/auth/prompt?sid={sid}",
                            ["Sec-Fetch-Dest"] = "empty",
                            ["Sec-Fetch-Mode"] = "cors",
                            ["Sec-Fetch-Site"] = "same-origin",
                        },
                        rest,
                        cancellationToken
                    )
                    .ConfigureAwait(false);

                var (status, text) = GetResponseStatus(response);
                await Util.UpdateUi(status, text, ui, cancellationToken).ConfigureAwait(false);

                switch (status)
                {
                    case DuoStatus.Success:
                        return true;
                    case DuoStatus.Error:
                        return false;
                }

                // TODO: Need to sleep or wait here!
            }

            throw Util.MakeInvalidResponseError("expected to receive a valid result or error, got none of it");
        }

        internal static (DuoStatus Status, string Text) GetResponseStatus(R.Status response)
        {
            var status = response.Result switch
            {
                "SUCCESS" => DuoStatus.Success,
                "FAILURE" => DuoStatus.Error,
                _ => DuoStatus.Info,
            };

            return (status, response.Reason ?? response.Code ?? "");
        }

        internal static CodeState FetchResult(string sid, string txid, string xsrf, DuoChoice choice, RestClient rest)
        {
            var response = rest.PostForm(
                "oidc/exit",
                new Dictionary<string, object>
                {
                    ["sid"] = sid,
                    ["txid"] = txid,
                    ["factor"] = Util.GetFactorParameterValue(choice.Factor),
                    ["device_key"] = choice.Device.Id,
                    ["_xsrf"] = xsrf,
                    ["dampen_choice"] = "false",
                }
            );

            if (!response.IsSuccessful)
                throw Util.MakeSpecializedError(response);

            return ExtractResult(response.RequestUri.AbsoluteUri);
        }

        internal static CodeState ExtractResult(string redirectUrl)
        {
            var code =
                Url.ExtractQueryParameter(redirectUrl, "code")
                ?? Url.ExtractQueryParameter(redirectUrl, "duo_code")
                ?? throw Util.MakeInvalidResponseError("failed to find the 'duo_code' auth token");

            var state = Url.ExtractQueryParameter(redirectUrl, "state") ?? "";

            return new CodeState(code, state);
        }

        //
        // Data
        //

        private static readonly Dictionary<string, string> KnownSystemProperties =
            new()
            {
                ["screen_resolution_width"] = "2560",
                ["screen_resolution_height"] = "1440",
                ["color_depth"] = "30",
                ["is_cef_browser"] = "false",
                ["is_ipad_os"] = "false",
                ["is_user_verifying_platform_authenticator_available"] = "false",
                ["react_support"] = "true",
            };

        private static readonly Dictionary<string, DuoFactor> StringToFactor =
            new()
            {
                ["Duo Push"] = DuoFactor.Push,
                ["Duo Mobile Passcode"] = DuoFactor.Passcode,
                ["SMS Passcode"] = DuoFactor.SendPasscodesBySms,
                ["Phone Call"] = DuoFactor.Call,
            };
    }
}
