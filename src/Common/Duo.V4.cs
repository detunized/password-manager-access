// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using HtmlAgilityPack;
using Newtonsoft.Json;

namespace PasswordManagerAccess.Common
{
    // V4 parts
    internal static partial class Duo
    {
        public static Result AuthenticateV4(string authUrl, IDuoUi ui, IRestTransport transport)
        {
            var rest = new RestClient(transport);

            // 1. First get the main page
            var (html, url, cookies) = GetMainHtml(authUrl, rest);

            // 2. The main page contains the form that we need to POST to
            string host;
            (host, cookies) = SubmitSystemProperties(html, url, cookies, rest);

            // 3. Get `sid`
            var sessionId = ExtractSessionId(url);

            // 4. Extract `xsrf` token. It's used in some requests.
            var xsrf = ExtractXsrf(html);

            // 5. New rest with the API host
            var apiRest = new RestClient(transport,
                                         $"https://{host}/frame/v4/",
                                         defaultHeaders: new Dictionary<string, string>
                                         {
                                             ["X-Xsrftoken"] = xsrf,
                                         },
                                         defaultCookies: cookies);

            // 6. Get available devices and their methods
            var devices = GetDevices(sessionId, apiRest);

            while (true)
            {
                // Ask the user to choose what to do
                var choice = ui.ChooseDuoFactor(devices);
                if (choice == null)
                    return null; // Canceled by user

                // SMS is a special case: it doesn't submit any codes, it rather tells the server to send
                // a new batch of passcodes to the phone via SMS.
                if (choice.Factor == DuoFactor.SendPasscodesBySms)
                {
                    _ = SubmitFactorV4(sessionId, choice, "", apiRest);
                    choice = new DuoChoice(choice.Device, DuoFactor.Passcode, choice.RememberMe);
                }

                // Ask for the passcode
                var passcode = "";
                if (choice.Factor == DuoFactor.Passcode)
                {
                    passcode = ui.ProvideDuoPasscode(choice.Device);
                    if (passcode.IsNullOrEmpty())
                        return null; // Canceled by user
                }

                var token = SubmitFactorAndWaitForTokenV4(sessionId, xsrf, choice, passcode, ui, apiRest);

                // Flow error like an incorrect passcode. The UI has been updated with the error. Keep going.
                if (token.IsNullOrEmpty())
                    continue;

                // All good
                return new Result(token, choice.RememberMe);
            }
        }

        //
        // Temp
        //

        internal static string SubmitFactorV4(string sid, DuoChoice choice, string passcode, RestClient rest)
        {
            var parameters = new Dictionary<string, object>
            {
                ["sid"] = sid,
                ["device"] = choice.Device.Id,
                ["factor"] = GetFactorParameterValue(choice.Factor),
                ["postAuthDestination"] = "OIDC_EXIT",
            };

            if (!passcode.IsNullOrEmpty())
                parameters["passcode"] = passcode;

            var response = PostForm<R.SubmitFactor>("prompt", parameters, rest);
            return response.TransactionId ?? "";
        }

        // Returns null when a recoverable flow error (like incorrect code or time out) happened
        // TODO: Don't return null, use something more obvious
        internal static string SubmitFactorAndWaitForTokenV4(string sid,
                                                             string xsrf,
                                                             DuoChoice choice,
                                                             string passcode,
                                                             IDuoUi ui,
                                                             RestClient rest)
        {
            var txid = SubmitFactorV4(sid, choice, passcode, rest);
            if (txid.IsNullOrEmpty())
                throw MakeInvalidResponseError("transaction ID (txid) is expected but wasn't found");

            if (!PollForResultUrlV4(sid, txid, ui, rest))
                return null;

            return FetchCodeV4(sid, txid, xsrf, choice, rest);
        }

        // Returns null when a recoverable flow error (like incorrect code or time out) happened
        // TODO: Don't return null, use something more obvious
        internal static bool PollForResultUrlV4(string sid, string txid, IDuoUi ui, RestClient rest)
        {
            const int maxPollAttempts = 100;

            // Normally it wouldn't poll nearly as many times. Just a few at most. It either bails on error or
            // returns the result. This number here just to prevent an infinite loop, which is never a good idea.
            for (var i = 0; i < maxPollAttempts; i += 1)
            {
                var response = PostForm<R.StatusV4>("status",
                                                    new Dictionary<string, object>
                                                    {
                                                        ["sid"] = sid,
                                                        ["txid"] = txid,
                                                    },
                                                    rest,
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
                                                    });

#if BLAH
#endif

                var (status, text) = GetResponseStatusV4(response);
                UpdateUi(status, text, ui);

                switch (status)
                {
                case DuoStatus.Success:
                    return true;
                case DuoStatus.Error:
                    return false;
                }

                // TODO: Need to sleep or wait here!
            }

            throw MakeInvalidResponseError("expected to receive a valid result or error, got none of it");
        }

        internal static (DuoStatus Status, string Text) GetResponseStatusV4(R.StatusV4 response)
        {
            var status = response.Result switch
            {
                "SUCCESS" => DuoStatus.Success,
                "FAILURE" => DuoStatus.Error,
                _ => DuoStatus.Info
            };

            return (status, response.Reason ?? response.Code ?? "");
        }

        internal static string FetchCodeV4(string sid, string txid, string xsrf, DuoChoice choice, RestClient rest)
        {
            var response = rest.PostForm("oidc/exit",
                                         new Dictionary<string, object>
                                         {
                                             ["sid"] = sid,
                                             ["txid"] = txid,
                                             ["factor"] = GetFactorParameterValue(choice.Factor),
                                             ["device_key"] = choice.Device.Id,
                                             ["_xsrf"] = xsrf,
                                             ["dampen_choice"] = "false",
                                         });

            if (!response.IsSuccessful)
                throw MakeSpecializedError(response);

            return ExtractCodeV4(response.RequestUri.AbsoluteUri);
        }

        internal static string ExtractCodeV4(string redirectUrl)
        {
            return ExtractQueryParameter("duo_code", redirectUrl) ??
                   throw MakeInvalidResponseError($"failed to find the 'duo_code' auth token");
        }

        //
        // Internal
        //

        internal static (HtmlDocument Html, string RedirectUrl, Dictionary<string, string> Cookies) GetMainHtml(
            string authUrl,
            RestClient rest)
        {
            var response = rest.Get(authUrl);
            if (!response.IsSuccessful)
                throw MakeSpecializedError(response);

            return (Parse(response.Content), response.RequestUri.AbsoluteUri, response.Cookies);
        }

        internal static string ExtractSessionId(string url)
        {
            return ExtractQueryParameter("sid", url) ??
                   throw MakeInvalidResponseError("failed to find the session ID parameter in the URL");
        }

        // Returns null when not found
        internal static string ExtractQueryParameter(string name, string url)
        {
            var nameEquals = name + '=';
            var start = url.IndexOf(nameEquals, StringComparison.Ordinal);
            if (start < 0)
                return null;

            start += nameEquals.Length;
            var end = url.IndexOf('&', start);

            return end < 0
                ? url.Substring(start) // The last parameter
                : url.Substring(start, end - start);
        }

        internal static string ExtractXsrf(HtmlDocument html)
        {
            var xsrf = html.DocumentNode
                .SelectSingleNode("//form[@id='plugin_form']/input[@name='_xsrf']")?
                .GetAttributeValue("value", "");

            if (xsrf.IsNullOrEmpty())
                throw MakeInvalidResponseError("failed to find the 'xsrf' token");

            return xsrf;
        }

        internal static (string Host, Dictionary<string, string> Cookies) SubmitSystemProperties(
            HtmlDocument html,
            string url,
            Dictionary<string, string> cookies,
            RestClient rest)
        {
            // Find the main form
            var form = html.DocumentNode.SelectSingleNode("//form[@id='plugin_form']");
            if (form == null)
                throw MakeInvalidResponseError("Duo HTML: the main form is not found");

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

            var response = rest.PostForm(url, properties, cookies: cookies);
            if (!response.IsSuccessful)
                throw MakeSpecializedError(response);

            return (response.RequestUri.Host, response.Cookies);
        }

        internal static DuoDevice[] GetDevices(string sessionId, RestClient rest)
        {
            var response = rest.Get<R.Envelope<R.Data>>($"auth/prompt/data?post_auth_action=OIDC_EXIT&sid={sessionId}");
            if (!response.IsSuccessful)
                throw MakeSpecializedError(response);

            return ParseDeviceData(response.Data.Payload);
        }

        internal static DuoDevice[] ParseDeviceData(R.Data data)
        {
            return data.Phones
                .Select(x => new DuoDevice(id: x.Id, name: x.Name, GetDeviceFactors(x.Key, data.Methods)))
                .ToArray();
        }

        internal static DuoFactor[] GetDeviceFactors(string key, R.Method[] methods)
        {
            return methods
                .Where(x => x.DeviceKey == key || x.DeviceKey.IsNullOrEmpty())
                .Where(x => StringToFactor.ContainsKey(x.Factor))
                .Select(x => StringToFactor[x.Factor])
                .ToArray();
        }

        //
        // Response models
        //

        internal static partial class R
        {
            public class Data
            {
                [JsonProperty("phones")]
                public Phone[] Phones;

                [JsonProperty("auth_method_order")]
                public Method[] Methods;
            }

            public class Phone
            {
                [JsonProperty("index")]
                public string Id;

                [JsonProperty("name")]
                public string Name;

                [JsonProperty("key")]
                public string Key;

                [JsonProperty("next_passcode")]
                public string NextPasscode;
            }

            public class Method
            {
                [JsonProperty("deviceKey")]
                public string DeviceKey;

                [JsonProperty("factor")]
                public string Factor;
            }

            public class StatusV4
            {
                [JsonProperty("status_code")]
                public string Code;

                [JsonProperty("result")]
                public string Result;

                [JsonProperty("reason")]
                public string Reason;
            }
        }

        //
        // Data
        //

        private static readonly Dictionary<string, string> KnownSystemProperties = new Dictionary<string, string>
        {
            ["screen_resolution_width"] = "2560",
            ["screen_resolution_height"] = "1440",
            ["color_depth"] = "30",
            ["is_cef_browser"] = "false",
            ["is_ipad_os"] = "false",
            ["is_user_verifying_platform_authenticator_available"] = "false",
            ["react_support"] = "true",
        };

        private static readonly Dictionary<string, DuoFactor> StringToFactor = new Dictionary<string, DuoFactor>
        {
            ["Duo Push"] = DuoFactor.Push,
            ["Duo Mobile Passcode"] = DuoFactor.Passcode,
            ["SMS Passcode"] = DuoFactor.SendPasscodesBySms,
            ["Phone Call"] = DuoFactor.Call,
        };
    }
}
