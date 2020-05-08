// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Linq;
using HtmlAgilityPack;
using Newtonsoft.Json;

namespace PasswordManagerAccess.Common
{
    internal static class Duo
    {
        public class Result
        {
            public readonly string Passcode;
            public readonly bool RememberMe;

            public Result(string passcode, bool rememberMe)
            {
                Passcode = passcode;
                RememberMe = rememberMe;
            }
        }

        // Returns the second factor token from Duo or null when canceled by the user.
        public static Result Authenticate(string host, string signature, IDuoUi ui, IRestTransport transport)
        {
            var rest = new RestClient(transport, $"https://{host}");

            var (tx, app) = ParseSignature(signature);
            var html = DownloadFrame(tx, rest);
            var (sid, devices) = ParseFrame(html);

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
                    SubmitFactor(sid, choice, "", rest);
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

                var token = SubmitFactorAndWaitForToken(sid, choice, passcode, ui, rest);

                // Flow error like an incorrect passcode. The UI has been updated with the error. Keep going.
                if (token.IsNullOrEmpty())
                    continue;

                // All good
                return new Result($"{token}:{app}", choice.RememberMe);
            }
        }

        // Duo signature looks like this: TX|ZGV...Dgx|5a8...cd4:APP|ZGV...zgx|f8d...24f
        internal static (string Tx, string App) ParseSignature(string signature)
        {
            var parts = signature.Split(':');
            if (parts.Length != 2)
                throw MakeInvalidResponseError("Duo HTML: the signature is invalid or in an unsupported format");

            return (parts[0], parts[1]);
        }

        internal static HtmlDocument DownloadFrame(string tx, RestClient rest)
        {
            const string parent = "https%3A%2F%2Fvault.bitwarden.com%2F%23%2F2fa";
            const string version = "2.6";

            return Parse(Post($"frame/web/v1/auth?tx={tx}&parent={parent}&v={version}", rest));
        }

        internal static string Post(string url, RestClient rest)
        {
            var response = rest.PostForm(url, new Dictionary<string, object>());
            if (response.IsSuccessful)
                return response.Content;

            throw MakeSpecializedError(response);
        }

        internal static HtmlDocument Parse(string html)
        {
            var doc = new HtmlDocument();
            doc.LoadHtml(html);
            return doc;
        }

        internal static (string Sid, DuoDevice[] Devices) ParseFrame(HtmlDocument html)
        {
            // Find the main form
            var form = html.DocumentNode.SelectSingleNode("//form[@id='login-form']");
            if (form == null)
                throw MakeInvalidResponseError("Duo HTML: main form is not found");

            // Find all the devices and the signature
            var sid = GetInputValue(form, "sid");
            var devices = GetDevices(form);

            if (sid == null || devices == null)
                throw MakeInvalidResponseError("Duo HTML: signature or devices are not found");

            return (sid, devices);
        }

        // All the info is the frame is stored in input fields <input name="name" value="value">
        internal static string GetInputValue(HtmlNode form, string name)
        {
            return form
                .SelectSingleNode($"./input[@name='{name}']")?
                .Attributes["value"]?
                .DeEntitizeValue;
        }

        // Returns the transaction id
        internal static string SubmitFactor(string sid, DuoChoice choice, string passcode, RestClient rest)
        {
            var parameters = new Dictionary<string, object>
            {
                {"sid", sid},
                {"device", choice.Device.Id},
                {"factor", GetFactorParameterValue(choice.Factor)},
            };

            if (!passcode.IsNullOrEmpty())
                parameters["passcode"] = passcode;

            var response = PostForm<R.SubmitFactor>("frame/prompt", parameters, rest);

            var id = response.TransactionId;
            if (id.IsNullOrEmpty())
                throw MakeInvalidResponseError("Duo: transaction ID (txid) is expected but wasn't found");

            return id;
        }

        // Returns null when a recoverable flow error (like incorrect code or time out) happened
        // TODO: Don't return null, use something more obvious
        internal static string SubmitFactorAndWaitForToken(string sid,
                                                           DuoChoice choice,
                                                           string passcode,
                                                           IDuoUi ui,
                                                           RestClient rest)
        {
            var txid = SubmitFactor(sid, choice, passcode, rest);

            var url = PollForResultUrl(sid, txid, ui, rest);
            if (url.IsNullOrEmpty())
                return null;

            return FetchToken(sid, url, ui, rest);
        }

        // Returns null when a recoverable flow error (like incorrect code or time out) happened
        // TODO: Don't return null, use something more obvious
        internal static string PollForResultUrl(string sid, string txid, IDuoUi ui, RestClient rest)
        {
            const int maxPollAttempts = 100;

            // Normally it wouldn't poll nearly as many times. Just a few at most. It either bails on error or
            // returns the result. This number here just to prevent an infinite loop, which is never a good idea.
            for (var i = 0; i < maxPollAttempts; i += 1)
            {
                var response = PostForm<R.Poll>("frame/status",
                                                new Dictionary<string, object> {["sid"] = sid, ["txid"] = txid},
                                                rest);

                var (status, text) = GetResponseStatus(response);
                UpdateUi(status, text, ui);

                switch (status)
                {
                case DuoStatus.Success:
                    var url = response.Url;
                    if (url.IsNullOrEmpty())
                        throw MakeInvalidResponseError("Duo: result URL (result_url) was expected but wasn't found");

                    // Done
                    return url;
                case DuoStatus.Error:
                    return null; // TODO: Use something better than null
                }
            }

            throw MakeInvalidResponseError("Duo: expected to receive a valid result or error, got none of it");
        }

        internal static string FetchToken(string sid, string url, IDuoUi ui, RestClient rest)
        {
            var response = PostForm<R.FetchToken>(url,
                                                  new Dictionary<string, object> {["sid"] = sid},
                                                  rest);

            UpdateUi(response, ui);

            var token = response.Cookie;
            if (token.IsNullOrEmpty())
                throw MakeInvalidResponseError("Duo: authentication token expected in response but wasn't found");

            return token;
        }

        internal static T PostForm<T>(string endpoint, Dictionary<string, object> parameters, RestClient rest)
        {
            var response = rest.PostForm<R.Envelope<T>>(endpoint, parameters);

            // All good
            if (response.IsSuccessful && response.Data.Status == "OK" && response.Data.Payload != null)
                return response.Data.Payload;

            throw MakeSpecializedError(response);
        }

        internal static void UpdateUi(R.Status response, IDuoUi ui)
        {
            var (status, text) = GetResponseStatus(response);
            UpdateUi(status, text, ui);
        }

        internal static void UpdateUi(DuoStatus status, string text, IDuoUi ui)
        {
            if (text.IsNullOrEmpty())
                return;

            ui.UpdateDuoStatus(status, text);
        }

        internal static (DuoStatus Status, string Text) GetResponseStatus(R.Status response)
        {
            var status = response.Result switch
            {
                "SUCCESS" => DuoStatus.Success,
                "FAILURE" => DuoStatus.Error,
                _ => DuoStatus.Info
            };

            return (status, response.Message ?? "");
        }

        // Extracts all devices listed in the login form.
        // Devices with no supported methods are ignored.
        internal static DuoDevice[] GetDevices(HtmlNode form)
        {
            var devices = form
                .SelectNodes("//select[@name='device']/option")?
                .Select(x => (Id: x.Attributes["value"]?.DeEntitizeValue,
                              Name: HtmlEntity.DeEntitize(x.InnerText ?? "")))
                .ToArray();

            if (devices == null || devices.Any(x => x.Id == null || x.Name == null))
                return null;

            return devices
                .Select(x => new DuoDevice(x.Id, x.Name, GetDeviceFactors(form, x.Id)))
                .Where(x => x.Factors.Length > 0)
                .ToArray();
        }

        // Extracts all the second factor methods supported by the device.
        // Unsupported methods are ignored.
        internal static DuoFactor[] GetDeviceFactors(HtmlNode form, string deviceId)
        {
            var sms = CanSendSmsToDevice(form, deviceId)
                ? new[] {DuoFactor.SendPasscodesBySms}
                : new DuoFactor[0];

            return form
                .SelectSingleNode($".//fieldset[@data-device-index='{deviceId}']")?
                .SelectNodes(".//input[@name='factor']")?
                .Select(x => x.Attributes["value"]?.DeEntitizeValue)?
                .Select(x => ParseFactor(x))?
                .Where(x => x != null)?
                .Select(x => x.Value)?
                .Concat(sms)?
                .ToArray() ?? new DuoFactor[0];
        }

        internal static bool CanSendSmsToDevice(HtmlNode form, string deviceId)
        {
            return form
                .SelectSingleNode($".//fieldset[@data-device-index='{deviceId}']")?
                .SelectSingleNode(".//input[@name='phone-smsable' and @value='true']") != null;
        }

        internal static DuoFactor? ParseFactor(string factor)
        {
            return factor switch
            {
                "Duo Push" => DuoFactor.Push,
                "Phone Call" => DuoFactor.Call,
                "Passcode" => DuoFactor.Passcode,
                _ => null
            };
        }

        internal static string GetFactorParameterValue(DuoFactor factor)
        {
            return factor switch
            {
                DuoFactor.Push => "Duo Push",
                DuoFactor.Call => "Phone Call",
                DuoFactor.Passcode => "Passcode",
                DuoFactor.SendPasscodesBySms => "sms",
                _ => ""
            };
        }

        internal static InternalErrorException MakeInvalidResponseError(string message)
        {
            return new InternalErrorException(message);
        }

        internal static BaseException MakeSpecializedError(RestResponse response, string extraInfo = "")
        {
            var text = $"Duo: rest call to {response.RequestUri} failed";

            if (response.IsHttpError)
                text += " (HTTP status: ${ response.StatusCode})";

            if (!extraInfo.IsNullOrEmpty())
                text += extraInfo;

            return new InternalErrorException(text, response.Error);
        }

        internal static BaseException MakeSpecializedError<T>(RestResponse<string, R.Envelope<T>> response)
        {
            var message = response.Data.Message.IsNullOrEmpty() ? "none" : response.Data.Message;
            return MakeSpecializedError(response, $"Server message: {message}");
        }

        //
        // Response models
        //

        internal static class R
        {
            public struct Envelope<T>
            {
                [JsonProperty("stat", Required = Required.Always)]
                public string Status;

                [JsonProperty("message")]
                public string Message;

                [JsonProperty("response")]
                public T Payload;
            }

            public class SubmitFactor
            {
                [JsonProperty("txid")]
                public string TransactionId;
            }

            public class Status
            {
                [JsonProperty("result")]
                public string Result;

                [JsonProperty("status")]
                public string Message;
            }

            public class FetchToken: Status
            {
                [JsonProperty("cookie")]
                public string Cookie;
            }

            public class Poll: Status
            {
                [JsonProperty("result_url")]
                public string Url;
            }
        }
    }
}
