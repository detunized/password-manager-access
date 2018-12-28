// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using HtmlAgilityPack;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Bitwarden
{
    // TODO: Error handling! It's pretty much non-existent here!
    internal static class Duo
    {
        // Returns the second factor token from Duo or blank when canceled by the user.
        public static string Authenticate(Response.InfoDuo info, Ui ui, IHttpClient http)
        {
            var signature = ParseSignature(info.Signature);
            var html = DownloadFrame(info.Host, signature.Tx, http);

            // Find the main form
            var form = html.DocumentNode.SelectSingleNode("//form[@id='login-form']");
            if (form == null)
                throw new InvalidOperationException("Duo HTML: main form is not found");

            // Find all the devices and the signature
            var sid = GetInputValue(form, "sid");
            var devices = GetDevices(form);

            if (sid == null || devices == null)
                throw new InvalidOperationException("Duo HTML: signature or devices are not found");

            // Ask the user to choose what to do
            var choice = ui.ProvideDuoResponse(devices);
            if (choice == null)
                return ""; // Canceled by user

            var jsonHttp = new JsonHttpClient(http, $"https://{info.Host}");

            // SMS is a special case: it doesn't submit any codes, it rather tells the server to send
            // a new batch of passcodes to the phone via SMS.
            if (choice.Factor == Ui.DuoFactor.SendPasscodesBySms)
            {
                SubmitFactor(choice, sid, jsonHttp);

                // Now we have to ask to choose again
                choice = ui.ProvideDuoResponse(devices);
                if (choice == null)
                    return ""; // Canceled by user
            }

            var token = SubmitFactorAndWaitForToken(choice, sid, ui, jsonHttp);
            if (token == "")
                return "";  // TODO: error

            return $"{token}:{signature.App}";
        }

        internal static (string Tx, string App) ParseSignature(string signature)
        {
            var parts = signature.Split(':');
            if (parts.Length < 2)
                throw new InvalidOperationException("Duo HTML: the signature is invalid");

            return (parts[0], parts[1]);
        }

        internal static HtmlDocument DownloadFrame(string host, string tx, IHttpClient http)
        {
            const string parent = "https%3A%2F%2Fvault.bitwarden.com%2F%23%2F2fa";
            const string version = "2.6";

            // Fetch
            var url = $"https://{host}/frame/web/v1/auth?tx={tx}&parent={parent}&v={version}";
            var response = http.Post(url, "", new Dictionary<string, string>());

            // Parse
            var html = new HtmlDocument();
            html.LoadHtml(response);

            return html;
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
        internal static string SubmitFactor(Ui.DuoResponse info, string sid, JsonHttpClient jsonHttp)
        {
            var parameters = new Dictionary<string, string>
            {
                {"sid", sid},
                {"device", info.Device.Id},
                {"factor", GetFactorParameterValue(info.Factor)},
            };

            if (info.Factor == Ui.DuoFactor.Passcode)
                parameters["passcode"] = info.Response;

            // Submit the factor
            var response = jsonHttp.PostForm("frame/prompt", parameters);

            // Something went wrong
            if ((string)response["stat"] != "OK")
                return "";  // TODO: error

            return (string)response["response"]?["txid"];
        }

        internal static string SubmitFactorAndWaitForToken(Ui.DuoResponse info, string sid, Ui ui, JsonHttpClient jsonHttp)
        {
            var txid = SubmitFactor(info, sid, jsonHttp);
            if (string.IsNullOrEmpty(txid))
                return ""; // TODO: error

            var url = PollForResultUrl(sid, txid, ui, jsonHttp);
            if (string.IsNullOrEmpty(url))
                return ""; // TODO: error

            return FetchToken(sid, url, ui, jsonHttp);
        }

        internal static string PollForResultUrl(string sid, string txid, Ui ui, JsonHttpClient jsonHttp)
        {
            const int MaxPollAttempts = 100;

            // Normally it wouldn't poll nearly as many times. Just a few at most. It either bails on error or
            // returns the result. This number here just to prevent an infinite loop, while is never a good idea.
            for (var i = 0; i < MaxPollAttempts; i += 1)
            {
                var response = jsonHttp.PostForm("frame/status", new Dictionary<string, string>
                {
                    {"sid", sid},
                    {"txid", txid},
                });

                if ((string)response["stat"] != "OK")
                    return ""; // TODO: error

                UpdateUi(response, ui);

                var status = GetResponseStatus(response);
                switch (status)
                {
                case Ui.DuoStatus.Success:
                    var url = (string)response["response"]?["result_url"];
                    if (string.IsNullOrEmpty(url))
                        return ""; // TODO: error

                    // Done
                    return url;
                case Ui.DuoStatus.Error:
                    return ""; // TODO: error
                }
            }

            return ""; // TODO: error
        }

        internal static string FetchToken(string sid, string url, Ui ui, JsonHttpClient jsonHttp)
        {
            var response = jsonHttp.PostForm(url, new Dictionary<string, string> { { "sid", sid } });

            if ((string)response["stat"] != "OK")
                return ""; // TODO: error

            UpdateUi(response, ui);

            var token = (string)response["response"]?["cookie"];
            if (string.IsNullOrEmpty(token))
                return "";  // TODO: error

            return token;
        }

        internal static void UpdateUi(JObject response, Ui ui)
        {
            var text = (string)response["response"]?["status"];
            if (string.IsNullOrEmpty(text))
                return;

            ui.UpdateDuoStatus(GetResponseStatus(response), text);
        }

        internal static Ui.DuoStatus GetResponseStatus(JObject response)
        {
            switch ((string)response["response"]?["result"])
            {
            case "SUCCESS":
                return Ui.DuoStatus.Success;
            case "FAILURE":
                return Ui.DuoStatus.Error;
            default:
                return Ui.DuoStatus.Info;
            }
        }

        // Extracts all devices listed in the login form.
        // Devices with no supported methods are ignored.
        internal static Ui.DuoDevice[] GetDevices(HtmlNode form)
        {
            var devices = form
                .SelectNodes("//select[@name='device']/option")?
                .Select(x => (Id: x.Attributes["value"]?.DeEntitizeValue,
                              Name: HtmlEntity.DeEntitize(x.InnerText ?? "")));

            if (devices == null || devices.Any(x => x.Id == null || x.Name == null))
                return null;

            return devices
                .Select(x => new Ui.DuoDevice(x.Id, x.Name, GetDeviceFactors(form, x.Id)))
                .Where(x => x.Factors.Length > 0)
                .ToArray();
        }

        // Extracts all the second factor methods supported by the device.
        // Unsupported methods are ignored.
        internal static Ui.DuoFactor[] GetDeviceFactors(HtmlNode form, string deviceId)
        {
            var sms = CanSendSmsToDevice(form, deviceId)
                ? new Ui.DuoFactor[] { Ui.DuoFactor.SendPasscodesBySms }
                : new Ui.DuoFactor[0];

            return form
                .SelectSingleNode($".//fieldset[@data-device-index='{deviceId}']")?
                .SelectNodes(".//input[@name='factor']")?
                .Select(x => x.Attributes["value"]?.DeEntitizeValue)?
                .Select(x => ParseFactor(x))?
                .Where(x => x != null)?
                .Select(x => x.Value)?
                .Concat(sms)?
                .ToArray() ?? new Ui.DuoFactor[0];
        }

        internal static bool CanSendSmsToDevice(HtmlNode form, string deviceId)
        {
            return form
                .SelectSingleNode($".//fieldset[@data-device-index='{deviceId}']")?
                .SelectSingleNode(".//input[@name='phone-smsable' and @value='true']") != null;
        }

        internal static Ui.DuoFactor? ParseFactor(string s)
        {
            switch (s)
            {
            case "Duo Push":
                return Ui.DuoFactor.Push;
            case "Phone Call":
                return Ui.DuoFactor.Call;
            case "Passcode":
                return Ui.DuoFactor.Passcode;
            }

            return null;
        }

        internal static string GetFactorParameterValue(Ui.DuoFactor factor)
        {
            switch (factor)
            {
            case Ui.DuoFactor.Push:
                return "Duo Push";
            case Ui.DuoFactor.Call:
                return "Phone Call";
            case Ui.DuoFactor.Passcode:
                return "Passcode";
            case Ui.DuoFactor.SendPasscodesBySms:
                return "sms";
            }

            return "";
        }
    }
}
