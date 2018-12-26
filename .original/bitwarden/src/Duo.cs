// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using HtmlAgilityPack;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Bitwarden
{
    // TODO: Error handling! It's pretty much non-existent here!
    internal static class Duo
    {
        public static string Authenticate(Response.InfoDuo info, Ui ui, IHttpClient http)
        {
            var signature = ParseSignature(info.Signature);
            var html = DownloadFrame(info.Host, signature.Tx);

            // Find the main form
            var form = html.DocumentNode.SelectSingleNode("//form[@id='login-form']");
            if (form == null)
                throw new InvalidOperationException("Duo HTML: main form is not found");

            // Find all the devices and the signature
            var sid = GetInputValue(form, "sid");
            var devices = GetDevices(form);

            if (sid == null || devices == null)
                throw new InvalidOperationException("Duo HTML: signature or devices are not found");

            var choice = ui.ProvideDuoResponse(devices);

            var jsonHttp = new JsonHttpClient(http, $"https://{info.Host}");
            var token = SubmitFactor(choice, sid, jsonHttp);

            if (token == "")
                return "";

            return $"{token}:{signature.App}";
        }

        internal static (string Tx, string App) ParseSignature(string signature)
        {
            var parts = signature.Split(':');
            if (parts.Length < 2)
                throw new InvalidOperationException("Duo HTML: the signature is invalid");

            return (parts[0], parts[1]);
        }

        internal static HtmlDocument DownloadFrame(string host, string tx)
        {
            const string parent = "https%3A%2F%2Fvault.bitwarden.com%2F%23%2F2fa";
            const string version = "2.6";

            var url = $"https://{host}/frame/web/v1/auth?tx={tx}&parent={parent}&v={version}";

            // TODO: Better would be to use the IHttpClient here but it doesn't support redirects ATM
            return new HtmlWeb() { CaptureRedirect = true }.Load(url, "POST");
        }

        // All the info is the frame is stored in input fields <input name="name" value="value">
        internal static string GetInputValue(HtmlNode form, string name)
        {
            return form
                .SelectSingleNode($"./input[@name='{name}']")?
                .Attributes["value"]?
                .DeEntitizeValue;
        }

        internal static string SubmitFactor(Ui.DuoResponse info, string sid, JsonHttpClient jsonHttp)
        {
            var parameters = new Dictionary<string, string>
            {
                {"sid", sid},
                {"device", info.Device.Id},
                {"factor", FactorToString(info.Factor)},
            };

            if (info.Factor == Ui.DuoFactor.Passcode)
                parameters["passcode"] = info.Response;

            // Submit the factor
            var response = jsonHttp.PostForm("frame/prompt", parameters);

            // Something went wrong
            if ((string)response["stat"] != "OK")
                return "";

            var txid = (string)response["response"]?["txid"];
            if (string.IsNullOrEmpty(txid))
                return "";

            // Ask for status once
            var status1 = jsonHttp.PostForm("frame/status", new Dictionary<string, string>
            {
                {"sid", sid},
                {"txid", txid},
            });

            if ((string)status1["stat"] != "OK")
                return "";

            // Ask for status twice. This is a long poll. It returns either when the server times out or
            // the user confirms or denies the request.
            var status2 = jsonHttp.PostForm("frame/status", new Dictionary<string, string>
            {
                {"sid", sid},
                {"txid", txid},
            });

            if ((string)status2["stat"] != "OK" || (string)status2["response"]?["result"] != "SUCCESS")
                return "";

            var url = (string)status2["response"]?["result_url"];
            if (string.IsNullOrEmpty(url))
                return "";

            var result = jsonHttp.PostForm(url, new Dictionary<string, string> { { "sid", sid } });

            if ((string)result["stat"] != "OK")
                return "";

            var token = (string)result["response"]?["cookie"];
            if (string.IsNullOrEmpty(token))
                return "";

            return token;
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
            return form
                .SelectSingleNode($".//fieldset[@data-device-index='{deviceId}']")?
                .SelectNodes(".//input[@name='factor']")?
                .Select(x => x.Attributes["value"]?.DeEntitizeValue)?
                .Select(x => ParseDuoFactor(x))?
                .Where(x => x != null)?
                .Select(x => x.Value)?
                .ToArray() ?? new Ui.DuoFactor[0];
        }

        internal static Ui.DuoFactor? ParseDuoFactor(string s)
        {
            switch (s)
            {
            case "Duo Push":
                return Ui.DuoFactor.Push;
            case "Passcode":
                return Ui.DuoFactor.Passcode;
            }

            return null;
        }

        internal static string FactorToString(Ui.DuoFactor factor)
        {
            switch (factor)
            {
            case Ui.DuoFactor.Push:
                return "Duo Push";
            case Ui.DuoFactor.Passcode:
                return "Passcode";
            }

            return "";
        }
    }
}
