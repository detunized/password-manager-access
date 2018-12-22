// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using HtmlAgilityPack;

namespace Bitwarden
{
    internal static class Duo
    {
        public static string Authenticate(Response.InfoDuo info, Ui ui)
        {
            var html = DownloadFrame(info);

            // Find the main form
            var form = html.DocumentNode.SelectSingleNode("//form[@id='login-form']");
            if (form == null)
                throw new InvalidOperationException("Duo HTML: main form is not found");

            // Find all the devices and the signature
            var sid = GetInputValue(form, "sid");
            var url = GetInputValue(form, "url");
            var devices = GetDevices(form);

            if (sid == null || url == null || devices == null)
                throw new InvalidOperationException("Duo HTML: signature, url or devices are not found");

            return "";
        }

        internal static HtmlDocument DownloadFrame(Response.InfoDuo info)
        {
            const string parent = "https%3A%2F%2Fvault.bitwarden.com%2F%23%2F2fa";
            const string version = "2.6";

            var tx = info.Signature.Split(':')[0];
            var url = $"https://{info.Host}/frame/web/v1/auth?tx={tx}&parent={parent}&v={version}";

            // TODO: Better would be to use the IHttpClient here but it doesn't support redirects ATM
            return new HtmlWeb() { CaptureRedirect = true }.Load(url, "POST");
        }

        internal static string GetInputValue(HtmlNode form, string name)
        {
            return form
                .SelectSingleNode($"./input[@name='{name}']")?
                .Attributes["value"]?
                .DeEntitizeValue;
        }

        internal struct Device
        {
            public readonly string Id;
            public readonly string Name;
            public readonly string[] Factors;

            public Device(string id, string name, string[] factors)
            {
                Id = id;
                Name = name;
                Factors = factors;
            }
        }

        internal static Device[] GetDevices(HtmlNode form)
        {
            var devices = form
                .SelectNodes("//select[@name='device']/option")?
                .Select(x => (Id: x.Attributes["value"]?.DeEntitizeValue,
                              Name: HtmlEntity.DeEntitize(x.InnerText ?? "")));

            if (devices == null || devices.Any(x => x.Id == null || x.Name == null))
                return null;

            return devices.Select(x => new Device(x.Id, x.Name, GetDeviceFactors(form, x.Id))).ToArray();
        }

        private static string[] GetDeviceFactors(HtmlNode form, string id)
        {
            return form
                .SelectSingleNode($".//fieldset[@data-device-index='{id}']")?
                .SelectNodes(".//input[@name='factor']")?
                .Select(x => x.Attributes["value"]?.DeEntitizeValue)?
                .Where(x => x != null)?
                .ToArray() ?? new string[0];
        }
    }
}
