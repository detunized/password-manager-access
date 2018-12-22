// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using HtmlAgilityPack;

namespace Bitwarden
{
    internal static class Duo
    {
        public static string Authenticate(Response.InfoDuo info, Ui ui)
        {
            var html = DownloadFrame(info);
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
    }
}
