// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Specialized;

namespace Dashlane
{
    static class Fetcher
    {
        public const string LatestUrl = "https://www.dashlane.com/12/backup/latest";

        public static string Fetch(string username, string uki)
        {
            using (var webClient = new WebClient())
                return Fetch(username, uki, webClient);
        }

        public static string Fetch(string username, string uki, IWebClient webClient)
        {
            return webClient.UploadValues(LatestUrl, new NameValueCollection
            {
                {"login", username},
                {"lock", "nolock"},
                {"timestamp", "1"},
                {"sharingTimestamp", "0"},
                {"uki", uki},
            }).ToUtf8();
        }
    }
}
