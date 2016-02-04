// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using System.Xml.Linq;
using System.Xml.XPath;

namespace Dashlane
{
    public static class Import
    {
        // TODO: Not sure how to test this!
        public static string ImportUki(string username, string password)
        {
            var xml = LoadSettings(username, password);
            // TODO: Check it parses!
            return XDocument.Parse(xml).XPathSelectElement("/root/KWLocalSettingsManager/KWDataItem[@key='uki']").Value;
        }

        private static string LoadSettings(string username, string password)
        {
            var blob = File.ReadAllBytes(FindSettingsFile(username));
            return Parse.DecryptBlob(blob, password).ToUtf8();
        }

        private static string FindSettingsFile(string username)
        {
            // TODO: Check the platform!
            // TODO: Check it exists!
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Dashlane",
                "profiles",
                username,
                "Settings",
                "localSettings.aes");
        }
    }
}
