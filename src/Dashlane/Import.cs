// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Dashlane
{
    public static class Import
    {
        // TODO: Not sure how to test this!
        public static string ImportLocalDeviceId(string username, string password)
        {
            return ImportDeviceIdFromSettingsFile(FindSettingsFile(username),
                                                  GetSettingsKey(username, password));
        }

        //
        // Internal
        //

        // Returns either the master password or the local key
        internal static byte[] GetSettingsKey(string username, string password)
        {
            var localKeyFilename = FindLocalKeyFile(username);
            if (localKeyFilename == null)
                return Parse.PasswordToBytes(password);

            return ImportLocalKey(localKeyFilename, password);
        }

        internal static string ImportDeviceIdFromSettingsFile(string filename, byte[] key)
        {
            return ImportDeviceIdFromSettings(LoadSettingsFile(filename, key));
        }

        internal static string ImportDeviceIdFromSettings(string settingsXml)
        {
            try
            {
                return ImportDeviceIdFromSettings(XDocument.Parse(settingsXml));
            }
            catch (XmlException e)
            {
                throw new InternalErrorException("Failed to parse XML settings file", e);
            }
        }

        internal static string ImportDeviceIdFromSettings(XDocument settings)
        {
            var id = settings.XPathSelectElement("/root/KWLocalSettingsManager/KWDataItem[@key='uki']");
            if (id != null)
                return id.Value;

            throw new InternalErrorException("The settings file doesn't contain a device ID");
        }

        // TODO: When the 2FA is set to "Each time I log in to Dashlane" this won't work. To make it
        // work we need to use the OPT to ask the server for the server key. That key is prepended
        // to the password and only then it's possible to decrypt the local settings file. The
        // Windows client actually warns about that when the option is turned on. Look into this.
        public static byte[] ImportLocalKey(string filename, string password)
        {
            var blob = File.ReadAllText(filename).Decode64();
            return Parse.DecryptBlob(blob, password, new Parse.DerivedKeyCache());
        }

        internal static string LoadSettingsFile(string filename, byte[] key)
        {
            var blob = File.ReadAllBytes(filename);
            return Parse.DecryptBlob(blob, key, new Parse.DerivedKeyCache()).ToUtf8();
        }

        // The local key is optional. It doesn't exist in the older versions. This function returns
        // null when the local key is not found.
        internal static string FindLocalKeyFile(string username)
        {
            // TODO: Are there other platforms besides Windows desktop we need to check on?
            var filename = Path.Combine(GetProfilePath(username), "Keys", "localKey.aes");
            return File.Exists(filename) ? filename : null;
        }

        // TODO: Not sure how to test this!
        internal static string FindSettingsFile(string username)
        {
            // TODO: Are there other platforms besides Windows desktop we need to check on?
            var filename = Path.Combine(GetProfilePath(username), "Settings", "localSettings.aes");
            if (File.Exists(filename))
                return filename;

            throw new InternalErrorException($"Profile '{username}' doesn't exist");
        }

        internal static string GetProfilePath(string username)
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            return Path.Combine(appData, "Dashlane", "profiles", username);
        }
    }
}
