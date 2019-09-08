// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
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
        public static string ImportUki(string username, string password)
        {
            return ImportUkiFromSettingsFile(FindSettingsFile(username),
                                             GetSettingsKey(username, password));
        }

        // Returns either the master password or the local key
        internal static byte[] GetSettingsKey(string username, string password)
        {
            var localKeyFilename = FindLocalKeyFile(username);
            if (localKeyFilename == null)
                return Parse.PasswordToBytes(password);

            return ImportLocalKey(localKeyFilename, password);
        }

        internal static string ImportUkiFromSettingsFile(string filename, byte[] key)
        {
            return ImportUkiFromSettings(LoadSettingsFile(filename, key));
        }

        internal static string ImportUkiFromSettings(string settingsXml)
        {
            try
            {
                return ImportUkiFromSettings(XDocument.Parse(settingsXml));
            }
            catch (XmlException e)
            {
                throw new ImportException(
                    ImportException.FailureReason.InvalidFormat,
                    "Failed to parse XML settings file",
                    e);
            }
        }

        internal static string ImportUkiFromSettings(XDocument settings)
        {
            var uki = settings.XPathSelectElement("/root/KWLocalSettingsManager/KWDataItem[@key='uki']");
            if (uki == null)
                throw new ImportException(
                    ImportException.FailureReason.InvalidFormat,
                    "The settings file doesn't contain an UKI");

            return uki.Value;
        }

        public static byte[] ImportLocalKey(string filename, string password)
        {
            var blob = File.ReadAllText(filename).Decode64();
            try
            {
                return Parse.DecryptBlob(blob, password);
            }
            catch (CryptoException e)
            {
                throw new ImportException(
                    ImportException.FailureReason.IncorrectPassword,
                    "The encryption key file is corrupted or the password is incorrect",
                    e);
            }
        }

        internal static string LoadSettingsFile(string filename, byte[] key)
        {
            var blob = File.ReadAllBytes(filename);
            try
            {
                return Parse.DecryptBlob(blob, key).ToUtf8();
            }
            catch (ParseException e)
            {
                throw new ImportException(
                    ImportException.FailureReason.IncorrectPassword,
                    "The settings file is corrupted or the password is incorrect",
                    e);
            }
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
            if (!File.Exists(filename))
                throw new ImportException(
                    ImportException.FailureReason.ProfileNotFound,
                    string.Format("Profile '{0}' doesn't exist", username));

            return filename;
        }

        internal static string GetProfilePath(string username)
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Dashlane",
                "profiles",
                username);
        }
    }
}
