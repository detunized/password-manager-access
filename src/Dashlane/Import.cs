// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;

// TODO: Add this!!!
// This actually works, it's how to import the new settings!
//
// var localKeyFilename = @"C:\Users\${username}\AppData\Roaming\Dashlane\profiles\lastpass.ruby+01-september-2019@gmail.com\Keys\localKey.aes";
// var localKeyBlob = File.ReadAllText(localKeyFilename).Decode64();
//
// var localSettingsFilename = @"C:\Users\${username}\AppData\Roaming\Dashlane\profiles\lastpass.ruby+01-september-2019@gmail.com\Settings\localSettings.aes";
// var localSettingsBlob = File.ReadAllBytes(localSettingsFilename);
//
// try
// {
//     var localKey = Parse.DecryptBlob(localKeyBlob, password);
//
//     var parsedSettingsBlob = Parse.ParseEncryptedBlob(localSettingsBlob);
//     var settingsKey = new Rfc2898DeriveBytes(localKey, parsedSettingsBlob.Salt, 10204).GetBytes(32);
//     var derivedSettingsKeyIv = Parse.DeriveEncryptionKeyAndIv(localKey, parsedSettingsBlob.Salt, parsedSettingsBlob.Iterations);
//     var compressedPlaintextSettings = Parse.DecryptAes256(parsedSettingsBlob.Ciphertext,
//                                                             derivedSettingsKeyIv.Iv,
//                                                             parsedSettingsBlob.UseDerivedKey ? derivedSettingsKeyIv.Key : localKey);
//     var plaintextSettings = parsedSettingsBlob.Compressed
//         ? Parse.Inflate(compressedPlaintextSettings.Sub(6, int.MaxValue))
//         : compressedPlaintextSettings;
// }
// catch (ParseException e)
// {
//     throw new ImportException(
//         ImportException.FailureReason.IncorrectPassword,
//         "The settings file is corrupted or the password is incorrect",
//         e);
// }

namespace PasswordManagerAccess.Dashlane
{
    public static class Import
    {
        // TODO: Not sure how to test this!
        public static string ImportUki(string username, string password)
        {
            return ImportUkiFromSettingsFile(FindSettingsFile(username), password);
        }

        public static string ImportUkiFromSettingsFile(string filename, string password)
        {
            return ImportUkiFromSettings(LoadSettingsFile(filename, password));
        }

        public static string ImportUkiFromSettings(string settingsXml)
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

        public static string ImportUkiFromSettings(XDocument settings)
        {
            var uki = settings.XPathSelectElement("/root/KWLocalSettingsManager/KWDataItem[@key='uki']");
            if (uki == null)
                throw new ImportException(
                    ImportException.FailureReason.InvalidFormat,
                    "The settings file doesn't contain an UKI");

            return uki.Value;
        }

        public static string LoadSettingsFile(string filename, string password)
        {
            var blob = File.ReadAllBytes(filename);
            try
            {
                return Parse.DecryptBlob(blob, password).ToUtf8();
            }
            catch (ParseException e)
            {
                throw new ImportException(
                    ImportException.FailureReason.IncorrectPassword,
                    "The settings file is corrupted or the password is incorrect",
                    e);
            }
        }

        // TODO: Not sure how to test this!
        public static string FindSettingsFile(string username)
        {
            // TODO: Are there other platforms besides Windows desktop we need to check on?

            var filename = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Dashlane",
                "profiles",
                username,
                "Settings",
                "localSettings.aes");

            if (!File.Exists(filename))
                throw new ImportException(
                    ImportException.FailureReason.ProfileNotFound,
                    string.Format("Profile '{0}' doesn't exist", username));

            return filename;
        }
    }
}
