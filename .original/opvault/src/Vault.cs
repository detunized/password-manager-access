// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Newtonsoft.Json.Linq;

namespace OPVault
{
    public class Vault
    {
        public static Account[] Open(string path, string password)
        {
            // Load all the files
            var profile = LoadProfile(path);
            var encryptedFolders = LoadFolders(path);
            var encryptedItems = LoadItems(path);

            // Derive key encryption key
            var kek = DeriveKek(profile, password);

            // sDecrypt main keys
            var masterKey = DecryptMasterKey(profile, kek);
            var overviewKey = DecryptOverviewKey(profile, kek);

            // Decrypt, parse and convert folders
            var folders = DecryptFolders(encryptedFolders, overviewKey);

            // Decrypt, parse, convert and assign folders
            return DecryptAccounts(encryptedItems, masterKey, overviewKey, folders);
        }

        internal static JObject LoadProfile(string path)
        {
            return LoadJsAsJson(MakeFilename(path, "profile.js"), "var profile=", ";");
        }

        internal static JObject[] LoadFolders(string path)
        {
            return LoadJsAsJson(MakeFilename(path, "folders.js"), "loadFolders(", ");")
                .Values()
                .Select(i => (JObject)i)
                .ToArray();
        }

        internal static JObject[] LoadItems(string path)
        {
            var items = new List<JObject>();
            foreach (var c in "0123456789ABCDEF")
            {
                var filename = MakeFilename(path, string.Format("band_{0}.js", c));
                if (!File.Exists(filename))
                    continue;

                items.AddRange(LoadBand(filename).Values().Select(i => (JObject)i));
            }

            return items.ToArray();
        }

        internal static JObject LoadBand(string filename)
        {
            return LoadJsAsJson(filename, "ld(", ");");
        }

        internal static JObject LoadJsAsJson(string filename, string prefix, string suffix)
        {
            return LoadJsAsJsonFromString(File.ReadAllText(filename), prefix, suffix);
        }

        internal static JObject LoadJsAsJsonFromString(string content, string prefix, string suffix)
        {
            if (content.Length < prefix.Length + suffix.Length)
                throw FormatError("JS/JSON: Content is too short");
            if (!content.StartsWith(prefix))
                throw FormatError("JS/JSON: Expected prefix is not found in the content");
            if (!content.EndsWith(suffix))
                throw FormatError("JS/JSON: Expected suffix is not found in the content");

            return JObject.Parse(content.Substring(prefix.Length, content.Length - prefix.Length - suffix.Length));
        }

        internal static string MakeFilename(string path, string filename)
        {
            return Path.Combine(NormalizeSlashes(path), "default", NormalizeSlashes(filename));
        }

        internal static string NormalizeSlashes(string path)
        {
            // TODO: Test on non Windows based platforms
            return path.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);
        }

        internal static KeyMac DeriveKek(JObject profile, string password)
        {
            // TODO: Handle JSON exceptions
            return Crypto.DeriveKek(password.ToBytes(),
                                    profile.StringAt("salt").Decode64(),
                                    profile.IntAt("iterations"));
        }

        internal static KeyMac DecryptMasterKey(JObject profile, KeyMac kek)
        {
            // TODO: Handle JSON exceptions
            return DecryptBase64Key(profile.StringAt("masterKey"), kek);
        }

        internal static KeyMac DecryptOverviewKey(JObject profile, KeyMac kek)
        {
            // TODO: Handle JSON exceptions
            return DecryptBase64Key(profile.StringAt("overviewKey"), kek);
        }

        internal static KeyMac DecryptBase64Key(string encryptedKeyBase64, KeyMac kek)
        {
            var raw = Opdata01.Decrypt(encryptedKeyBase64, kek);
            return new KeyMac(Crypto.Sha512(raw));
        }

        internal static Dictionary<string, Folder> DecryptFolders(JObject[] encryptedFolders, KeyMac overviewKey)
        {
            return encryptedFolders
                .Where(i => !i.BoolAt("trashed", false))
                .Select(i => DecryptFolder(i, overviewKey))
                .ToDictionary(i => i.Id);
        }

        internal static Account[] DecryptAccounts(JObject[] encryptedItems,
                                                  KeyMac masterKey,
                                                  KeyMac overviewKey,
                                                  Dictionary<string, Folder> folders)
        {
            return encryptedItems
                .Where(i => !i.BoolAt("trashed", false))
                .Where(i => i.StringAt("category", "") == "001")
                .Select(i => DecryptAccount(i, masterKey, overviewKey, folders))
                .ToArray();
        }

        private static Folder DecryptFolder(JObject folder, KeyMac overviewKey)
        {
            // TODO: Handle JSON exceptions
            var overview = DecryptJson(folder.StringAt("overview"), overviewKey);
            return new Folder(folder.StringAt("uuid"), overview.StringAt("title"));
        }

        private static Account DecryptAccount(JObject encryptedItem,
                                              KeyMac masterKey,
                                              KeyMac overviewKey,
                                              Dictionary<string, Folder> folders)
        {
            VerifyAccountTag(encryptedItem, overviewKey);

            var overview = DecryptAccountOverview(encryptedItem, overviewKey);
            var accountKey = DecryptAccountKey(encryptedItem, masterKey);
            var details = DecryptAccountDetails(encryptedItem, accountKey);

            // Folder is optional. Use null to mark a non-existent folder.
            Folder folder;
            folders.TryGetValue(encryptedItem.StringAt("folder", ""), out folder);

            return new Account(id: encryptedItem.StringAt("uuid", ""),
                               name: overview.StringAt("title", ""),
                               username: FindDetailField(details, "username"),
                               password: FindDetailField(details, "password"),
                               url: overview.StringAt("url", ""),
                               note: details.StringAt("notesPlain", ""),
                               folder: folder ?? Folder.None);
        }

        private static void VerifyAccountTag(JObject encryptedItem, KeyMac key)
        {
            // We need to hash everything but the "hmac" field
            var properties = encryptedItem
                .Properties()
                .Where(i => i.Name != "hmac")
                .OrderBy(i => i.Name);

            // Join all the properties in the alphabetical oder into a flat string
            var hashedContent = new StringBuilder();
            foreach (var i in properties)
            {
                hashedContent.Append(i.Name);
                hashedContent.Append(i.Value);
            }

            // Check against the stored HMAC/tag
            var storedTag = encryptedItem.StringAt("hmac").Decode64();
            var computedTag = Crypto.Hmac(hashedContent.ToString().ToBytes(), key);

            // TODO: Use custom exceptions
            if (!computedTag.SequenceEqual(storedTag))
                throw new InvalidOperationException("Item is corrupted: tag doesn't match");
        }

        private static JObject DecryptAccountOverview(JObject encryptedItem, KeyMac overviewKey)
        {
            // TODO: Handle JSON exceptions
            return DecryptJson(encryptedItem.StringAt("o"), overviewKey);
        }

        private static KeyMac DecryptAccountKey(JObject encryptedItem, KeyMac masterKey)
        {
            // TODO: Handle JSON exceptions
            // TODO: Use custom exceptions
            var raw = encryptedItem.StringAt("k").Decode64();
            if (raw.Length != 112)
                throw new InvalidOperationException("Item key is corrupted: invalid size");

            using (var io = new BinaryReader(new MemoryStream(raw, false)))
            {
                var iv = io.ReadBytes(16);
                var ciphertext = io.ReadBytes(64);
                var storedTag = io.ReadBytes(32);

                // Rewind and reread everything to the tag
                io.BaseStream.Seek(0, SeekOrigin.Begin);
                var hashedContent = io.ReadBytes(80);

                var computedTag = Crypto.Hmac(hashedContent, masterKey);
                if (!computedTag.SequenceEqual(storedTag))
                    throw new InvalidOperationException("Item key is corrupted: tag doesn't match");

                return new KeyMac(Crypto.DecryptAes(ciphertext, iv, masterKey));
            }
        }

        private static JObject DecryptAccountDetails(JObject encryptedItem, KeyMac accountKey)
        {
            // TODO: Handle JSON exceptions
            return DecryptJson(encryptedItem.StringAt("d"), accountKey);
        }

        private static JObject DecryptJson(string encryptedJsonBase64, KeyMac key)
        {
            return JObject.Parse(Opdata01.Decrypt(encryptedJsonBase64, key).ToUtf8());
        }

        // TODO: Write a test
        private static string FindDetailField(JObject details, string name)
        {
            foreach (var i in details.At("fields", new JArray()))
                if (i.StringAt("designation", "") == name)
                    return i.StringAt("value", "");

            return "";
        }

        private static ParseException FormatError(string message)
        {
            return new ParseException(ParseException.FailureReason.InvalidFormat, message);
        }
    }
}
