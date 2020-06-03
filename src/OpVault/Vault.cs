// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Newtonsoft.Json.Linq;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.OpVault
{
    public class Vault
    {
        public static Account[] Open(string path, string password)
        {
            // Load all the files
            var profile = LoadProfile(path);
            var encryptedFolders = LoadFolders(path);
            var encryptedItems = LoadItems(path);

            try
            {
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
            catch (JTokenAccessException e)
            {
                throw FormatError("Unexpected JSON schema", e);
            }
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
            return LoadJsAsJsonFromString(LoadTextFile(filename), prefix, suffix);
        }

        internal static string LoadTextFile(string filename)
        {
            // We're deliberately not trying to catch all the possible file/io errors.
            // It's impossible to handle them all. Just a basic check that the file is there.
            if (!File.Exists(filename))
                throw new ParseException(ParseException.FailureReason.FileNotFound,
                                         string.Format("File '{0}' doesn't exist", filename));

            return File.ReadAllText(filename);
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
            return Util.DeriveKek(password.ToBytes(),
                                  profile.StringAt("salt").Decode64(),
                                  profile.IntAt("iterations"));
        }

        internal static KeyMac DecryptMasterKey(JObject profile, KeyMac kek)
        {
            try
            {
                return DecryptBase64Key(profile.StringAt("masterKey"), kek);
            }
            catch (ParseException e)
            {
                // This is a bit hacky. There's no sure way to verify if the password is correct. The things
                // will start failing to decrypt on HMAC/tag verification. So only for the master key we assume
                // that the structure of the vault is not corrupted (which is unlikely) but rather the master
                // password wasn't given correctly. So we rethrow the "corrupted" exception as the "incorrect
                // password". Unfortunately we have to rely on the contents of the error message as well.
                if (e.Reason == ParseException.FailureReason.Corrupted && e.Message.Contains("tag doesn't match"))
                    throw new ParseException(ParseException.FailureReason.IncorrectPassword,
                                             "Most likely the master password is incorrect",
                                             e);

                throw;
            }
        }

        internal static KeyMac DecryptOverviewKey(JObject profile, KeyMac kek)
        {
            return DecryptBase64Key(profile.StringAt("overviewKey"), kek);
        }

        internal static KeyMac DecryptBase64Key(string encryptedKeyBase64, KeyMac kek)
        {
            var raw = Opdata01.Decrypt(encryptedKeyBase64, kek);
            return new KeyMac(Crypto.Sha512(raw));
        }

        internal static Dictionary<string, Folder> DecryptFolders(JObject[] encryptedFolders, KeyMac overviewKey)
        {
            var activeFolders = encryptedFolders.Where(i => !i.BoolAt("trashed", false)).ToArray();
            var childToParent = activeFolders.ToDictionary(i => i.StringAt("uuid"), i => i.StringAt("parent", ""));
            var folders = activeFolders.Select(i => DecryptFolder(i, overviewKey)).ToDictionary(i => i.Id);

            // Assign parent folders
            foreach (var i in folders)
            {
                var parentId = childToParent[i.Key];
                if (folders.ContainsKey(parentId))
                    i.Value.Parent = folders[parentId];
            }

            return folders;
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
            var computedTag = Crypto.HmacSha256(hashedContent.ToString().ToBytes(), key.MacKey);

            if (!computedTag.SequenceEqual(storedTag))
                throw CorruptedError("Vault item is corrupted: tag doesn't match");
        }

        private static JObject DecryptAccountOverview(JObject encryptedItem, KeyMac overviewKey)
        {
            return DecryptJson(encryptedItem.StringAt("o"), overviewKey);
        }

        private static KeyMac DecryptAccountKey(JObject encryptedItem, KeyMac masterKey)
        {
            var raw = encryptedItem.StringAt("k").Decode64();
            if (raw.Length != 112)
                throw CorruptedError("Vault item key is corrupted: invalid size");

            using (var io = new BinaryReader(new MemoryStream(raw, false)))
            {
                var iv = io.ReadBytes(16);
                var ciphertext = io.ReadBytes(64);
                var storedTag = io.ReadBytes(32);

                // Rewind and reread everything to the tag
                io.BaseStream.Seek(0, SeekOrigin.Begin);
                var hashedContent = io.ReadBytes(80);

                var computedTag = Crypto.HmacSha256(hashedContent, masterKey.MacKey);
                if (!computedTag.SequenceEqual(storedTag))
                    throw CorruptedError("Vault item key is corrupted: tag doesn't match");

                return new KeyMac(Util.DecryptAes(ciphertext, iv, masterKey));
            }
        }

        private static JObject DecryptAccountDetails(JObject encryptedItem, KeyMac accountKey)
        {
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

        private static ParseException FormatError(string message, Exception innerException = null)
        {
            return new ParseException(ParseException.FailureReason.InvalidFormat, message, innerException);
        }

        private static ParseException CorruptedError(string message)
        {
            return new ParseException(ParseException.FailureReason.Corrupted, message);
        }
    }
}
