// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Newtonsoft.Json;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.OpVault
{
    using M = Model;

    public static class Vault
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

                // Decrypt main keys
                var masterKey = DecryptMasterKey(profile, kek);
                var overviewKey = DecryptOverviewKey(profile, kek);

                // Decrypt, parse and convert folders
                var folders = DecryptFolders(encryptedFolders, overviewKey);

                // Decrypt, parse, convert and assign folders
                return DecryptAccounts(encryptedItems, masterKey, overviewKey, folders);
            }
            catch (JsonException e)
            {
                throw FormatError("Unexpected JSON schema", e);
            }
        }

        //
        // Internal
        //

        internal static M.Profile LoadProfile(string path)
        {
            return LoadJsAsJson<M.Profile>(MakeFilename(path, "profile.js"), "var profile=", ";");
        }

        internal static M.Folder[] LoadFolders(string path)
        {
            var folders = LoadJsAsJson<Dictionary<string, M.Folder>>(MakeFilename(path, "folders.js"),
                                                                     "loadFolders(",
                                                                     ");");
            return folders.Values.ToArray();
        }

        internal static M.Item[] LoadItems(string path)
        {
            var items = new List<M.Item>();
            foreach (var c in "0123456789ABCDEF")
            {
                var filename = MakeFilename(path, $"band_{c}.js");
                if (!File.Exists(filename))
                    continue;

                items.AddRange(LoadBand(filename));
            }

            return items.ToArray();
        }

        internal static IEnumerable<M.Item> LoadBand(string filename)
        {
            var band = LoadJsAsJson<Dictionary<string, M.Item>>(filename, "ld(", ");");
            return band.Values;
        }

        internal static T LoadJsAsJson<T>(string filename, string prefix, string suffix)
        {
            return LoadJsAsJsonFromString<T>(LoadTextFile(filename), prefix, suffix);
        }

        internal static string LoadTextFile(string filename)
        {
            // We're deliberately not trying to catch all the possible file/io errors.
            // It's impossible to handle them all. Just a basic check that the file is there.
            if (!File.Exists(filename))
                throw new InternalErrorException($"File '{filename}' doesn't exist");

            return File.ReadAllText(filename);
        }

        internal static T LoadJsAsJsonFromString<T>(string content, string prefix, string suffix)
        {
            if (content.Length < prefix.Length + suffix.Length)
                throw FormatError("JS/JSON: Content is too short");

            if (!content.StartsWith(prefix))
                throw FormatError("JS/JSON: Expected prefix is not found in the content");

            if (!content.EndsWith(suffix))
                throw FormatError("JS/JSON: Expected suffix is not found in the content");

            var json = content.Substring(prefix.Length, content.Length - prefix.Length - suffix.Length);

            try
            {
                return JsonConvert.DeserializeObject<T>(json);
            }
            catch (JsonException e)
            {
                // TODO: Generic types have ugly names
                throw FormatError($"JS/JSON: Invalid JSON schema for {typeof(T).Name}", e);
            }
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

        internal static KeyMac DeriveKek(M.Profile profile, string password)
        {
            return Util.DeriveKek(password.ToBytes(), profile.Salt.Decode64(), profile.Iterations);
        }

        internal static KeyMac DecryptMasterKey(M.Profile profile, KeyMac kek)
        {
            try
            {
                return DecryptBase64Key(profile.MasterKey, kek);
            }
            catch (InternalErrorException e) when (e.Message.Contains("tag doesn't match"))
            {
                // This is a bit hacky. There's no sure way to verify if the password is correct. The things
                // will start failing to decrypt on HMAC/tag verification. So only for the master key we assume
                // that the structure of the vault is not corrupted (which is unlikely) but rather the master
                // password wasn't given correctly. So we rethrow the "corrupted" exception as the "incorrect
                // password". Unfortunately we have to rely on the contents of the error message as well.
                throw new BadCredentialsException("Most likely the master password is incorrect", e);
            }
        }

        internal static KeyMac DecryptOverviewKey(M.Profile profile, KeyMac kek)
        {
            return DecryptBase64Key(profile.OverviewKey, kek);
        }

        internal static KeyMac DecryptBase64Key(string encryptedKeyBase64, KeyMac kek)
        {
            var raw = Opdata01.Decrypt(encryptedKeyBase64, kek);
            return new KeyMac(Crypto.Sha512(raw));
        }

        internal static Dictionary<string, Folder> DecryptFolders(M.Folder[] encryptedFolders, KeyMac overviewKey)
        {
            var activeFolders = encryptedFolders.Where(i => !i.Deleted).ToArray();
            var childToParent = activeFolders.ToDictionary(i => i.Id, i => i.ParentId ?? "");
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

        internal static Account[] DecryptAccounts(M.Item[] encryptedItems,
                                                  KeyMac masterKey,
                                                  KeyMac overviewKey,
                                                  Dictionary<string, Folder> folders)
        {
            return encryptedItems
                .Where(i => !i.Deleted)
                .Where(i => i.Category == "001")
                .Select(i => DecryptAccount(i, masterKey, overviewKey, folders))
                .ToArray();
        }

        private static Folder DecryptFolder(M.Folder folder, KeyMac overviewKey)
        {
            var overview = DecryptJson<M.FolderOverview>(folder.Overview, overviewKey);
            return new Folder(folder.Id, overview.Title);
        }

        private static Account DecryptAccount(M.Item encryptedItem,
                                              KeyMac masterKey,
                                              KeyMac overviewKey,
                                              Dictionary<string, Folder> folders)
        {
            var overview = DecryptAccountOverview(encryptedItem, overviewKey);
            var accountKey = DecryptAccountKey(encryptedItem, masterKey);
            var details = DecryptAccountDetails(encryptedItem, accountKey);

            return new Account(id: encryptedItem.Id,
                               name: overview.Title ?? "",
                               username: FindDetailField(details, "username"),
                               password: FindDetailField(details, "password"),
                               url: overview.Url ?? "",
                               note: details.Notes ?? "",
                               folder: folders.GetOrDefault(encryptedItem.FolderId ?? "", Folder.None));
        }

        private static M.ItemOverview DecryptAccountOverview(M.Item encryptedItem, KeyMac overviewKey)
        {
            return DecryptJson<M.ItemOverview>(encryptedItem.Overview, overviewKey);
        }

        private static KeyMac DecryptAccountKey(M.Item encryptedItem, KeyMac masterKey)
        {
            var raw = encryptedItem.Key.Decode64();
            if (raw.Length != 112)
                throw CorruptedError("key has invalid size");

            using var io = new BinaryReader(new MemoryStream(raw, false));
            var iv = io.ReadBytes(16);
            var ciphertext = io.ReadBytes(64);
            var storedTag = io.ReadBytes(32);

            // Rewind and reread everything to the tag
            io.BaseStream.Seek(0, SeekOrigin.Begin);
            var hashedContent = io.ReadBytes(80);

            var computedTag = Crypto.HmacSha256(hashedContent, masterKey.MacKey);
            if (!computedTag.SequenceEqual(storedTag))
                throw CorruptedError("key tag doesn't match");

            return new KeyMac(Util.DecryptAes(ciphertext, iv, masterKey));
        }

        private static M.ItemDetails DecryptAccountDetails(M.Item encryptedItem, KeyMac accountKey)
        {
            return DecryptJson<M.ItemDetails>(encryptedItem.Details, accountKey);
        }

        private static T DecryptJson<T>(string encryptedJsonBase64, KeyMac key)
        {
            return JsonConvert.DeserializeObject<T>(Opdata01.Decrypt(encryptedJsonBase64, key).ToUtf8());
        }

        // TODO: Write a test
        private static string FindDetailField(M.ItemDetails details, string name)
        {
            if (details.Fields == null)
                return "";

            foreach (var i in details.Fields)
                if (i.Designation == name)
                    return i.Value ?? "";

            return "";
        }

        private static InternalErrorException FormatError(string message, Exception innerException = null)
        {
            return new InternalErrorException(message, innerException);
        }

        private static InternalErrorException CorruptedError(string message)
        {
            return new InternalErrorException($"Vault item is corrupted: {message}");
        }
    }
}
