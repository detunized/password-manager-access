// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Newtonsoft.Json.Linq;

namespace OPVault
{
    public class Vault
    {
        public static void Open(string path, string password)
        {
            // Load all the files
            var profile = LoadProfile(path);
            var encryptedFolders = LoadFolders(path);
            var encryptedItems = LoadItems(path);

            var kek = DeriveKek(profile, password);
            var masterKey = DecryptMasterKey(profile, kek);
            var overviewKey = DecryptOverviewKey(profile, kek);

            var folders = DecryptFolders(encryptedFolders, overviewKey);
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
            // TODO: Use custom exception
            if (content.Length < prefix.Length + suffix.Length)
                throw new InvalidOperationException("Content is too short");
            if (!content.StartsWith(prefix))
                throw new InvalidOperationException("Expected prefix is not found in content");
            if (!content.EndsWith(suffix))
                throw new InvalidOperationException("Expected suffix is not found in content");

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

        private static Folder DecryptFolder(JObject folder, KeyMac overviewKey)
        {
            // TODO: Handle JSON exceptions
            var overview = JObject.Parse(Opdata01.Decrypt(folder.StringAt("overview"), overviewKey).ToUtf8());
            return new Folder(folder.StringAt("uuid"), overview.StringAt("title"));
        }
    }
}
