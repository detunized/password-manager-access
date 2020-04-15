// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Example.Common
{
    // A primitive not-so-secure secure storage implementation. It stores a dictionary
    // as a list of strings in a text file. It could be JSON or something but we don't
    // want any extra dependencies.
    public class PlainStorage: ISecureStorage
    {
        public PlainStorage(): this(FindFilename())
        {
        }

        public PlainStorage(string filename)
        {
            // Use the absolute path in case the application changes the current directory
            _filename = Path.GetFullPath(filename);

            if (File.Exists(_filename))
                _storage = Util.ReadConfig(_filename);
        }

        public void StoreString(string name, string value)
        {
            if (value == null)
                _storage.Remove(name);
            else
                _storage[name] = EncodeValue(value);

            Save();
        }

        public string LoadString(string name)
        {
            return _storage.ContainsKey(name) ? DecodeValue(_storage[name]) : null;
        }

        private static string FindFilename()
        {
            // Look in the same place as config.yaml
            var filename = Util.FindFile("config.yaml", 3);
            if (filename == null)
                throw new InvalidOperationException("Couldn't find config.yaml, " +
                                                    "wanted to put storage.yaml in the same directory");

            return Path.GetDirectoryName(filename) + "/storage.yaml";
        }

        private static string EncodeValue(string s)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(s));
        }

        private static string DecodeValue(string s)
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(s));
        }

        private void Save()
        {
            File.WriteAllLines(_filename, _storage.Select(x => $"{x.Key}: {x.Value}"));
        }

        private readonly string _filename;
        private readonly Dictionary<string, string> _storage = new Dictionary<string, string>();
    }
}
