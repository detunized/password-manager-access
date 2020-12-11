// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace PasswordManagerAccess.Kdbx
{
    public class Account
    {
        public readonly string Id;
        public readonly string Name;
        public readonly string Username;
        public readonly string Password;
        public readonly string Url;
        public readonly string Note;
        public readonly string Path;
        public readonly IReadOnlyDictionary<string, string> Fields;

        public Account(string id,
                       string name,
                       string username,
                       string password,
                       string url,
                       string note,
                       string path,
                       IReadOnlyDictionary<string, string> fields)
        {
            Id = id;
            Name = name;
            Username = username;
            Password = password;
            Url = url;
            Note = note;
            Path = path;
            Fields = fields;
        }

        internal static readonly IReadOnlyDictionary<string, string> NoFields =
            new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(0));
    }
}
