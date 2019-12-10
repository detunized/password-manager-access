// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace OnePassword
{
    public class Account
    {
        public struct Url
        {
            public readonly string Name;
            public readonly string Value;

            public Url(string name, string value)
            {
                Name = name;
                Value = value;
            }
        }

        public struct Field
        {
            public readonly string Name;
            public readonly string Value;
            public readonly string Section;

            public Field(string name, string value, string section)
            {
                Name = name;
                Value = value;
                Section = section;
            }
        }

        public readonly string Id;
        public readonly string Name;
        public readonly string Username;
        public readonly string Password;
        public readonly string MainUrl;
        public readonly string Note;

        public readonly Url[] Urls;
        public readonly Field[] Fields;

        public Account(string id,
                       string name,
                       string username,
                       string password,
                       string mainUrl,
                       string note,
                       Url[] urls,
                       Field[] fields)
        {
            Id = id;
            Name = name;
            Username = username;
            Password = password;
            MainUrl = mainUrl;
            Note = note;
            Urls = urls;
            Fields = fields;
        }
    }
}
