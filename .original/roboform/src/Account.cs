// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;

namespace RoboForm
{
    public class Account
    {
        public readonly string Name;
        public readonly string Path;
        public readonly string Url;
        public readonly KeyValuePair<string, string>[] Fields;

        public Account(string name, string path, string url, KeyValuePair<string, string>[] fields)
        {
            Name = name;
            Path = path;
            Url = url;
            Fields = fields;
        }
    }
}
