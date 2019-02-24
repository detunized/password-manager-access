// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.IO;
using System.Linq;
using PasswordManagerAccess.Keeper;

namespace Keeper
{
    static class Program
    {
        public static Dictionary<string, string> ReadConfig(string filename)
        {
            return File.ReadAllLines(filename)
                .Select(line => line.Trim())
                .Where(line => line.Length > 0 && !line.StartsWith("#"))
                .Select(line => line.Split(new[] {':'}, 2))
                .Where(parts => parts.Length == 2)
                .ToDictionary(parts => parts[0].Trim(), parts => parts[1].Trim());
        }

        public static void Main()
        {
            var config = ReadConfig("../../../config.yaml");
            Vault.Open(config["username"], config["password"]);
        }
    }
}
