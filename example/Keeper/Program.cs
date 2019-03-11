// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
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
            var accounts = Vault.Open(config["username"], config["password"]);
            for (var i = 0; i < accounts.Length; i++)
            {
                var a = accounts[i];
                Console.WriteLine($" - {i + 1}");
                Console.WriteLine($"            id: {a.Id}");
                Console.WriteLine($"          name: {a.Name}");
                Console.WriteLine($"      username: {a.Username}");
                Console.WriteLine($"      password: {a.Password}");
                Console.WriteLine($"           url: {a.Url}");
                Console.WriteLine($"          note: {a.Note}");
                Console.WriteLine($"        folder: {a.Folder}");
            }
        }
    }
}
