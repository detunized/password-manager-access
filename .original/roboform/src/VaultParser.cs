// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json.Linq;

namespace RoboForm
{
    internal static class VaultParser
    {
        public static Vault Parse(JObject json)
        {
            var c = json["c"] as JArray;
            if (c == null || c.Count < 2)
                throw ParseError("Invalid format");

            var root = c[1];
            if (root == null)
                throw ParseError("Root node not found");

            if (!root.BoolAt("i/F", false) || root.StringAt("i/n", "") != "root")
                throw ParseError("Invalid root node format");

            var accounts = new List<Account>();
            TraverseParse(root["c"], "", accounts);

            return new Vault(accounts.ToArray());
        }

        private static void TraverseParse(JToken node, string path, List<Account> accounts)
        {
            foreach (var i in node)
            {
                var name = i.StringAt("i/n", "");
                if (i.BoolAt("i/F", false))
                    TraverseParse(i["c"], path.Length == 0 ? name : path + "/" + name, accounts);
                else
                    accounts.Add(ParseAccount(i.StringAt("b", "{}"), name, path));
            }
        }

        private static Account ParseAccount(string content, string name, string path)
        {
            var json = JObject.Parse(content);
            var url = json.StringAt("g", json.StringAt("m", ""));
            var fields = ParseFields(json["f"] as JArray ?? new JArray());

            return new Account(name, path, url, fields);
        }

        private static KeyValuePair<string, string>[] ParseFields(JArray fields)
        {
            return fields
                .Where(i => InRange(i.IntAt("t", 1), 1, 2)) // Only keep text (1) and password (2) inputs
                .Where(i => !i.BoolAt("d", false))          // Don't need input fields with default values
                .Select(i => new KeyValuePair<string, string>(i.StringAt("n", ""), i.StringAt("v", "")))
                .Where(i => i.Key.Length != 0 || i.Value.Length != 0)
                .ToArray();
        }

        private static bool InRange(int i, int min, int max)
        {
            return i >= min && i <= max;
        }

        private static ClientException ParseError(string format, params object[] args)
        {
            return new ClientException(ClientException.FailureReason.ParseError,
                                       string.Format("Vault " + format, args));
        }
    }
}
