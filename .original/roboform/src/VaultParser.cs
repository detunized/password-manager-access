// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
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

        private static Account.Field[] ParseFields(JArray fields)
        {
            var parsedFields = new List<Account.Field>();
            foreach (var field in fields)
            {
                Account.FieldKind kind;
                switch (field.IntAt("t", 1))
                {
                case 1:
                    kind = Account.FieldKind.Text;
                    break;
                case 2:
                    kind = Account.FieldKind.Password;
                    break;
                default:
                    // Ignore all other types of fields like buttons and dropdowns.
                    continue;
                }

                // Ignore fields with default values
                if (field.BoolAt("d", false))
                    continue;

                // Name cannot be blank
                var name = field.StringAt("n", "");
                if (name == "")
                    continue;

                // Value also cannot be blank
                var value = field.StringAt("v", "");
                if (value == "")
                    continue;

                parsedFields.Add(new Account.Field(name, value, kind));
            }

            return parsedFields.ToArray();
        }

        private static ClientException ParseError(string format, params object[] args)
        {
            return new ClientException(ClientException.FailureReason.ParseError,
                                       string.Format("Vault " + format, args));
        }
    }
}
