// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json.Linq;

namespace PasswordManagerAccess.RoboForm
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
            var username = GuessUsername(fields);
            var password = GuessPassword(fields);

            return new Account(name, path, url, fields, username, password);
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

        private static string GuessUsername(Account.Field[] fields)
        {
            // If there's only one text field with a special name then it's the username.
            var username = fields.Where(i => i.Kind == Account.FieldKind.Text &&
                                             UsernameFields.Contains(i.Name.ToLower())).ToArray();
            if (username.Length == 1)
                return username[0].Value;

            // If there's only one text field, assume it's the username.
            username = fields.Where(i => i.Kind == Account.FieldKind.Text).ToArray();
            if (username.Length == 1)
                return username[0].Value;

            return null;
        }

        private static string GuessPassword(Account.Field[] fields)
        {
            // Search all fields first with the appropriate names
            var password = fields.Where(i => PasswordFields.Contains(i.Name.ToLower())).ToArray();
            if (password.Length == 1)
                return password[0].Value;

            // We have too many, remove all the text fields.
            // If there's only one left then it's the password.
            password = password.Where(i => i.Kind == Account.FieldKind.Password).ToArray();
            if (password.Length == 1)
                return password[0].Value;

            // If there's only one password field, assume it's the password.
            password = fields.Where(i => i.Kind == Account.FieldKind.Password).ToArray();
            if (password.Length == 1)
                return password[0].Value;

            return null;
        }

        private static ClientException ParseError(string format, params object[] args)
        {
            return new ClientException(ClientException.FailureReason.ParseError,
                                       string.Format("Vault " + format, args));
        }

        private static readonly HashSet<string> UsernameFields = new HashSet<string>
        {
            "username",
            "login",
            "email",
            "user",
            "u",
        };

        private static readonly HashSet<string> PasswordFields = new HashSet<string>
        {
            "password",
            "passwd",
            "pwd",
            "pass",
            "p",
        };
    }
}
