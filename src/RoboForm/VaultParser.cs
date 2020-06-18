// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Newtonsoft.Json.Linq;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.RoboForm
{
    // TODO: Could be beneficial to convert at least some of the JToken.*At access to
    // de-serialization. The input json is recursive with somewhat dynamic structure.
    internal static class VaultParser
    {
        public static (Account[] Accounts, RSAParameters? PrivateKey) Parse(JObject json)
        {
            // The top-level item must be a folder
            var topLevel = GetFolderContent(json);
            if (topLevel == null)
                throw new InternalErrorException("Invalid format: top level folder not found");

            // There's a root folder somewhere at the second level
            var root = FindNamedItem(topLevel, "root");
            if (root == null || !IsFolder(root))
                throw new InternalErrorException("Invalid format: root folder not found");

            // Traverse the root folder recursively and parse all the accounts
            var accounts = new List<Account>();
            if (root["c"] is JArray c)
                TraverseParse(c, "", accounts);

            // Parse the private key
            RSAParameters? rsa = null;
            var privateKey = FindNamedItem(topLevel, "private-key.pem").StringAt("b", "");
            if (!privateKey.IsNullOrEmpty())
                rsa = Pem.ParseRsaPrivateKeyPkcs1(privateKey);

            return (accounts.ToArray(), rsa);
        }

        internal static bool IsFolder(JToken json)
        {
            if (json["i"] is JObject i)
                return i.BoolAt("F", false);

            return false;
        }

        // Gets the folder content only if this token represents a valid folder
        internal static JArray GetFolderContent(JToken json)
        {
            if (IsFolder(json) && json["c"] is JArray c)
                return c;

            return null;
        }

        internal static JObject FindNamedItem(JArray items, string name)
        {
            if (items.FirstOrDefault(x => x["i"].StringAt("n", "") == name) is JObject o)
                return o;

            return null;
        }

        internal static void TraverseParse(JArray items, string path, List<Account> accounts)
        {
            foreach (var item in items)
            {
                if (!(item["i"] is JObject info))
                    throw new InternalErrorException("Invalid format: item info block not found");

                if (IsFolder(item))
                {
                    if (item["c"] is JArray c)
                    {
                        var name = info.StringAt("n", "-");
                        TraverseParse(c, path.Length == 0 ? name : path + "/" + name, accounts);
                    }
                }
                else
                {
                    var account = ParseAccount(content: item.StringAt("b", "{}"),
                                               name: info.StringAt("n", ""),
                                               path: path);
                    accounts.Add(account);
                }
            }
        }

        internal static Account ParseAccount(string content, string name, string path)
        {
            var json = JObject.Parse(content);
            var url = json.StringAt("g", json.StringAt("m", ""));
            var fields = ParseFields(json["f"] as JArray ?? new JArray());
            var username = GuessUsername(fields);
            var password = GuessPassword(fields);

            return new Account(name, path, url, fields, username, password);
        }

        internal static Account.Field[] ParseFields(JArray fields)
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

        internal static string GuessUsername(Account.Field[] fields)
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

        internal static string GuessPassword(Account.Field[] fields)
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
