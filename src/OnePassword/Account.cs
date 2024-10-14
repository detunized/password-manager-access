// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.Collections.Generic;
using System.Linq;
using PasswordManagerAccess.Common;
using R = PasswordManagerAccess.OnePassword.Response;

namespace PasswordManagerAccess.OnePassword
{
    // TODO: Inherit from VaultItem!
    public class Account
    {
        public string Id => _itemInfo.Id;

        // Decrypted on demand
        public string Name => Overview.Title ?? "";
        public string Username => _username ??= GetUsername();
        public string Password => _password ??= GetPassword();
        public string MainUrl => _url ??= GetUrl();
        public string Note => Details.Note ?? "";
        public Url[] Urls => _urls ?? AssignUrls();
        public Otp[] Otps => _otps ?? AssignOtps();
        public Field[] Fields => _fields ?? AssignFields();

        public readonly struct Url
        {
            public readonly string Name;
            public readonly string Value;

            internal Url(string name, string value)
            {
                Name = name;
                Value = value;
            }
        }

        public readonly struct Otp
        {
            public readonly string Name;
            public readonly string Secret;
            public readonly string Section;

            internal Otp(string name, string secret, string section)
            {
                Name = name;
                Secret = secret;
                Section = section;
            }
        }

        public readonly struct Field
        {
            public readonly string Name;
            public readonly string Value;
            public readonly string Section;

            internal Field(string name, string value, string section)
            {
                Name = name;
                Value = value;
                Section = section;
            }
        }

        //
        // Internal
        //

        internal const string LoginTemplateId = "001";
        internal const string ServerTemplateId = "110";

        internal Account(R.VaultItem itemInfo, Keychain keychain)
        {
            _itemInfo = itemInfo;
            _keychain = keychain;
        }

        internal R.VaultItemOverview DecryptOverview()
        {
            return Util.Decrypt<R.VaultItemOverview>(_itemInfo.Overview, _keychain);
        }

        internal R.VaultItemDetails DecryptDetails()
        {
            return Util.Decrypt<R.VaultItemDetails>(_itemInfo.Details, _keychain);
        }

        internal string GetUsername()
        {
            return FindField("username");
        }

        internal string GetPassword()
        {
            return FindField("password");
        }

        internal string GetUrl()
        {
            // TODO: See if this could be written as `Overview.Url ?? FindField("URL") ?? ""`
            return _itemInfo.TemplateId switch
            {
                LoginTemplateId => Overview.Url ?? "",
                ServerTemplateId => FindField("URL"),
                var id => throw new InternalErrorException($"Unsupported vault item type {id}"),
            };
        }

        internal string FindField(string name)
        {
            // Logins have their fields here.
            if (Details.Fields != null)
                foreach (var field in Details.Fields)
                    if (field.Designation == name)
                        return field.Value ?? "";

            // Servers have some of the stuff stored here.
            // There wasn't nearly enough nesting above. Gimme more!
            if (Details.Sections != null)
                foreach (var section in Details.Sections)
                    if (section.Fields != null)
                        foreach (var field in section.Fields)
                            if (field.Name == name)
                                return field.Value ?? "";

            return "";
        }

        internal Url[] AssignUrls()
        {
            _urls = Overview.Urls?.Select(x => new Url(name: x.Name, value: x.Url)).ToArray() ?? Array.Empty<Url>();
            return _urls;
        }

        internal Otp[] AssignOtps()
        {
            ParseFields();
            return _otps!;
        }

        internal Field[] AssignFields()
        {
            ParseFields();
            return _fields!;
        }

        internal void ParseFields()
        {
            var otps = new List<Otp>();
            var fields = new List<Field>();

            foreach (var section in Details.Sections ?? Array.Empty<R.VaultItemSection>())
            {
                foreach (var field in section.Fields ?? Array.Empty<R.VaultItemSectionField>())
                {
                    if (field.Kind == "concealed" && field.Id?.StartsWith("TOTP_") == true)
                        otps.Add(new Otp(name: field.Name, secret: field.Value, section: section.Name));
                    else
                        fields.Add(new Field(name: field.Name, value: field.Value, section: section.Name));
                }
            }

            _otps = otps.ToArray();
            _fields = fields.ToArray();
        }

        //
        // Private
        //

        private readonly R.VaultItem _itemInfo;
        private readonly Keychain _keychain;

        // Cache
        private R.VaultItemOverview Overview => _overview ??= DecryptOverview();
        private R.VaultItemOverview? _overview;
        private R.VaultItemDetails Details => _details ??= DecryptDetails();
        private R.VaultItemDetails? _details;
        private string? _username;
        private string? _password;
        private string? _url;
        private Url[]? _urls;
        private Otp[]? _otps;
        private Field[]? _fields;
    }
}
