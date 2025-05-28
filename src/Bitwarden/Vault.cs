// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using PasswordManagerAccess.Bitwarden.Ui;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Bitwarden
{
    public class Vault
    {
        public readonly Account[] Accounts;
        public readonly SshKey[] SshKeys;
        public readonly Collection[] Collections;
        public readonly Organization[] Organizations;
        public readonly ParseError[] ParseErrors;

        public readonly IReadOnlyDictionary<string, Collection> CollectionsById;
        public readonly IReadOnlyDictionary<string, Organization> OrganizationsById;

        // The main entry point. Use this function to open the vault in the browser mode. In
        // this the login process is interactive when 2FA is enabled. This is an old mode
        // that might potentially trigger a captcha. Captcha solving is not supported.
        // There's no way to complete a login and get the vault if the captcha is triggered.
        // Use the CLI/API mode. This mode requires a different type of credentials.
        // The device ID should be unique to each installation, but it should not be new on
        // every run. A new random device ID should be generated with GenerateRandomDeviceId
        // on the first run and reused later on.
        public static Vault Open(ClientInfoBrowser clientInfo, IUi ui, ISecureStorage storage)
        {
            return Open(clientInfo, null, ui, storage);
        }

        // This version allows custom base URL. baseUrl could be set to null or "" for the default value.
        public static Vault Open(ClientInfoBrowser clientInfo, string baseUrl, IUi ui, ISecureStorage storage)
        {
            var session = Client.LogInBrowser(clientInfo: clientInfo, baseUrl: baseUrl, ui: ui, storage: storage);
            try
            {
                var (accounts, sshKeys, collections, organizations, errors) = Client.DownloadVault(session);
                return new Vault(accounts, sshKeys, collections, organizations, errors);
            }
            finally
            {
                Client.LogOut(session);
            }
        }

        // The main entry point. Use this function to open the vault in the CLI/API mode. In
        // this mode the login is fully non-interactive even with 2FA enabled. Bitwarden servers
        // don't use 2FA in this mode and permit to bypass it. There's no captcha in this mode
        // either. If the browser mode is triggering a captcha, this mode should be used instead.
        // This mode requires a different type of credentials that could be found in the vault
        // settings: the client ID and the client secret.
        // The device ID should be unique to each installation, but it should not be new on
        // every run. A new random device ID should be generated with GenerateRandomDeviceId
        // on the first run and reused later on.
        public static Vault Open(ClientInfoCliApi clientInfo, string baseUrl = null)
        {
            var session = Client.LogInCliApi(clientInfo: clientInfo, baseUrl: baseUrl);
            try
            {
                var (accounts, sshKeys, collections, organizations, errors) = Client.DownloadVault(session);
                return new Vault(accounts, sshKeys, collections, organizations, errors);
            }
            finally
            {
                Client.LogOut(session);
            }
        }

        public static string GenerateRandomDeviceId()
        {
            return Guid.NewGuid().ToString();
        }

        //
        // Private
        //

        private Vault(Account[] accounts, SshKey[] sshKeys, Collection[] collections, Organization[] organizations, ParseError[] parseErrors)
        {
            Accounts = accounts;
            SshKeys = sshKeys;
            Collections = collections;
            Organizations = organizations;
            ParseErrors = parseErrors;

            CollectionsById = collections.ToDictionary(x => x.Id);
            OrganizationsById = organizations.ToDictionary(x => x.Id);
        }
    }
}
