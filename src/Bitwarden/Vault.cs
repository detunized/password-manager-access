// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System.Collections.Generic;
using System.Linq;

namespace PasswordManagerAccess.Bitwarden
{
    public record Vault(Account[] Accounts, SshKey[] SshKeys, Collection[] Collections, Organization[] Organizations, ParseError[] ParseErrors)
    {
        public IReadOnlyDictionary<string, Collection> CollectionsById => _collectionsById ??= Collections.ToDictionary(c => c.Id);
        public IReadOnlyDictionary<string, Organization> OrganizationsById => _organizationsById ??= Organizations.ToDictionary(o => o.Id);

        //
        // Private
        //

        private IReadOnlyDictionary<string, Collection>? _collectionsById;
        private IReadOnlyDictionary<string, Organization>? _organizationsById;
    }
}
