// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Linq;

namespace PasswordManagerAccess.Bitwarden
{
    public class Vault
    {
        public required Account[] Accounts { get; init; }
        public required SshKey[] SshKeys { get; init; }
        public required Collection[] Collections { get; init; }
        public required Organization[] Organizations { get; init; }
        public required ParseError[] ParseErrors { get; init; }

        public IReadOnlyDictionary<string, Collection> CollectionsById => Collections.ToDictionary(c => c.Id);
        public IReadOnlyDictionary<string, Organization> OrganizationsById => Organizations.ToDictionary(o => o.Id);
    }
}
