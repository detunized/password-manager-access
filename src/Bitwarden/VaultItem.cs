// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.Bitwarden
{
    public class VaultItem
    {
        public string Id { get; init; }
        public string Name { get; init; }
        public string Note { get; init; }
        public string Folder { get; init; }
        public string[] CollectionIds { get; init; }
        public bool HidePassword { get; init; }
        public CustomField[] CustomFields { get; init; }
    }

    public record CustomField(string Name, string Value) { }
}
