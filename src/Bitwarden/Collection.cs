// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.Bitwarden
{
    public class Collection
    {
        public readonly string Id;
        public readonly string Name;
        public readonly string OrganizationId;
        public readonly bool HidePasswords;

        public Collection(string id, string name, string organizationId, bool hidePasswords)
        {
            Id = id;
            Name = name;
            OrganizationId = organizationId;
            HidePasswords = hidePasswords;
        }
    }
}
