// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.Bitwarden
{
    public class SshKey : VaultItem
    {
        public SshKey(VaultItem item)
        {
            Id = item.Id;
            Name = item.Name;
            Notes = item.Notes;
            DeletedDate = item.DeletedDate;
            Folder = item.Folder;
            CollectionIds = item.CollectionIds;
            HidePassword = item.HidePassword;
            CustomFields = item.CustomFields;
        }

        public string PublicKey { get; init; }
        public string PrivateKey { get; init; }
        public string Fingerprint { get; init; }
    }
}
