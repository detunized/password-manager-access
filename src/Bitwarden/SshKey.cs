// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.Bitwarden
{
    public class SshKey : VaultItem
    {
        // TODO: Add 'required' modifier to all properties
        public string PublicKey { get; init; }
        public string PrivateKey { get; init; }
        public string Fingerprint { get; init; }

        //
        // Internal
        //

        internal SshKey(VaultItem item)
        {
            Id = item.Id;
            Name = item.Name;
            Note = item.Note;
            DeletedDate = item.DeletedDate;
            Folder = item.Folder;
            CollectionIds = item.CollectionIds;
            HidePassword = item.HidePassword;
            CustomFields = item.CustomFields;
        }
    }
}
