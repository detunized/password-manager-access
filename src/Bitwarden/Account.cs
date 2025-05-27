// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.Bitwarden
{
    public class Account : VaultItem
    {
        // TODO: Add 'required' modifier to all properties
        public string Username { get; init; }
        public string Password { get; init; }
        public string Url { get; init; }
        public string Totp { get; init; }

        //
        // Internal
        //

        internal Account(VaultItem item)
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
