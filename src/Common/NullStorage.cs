// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.Common
{
    // Secure storage that is safe to use to disable the "remember me" feature.
    // Simply pass `new NullStorage()` to `Vault.Open` of any of the password managers
    // when the "remember me" feature is not needed.
    public class NullStorage : ISecureStorage
    {
        public string LoadString(string name)
        {
            return null;
        }

        public void StoreString(string name, string value)
        {
        }
    }
}
