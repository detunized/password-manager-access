// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.Common
{
    // This is the interface to be implemented by the user of the library.
    // It's used to securely store things like the second factor token between
    // sessions when "remember me" option is used.
    public interface ISecureStorage
    {
        // Returns null if no value exists
        string LoadString(string name);

        // Pass null to delete the value
        void StoreString(string name, string value);
    }
}
