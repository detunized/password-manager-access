// Copyright (C) 2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace OnePassword
{
    // This is the interface to be implemented by the user of the library.
    // It's used to securely store the second factor token when "remember me"
    // option is used.
    public interface ISecureStorage
    {
        void StoreString(string name, string value);
        string LoadString(string name);
    }
}
