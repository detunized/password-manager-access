// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace TrueKey
{
    // This is the interface to be implemented by the user of the library.
    // It's used to securely store the device ID and the client token for
    // the registered device between sessions. It's possible to just return
    // null and not store anything. Everything will work fine but it will
    // force a new device to be registered at every login. This will
    // pollute the list of known devices on the server and could possibly
    // lead to a situation where no more devices could be added.
    public interface ISecureStorage
    {
        void StoreString(string name, string value);
        string LoadString(string name);
    }
}
