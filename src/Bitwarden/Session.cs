// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using PasswordManagerAccess.Common;
using R = PasswordManagerAccess.Bitwarden.Response;

namespace PasswordManagerAccess.Bitwarden
{
    // The session object is opaque to the user. It holds all the state needed by Client to perform
    // various operations like downloading vaults or logging out.
    public class Session
    {
        internal string Token { get; }
        internal byte[] Key { get; }
        internal R.Profile Profile { get; }
        internal RestClient Rest { get; }
        internal IRestTransport Transport { get; }

        // Set lazily if needed
        internal R.Folder[]? Folders { get; set; }
        internal R.Collection[]? Collections { get; set; }

        internal Session(string token, byte[] key, R.Profile profile, RestClient rest, IRestTransport transport)
        {
            Token = token;
            Key = key;
            Profile = profile;
            Rest = rest;
            Transport = transport;
        }
    }
}
