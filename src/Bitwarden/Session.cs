// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System.Collections.Generic;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Bitwarden
{
    // The session object is opaque to the user. It holds all the state needed by Client to perform
    // various operations like downloading vaults or logging out.
    public class Session
    {
        internal string Token { get; }
        internal byte[] Key { get; }
        internal Profile Profile { get; }
        internal RestClient Rest { get; }
        internal IRestTransport Transport { get; }

        // Set lazily if/when needed
        internal Dictionary<string, string>? Folders { get; set; }
        internal Dictionary<string, Collection>? Collections { get; set; }

        internal Session(string token, byte[] key, Profile profile, RestClient rest, IRestTransport transport)
        {
            Token = token;
            Key = key;
            Profile = profile;
            Rest = rest;
            Transport = transport;
        }
    }

    // TODO: Move to Model maybe?
    internal record Profile(byte[] VaultKey, byte[] PrivateKey, Dictionary<string, Organization> Organizations, Dictionary<string, byte[]> OrgKeys);
}
