// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Bitwarden
{
    // The session object is opaque to the user. It holds all the state needed by Client to perform
    // various operations like downloading vaults or logging out.
    public class Session
    {
        internal readonly string Token;
        internal readonly byte[] Key;
        internal readonly (RestClient Api, RestClient Identity) Rest;

        internal Session(string token, byte[] key, (RestClient Api, RestClient Identity) rest)
        {
            Token = token;
            Key = key;
            Rest = rest;
        }
    }
}
