// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using TrueKey;

namespace Example
{
    class Program
    {
        static void Main(string[] args)
        {
            // TODO: Read the credentials from a config file
            var username = "username@example.com";
            var password = "password";

            var vault = Vault.Open(username, password);
        }
    }
}
