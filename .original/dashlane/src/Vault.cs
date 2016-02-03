// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace Dashlane
{
    public class Vault
    {
        public static Vault Open(string username, string password, string uki, IWebClient webClient)
        {
            return new Vault();
        }

        public Account[] Accounts { get; private set; }

        private Vault()
        {
            Accounts = new Account[] {};
        }
    }
}
