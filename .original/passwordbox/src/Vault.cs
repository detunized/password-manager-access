// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordBox
{
    public class Vault
    {
        public static Vault Create(string username, string password)
        {
            using (var webClient = new WebClient())
                return Create(username, password, webClient);
        }

        public static Vault Create(string username, string password, IWebClient webClient)
        {
            var session = Fetcher.Login(username, password, webClient);
            var accounts = Fetcher.Fetch(session, webClient);
            Fetcher.Logout(session);

            return new Vault(accounts);
        }

        public Account[] Accounts { get; private set; }

        private Vault(Account[] accounts)
        {
            Accounts = accounts;
        }
    }
}
