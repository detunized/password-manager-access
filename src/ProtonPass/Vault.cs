// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Threading.Tasks;

namespace PasswordManagerAccess.ProtonPass
{
    public class Vault
    {
        public static async Task<Vault> Open(string username, string password)
        {
            return new Vault();
        }
    }
}
