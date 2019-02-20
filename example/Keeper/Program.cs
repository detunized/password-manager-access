// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Keeper;

namespace Keeper
{
    static class Program
    {
        public static void Main()
        {
            Vault.Open("someone@example.com", "passw0rd!");
        }
    }
}
