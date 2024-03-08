// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using PasswordManagerAccess.Example.Common;
using PasswordManagerAccess.ProtonPass;

namespace PasswordManagerAccess.Example.ProtonPass
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            var config = Util.ReadConfig();

            try
            {
                var vault = Vault.Open(config["username"], config["password"]).GetAwaiter().GetResult();
            }
            catch (BaseException e)
            {
                Util.PrintException(e);
            }
        }
    }
}
