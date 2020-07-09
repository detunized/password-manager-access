// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using PasswordManagerAccess.Example.Common;
using PasswordManagerAccess.Kaspersky;

namespace PasswordManagerAccess.Example.Kaspersky
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            var config = Util.ReadConfig();

            try
            {
                var vault = Vault.Open(config["username"], config["password"]);
            }
            catch (BaseException e)
            {
                Util.PrintException(e);
            }
        }
    }
}
