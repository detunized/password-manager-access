// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.Duo
{
    internal class Result
    {
        public readonly string Passcode;
        public readonly bool RememberMe;

        public Result(string passcode, bool rememberMe)
        {
            Passcode = passcode;
            RememberMe = rememberMe;
        }
    }
}
