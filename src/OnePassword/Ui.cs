// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.OnePassword
{
    public abstract class Ui
    {
        public class Passcode
        {
            public readonly string Code;
            public readonly bool RememberMe;

            public Passcode(string code, bool rememberMe)
            {
                Code = code;
                RememberMe = rememberMe;
            }
        }

        // Return null or cancel
        public abstract Passcode ProvideGoogleAuthPasscode();
    }
}
