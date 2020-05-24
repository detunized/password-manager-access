// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.OnePassword
{
    public abstract class Ui: IDuoUi
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

        // Duo
        public abstract DuoChoice ChooseDuoFactor(DuoDevice[] devices);
        public abstract string ProvideDuoPasscode(DuoDevice device);
        public abstract void UpdateDuoStatus(DuoStatus status, string text);
    }
}
