// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Bitwarden
{
    public abstract class Ui: IDuoUi
    {
        // The UI will no longer be used and could be closed
        public abstract void Close();

        public enum MfaMethod
        {
            // Always available
            Cancel,

            GoogleAuth,
            Email,
            Duo,
            YubiKey,
            U2f,
        }

        // To cancel return Method.Cancel (always available)
        public abstract MfaMethod ChooseMfaMethod(MfaMethod[] availableMethods);

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

        // To cancel any of these return null
        public abstract Passcode ProvideGoogleAuthPasscode();
        public abstract Passcode ProvideEmailPasscode(string emailHint);
        public abstract Passcode ProvideYubiKeyPasscode();

        //
        // Duo
        //

        public abstract DuoChoice ChooseDuoFactor(DuoDevice[] devices);
        public abstract string ProvideDuoPasscode(DuoDevice device);
        public abstract void UpdateDuoStatus(DuoStatus status, string text);
    }
}
