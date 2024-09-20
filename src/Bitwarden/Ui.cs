// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Duo;

namespace PasswordManagerAccess.Bitwarden.Ui
{
    public interface IUi : IDuoUi
    {
        // The UI will no longer be used and could be closed
        public abstract void Close();

        // To cancel return Method.Cancel (always available)
        MfaMethod ChooseMfaMethod(MfaMethod[] availableMethods);

        // To cancel any of these return null
        Passcode ProvideGoogleAuthPasscode();
        Passcode ProvideEmailPasscode(string emailHint);
        Passcode ProvideYubiKeyPasscode();
    }

    public enum MfaMethod
    {
        // Always available
        Cancel,

        GoogleAuth,
        Email,
        Duo,
        YubiKey,
        U2f,
        DuoOrg,
    }

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
}
