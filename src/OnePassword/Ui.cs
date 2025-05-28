// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Duo;

namespace PasswordManagerAccess.OnePassword.Ui
{
    public interface IUi : IDuoUi
    {
        // Return Passcode.Cancel to cancel
        Passcode ProvideGoogleAuthPasscode();

        // Only the `Passcode.RememberMe` is used. The `Passcode.Code` is ignored as it's requested later
        // with the system UI and there's no way around it.
        // Return Passcode.Cancel to cancel
        Passcode ProvideWebAuthnRememberMe();

        // TODO: Make this non-optional
        string PerformSsoLogin(string url, string expectedRedirectUrl)
        {
            return "";
        }

        // TODO: Make this non-optional
        Passcode ProvideDeviceEnrollmentVerificationCode()
        {
            return Passcode.Cancel;
        }
    }

    public class Passcode
    {
        public static readonly Passcode Cancel = new Passcode("cancel", false);

        public readonly string Code;
        public readonly bool RememberMe;

        public Passcode(string code, bool rememberMe)
        {
            Code = code;
            RememberMe = rememberMe;
        }
    }
}
