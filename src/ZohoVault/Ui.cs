// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.ZohoVault.Ui
{
    public interface IUi
    {
        // To cancel return Passcode.Cancel
        public abstract Passcode ProvideGoogleAuthPasscode();
    }

    // Passcode result
    public class Passcode
    {
        // Return this to signal the cancellation of the operation
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
