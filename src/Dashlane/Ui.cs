// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.Dashlane
{
    public abstract class Ui
    {
        //
        // MFA
        //

        // Passcode result
        public class Passcode
        {
            // Return this to signal the cancellation of the operation
            public static readonly Passcode Cancel = new Passcode("cancel", false);

            // Return this to resend the email token (not valid for Google Auth)
            public static readonly Passcode Resend = new Passcode("resend", false);

            public readonly string Code;
            public readonly bool RememberMe;

            public Passcode(string code, bool rememberMe)
            {
                Code = code;
                RememberMe = rememberMe;
            }
        }

        // To cancel return Passcode.Cancel
        public abstract Passcode ProvideGoogleAuthPasscode(int attempt);

        // To cancel return Passcode.Cancel
        // To resend the token return Passcode.Resend
        public abstract Passcode ProvideEmailPasscode(int attempt);
    }
}
