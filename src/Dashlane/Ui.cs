// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.Dashlane
{
    public abstract class Ui
    {
        //
        // MFA
        //

        // Passcode result
        public record Passcode(string Code, bool RememberMe)
        {
            // Return this to signal the cancellation of the operation
            public static readonly Passcode Cancel = new("cancel", false);

            // Return this to resend the email token (not valid for Google Auth)
            public static readonly Passcode Resend = new("resend", false);
        }

        // To cancel return Passcode.Cancel
        // DO NOT return Passcode.Resend, it's only valid for email passcode
        public abstract Passcode ProvideGoogleAuthPasscode(int attempt);

        // To cancel return Passcode.Cancel
        // To resend the token return Passcode.Resend
        public abstract Passcode ProvideEmailPasscode(int attempt);
    }
}
