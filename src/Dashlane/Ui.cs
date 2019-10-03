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

        //
        // Device ID registration
        //

        public class EmailToken
        {
            // Return this to signal the cancellation of the operation
            public static readonly EmailToken Cancel = new EmailToken("cancel");

            // Return this to resend the email token
            public static readonly EmailToken Resend = new EmailToken("resend");

            public readonly string Token;

            public EmailToken(string token)
            {
                Token = token;
            }
        }

        // To cancel return EmailToken.Cancel
        // To resend the token return EmailToken.Resend
        public abstract EmailToken ProvideEmailToken();
    }
}
