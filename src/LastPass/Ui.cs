// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.LastPass
{
    // TODO: We need to support optional passcodes on out-of-band auth.
    public abstract class Ui
    {
        // TODO: Think about how to deal with the cancellation.
        public enum SecondFactorMethod
        {
            GoogleAuth,
            MicrosoftAuth,
            Yubikey,
            // TODO: See which other methods should be supported.
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

        public enum OutOfBandMethod
        {
            LastPassAuth,
            Toopher,
            Duo,
        }

        public enum OufOfBandAction
        {
            Cancel,
            Continue,
            ContinueAndRememberMe,
        }

        // To cancel return Passcode.Cancel, otherwise only valid data is expected.
        public abstract Passcode ProvideSecondFactorPasscode(SecondFactorMethod method);

        // Should return immediately to allow the login process to continue. Once the OOB is approved
        // or declined by the user the library will return the result or throw an error.
        public abstract OufOfBandAction AskToApproveOutOfBand(OutOfBandMethod method);
    }
}
