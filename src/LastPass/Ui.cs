// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.LastPass.Ui
{
    // TODO: We need to support optional passcodes on out-of-band auth.
    public interface IUi
    {
        // To cancel return Passcode.Cancel, otherwise only valid data is expected.
        public abstract Passcode ProvideSecondFactorPasscode(SecondFactorMethod method);

        // Should return immediately to allow the login process to continue. Once the OOB is approved
        // or declined by the user the library will return the result or throw an error.
        public abstract OufOfBandAction AskToApproveOutOfBand(OutOfBandMethod method);
    }

    public enum SecondFactorMethod
    {
        GoogleAuth,
        MicrosoftAuth,
        Yubikey,
    }

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
}
