// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Threading;
using System.Threading.Tasks;
using OneOf;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Duo;

namespace PasswordManagerAccess.OnePassword.Ui
{
    public interface IAsyncUi : IDuoAsyncUi
    {
        // OTP (one-time passcode) method
        // This method should return one of the following three options:
        //   1. new Otp(...): the user provided a valid passcode
        //   2. one of the MFA methods from `otherMethods`: the user chose a different MFA method
        //   3. new Canceled(...): the user canceled the operation
        Task<OneOf<Otp, MfaMethod, Canceled>> ProvideGoogleAuthPasscode(int attempt, MfaMethod[] otherMethods, CancellationToken cancellationToken);

        // RememberMe for WebAuthn
        // This method should return one of the following four options:
        //   1. new RememberMe(...): the user provided remember-me option (the actual WebAuthn interaction is done outside of this method by the OS)
        //   2. one of the MFA methods from `otherMethods`: the user chose a different MFA method
        //   4. new Canceled(...): the user canceled the operation
        Task<OneOf<RememberMe, MfaMethod, Canceled>> ProvideWebAuthnRememberMe(
            int attempt,
            MfaMethod[] otherMethods,
            CancellationToken cancellationToken
        );

        // SSO login
        // This method should open the SSO login URL (typically in a browser) and wait for the user to complete
        // the authentication flow. The SSO provider will redirect to `redirectTo` URL with the authentication code.
        // Returns the final redirect URL containing the code and state parameters, or an empty string if canceled.
        Task<string> PerformSsoLogin(string ssoLoginUrl, string redirectTo, CancellationToken cancellationToken);

        // Device enrollment verification code
        // When enrolling a new device for SSO, the user needs to enter a verification code that is displayed
        // on an already enrolled device. This method prompts the user for that code.
        // Returns the verification code, or an empty string if canceled.
        Task<string> ProvideDeviceEnrollmentVerificationCode(CancellationToken cancellationToken);
    }

    public record Otp(string Passcode, bool RememberMe);

    public record RememberMe(bool Value);

    public record Canceled(string Reason);
}
