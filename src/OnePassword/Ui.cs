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

        // TODO: SSO
    }

    public record Otp(string Passcode, bool RememberMe);

    public record RememberMe(bool Value);

    public record Canceled(string Reason);
}
