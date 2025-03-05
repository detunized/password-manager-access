// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Threading;
using System.Threading.Tasks;
using OneOf;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Duo;

namespace PasswordManagerAccess.LastPass.Ui
{
    public interface IAsyncUi : IDuoAsyncUi
    {
        // OTP (one-time passcode) methods
        // Each of these methods should return one of the following three options:
        //   1. new Otp(...): the user provided a valid passcode
        //   2. one of the MFA methods from `otherMethods`: the user chose a different MFA method
        //   3. new Canceled(...): the user canceled the operation
        Task<OneOf<Otp, MfaMethod, Canceled>> ProvideGoogleAuthPasscode(int attempt, MfaMethod[] otherMethods, CancellationToken cancellationToken);
        Task<OneOf<Otp, MfaMethod, Canceled>> ProvideMicrosoftAuthPasscode(
            int attempt,
            MfaMethod[] otherMethods,
            CancellationToken cancellationToken
        );
        Task<OneOf<Otp, MfaMethod, Canceled>> ProvideYubikeyPasscode(int attempt, MfaMethod[] otherMethods, CancellationToken cancellationToken);

        // OOB (out-of-band) methods
        // This method should return one of the following four options:
        //   1. new Otp(...): the user provided a valid passcode
        //   2. new WaitForOutOfBand(...): the user chose to perform an out-of-band action
        //   3. one of the MFA methods from `otherMethods`: the user chose a different MFA method
        //   4. new Canceled(...): the user canceled the operation
        Task<OneOf<Otp, WaitForOutOfBand, MfaMethod, Canceled>> ApproveLastPassAuth(
            int attempt, // TODO: Remove this parameter
            MfaMethod[] otherMethods,
            CancellationToken cancellationToken
        );

        // SSO
        // This method should be used to display an interactive browser session to allow the user to log into
        // the SSO provider. After a successful login the user should be redirected to a URL beginning with
        // `expectedRedirectUrl`.
        // This method should return one of the following two options:
        //   1. The complete URL the SSO login process was redirected to in the end (should start with `expectedRedirectUrl`)
        //   2. new Canceled(...): the user canceled the operation
        Task<OneOf<string, Canceled>> PerformSsoLogin(string url, string expectedRedirectUrl, CancellationToken cancellationToken);
    }

    public record Otp(string Passcode, bool RememberMe);

    public record WaitForOutOfBand(bool RememberMe);

    public record Canceled(string Reason);
}
