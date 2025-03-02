// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Threading;
using System.Threading.Tasks;
using OneOf;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Duo;

// TODO: Remove this namespace
namespace PasswordManagerAccess.LastPass.Ui
{
    public interface IAsyncUi : IDuoAsyncUi
    {
        // OTP (one-time passcode) methods
        // Each of these methods should return one of the following three options:
        //   1. new Otp(...): the user provided a valid passcode
        //   2. one of the MFA methods from `otherMethods`: the user chose a different MFA method
        //   3. new Cancelled(...): the user cancelled the operation
        Task<OneOf<Otp, MfaMethod, Cancelled>> ProvideGoogleAuthPasscode(int attempt, MfaMethod[] otherMethods, CancellationToken cancellationToken);
        Task<OneOf<Otp, MfaMethod, Cancelled>> ProvideMicrosoftAuthPasscode(
            int attempt,
            MfaMethod[] otherMethods,
            CancellationToken cancellationToken
        );
        Task<OneOf<Otp, MfaMethod, Cancelled>> ProvideYubikeyPasscode(int attempt, MfaMethod[] otherMethods, CancellationToken cancellationToken);

        // OOB (out-of-band) methods
        // Each of these methods should return one of the following four options:
        //   1. new Otp(...): the user provided a valid passcode
        //   2. new WaitForOutOfBand(...): the user chose to perform an out-of-band action
        //   3. one of the MFA methods from `otherMethods`: the user chose a different MFA method
        //   4. new Cancelled(...): the user cancelled the operation
        Task<OneOf<Otp, WaitForOutOfBand, MfaMethod, Cancelled>> ApproveLastPassAuth(
            int attempt, // TODO: Remove this parameter
            MfaMethod[] otherMethods,
            CancellationToken cancellationToken
        );
    }

    public record Otp(string Passcode, bool RememberMe);

    public record WaitForOutOfBand(bool RememberMe);

    public record Cancelled(string Reason);
}
