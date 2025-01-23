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
        // Each of these methods could return one of the following three options:
        //   1. new Otp(...): the user provided a valid passcode
        //   2. one of the MFA methods from `otherMethods`: the user chose a different MFA method
        //   3. new Cancelled(...): the user cancelled the operation
        Task<OneOf<Otp, MfaMethod, Cancelled>> ProvideGoogleAuthPasscode(MfaMethod[] otherMethods, CancellationToken cancellationToken);
        Task<OneOf<Otp, MfaMethod, Cancelled>> ProvideMicrosoftAuthPasscode(MfaMethod[] otherMethods, CancellationToken cancellationToken);
        Task<OneOf<Otp, MfaMethod, Cancelled>> ProvideYubikeyPasscode(MfaMethod[] otherMethods, CancellationToken cancellationToken);

        // OOB (out-of-band) methods
        Task<OneOf<OobResult, MfaMethod, Cancelled>> ApproveLastPassAuth(MfaMethod[] otherMethods, CancellationToken cancellationToken);
        Task<OneOf<OobResult, MfaMethod, Cancelled>> ApproveDuo(MfaMethod[] otherMethods, CancellationToken cancellationToken);
        Task<OneOf<OobResult, MfaMethod, Cancelled>> ApproveSalesforceAuth(MfaMethod[] otherMethods, CancellationToken cancellationToken);
    }

    public record Otp(string Passcode, bool RememberMe);

    public record WaitForOutOfBand(bool RememberMe);

    public record Cancelled(string Reason);

    //
    // Legacy
    //

    public interface IUi : IDuoUi
    {
        // To cancel return OtpResult.Cancel, otherwise only valid data is expected.
        OtpResult ProvideGoogleAuthPasscode();
        OtpResult ProvideMicrosoftAuthPasscode();
        OtpResult ProvideYubikeyPasscode();

        // The UI implementations should provide the following possibilities for the user:
        //
        // 1. Cancel. Return OobResult.Cancel to cancel.
        //
        // 2. Go through with the out-of-band authentication where a third party app is used to approve or decline
        //    the action. In this case return OobResult.WaitForApproval(rememberMe). The UI should return as soon
        //    as possible to allow the library to continue polling the service. Even though it's possible to return
        //    control to the library only after the user performed the out-of-band action, it's not necessary. It
        //    could be also done sooner.
        //
        // 3. Allow the user to provide the passcode manually. All supported OOB methods allow to enter the
        //    passcode instead of performing an action in the app. In this case the UI should return
        //    OobResult.ContinueWithPasscode(passcode, rememberMe).
        OobResult ApproveLastPassAuth();
        OobResult ApproveDuo();
        OobResult ApproveSalesforceAuth();
    }

    public record OtpResult(string Passcode, bool RememberMe);

    public record OobResult(bool WaitForOutOfBand, string Passcode, bool RememberMe);
}
