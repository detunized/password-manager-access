// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Duo;

namespace PasswordManagerAccess.LastPass.Ui
{
    public interface IAsyncUi
    {
        Task<OtpResult> ProvideGoogleAuthPasscode(CancellationToken cancellationToken);
        Task<OtpResult> ProvideMicrosoftAuthPasscode(CancellationToken cancellationToken);
        Task<OtpResult> ProvideYubikeyPasscode(CancellationToken cancellationToken);

        Task<OobResult> ApproveLastPassAuth(CancellationToken cancellationToken);
        Task<OobResult> ApproveDuo(CancellationToken cancellationToken);
        Task<OobResult> ApproveSalesforceAuth(CancellationToken cancellationToken);
    }

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

    public class OtpResult
    {
        // Return this to signal the cancellation of the operation
        public static readonly OtpResult Cancel = new OtpResult("cancel", false);

        public readonly string Passcode;
        public readonly bool RememberMe;

        public OtpResult(string passcode, bool rememberMe)
        {
            Passcode = passcode;
            RememberMe = rememberMe;
        }
    }

    public class OobResult
    {
        // Return this to signal the cancellation of the operation
        public static readonly OobResult Cancel = new OobResult(false, "cancel", false);

        public readonly bool WaitForOutOfBand;
        public readonly string Passcode;
        public readonly bool RememberMe;

        public static OobResult WaitForApproval(bool rememberMe)
        {
            return new OobResult(true, "", rememberMe);
        }

        public static OobResult ContinueWithPasscode(string passcode, bool rememberMe)
        {
            return new OobResult(false, passcode, rememberMe);
        }

        private OobResult(bool waitForOutOfBand, string passcode, bool rememberMe)
        {
            WaitForOutOfBand = waitForOutOfBand;
            Passcode = passcode;
            RememberMe = rememberMe;
        }
    }
}
