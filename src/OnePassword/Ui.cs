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

        // Begin SSO device enrollment
        // This method should show the enrollment UI and return a context object for managing the enrollment lifecycle.
        // The context provides bidirectional communication between the library and UI.
        // The context's EndEnrollment method will be called when enrollment completes (success or failure).
        Task<ISsoEnrollmentContext> BeginSsoEnrollment(CancellationToken cancellationToken);

        // DEPRECATED: Device enrollment verification code
        // This method is still supported but will eventually be replaced by ISsoEnrollmentContext.ProvideVerificationCode
        // When enrolling a new device for SSO, the user needs to enter a verification code that is displayed
        // on an already enrolled device. This method prompts the user for that code.
        // Returns the verification code, or an empty string if canceled.
        Task<string> ProvideDeviceEnrollmentVerificationCode(CancellationToken cancellationToken);
    }

    public record Otp(string Passcode, bool RememberMe);

    public record RememberMe(bool Value);

    public record Canceled(string Reason);

    //
    // SSO Enrollment Context
    //

    // Context for managing SSO device enrollment UI lifecycle
    // This interface provides bidirectional communication between the library and UI:
    // - Library can send status updates via UpdateStatus
    // - UI can signal cancellation via IsCancellationRequested
    // - Both can participate in the enrollment flow via ProvideVerificationCode
    public interface ISsoEnrollmentContext
    {
        // Status updates from library to UI
        // Called at various stages during enrollment to update the UI with progress
        Task UpdateStatus(EnrollmentStatus status, string message, CancellationToken cancellationToken);

        // Get verification code from user
        // Returns either the code entered by the user, or EnrollmentCanceled if canceled
        Task<OneOf<string, EnrollmentCanceled>> ProvideVerificationCode(CancellationToken cancellationToken);

        // Check if user has requested cancellation
        // The library should periodically check this during long-running operations
        bool IsCancellationRequested { get; }

        // Cleanup and close the enrollment UI
        // Guaranteed to be called regardless of success/failure
        Task EndEnrollment(bool success, CancellationToken cancellationToken);
    }

    // Enrollment status stages
    public enum EnrollmentStatus
    {
        WaitingForApproval, // Waiting for user on enrolled device to approve
        VerificationCodeNeeded, // About to request verification code from user
        ExchangingCredentials, // Performing CPACE credential exchange
        Completing, // Final enrollment steps
    }

    // Returned when enrollment is canceled
    public record EnrollmentCanceled(string Reason);
}
