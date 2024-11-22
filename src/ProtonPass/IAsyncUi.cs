// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable
using System.Threading;
using System.Threading.Tasks;

namespace PasswordManagerAccess.ProtonPass
{
    public interface IAsyncUi
    {
        public record CaptchaResult(bool Solved, string Token)
        {
            // Return this to signal the cancellation of the operation
            public static readonly CaptchaResult Cancel = new CaptchaResult(false, "");
        }

        // We don't have remember-me for ProtonPass like in other modules
        // TODO: Figure out how it's implemented if at all
        public record PasscodeResult(string Passcode)
        {
            // Return this to signal the cancellation of the operation
            public static readonly PasscodeResult Cancel = new PasscodeResult("cancel");
        }

        // Return CaptchaResult.Cancel to cancel
        Task<CaptchaResult> SolveCaptcha(string url, string humanVerificationToken, CancellationToken cancellationToken);

        // Return OtpResult.Cancel to cancel
        Task<PasscodeResult> ProvideExtraPassword(int attempt, CancellationToken cancellationToken);

        // Return OtpResult.Cancel to cancel
        Task<PasscodeResult> ProvideGoogleAuthPasscode(CancellationToken cancellationToken);
    }
}
