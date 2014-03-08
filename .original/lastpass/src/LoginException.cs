// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace LastPass
{
    public class LoginException: BaseException
    {
        public enum FailureReason
        {
            // LastPass returned errors
            LastPassInvalidUsername,
            LastPassInvalidPassword,
            LastPassIncorrectGoogleAuthenticatorCode,
            LastPassIncorrectYubikeyPassword,
            LastPassOutOfBandAuthenticationRequired,
            LastPassOutOfBandAuthenticationFailed,
            LastPassOther, // Message property contains the message given by the LastPass server
            LastPassUnknown,

            // Other
            UnknownResponseSchema,
            InvalidResponse,
            WebException
        }

        public LoginException(FailureReason reason, string message): base(message)
        {
            Reason = reason;
        }

        public LoginException(FailureReason reason, string message, Exception innerException):
            base(message, innerException)
        {
            Reason = reason;
        }

        public FailureReason Reason { get; private set; }
    }
}