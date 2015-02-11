// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace PasswordBox
{
    public class LoginException: BaseException
    {
        public enum FailureReason
        {
            InvalidCredentials,
            InvalidResponse,
            Other, // Message property contains the message given by the LastPass server
            Unknown,
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
