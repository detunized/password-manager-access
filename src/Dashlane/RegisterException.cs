// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace Dashlane
{
    public class RegisterException: BaseException
    {
        public enum FailureReason
        {
            NetworkError,
            InvalidResponse,
        }

        public RegisterException(FailureReason reason, string message): base(message)
        {
            Reason = reason;
        }

        public RegisterException(FailureReason reason, string message, Exception innerException):
            base(message, innerException)
        {
            Reason = reason;
        }

        public FailureReason Reason { get; private set; }
    }
}
