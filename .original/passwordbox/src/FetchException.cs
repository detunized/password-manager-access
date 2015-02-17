// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace PasswordBox
{
    public class FetchException: FetcherException
    {
        public enum FailureReason
        {
            Network,
            InvalidResponse,
            LegacyUser,
            Unknown,
        }

        public FetchException(FailureReason reason, string message): base(message)
        {
            Reason = reason;
        }

        public FetchException(FailureReason reason, string message, Exception innerException):
            base(message, innerException)
        {
            Reason = reason;
        }

        public FailureReason Reason { get; private set; }
    }
}
