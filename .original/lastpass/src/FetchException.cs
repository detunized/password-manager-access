// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace LastPass
{
    public class FetchException: BaseException
    {
        public enum FailureReason
        {
            InvalidResponse,
            WebException
        }

        public FetchException(FailureReason reason, string message): base(message)
        {
            Reason = reason;
        }

        public FetchException(FailureReason reason, string message, Exception innerException): base(message, innerException)
        {
            Reason = reason;
        }

        public FailureReason Reason { get; private set; }
    }
}