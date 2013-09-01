using System;

namespace LastPass
{
    public class FetchException: Exception
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