using System;

namespace LastPass
{
    public class LoginException: Exception
    {
        public enum FailureReason
        {
            // LastPass returned errors
            LastPassInvalidUsername,
            LastPassInvalidPassword,
            LastPassOther,
            LastPassUnknown,

            // Other
            InvalidResponse,
            WebException
        }

        public LoginException(FailureReason reason, string message): base(message)
        {
            Reason = reason;
        }

        public LoginException(FailureReason reason, string message, Exception innerException): base(message, innerException)
        {
            Reason = reason;
        }

        public FailureReason Reason { get; private set; }
    }
}