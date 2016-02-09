using System;

namespace Dashlane
{
    public class ParseException: BaseException
    {
        public enum FailureReason
        {
            IncorrectPassword,
        }

        public ParseException(FailureReason reason, string message): base(message)
        {
            Reason = reason;
        }

        public ParseException(FailureReason reason, string message, Exception innerException):
            base(message, innerException)
        {
            Reason = reason;
        }

        public FailureReason Reason { get; private set; }
    }
}
