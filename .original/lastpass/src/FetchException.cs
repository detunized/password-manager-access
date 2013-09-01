using System;

namespace LastPass
{
    public class FetchException: Exception
    {
        public FetchException(string message): base(message)
        {
        }

        public FetchException(string message, Exception innerException): base(message, innerException)
        {
        }
    }
}