using System;

namespace LastPass
{
    public class LoginException: Exception
    {
        public LoginException(string message): base(message)
        {
        }
    }
}