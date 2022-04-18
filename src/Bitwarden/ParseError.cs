// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.Bitwarden
{
    public class ParseError
    {
        public readonly string Description;
        public readonly string Message;
        public readonly string CallStack;

        public ParseError(string description, string message, string callStack)
        {
            Description = description;
            Message = message;
            CallStack = callStack;
        }
    }
}
