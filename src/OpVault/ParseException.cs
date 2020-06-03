// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace PasswordManagerAccess.OpVault
{
    public class ParseException: BaseException
    {
        public enum FailureReason
        {
            FileNotFound
        }

        public ParseException(FailureReason reason, string message):
            this(reason, message, null)
        {
        }

        public ParseException(FailureReason reason, string message, Exception innerException):
            base(message, innerException)
        {
            Reason = reason;
        }

        public FailureReason Reason { get; private set; }
    }
}
