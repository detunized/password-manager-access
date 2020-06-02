// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace PasswordManagerAccess.OpVault
{
    public abstract class BaseException: Exception
    {
        protected BaseException(string message): base(message)
        {
        }

        protected BaseException(string message, Exception innerException):
            base(message, innerException)
        {
        }
    }
}
