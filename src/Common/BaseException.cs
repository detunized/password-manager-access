// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace PasswordManagerAccess.Common
{
    public class BaseException: Exception
    {
        protected BaseException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
