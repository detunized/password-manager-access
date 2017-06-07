// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace OnePassword
{
    public class BaseException: Exception
    {
        public BaseException(string message): base(message)
        {
        }

        public BaseException(string message, Exception innerException):
            base(message, innerException)
        {
        }
    }
}
