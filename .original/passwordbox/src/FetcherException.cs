// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace PasswordBox
{
    public class FetcherException: Exception
    {
        public FetcherException(string message): base(message)
        {
        }

        public FetcherException(string message, Exception innerException):
            base(message, innerException)
        {
        }
    }
}
