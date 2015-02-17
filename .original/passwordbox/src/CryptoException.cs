// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace PasswordBox
{
    public class CryptoException: Exception
    {
        public CryptoException(string message): base(message)
        {
        }

        public CryptoException(string message, Exception innerException):
            base(message, innerException)
        {
        }
    }
}
