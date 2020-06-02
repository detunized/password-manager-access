// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace PasswordManagerAccess.OpVault
{
    public class JTokenAccessException: BaseException
    {
        public JTokenAccessException(string message): base(message)
        {
        }

        public JTokenAccessException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}
