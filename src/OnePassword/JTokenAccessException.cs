// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace PasswordManagerAccess.OnePassword
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
