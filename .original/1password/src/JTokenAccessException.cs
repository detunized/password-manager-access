// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace OnePassword
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
