// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using Xunit;

namespace PasswordManagerAccess.Common
{
    internal static class Exceptions
    {
        public static InternalErrorException AssertThrowsInternalError(Action action, string message = "")
        {
            var e = Assert.Throws<InternalErrorException>(action);
            Assert.NotNull(e.Message);
            Assert.Contains(message, e.Message);

            return e;
        }
    }
}
