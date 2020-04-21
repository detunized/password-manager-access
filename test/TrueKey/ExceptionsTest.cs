// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.TrueKey;
using Xunit;

namespace PasswordManagerAccess.Test.TrueKey
{
    public class ExceptionsTest
    {
        [Fact]
        public void BaseException_properties_are_set()
        {
            VerifyException(new BaseException(Message, InnerException));
        }

        //
        // Data
        //

        private const string Message = "message";
        private static readonly Exception InnerException = new Exception();

        //
        // Helpers
        //

        private static void VerifyException(BaseException e)
        {
            Assert.Equal(Message, e.Message);
            Assert.Same(InnerException, e.InnerException);
        }
    }
}
