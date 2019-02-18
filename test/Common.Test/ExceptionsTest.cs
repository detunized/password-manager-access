// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using Xunit;

namespace PasswordManagerAccess.Common.Test
{
    public class ExceptionsTest
    {
        [Fact]
        public void ClientException_properties_are_set()
        {
            var e = new ClientException(ClientException.FailureReason.UnknownError,
                                        Message,
                                        InnerException);
            VerifyException(e);
            Assert.Equal(ClientException.FailureReason.UnknownError, e.Reason);
        }

        //
        // Data
        //

        private const string Message = "message";
        private static readonly Exception InnerException = new Exception();

        private static void VerifyException(BaseException e)
        {
            Assert.Equal(Message, e.Message);
            Assert.Same(InnerException, e.InnerException);
        }
    }
}
