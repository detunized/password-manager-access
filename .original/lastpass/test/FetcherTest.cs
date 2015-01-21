// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using Moq.Language;
using Moq.Language.Flow;
using NUnit.Framework;

namespace LastPass.Test
{
    [TestFixture]
    partial class FetcherTest
    {
        //
        // Data shared between Login and Fetcher tests
        //

        private const int IterationCount = 5000;
        private const string SessionId = "53ru,Hb713QnEVM5zWZ16jMvxS0";

        private const string WebExceptionMessage = "WebException occured";

        class ResponseOrException
        {
            public ResponseOrException(string response)
            {
                _response = response.ToBytes();
            }

            public ResponseOrException(Exception exception)
            {
                _exception = exception;
            }

            public void ReturnOrThrow(ISetup<IWebClient, byte[]> setup)
            {
                if (_exception != null)
                    setup.Throws(_exception);
                else
                    setup.Returns(_response);
            }

            public void ReturnOrThrow(ISetupSequentialResult<byte[]> setup)
            {
                if (_exception != null)
                    setup.Throws(_exception);
                else
                    setup.Returns(_response);
            }

            private readonly byte[] _response;
            private readonly Exception _exception;
        }
    }
}
