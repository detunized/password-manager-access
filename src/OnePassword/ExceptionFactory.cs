// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace OnePassword
{
    // This class is here to untie various subsystems from explicitly throwing ClientException.
    // We want to throw ClientException for everything to make the user's life easier but it's
    // not right to let Crypto or Srp throw ClientException directly.
    //
    // This is a poor man's factory. No fancy virtual methods or interfaces.
    // It's here just to move the code to some other place.
    internal static class ExceptionFactory
    {
        public static BaseException MakeUnsupported(string message, Exception innerException = null)
        {
            return new ClientException(ClientException.FailureReason.UnsupportedFeature,
                                       message,
                                       innerException);
        }

        public static BaseException MakeInvalidOperation(string message,
                                                         Exception innerException = null)
        {
            return new ClientException(ClientException.FailureReason.InvalidOperation,
                                       message,
                                       innerException);
        }
    }
}
