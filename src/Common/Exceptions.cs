// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace PasswordManagerAccess.Common
{
    // These are all the exceptions that are thrown by the library. Each class of error has its own
    // exception class. This way the error handling on the client is cleaner. Only the exceptions
    // the application could do something about have their own class. For example, when the
    // applications catches a BadCredentialsException it could present a user with a choice to
    // correct them and try again. All the other error are grouped under InternalErrorException
    // and should be simply logged by the application. The application cannot really do anything
    // when those kinds of errors occur. It usually means some logical error or we ran into some
    // unknown data format or something changed on the server. Either way, it would require some
    // additional investigation. The only exception is the UnsupportedFeatureException. It's kind
    // an internal error as well, but it has a clear purpose: to gather information about what
    // features are needed and should be added in the future.

    // Don't want to be warned about missing constructors. We're not using them.
#pragma warning disable RCS1194

    public abstract class BaseException : Exception
    {
        protected BaseException(string message, Exception inner)
            : base(message, inner) { }
    }

    // Bad credentials supplied by the user: email, username, password, etc.
    public class BadCredentialsException : BaseException
    {
        public BadCredentialsException(string message, Exception inner = null)
            : base(message, inner) { }
    }

    // Bad 2FA/MFA code or whatever else is used in that particular 2FA/MFA method.
    public class BadMultiFactorException : BaseException
    {
        public BadMultiFactorException(string message, Exception inner = null)
            : base(message, inner) { }
    }

    // The user canceled the 2FA/MFA sequence. This is more of a control flow exception, a deep return.
    public class CanceledMultiFactorException : BaseException
    {
        public CanceledMultiFactorException(string message, Exception inner = null)
            : base(message, inner) { }
    }

    // Something went wrong with the network. Not an unexpected response, but rather a connectivity issue.
    public class NetworkErrorException : BaseException
    {
        public NetworkErrorException(string message, Exception inner = null)
            : base(message, inner) { }
    }

    // Thrown when we know of a feature and it's known not to be supported. The opposite would be
    // an unsupported feature that is not known to us and then it would most likely end up being
    // thrown as an InternalErrorException.
    public class UnsupportedFeatureException : BaseException
    {
        public UnsupportedFeatureException(string message, Exception inner = null)
            : base(message, inner) { }
    }

    // Pretty much all the other errors. There's nothing the application can do about those and thus
    // there's no need for any structured information like a failure reason or any additional info or
    // whatever.
    public class InternalErrorException : BaseException
    {
        public InternalErrorException(string message, Exception inner = null)
            : base(message, inner) { }
    }

    //
    // Internal exceptions
    //

    // This is thrown by internal crypto code and should not leak outside. At least that the idea.
    // TODO: Evaluate if it's a good idea. Maybe we should just throw the internal error here.
    //       It's tedious to catch and rethrow all over the place.
    internal class CryptoException : BaseException
    {
        public CryptoException(string message, Exception inner = null)
            : base(message, inner) { }
    }
}
