// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.OnePassword
{
    // This part only compiles under .NET Core
    public static partial class Client
    {
        internal static SecondFactorResult AuthenticateWithWebAuthn(SecondFactor factor, ClientInfo clientInfo)
        {
            throw new UnsupportedFeatureException("WebAuthn is not supported on this platform");
        }

        private static readonly SecondFactorKind[] SecondFactorPriority =
        {
            SecondFactorKind.Duo,
            SecondFactorKind.GoogleAuthenticator,
        };
    }
}
