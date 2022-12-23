// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using PasswordManagerAccess.Common;
using R = PasswordManagerAccess.OnePassword.Response;
using U2fWin10;

namespace PasswordManagerAccess.OnePassword
{
    // This part only compiles under .NET Framework
    public static partial class Client
    {
        internal static SecondFactorResult AuthenticateWithWebAuthn(SecondFactor factor, ClientInfo clientInfo)
        {
            // TODO: Support RemeberMe! Need to request this from the UI!

            if (!(factor.Parameters is R.WebAuthnMfa extra))
                throw new InternalErrorException("WebAuthn extra parameters expected");

            if (extra.KeyHandles.Length > 1)
                throw new UnsupportedFeatureException("Multiple WebAuthn keys are not supported");

            try
            {
                var assertion = WebAuthN.GetAssertion(appId: "1password.com",
                                                      challenge: extra.Challenge,
                                                      origin: $"https://{clientInfo.Domain}",
                                                      crossOrigin: false,
                                                      keyHandle: extra.KeyHandles[0]);

                return SecondFactorResult.Done(new Dictionary<string, string>
                                               {
                                                   ["keyHandle"] = assertion.KeyHandle,
                                                   ["signature"] = assertion.Signature,
                                                   ["authData"] = assertion.AuthData,
                                                   ["clientData"] = assertion.ClientData,
                                               },
                                               false);
            }
            catch (CanceledException)
            {
                return SecondFactorResult.Cancel();
            }
            catch (ErrorException e)
            {
                throw new InternalErrorException("WebAuthn authentication failed", e);
            }
        }

        private static readonly SecondFactorKind[] SecondFactorPriority =
        {
            SecondFactorKind.WebAuthn,
            SecondFactorKind.Duo,
            SecondFactorKind.GoogleAuthenticator,
        };
    }
}
