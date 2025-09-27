// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

namespace PasswordManagerAccess.Dashlane;

// This signer is used to sign all requests before the device is registered.
internal class Dl1AppRequestSigner : Dl1BaseRequestSigner
{
    //
    // Protected
    //

    protected override string GetSigningKey() => AppAccessSecret;

    protected override string GetAuthIdentity() => $"AppAccessKey={AppAccessKey}";
}
