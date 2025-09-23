// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

namespace PasswordManagerAccess.Dashlane;

// This signer is used to sign all requests after the device is registered.
internal class Dl1DeviceRequestSigner : Dl1BaseRequestSigner
{
    public required string Username { get; init; }
    public required string DeviceAccessKey { get; init; }
    public required string DeviceSecretKey { get; init; }

    //
    // Protected
    //

    protected override string GetSigningKey() => $"{AppAccessSecret}\n{DeviceSecretKey}";

    protected override string GetAuthIdentity() => $"Login={Username},AppAccessKey={AppAccessKey},DeviceAccessKey={DeviceAccessKey}";
}
