// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Duo;

namespace PasswordManagerAccess.OnePassword.Ui;

// TODO: Switch to OneOf
public interface IAsyncUi : IDuoAsyncUi
{
    // Return Passcode.Cancel to cancel
    Task<Passcode> ProvideGoogleAuthPasscode(CancellationToken cancellationToken);

    // Only the `Passcode.RememberMe` is used. The `Passcode.Code` is ignored as it's requested later
    // with the system UI and there's no way around it.
    // Return Passcode.Cancel to cancel
    Task<Passcode> ProvideWebAuthnRememberMe(CancellationToken cancellationToken);

    // TODO: SSO
}
