# Upgrade notes

## To 24.0.0

Similar to v23.0.0. This release introduces an incompatible API change for ZohoVault: the previous
single-call `Vault.Open` method has been split into three separate methods to allow multiple
downloads per login. Instead of calling `Vault.Open` which was removed, you should now use
`Client.LogIn` to authenticate and obtain a session object, `Client.DownloadVault` to fetch the
vault data, and `Client.LogOut` to clean up resources when finished. This change allows for more
flexible session management and better error handling throughout the authentication and vault
retrieval process.

`Client.LogOut` is optional. To keep the session open, don't preform the logout action and only
dispose of the `Session` object returned by the `Client.LogIn` by calling `Session.Dispose`. See
`Program.cs` for an example.

Additionally, a new method `Client.GetItem` has been introduced, allowing you to fetch a single item
from the vault by its ID using an existing session. This is useful for scenarios where you only need
access to a specific item without downloading the entire vault. `Client.GetItem` can be called
multiple times until the session expired. The session refresh functionality will be introduced in
further releases.


If you prefer the previous single-call approach, an easy replacement is provided: `Client.Open`.
This method wraps the new sequence (`LogIn`, `DownloadVault`, and `LogOut`) into a single call,
closely matching the old `Vault.Open` behavior for convenience. The `Vault` is a simple POD type now
with no further functionality. Please note that this method unlike `Bitwarden.Client.Open` takes a
`Settings` object which could be used to suppress log out. In case when `Setting.KeepSession` is set
to `true` the session cookies are not erased and the follow-up logins are reusing the session if it
hasn't expired.



## To 23.0.0

This release introduces an incompatible API change for Bitwarden: the previous single-call
`Vault.Open` method has been split into three separate methods to allow multiple downloads per
login. Instead of calling `Vault.Open` which was removed, you should now use `Client.LogIn` to
authenticate and obtain a session object, `Client.DownloadVault` to fetch the vault data, and
`Client.LogOut` to clean up resources when finished. This change allows for more flexible session
management and better error handling throughout the authentication and vault retrieval process.

If you prefer the previous single-call approach, an easy replacement is provided: `Client.Open`.
This method wraps the new sequence (`LogIn`, `DownloadVault`, and `LogOut`) into a single call,
closely matching the old `Vault.Open` behavior for convenience. The `Vault` is a simple POD type now
with no further functionality.

Additionally, a new method `Client.GetItem` has been introduced, allowing you to fetch a single item
from the vault by its ID using an existing session. This is useful for scenarios where you only need
access to a specific item without downloading the entire vault. `Client.GetItem` can be called
multiple times until the session expired. The session refresh functionality will be introduced in
further releases.

One side note: that `Client.GetItem` does not provide any organizations or collections as they are
not part of the item data blob.

As with one password, GetItem returns a `OneOf` object. Please refer to the `Bitwarden/Program.cs`
for a working example.

## To 22.0.2

This release introduces a lot of incompatible API changes, mainly related to the async refactoring
of the LastPass module.

The entry point changed to:

```cs
public class Vault
{
    public static Task<Vault> Open(
        string username,
        string password,
        ClientInfo clientInfo,
        IAsyncUi ui,
        ParserOptions options,
        ISecureLogger? logger,
        CancellationToken cancellationToken
    );

    public static Task<bool> IsSsoAccount(string username, CancellationToken cancellationToken);
}
```

The `Open` method is now async and now accepts the modified `ui` parameter of type `IAsyncUi` and
the cancellation token. This token can be used to cancel the login operation. Refer to the Avalonio
GUI example to see how to implement that.

### IAsyncUi

The UI looks the following now:

```cs
public interface IAsyncUi : IDuoAsyncUi
{
    // OTP
    Task<OneOf<Otp, MfaMethod, Canceled>> ProvideGoogleAuthPasscode(int attempt, MfaMethod[] otherMethods, CancellationToken cancellationToken);
    Task<OneOf<Otp, MfaMethod, Canceled>> ProvideMicrosoftAuthPasscode(int attempt, MfaMethod[] otherMethods, CancellationToken cancellationToken);
    Task<OneOf<Otp, MfaMethod, Canceled>> ProvideYubikeyPasscode(int attempt, MfaMethod[] otherMethods, CancellationToken cancellationToken);

    // OOB
    Task<OneOf<Otp, WaitForOutOfBand, MfaMethod, Canceled>> ApproveLastPassAuth(int attempt, MfaMethod[] otherMethods, CancellationToken cancellationToken);

    // SSO
    Task<OneOf<string, Canceled>> PerformSsoLogin(string url, string expectedRedirectUrl, CancellationToken cancellationToken);
}
```

All the methods are now async. Both OTP and OOB methods now accept the `otherMethods` parameters
which could be used to select a different MFA method. OTP method also accepts the `attempt`
parameter which is the attempt number. It goes from 0 to 2. Even though the OOB method also accept
the `attempt` parameter, it's always 0 as the LastPass server doesn't support OOB login failures.

For the OTP methods the return values is a one of the following:

- `Otp`: to provide a passcode
- `MfaMethod`: return one of the other methods to select a different MFA method. Only the methods
  from the `otherMethods` array are allowed. Might be empty.
- `Canceled`: to cancel the operation

For the OOB method the return values is a one of the following:

- `Otp`: the user provided a valid passcode
- `WaitForOutOfBand`: the user chose to perform an out-of-band action. The library will keep waiting
  and polling the server for the result.
- `MfaMethod`: return one of the other methods to select a different MFA method. Only the methods
  from the `otherMethods` array are allowed. Might be empty.
- `Canceled`: to cancel the operation

Any of the methods above should try not to block and use the async/await pattern inside to allow the
library to work in the background. These methods should also support the cancellation from the top
level cancellation token which is passed down from the `Open` method. Please refer to the Avalonia
GUI example for more details.

### IDuoAsyncUi

```cs
public interface IDuoAsyncUi
{
    Task<OneOf<DuoChoice, MfaMethod, DuoCancelled>> ChooseDuoFactor(DuoDevice[] devices, MfaMethod[] otherMethods, CancellationToken cancellationToken);
    Task<OneOf<DuoPasscode, DuoCancelled>> ProvideDuoPasscode(DuoDevice device, CancellationToken cancellationToken);
    Task DuoDone(CancellationToken cancellationToken);
    Task UpdateDuoStatus(DuoStatus status, string text, CancellationToken cancellationToken);
}
```

The Duo interface is async now as well. It also supports the `otherMethods` parameter and the
cancellation token.

One notable difference from the previous version is that now there is a `DuoDone` method which could
be used to shut down the Duo UI if necessary. It's guaranteed to be called after all of the UI tasks
are done regardless of the outcome.

### SSO

The SSO integration is now done via the `PerformSsoLogin` method. It's guaranteed to be called only
once and only in case the account is an SSO account which is determined during the login process.
The SSO account do not require a password. The `password` parameter might be left blank. The library
provides a helper method to check whether the username belongs to an SSO account or not (see
`Vault.IsSsoAccount`).

The perform SSO login method should bring up a browser session and allow the user to log into their
identity provider. After a successful login the user should be redirected to a URL beginning with
`expectedRedirectUrl`. The browser implementation should capture that URL and return it back to the
library. In case the user fails or closes the browser, the method should return `Canceled` object.
To allow the subsequent passwordless logins, the application should implement an ability to store
the browser state and restore it in the subsequent logins. Please refer to the Avalonia example for
more details.

For the SSO method the return values is a one of the following:

- `string`: the complete URL the SSO login process was redirected to in the end (should start with
  `expectedRedirectUrl`)
- `Canceled`: to cancel the operation
