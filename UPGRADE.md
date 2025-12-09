# Upgrade notes

## To 30.0.0

`ClientInfoCliApi` has been renamed to `ClientInfoApi` for clarity. This is an API mode and has
nothing to do with CLI. And its constructor with positional parameters has been removed in favor of
required init-only properties. This makes it harder to pass wrong values.

```cs
public record ClientInfoApi
{
    public required string ClientId { get; init; }
    public required string ClientSecret { get; init; }
    public required string Password { get; init; }
    public required string DeviceId { get; init; }
}
```

All the "browser mode" methods have been removed along with the storage and the UI.

The one shot `Open` method is now async and takes a cancellation token.

```cs
public static class Client
{
    public static async Task<Vault> Open(
        ClientInfoApi clientInfo,
        string baseUrl,
        CancellationToken cancellationToken
    );
}
```

The `LogIn`, `Download` , `GetItem` and `LogOut` methods are now async as well.

```cs
public static class Client
{
    public static async Task<Session> LogIn(
        ClientInfoApi clientInfo,
        string baseUrl,
        CancellationToken cancellationToken
    );

    public static async Task<Vault> DownloadVault(
        Session session,
        CancellationToken cancellationToken
    );

    public static Task LogOut(
        Session session,
        CancellationToken cancellationToken
    );

    public static async Task<OneOf<Account, SshKey, NoItem>> GetItem(
        string itemId,
        Session session,
        CancellationToken cancellationToken
    );
}
```

The SSO API adds a new `LogIn` method along with some additional data structures.

```cs
public static class Client
{
    public static async Task<Session> LogInSso(
        ClientInfoSso clientInfo,
        string baseUrl,
        IAsyncUi ui,
        CancellationToken cancellationToken
    );
}
```

`ClientInfoSso` must be passed in to be able to log in. `Password` is the master password and it's
needed to decrypt the vault later. `DeviceId` is the same as in the `ClientInfoApi` data structure.
`Organization` is the organization ID that the user enters while performing an SSO login. It's
optional and if not provided the web UI is going to ask for it. So to provide it or not depends on
your preferred UI implementation.

```cs
public record ClientInfoSso
{
    public required string Password { get; init; }
    public required string DeviceId { get; init; }
    public required string Organization { get; init; } = "";
}
```

`IAsyncUi` completely replaces the old browser mode UI and now is only used during the SSO login
flow. Look at the comments in the code that explain how to use this properly. Also,
`example/Bitwarden/Program.cs` has an example implementation with comments with extra useful tips.

```cs
public interface IAsyncUi
{
    // Should open a browser window and navigate to the specified URL to allow the user to log in. There's no need to monitor
    // the redirects or anything like that. The library receives the redirect internally. Bitwarden allows redirects to localhost.
    //
    // The application could do the following things:
    //
    // 1. Return immediately and wait for CloseBrowser to be called later. CloseBrowser is guaranteed to be called whether
    //    the login is completed or failed. It's easier to implement, but in this case there's no way to signal the cancellation
    //    if the user closes the browser.
    //
    // 2. Do not return from this method to allow the user to interact with the browser for as long as needed. In this case it's
    //    possible to signal the cancellation by returning Canceled when the user closes the browser or navigates away, for example.
    //    The library will trigger the cancellationToken to make the application aware that it's time to return from this method.
    //    CloseBrowser will be called afterwards regardless of success or failure. This is a bit harder to implement, but
    //    allows for more flexible UX.
    //
    // 3. Return Cancel at any point to cancel the operation.
    Task<Canceled?> PerformSsoLogin(string url, CancellationToken cancellationToken);

    // Should close the browser opened by OpenInBrowser. Always called after, regardless of success or failure.
    Task CloseBrowser(bool success, CancellationToken cancellationToken);
}
```

## To 29.0.0

This version introduces a lot of API changes. They are quite similar to the changes with the other
modules that were migrated to async (see LastPass).

The main non-SSO entry points have changed to the following:

```cs
public static class Client
{
    public static async Task<Session> LogIn(
        Credentials credentials,
        AppInfo app,
        IAsyncUi ui,
        IAsyncSecureStorage storage,
        CancellationToken cancellationToken
    );

    public static async Task<Session> LogIn(
        ServiceAccount serviceAccount,
        AppInfo app,
        CancellationToken cancellationToken
    );

    public static async Task LogOut(
        Session session,
        CancellationToken cancellationToken
    );

    public static async Task<VaultInfo[]> ListAllVaults(
        Session session,
        CancellationToken cancellationToken
    );

    public static async Task<Vault> OpenVault(
        VaultInfo info,
        Session session,
        CancellationToken cancellationToken
    );

    public static async Task<OneOf<Account, SshKey, NoItem>> GetItem(
        string itemId,
        string vaultId,
        Session session,
        CancellationToken cancellationToken
    );
}
```

Changes to all the methods are pretty straightforward, except the first `LogIn`. The UI has changed into:

```cs
public interface IAsyncUi : IDuoAsyncUi
{
    Task<OneOf<Otp, MfaMethod, Canceled>> ProvideGoogleAuthPasscode(
        int attempt,
        MfaMethod[] otherMethods,
        CancellationToken cancellationToken
    );

    Task<OneOf<RememberMe, MfaMethod, Canceled>> ProvideWebAuthnRememberMe(
        int attempt,
        MfaMethod[] otherMethods,
        CancellationToken cancellationToken
    );

    // SSO
    Task<OneOf<string, Canceled>> PerformSsoLogin(string ssoLoginUrl, string redirectTo, CancellationToken cancellationToken);
    Task<ISsoEnrollmentContext> BeginSsoEnrollment(CancellationToken cancellationToken);
}
```

`ProvideGoogleAuthPasscode` and `ProvideWebAuthnRememberMe` now are both async and return `OneOf` of
different options. They are used to return a result, select a different MFA method or signal a
cancellation. See LastPass for more details. The changes are very similar. Make sure to not return
any MFA methods that are not passed in the `otherMethods` parameter. The UI implementation should
also respect the `cancellationToken` and allow the top-level to cancel the whole operation if
needed.

The next big features is the SSO support. This is a big and complex beast. It has a couple of top
level APIs of its own:

```cs
public static partial class Client
{
    public static async Task<bool> IsSsoAccount(
        string username,
        CancellationToken cancellationToken
    );

    public static async Task<Session> SsoLogIn(
        Credentials credentials,
        AppInfo app,
        IAsyncUi ui,
        IAsyncSecureStorage storage,
        CancellationToken cancellationToken
    );

```

`IsSsoAccount` could be used to check if the account supports SSO login type. This could be done
from the UI before showing the user input dialog, for example. Since there's no need to enter the
password for SSO.

`SsoLogIn` could be called directly by the application to initiate an SSO login. But that's not
necessary, as `LogIn` will check if it's an SSO account and will call it for you. It's up to the
implementation which way to go about this.

The biggest change comes with the `IAsyncUi`:

```cs
Task<OneOf<string, Canceled>> PerformSsoLogin(string ssoLoginUrl, string redirectTo, CancellationToken cancellationToken);
```

`PerformSsoLogin` must present an interactive browser and allow the user to log into their SSO
provider. The application should monitor the browser redirect URLs and stop at the URL that start
with the value of `redirectTo`. Please refer to the LastPass upgrade notes for more details. It's
the same.

```cs
Task<ISsoEnrollmentContext> BeginSsoEnrollment(CancellationToken cancellationToken);
```

`BeginSsoEnrollment` is called for new devices and it must present a user with a special UI to enter
the code. When `BeginSsoEnrollment` is called the sequence starts. It might get cancelled or failed
at any time. `BeginSsoEnrollment` returns a context object that must implement the
`ISsoEnrollmentContext` interface.

```cs
public interface ISsoEnrollmentContext
{
    CancellationToken Token { get; }
    Task UpdateStatus(EnrollmentStatus status, string message, CancellationToken cancellationToken);
    Task<OneOf<string, EnrollmentCanceled>> ProvideVerificationCode(CancellationToken cancellationToken);
    Task EndEnrollment(SsoEnrollmentResult result, CancellationToken cancellationToken);
}
```

This object allows a two-way communication between the library and the application. `Token` must be
provided by the application to allow the cancellation from the application side. It is monitored by
the library.

`UpdateStatus` is used to send updated to the application in case it wants to display info to the
user on how things are progressing.

At some point in the process of the new device enrollment, the library would request the application
to provide a verification code that the user must enter in the UI. It should be returned from
`ProvideVerificationCode`.

`EndEnrollment` is guaranteed to be called regardless of the outcome of the enrollment, would it be
failure, cancellation or success.

## To 28.0.0

`Ui.OpenInBrowser` must be implemeneted to allow the user to open a URL in a browser to trigger the
email token to be sent. The easiest way is to offer the user to open the URL in their own browser.
There's no state or cookies to manage, no logging in is required. In fact, the user's browser is much
better for this than an embedded one, as Cloudflare is more likely to ignore the captcha and just send
the code without any interaction. Return `true` from this method to continue the login process and
`false` to cancel the login process.

## To 27.0.0

Delete all references to `Bitwarden.VaultItem.DeletedDate` as it's no longer available.

## To 26.1.0

The `baseUrl` parameter in all the relevant `Client.*` methods is no longer optional and must be
provided. Some overloads don't have it and are defaulted to the `Client.DefaultBaseUlr` which is set
to https://vault.bitwarden.com. All the overloads with the `baseUrl` parameter must receive either a
valid URL to a self-hosted instance or either `Client.BaseUrlUs` or `Client.BaseUrlEu` for the US and
EU cloud instances respectively.

## To 26.0.0

Remove DropboxPasswords and Kaspersky from the application.

## To 25.0.0

Similar to v24.0.0. This release introduces an incompatible API change for ProtonPass: the previous
single-call `Vault.OpenAll` method has been split into three separate methods to allow multiple
downloads per login. Instead of calling `Vault.OpenAll` which was removed, you should now use
`Client.LogIn` to authenticate and obtain a session object, `Client.ListAllVaults` to fetch all the
vaults, and `Client.LogOut` to clean up resources when finished. This change allows for more flexible
session management and better error handling throughout the authentication and vault retrieval
process.

Additionally, two new methods have been introduced to provide more granular control over vault access:
`Client.ListAllVaults` which returns metadata about all available vaults without downloading their
contents, and `Client.DownloadVault` which comes in two variants - one accepting a `VaultInfo` object
returned by `Client.ListAllVaults`, and another accepting a vault ID string. These methods allow you
to selectively download individual vaults rather than fetching all vaults at once, which can be more
efficient when you only need access to specific vaults. Both variants of `Client.DownloadVault` can be
called multiple times with an existing session until the session expires.

`Client.DownloadVault` with the string ID returns a `OneOf<Vault, NoVault>` object and returns
`NoVault` in case of an invalid vault ID. The `VaultInfo` variant throws an exception in case of
an invalid vault info.

Additionally, a new method `Client.GetItem` has been introduced, allowing you to fetch a single item
from one of the vaults by providing two IDs using an existing session. This is useful for scenarios
where you only need access to a specific item without downloading the entire vault. `Client.GetItem`
can be called multiple times until the session expired. The session refresh functionality will be
introduced in further releases.

`Client.GetItem` returns a `OneOf<Account, NoItem, NoVault>` object. See `Program.cs` for the
demonstration of all the variants in action.

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
