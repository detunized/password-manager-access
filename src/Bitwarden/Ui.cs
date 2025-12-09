// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable
using System.Threading;
using System.Threading.Tasks;

// ReSharper disable once CheckNamespace
namespace PasswordManagerAccess.Bitwarden.Ui;

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

public record Canceled(string Reason);
