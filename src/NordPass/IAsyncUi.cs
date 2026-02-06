// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Threading;
using System.Threading.Tasks;

namespace PasswordManagerAccess.NordPass;

public interface IAsyncUi
{
    // Opens the given URL in a browser for the user to authenticate with Nord Account.
    // After successful authentication, the browser redirects to a URL containing a verify_token
    // query parameter. This method should return that token.
    // Return null to cancel the operation.
    Task<string?> AuthorizeOAuth(string url, CancellationToken cancellationToken);
}
