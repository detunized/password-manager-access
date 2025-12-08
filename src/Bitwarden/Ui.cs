// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable
using System.Threading;
using System.Threading.Tasks;

namespace PasswordManagerAccess.Bitwarden.Ui;

public interface IAsyncUi
{
    // Should open the URL in the browser and return immediately.
    // Should return Canceled if the user canceled the operation, otherwise null.
    Task<Canceled?> OpenInBrowser(string url, CancellationToken cancellationToken);

    // Should close the browser opened by OpenInBrowser. Always called after, regardless of success or failure.
    Task CloseBrowser(bool success, CancellationToken cancellationToken);
}

public record Canceled(string Reason);
