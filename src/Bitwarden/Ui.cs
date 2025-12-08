// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable
namespace PasswordManagerAccess.Bitwarden.Ui;

public interface IAsyncUi
{
    void OpenInBrowser(string url);
    void CloseBrowser();
}

public record Canceled(string Reason);
