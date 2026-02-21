// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Interactivity;
using PasswordManagerAccess.Example.Common;
using PasswordManagerAccess.NordPass;

namespace NordPassAvalonia;

public partial class MainWindow : Window, IAsyncUi
{
    private TaskCompletionSource<string?>? _authTcs;

    public MainWindow()
    {
        InitializeComponent();

        try
        {
            var config = Util.ReadConfig();
            config.TryGetValue("username", out var username);
            config.TryGetValue("master-password", out var password);
            UsernameBox.Text = username ?? "";
            PasswordBox.Text = password ?? "";
        }
        catch
        {
            // No config file found, user can type in the fields
        }
    }

    private async void Login_Click(object? sender, RoutedEventArgs e)
    {
        LoginButton.IsEnabled = false;
        StatusText.Text = "Logging in...";

        try
        {
            using var cts = new CancellationTokenSource();
            var vault = await Client.OpenVault(UsernameBox.Text ?? "", PasswordBox.Text ?? "", this, new PlainStorage(), cts.Token);

            StatusText.Text = $"Got {vault.Accounts.Length} accounts";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"{ex.GetType().Name}: {ex.Message}";
        }
        finally
        {
            LoginButton.IsEnabled = true;
        }
    }

    public Task<string?> AuthorizeOAuth(string url, CancellationToken cancellationToken)
    {
        _authTcs = new TaskCompletionSource<string?>();

        AuthWebView.IsVisible = true;
        AuthWebView.NavigationStarting += OnNavigationStarting;
        AuthWebView.Url = new Uri(url);

        cancellationToken.Register(() => _authTcs.TrySetResult(null));

        return _authTcs.Task;
    }

    private void OnNavigationStarting(object? sender, WebViewCore.Events.WebViewUrlLoadingEventArg args)
    {
        var frameUrl = args.Url?.ToString() ?? "";
        if (!frameUrl.Contains("app.nordpass.com") || !frameUrl.Contains("verify_token="))
            return;

        var uri = new Uri(frameUrl);
        var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
        var token = query["verify_token"];

        if (!string.IsNullOrEmpty(token))
        {
            AuthWebView.NavigationStarting -= OnNavigationStarting;
            AuthWebView.Url = new Uri("about:blank");
            AuthWebView.IsVisible = false;
            _authTcs?.TrySetResult(token);
        }
    }
}
