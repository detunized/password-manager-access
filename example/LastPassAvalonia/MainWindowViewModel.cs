// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Duo;
using PasswordManagerAccess.LastPass;
using PasswordManagerAccess.LastPass.Ui;
using ReactiveUI;

namespace LastPassAvalonia;

public class MainWindowViewModel : ViewModelBase, IAsyncUi
{
    private string _username = "1";
    private string _password = "2";
    private string _status = "Press Login to continue";
    private bool _isLoggingIn = false;

    public string Username
    {
        get => _username;
        set
        {
            this.RaiseAndSetIfChanged(ref _username, value);
            this.RaisePropertyChanged(nameof(IsLoginEnabled));
        }
    }

    public string Password
    {
        get => _password;
        set
        {
            this.RaiseAndSetIfChanged(ref _password, value);
            this.RaisePropertyChanged(nameof(IsLoginEnabled));
        }
    }

    public string Status
    {
        get => _status;
        set => this.RaiseAndSetIfChanged(ref _status, value);
    }

    public bool IsLoginEnabled => !string.IsNullOrEmpty(Username) && !string.IsNullOrEmpty(Password) && !_isLoggingIn;

    private CancellationTokenSource? _loginCancellationTokenSource;

    public async Task Login()
    {
        _isLoggingIn = true;
        this.RaisePropertyChanged(nameof(IsLoginEnabled));

        _loginCancellationTokenSource = new CancellationTokenSource();

        try
        {
            Status = "Logging in...";
            var vault = await Vault.Open(
                Username,
                Password,
                new ClientInfo(Platform.Desktop, "385e2742aefd399bd182c1ea4c1aac4d-3", "Example for lastpass-sharp"),
                this,
                new ParserOptions
                {
                    // Set to true to parse "server" secure notes
                    ParseSecureNotesToAccount = false,
                    LoggingEnabled = true,
                },
                null,
                _loginCancellationTokenSource.Token
            );

            Status = $"Got {vault.Accounts.Length} accounts";
        }
        catch (Exception e)
        {
            Status = e.Message;
        }
        finally
        {
            _loginCancellationTokenSource.Dispose();
            _loginCancellationTokenSource = null;
            _isLoggingIn = false;
            this.RaisePropertyChanged(nameof(IsLoginEnabled));
        }
    }

    //
    // IAsyncUi
    //

    public Task<OneOf<OtpResult, MfaMethod, PasswordManagerAccess.LastPass.Ui.Cancelled>> ProvideGoogleAuthPasscode(
        MfaMethod[] otherMethods,
        CancellationToken cancellationToken
    )
    {
        throw new NotImplementedException();
    }

    public Task<OneOf<OtpResult, MfaMethod, PasswordManagerAccess.LastPass.Ui.Cancelled>> ProvideMicrosoftAuthPasscode(
        MfaMethod[] otherMethods,
        CancellationToken cancellationToken
    )
    {
        throw new NotImplementedException();
    }

    public Task<OneOf<OtpResult, MfaMethod, PasswordManagerAccess.LastPass.Ui.Cancelled>> ProvideYubikeyPasscode(
        MfaMethod[] otherMethods,
        CancellationToken cancellationToken
    )
    {
        throw new NotImplementedException();
    }

    public Task<OneOf<OobResult, MfaMethod, PasswordManagerAccess.LastPass.Ui.Cancelled>> ApproveLastPassAuth(
        MfaMethod[] otherMethods,
        CancellationToken cancellationToken
    )
    {
        throw new NotImplementedException();
    }

    public Task<OneOf<OobResult, MfaMethod, PasswordManagerAccess.LastPass.Ui.Cancelled>> ApproveDuo(
        MfaMethod[] otherMethods,
        CancellationToken cancellationToken
    )
    {
        throw new NotImplementedException();
    }

    public Task<OneOf<OobResult, MfaMethod, PasswordManagerAccess.LastPass.Ui.Cancelled>> ApproveSalesforceAuth(
        MfaMethod[] otherMethods,
        CancellationToken cancellationToken
    )
    {
        throw new NotImplementedException();
    }

    public Task<OneOf<Choice, MfaMethod, PasswordManagerAccess.Duo.Cancelled>> ChooseFactor(
        Device[] devices,
        MfaMethod[] otherMethods,
        CancellationToken cancellationToken
    )
    {
        throw new NotImplementedException();
    }

    public Task<OneOf<Passcode, PasswordManagerAccess.Duo.Cancelled>> ProvidePasscode(Device device, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task UpdateStatus(Status status, string text, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}
