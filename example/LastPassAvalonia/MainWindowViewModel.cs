// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Reactive;
using System.Threading;
using System.Threading.Tasks;
using OneOf;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Duo;
using PasswordManagerAccess.LastPass;
using PasswordManagerAccess.LastPass.Ui;
using ReactiveUI;

namespace LastPassAvalonia;

public class MainWindowViewModel : ViewModelBase, IAsyncUi
{
    private string _username = "lastpass.ruby+24-april-2020@gmail.com";
    private string _password = "Password123!";
    private string _status = "Press Login to continue";
    private bool _isLoggingIn = false;
    private CancellationTokenSource? _loginCancellationTokenSource;

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
                new ClientInfo(Platform.Desktop, "385e2742aefd399bd182c1ea4c1aac4d", "Example for lastpass-sharp"),
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
    // Google Auth
    //

    private bool _isGoogleAuthEnabled = false;
    public bool IsGoogleAuthEnabled
    {
        get => _isGoogleAuthEnabled;
        set => this.RaiseAndSetIfChanged(ref _isGoogleAuthEnabled, value);
    }

    private string _googleAuthPasscode = "";
    public string GoogleAuthPasscode
    {
        get => _googleAuthPasscode;
        set => this.RaiseAndSetIfChanged(ref _googleAuthPasscode, value);
    }

    private TaskCompletionSource<bool>? _approveGoogleAuthTcs;

    public void ApproveGoogleAuth()
    {
        _approveGoogleAuthTcs?.SetResult(true);
    }

    //
    // Duo
    //

    private TaskCompletionSource<bool>? _approveDuoTcs;

    public record DuoMethod(string Name, bool IsChecked, int DeviceIndex, int FactorIndex);

    public ObservableCollection<DuoMethod> DuoMethods { get; } = [];

    private bool _rememberMe = false;
    public bool RememberMe
    {
        get => _rememberMe;
        set => this.RaiseAndSetIfChanged(ref _rememberMe, value);
    }

    private bool _isDuoEnabled = false;
    public bool IsDuoEnabled
    {
        get => _isDuoEnabled;
        set => this.RaiseAndSetIfChanged(ref _isDuoEnabled, value);
    }

    private string _duoStatus = "";
    public string DuoStatus
    {
        get => _duoStatus;
        set => this.RaiseAndSetIfChanged(ref _duoStatus, value);
    }

    public void ApproveDuo()
    {
        _approveDuoTcs?.SetResult(true);
    }

    //
    // MFA method selection
    //

    private TaskCompletionSource<MfaMethod>? _selectMfaTcs;
    private TaskCompletionSource<bool>? _cancelMfaTcs;

    public record EnabledMfaMethod(string Name, MfaMethod Method, ReactiveCommand<Unit, Unit> Select);

    public ObservableCollection<EnabledMfaMethod> EnabledMfaMethods { get; } = [];

    private bool _isMfaEnabled = false;
    public bool IsMfaEnabled
    {
        get => _isMfaEnabled;
        set => this.RaiseAndSetIfChanged(ref _isMfaEnabled, value);
    }

    public void SelectMfaMethod(MfaMethod method)
    {
        _selectMfaTcs?.SetResult(method);
    }

    public void CancelMfa()
    {
        _cancelMfaTcs?.SetResult(true);
    }

    //
    // IAsyncUi
    //

    public async Task<OneOf<Otp, MfaMethod, Cancelled>> ProvideGoogleAuthPasscode(MfaMethod[] otherMethods, CancellationToken cancellationToken)
    {
        try
        {
            IsGoogleAuthEnabled = true;
            SetMfaMethods(otherMethods);

            _approveGoogleAuthTcs = new TaskCompletionSource<bool>();
            var done = await Task.WhenAny(_approveGoogleAuthTcs.Task, _selectMfaTcs.Task, _cancelMfaTcs.Task);

            if (done == _selectMfaTcs.Task)
                return _selectMfaTcs.Task.Result;

            if (done == _cancelMfaTcs.Task)
                return new Cancelled("User cancelled");

            return new Otp(GoogleAuthPasscode, RememberMe);
        }
        finally
        {
            ClearMfaMethods();
            _approveGoogleAuthTcs = null;
            IsGoogleAuthEnabled = false;
        }
    }

    public Task<OneOf<Otp, MfaMethod, Cancelled>> ProvideMicrosoftAuthPasscode(MfaMethod[] otherMethods, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task<OneOf<Otp, MfaMethod, Cancelled>> ProvideYubikeyPasscode(MfaMethod[] otherMethods, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task<OneOf<Otp, WaitForOutOfBand, MfaMethod, Cancelled>> ApproveLastPassAuth(MfaMethod[] otherMethods, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task<OneOf<Otp, WaitForOutOfBand, MfaMethod, Cancelled>> ApproveDuo(MfaMethod[] otherMethods, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task<OneOf<Otp, WaitForOutOfBand, MfaMethod, Cancelled>> ApproveSalesforceAuth(
        MfaMethod[] otherMethods,
        CancellationToken cancellationToken
    )
    {
        throw new NotImplementedException();
    }

    public async Task<OneOf<DuoChoice, MfaMethod, DuoCancelled>> ChooseDuoFactor(
        DuoDevice[] devices,
        MfaMethod[] otherMethods,
        CancellationToken cancellationToken
    )
    {
        try
        {
            SetMfaMethods(otherMethods);

            DuoMethods.RemoveAll();
            for (int di = 0; di < devices.Length; di++)
            {
                var device = devices[di];
                for (int fi = 0; fi < device.Factors.Length; fi++)
                {
                    var factor = device.Factors[fi];
                    DuoMethods.Add(new DuoMethod($"{device.Name}: {factor}", di == 0 && fi == 0, di, fi));
                }
            }
            IsDuoEnabled = true;

            // TODO: Use cancellation token
            _approveDuoTcs = new TaskCompletionSource<bool>();

            var done = await Task.WhenAny(_approveDuoTcs.Task, _cancelMfaTcs.Task, _selectMfaTcs.Task);

            if (done == _cancelMfaTcs.Task)
                return new DuoCancelled("User cancelled");

            if (done == _selectMfaTcs.Task)
                return _selectMfaTcs.Task.Result;

            var selectedMethod = DuoMethods.First(m => m.IsChecked);
            return new DuoChoice(
                devices[selectedMethod.DeviceIndex],
                devices[selectedMethod.DeviceIndex].Factors[selectedMethod.FactorIndex],
                RememberMe
            );
        }
        finally
        {
            ClearMfaMethods();
            _approveDuoTcs = null;
            IsDuoEnabled = false;
        }
    }

    public Task<OneOf<DuoPasscode, DuoCancelled>> ProvideDuoPasscode(DuoDevice device, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task UpdateDuoStatus(DuoStatus status, string text, CancellationToken cancellationToken)
    {
        DuoStatus = text;
        return Task.CompletedTask;
    }

    //
    // Helpers
    //

    private void SetMfaMethods(MfaMethod[] methods)
    {
        ClearMfaMethods();

        foreach (var method in methods)
            EnabledMfaMethods.Add(new EnabledMfaMethod(method.GetName(), method, ReactiveCommand.Create(() => SelectMfaMethod(method))));

        _selectMfaTcs = new TaskCompletionSource<MfaMethod>();
        _cancelMfaTcs = new TaskCompletionSource<bool>();

        IsMfaEnabled = true;
    }

    private void ClearMfaMethods()
    {
        IsMfaEnabled = false;

        EnabledMfaMethods.RemoveAll();

        _selectMfaTcs = null;
        _cancelMfaTcs = null;
    }
}

internal static class ObservableCollectionExtensions
{
    // For some reason .Clear doesn't update the UI properly. This works.
    public static void RemoveAll<T>(this ObservableCollection<T> collection)
    {
        while (collection.Count > 0)
            collection.RemoveAt(collection.Count - 1);
    }
}
