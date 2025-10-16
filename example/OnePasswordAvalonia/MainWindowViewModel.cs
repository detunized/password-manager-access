// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Reactive;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using OneOf;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Duo;
using PasswordManagerAccess.OnePassword;
using PasswordManagerAccess.OnePassword.Ui;
using ReactiveUI;

namespace OnePasswordAvalonia;

public class MainWindowViewModel : ViewModelBase, IAsyncUi
{
    private string _username = "";
    public string Username
    {
        get => _username;
        set
        {
            this.RaiseAndSetIfChanged(ref _username, value);
            this.RaisePropertyChanged(nameof(IsLoginEnabled));
        }
    }

    private string _password = "";
    public string Password
    {
        get => _password;
        set
        {
            this.RaiseAndSetIfChanged(ref _password, value);
            this.RaisePropertyChanged(nameof(IsLoginEnabled));
        }
    }

    private string _accountKey = "";
    public string AccountKey
    {
        get => _accountKey;
        set
        {
            this.RaiseAndSetIfChanged(ref _accountKey, value);
            this.RaisePropertyChanged(nameof(IsLoginEnabled));
        }
    }

    private string _deviceId = "";
    public string DeviceId
    {
        get => _deviceId;
        set
        {
            this.RaiseAndSetIfChanged(ref _deviceId, value);
            this.RaisePropertyChanged(nameof(IsLoginEnabled));
        }
    }

    public void GenerateDeviceId()
    {
        DeviceId = Client.GenerateRandomUuid();
    }

    private string _domain = "my.1password.com";
    public string Domain
    {
        get => _domain;
        set => this.RaiseAndSetIfChanged(ref _domain, value);
    }

    private string _status = "Press Login to continue";
    public string Status
    {
        get => _status;
        set => this.RaiseAndSetIfChanged(ref _status, value);
    }

    private bool _isLoggingIn = false;
    public bool IsLoginEnabled =>
        !string.IsNullOrEmpty(Username) && !string.IsNullOrEmpty(Password) && !string.IsNullOrEmpty(AccountKey) && !string.IsNullOrEmpty(DeviceId) && !_isLoggingIn;

    public bool IsCancelEnabled => _isLoggingIn;

    private CancellationTokenSource? _loginCancellationTokenSource;

    public async Task Login()
    {
        _isLoggingIn = true;
        this.RaisePropertyChanged(nameof(IsLoginEnabled));
        this.RaisePropertyChanged(nameof(IsCancelEnabled));

        _loginCancellationTokenSource = new CancellationTokenSource();

        try
        {
            Status = "Logging in...";
            var session = await Client.LogIn(
                new Credentials
                {
                    Username = Username,
                    Password = Password,
                    AccountKey = AccountKey,
                    Domain = string.IsNullOrWhiteSpace(Domain) ? Client.DefaultDomain : Domain,
                    DeviceUuid = DeviceId,
                },
                new AppInfo { Name = "PMA 1Password Avalonia Example", Version = "1.0.0" },
                this,
                new AsyncPlainStorage(),
                _loginCancellationTokenSource.Token
            );

            var vaults = await Client.ListAllVaults(session, _loginCancellationTokenSource.Token);
            await Client.LogOut(session, _loginCancellationTokenSource.Token);

            Status = $"Got {vaults.Length} vaults";
        }
        catch (Exception e)
        {
            Status = $"{e.GetType().Name}: {e.Message}";
        }
        finally
        {
            _loginCancellationTokenSource.Dispose();
            _loginCancellationTokenSource = null;
            _isLoggingIn = false;
            this.RaisePropertyChanged(nameof(IsLoginEnabled));
            this.RaisePropertyChanged(nameof(IsCancelEnabled));
        }
    }

    public void CancelLogin()
    {
        _loginCancellationTokenSource?.Cancel();
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
    // WebAuthn
    //

    private bool _isWebAuthnEnabled = false;
    public bool IsWebAuthnEnabled
    {
        get => _isWebAuthnEnabled;
        set => this.RaiseAndSetIfChanged(ref _isWebAuthnEnabled, value);
    }

    private TaskCompletionSource<bool>? _approveWebAuthnTcs;

    public void ApproveWebAuthn()
    {
        _approveWebAuthnTcs?.SetResult(true);
    }

    //
    // Duo
    //

    private TaskCompletionSource<bool>? _selectDuoTcs;
    private TaskCompletionSource<bool>? _submitDuoPasscodeTcs;

    public record DuoMethod(string Name, bool IsChecked, int DeviceIndex, int FactorIndex);

    public ObservableCollection<DuoMethod> DuoMethods { get; } = [];

    private string _mfaStatus = "MFA section";
    public string MfaStatus
    {
        get => _mfaStatus;
        set => this.RaiseAndSetIfChanged(ref _mfaStatus, value);
    }

    private bool _rememberMe = false;
    public bool RememberMe
    {
        get => _rememberMe;
        set => this.RaiseAndSetIfChanged(ref _rememberMe, value);
    }

    private string _mfaAttempt = "";
    public string MfaAttempt
    {
        get => _mfaAttempt;
        set => this.RaiseAndSetIfChanged(ref _mfaAttempt, value);
    }

    private bool _isDuoEnabled = false;
    public bool IsDuoEnabled
    {
        get => _isDuoEnabled;
        set => this.RaiseAndSetIfChanged(ref _isDuoEnabled, value);
    }

    private bool _isDuoFactorSelectionEnabled = false;
    public bool IsDuoFactorSelectionEnabled
    {
        get => _isDuoFactorSelectionEnabled;
        set => this.RaiseAndSetIfChanged(ref _isDuoFactorSelectionEnabled, value);
    }

    private bool _isDuoPasscodeEnabled = false;
    public bool IsDuoPasscodeEnabled
    {
        get => _isDuoPasscodeEnabled;
        set => this.RaiseAndSetIfChanged(ref _isDuoPasscodeEnabled, value);
    }

    private string _duoPasscode = "";
    public string DuoPasscode
    {
        get => _duoPasscode;
        set => this.RaiseAndSetIfChanged(ref _duoPasscode, value);
    }

    private string _duoStatus = "";
    public string DuoStatus
    {
        get => _duoStatus;
        set => this.RaiseAndSetIfChanged(ref _duoStatus, value);
    }

    private string _duoState = "";
    public string DuoState
    {
        get => _duoState;
        set => this.RaiseAndSetIfChanged(ref _duoState, value);
    }

    public void SelectDuo()
    {
        _selectDuoTcs?.SetResult(true);
    }

    public void SubmitDuoPasscode()
    {
        _submitDuoPasscodeTcs?.SetResult(true);
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

    public async Task<OneOf<Otp, MfaMethod, Canceled>> ProvideGoogleAuthPasscode(
        int attempt,
        MfaMethod[] otherMethods,
        CancellationToken cancellationToken
    )
    {
        try
        {
            IsGoogleAuthEnabled = true;
            SetMfaMethods(otherMethods, "Please enter Google Authenticator code", attempt);

            _approveGoogleAuthTcs = new TaskCompletionSource<bool>();
            var done = await WhenAnyWithCancellation(cancellationToken, _approveGoogleAuthTcs.Task, _selectMfaTcs!.Task, _cancelMfaTcs!.Task);

            if (done == _selectMfaTcs.Task)
                return _selectMfaTcs.Task.Result;

            if (done == _cancelMfaTcs.Task)
                return new Canceled("User cancelled");

            return new Otp(GoogleAuthPasscode, RememberMe);
        }
        finally
        {
            ClearMfaMethods();
            IsGoogleAuthEnabled = false;
            _approveGoogleAuthTcs = null;
        }
    }

    public async Task<OneOf<RememberMe, MfaMethod, Canceled>> ProvideWebAuthnRememberMe(
        int attempt,
        MfaMethod[] otherMethods,
        CancellationToken cancellationToken
    )
    {
        try
        {
            IsWebAuthnEnabled = true;
            SetMfaMethods(otherMethods, "WebAuthn authentication will be requested. Press OK to continue.", attempt);

            _approveWebAuthnTcs = new TaskCompletionSource<bool>();
            var done = await WhenAnyWithCancellation(cancellationToken, _approveWebAuthnTcs.Task, _selectMfaTcs!.Task, _cancelMfaTcs!.Task);

            if (done == _selectMfaTcs.Task)
                return _selectMfaTcs.Task.Result;

            if (done == _cancelMfaTcs.Task)
                return new Canceled("User cancelled");

            return new RememberMe(RememberMe);
        }
        finally
        {
            ClearMfaMethods();
            IsWebAuthnEnabled = false;
            _approveWebAuthnTcs = null;
        }
    }

    public async Task<OneOf<DuoChoice, MfaMethod, DuoCancelled>> ChooseDuoFactor(
        DuoDevice[] devices,
        MfaMethod[] otherMethods,
        CancellationToken cancellationToken
    )
    {
        try
        {
            SetMfaMethods(otherMethods, "Please choose a Duo factor", 0);
            DuoState = "Duo is in progress";

            DuoMethods.RemoveAll();
            for (var di = 0; di < devices.Length; di++)
            {
                var device = devices[di];
                for (var fi = 0; fi < device.Factors.Length; fi++)
                {
                    var factor = device.Factors[fi];
                    DuoMethods.Add(new DuoMethod($"{device.Name}: {factor}", di == 0 && fi == 0, di, fi));
                }
            }
            IsDuoEnabled = true;
            IsDuoFactorSelectionEnabled = true;
            _selectDuoTcs = new TaskCompletionSource<bool>();

            var done = await WhenAnyWithCancellation(cancellationToken, _selectDuoTcs.Task, _cancelMfaTcs.Task, _selectMfaTcs.Task);

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
            IsDuoFactorSelectionEnabled = false;
            _selectDuoTcs = null;
        }
    }

    public async Task<OneOf<DuoPasscode, DuoCancelled>> ProvideDuoPasscode(DuoDevice device, CancellationToken cancellationToken)
    {
        try
        {
            IsDuoPasscodeEnabled = true;
            DuoState = "Please enter Duo passcode";

            _submitDuoPasscodeTcs = new TaskCompletionSource<bool>();

            await WhenAnyWithCancellation(cancellationToken, _submitDuoPasscodeTcs.Task);

            return string.IsNullOrWhiteSpace(DuoPasscode) ? new DuoCancelled("User cancelled") : new DuoPasscode(DuoPasscode);
        }
        finally
        {
            IsDuoPasscodeEnabled = false;
            _submitDuoPasscodeTcs = null;
        }
    }

    public Task DuoDone(CancellationToken cancellationToken)
    {
        ClearMfaMethods();
        IsDuoEnabled = false;
        DuoState = "Duo is done";
        return Task.CompletedTask;
    }

    public Task UpdateDuoStatus(DuoStatus status, string text, CancellationToken cancellationToken)
    {
        DuoStatus = text;
        return Task.CompletedTask;
    }

    //
    // Helpers
    //

    [MemberNotNull(nameof(_cancelMfaTcs), nameof(_selectMfaTcs))]
    private void SetMfaMethods(MfaMethod[] methods, string status, int attempt)
    {
        ClearMfaMethods();

        foreach (var method in methods)
            EnabledMfaMethods.Add(new EnabledMfaMethod(method.GetName(), method, ReactiveCommand.Create(() => SelectMfaMethod(method))));

        _selectMfaTcs = new TaskCompletionSource<MfaMethod>();
        _cancelMfaTcs = new TaskCompletionSource<bool>();

        MfaStatus = status;
        MfaAttempt = $"Attempt: {attempt + 1}";
        IsMfaEnabled = true;
    }

    private void ClearMfaMethods()
    {
        IsMfaEnabled = false;
        MfaStatus = "";
        EnabledMfaMethods.RemoveAll();

        _selectMfaTcs = null;
        _cancelMfaTcs = null;
    }

    private static async Task<Task> WhenAnyWithCancellation(CancellationToken cancellationToken, params Task[] tasks)
    {
        var cancelTcs = new TaskCompletionSource<object>();
        await using (cancellationToken.Register(() => cancelTcs.TrySetCanceled(cancellationToken)))
        {
            var completedTask = await Task.WhenAny(tasks.Append(cancelTcs.Task)).ConfigureAwait(false);

            if (completedTask == cancelTcs.Task)
                await completedTask.ConfigureAwait(false); // Await the canceled task to throw the exception

            return completedTask;
        }
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
