// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
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
    private string _username = "lastpass.ruby+20-january-2025@gmail.com";
    public string Username
    {
        get => _username;
        set
        {
            this.RaiseAndSetIfChanged(ref _username, value);
            this.RaisePropertyChanged(nameof(IsLoginEnabled));
        }
    }

    private string _password = "Arousal3-Catalog-Overtly-Slobbery-Entitle";
    public string Password
    {
        get => _password;
        set
        {
            this.RaiseAndSetIfChanged(ref _password, value);
            this.RaisePropertyChanged(nameof(IsLoginEnabled));
        }
    }

    private string _status = "Press Login to continue";
    public string Status
    {
        get => _status;
        set => this.RaiseAndSetIfChanged(ref _status, value);
    }

    private bool _isLoggingIn = false;
    public bool IsLoginEnabled => !string.IsNullOrEmpty(Username) && !string.IsNullOrEmpty(Password) && !_isLoggingIn;
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
    // Microsoft Auth
    //

    private bool _isMicrosoftAuthEnabled = false;
    public bool IsMicrosoftAuthEnabled
    {
        get => _isMicrosoftAuthEnabled;
        set => this.RaiseAndSetIfChanged(ref _isMicrosoftAuthEnabled, value);
    }

    private string _microsoftAuthPasscode = "";
    public string MicrosoftAuthPasscode
    {
        get => _microsoftAuthPasscode;
        set => this.RaiseAndSetIfChanged(ref _microsoftAuthPasscode, value);
    }

    private TaskCompletionSource<bool>? _approveMicrosoftAuthTcs;

    public void ApproveMicrosoftAuth()
    {
        _approveMicrosoftAuthTcs?.SetResult(true);
    }

    //
    // LastPass Auth
    //

    private bool _isLastPassAuthEnabled = false;
    public bool IsLastPassAuthEnabled
    {
        get => _isLastPassAuthEnabled;
        set => this.RaiseAndSetIfChanged(ref _isLastPassAuthEnabled, value);
    }

    private string _lastPassAuthPasscode = "";
    public string LastPassAuthPasscode
    {
        get => _lastPassAuthPasscode;
        set => this.RaiseAndSetIfChanged(ref _lastPassAuthPasscode, value);
    }

    private TaskCompletionSource<bool>? _approveLastPassAuthTcs;
    private TaskCompletionSource<bool>? _pushToMobileLastPassAuthTcs;

    public void ApproveLastPassAuth()
    {
        _approveLastPassAuthTcs?.SetResult(true);
    }

    public void PushToMobileLastPassAuth()
    {
        _pushToMobileLastPassAuthTcs?.SetResult(true);
    }

    //
    // Duo
    //

    private TaskCompletionSource<bool>? _approveDuoTcs;

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
    // YubiKey
    //

    private bool _isYubiKeyEnabled = false;
    public bool IsYubiKeyEnabled
    {
        get => _isYubiKeyEnabled;
        set => this.RaiseAndSetIfChanged(ref _isYubiKeyEnabled, value);
    }

    private string _yubiKeyPasscode = "";
    public string YubiKeyPasscode
    {
        get => _yubiKeyPasscode;
        set => this.RaiseAndSetIfChanged(ref _yubiKeyPasscode, value);
    }

    private TaskCompletionSource<bool>? _approveYubiKeyTcs;

    public void ApproveYubiKey()
    {
        _approveYubiKeyTcs?.SetResult(true);
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
            SetMfaMethods(otherMethods, "Please enter Google Authenticator code");

            _approveGoogleAuthTcs = new TaskCompletionSource<bool>();
            var done = await WhenAnyWithCancellation(cancellationToken, _approveGoogleAuthTcs.Task, _selectMfaTcs!.Task, _cancelMfaTcs!.Task);

            if (done == _selectMfaTcs.Task)
                return _selectMfaTcs.Task.Result;

            if (done == _cancelMfaTcs.Task)
                return new Cancelled("User cancelled");

            return new Otp(GoogleAuthPasscode, RememberMe);
        }
        finally
        {
            ClearMfaMethods();
            IsGoogleAuthEnabled = false;
            _approveGoogleAuthTcs = null;
        }
    }

    public async Task<OneOf<Otp, MfaMethod, Cancelled>> ProvideMicrosoftAuthPasscode(MfaMethod[] otherMethods, CancellationToken cancellationToken)
    {
        try
        {
            IsMicrosoftAuthEnabled = true;
            SetMfaMethods(otherMethods, "Please enter Microsoft Authenticator code");

            _approveMicrosoftAuthTcs = new TaskCompletionSource<bool>();
            var done = await WhenAnyWithCancellation(cancellationToken, _approveMicrosoftAuthTcs.Task, _selectMfaTcs.Task, _cancelMfaTcs.Task);

            if (done == _selectMfaTcs.Task)
                return _selectMfaTcs.Task.Result;

            if (done == _cancelMfaTcs.Task)
                return new Cancelled("User cancelled");

            return new Otp(MicrosoftAuthPasscode, RememberMe);
        }
        finally
        {
            ClearMfaMethods();
            IsMicrosoftAuthEnabled = false;
            _approveMicrosoftAuthTcs = null;
        }
    }

    public async Task<OneOf<Otp, MfaMethod, Cancelled>> ProvideYubikeyPasscode(MfaMethod[] otherMethods, CancellationToken cancellationToken)
    {
        try
        {
            IsYubiKeyEnabled = true;
            SetMfaMethods(otherMethods, "Please enter YubiKey passcode");

            _approveYubiKeyTcs = new TaskCompletionSource<bool>();
            var done = await WhenAnyWithCancellation(cancellationToken, _approveYubiKeyTcs.Task, _selectMfaTcs.Task, _cancelMfaTcs.Task);

            if (done == _selectMfaTcs.Task)
                return _selectMfaTcs.Task.Result;

            if (done == _cancelMfaTcs.Task)
                return new Cancelled("User cancelled");

            return new Otp(YubiKeyPasscode, RememberMe);
        }
        finally
        {
            ClearMfaMethods();
            IsYubiKeyEnabled = false;
            _approveYubiKeyTcs = null;
        }
    }

    public async Task<OneOf<Otp, WaitForOutOfBand, MfaMethod, Cancelled>> ApproveLastPassAuth(
        MfaMethod[] otherMethods,
        CancellationToken cancellationToken
    )
    {
        try
        {
            IsLastPassAuthEnabled = true;
            SetMfaMethods(otherMethods, "Please enter LastPass Authenticator passcode or choose to push to mobile");

            _approveLastPassAuthTcs = new TaskCompletionSource<bool>();
            _pushToMobileLastPassAuthTcs = new TaskCompletionSource<bool>();

            var done = await WhenAnyWithCancellation(
                cancellationToken,
                _approveLastPassAuthTcs.Task,
                _pushToMobileLastPassAuthTcs.Task,
                _selectMfaTcs.Task,
                _cancelMfaTcs.Task
            );

            if (done == _selectMfaTcs.Task)
                return _selectMfaTcs.Task.Result;

            if (done == _cancelMfaTcs.Task)
                return new Cancelled("User cancelled");

            if (done == _pushToMobileLastPassAuthTcs.Task)
                return new WaitForOutOfBand(RememberMe);

            return new Otp(LastPassAuthPasscode, RememberMe);
        }
        finally
        {
            ClearMfaMethods();
            IsLastPassAuthEnabled = false;
            _approveLastPassAuthTcs = null;
            _pushToMobileLastPassAuthTcs = null;
        }
    }

    public Task<OneOf<Otp, WaitForOutOfBand, MfaMethod, Cancelled>> ApproveDuo(MfaMethod[] otherMethods, CancellationToken cancellationToken)
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
            SetMfaMethods(otherMethods, "Please choose a Duo factor");

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

            _approveDuoTcs = new TaskCompletionSource<bool>();

            var done = await WhenAnyWithCancellation(cancellationToken, _approveDuoTcs.Task, _cancelMfaTcs.Task, _selectMfaTcs.Task);

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
            IsDuoEnabled = false;
            _approveDuoTcs = null;
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

    [MemberNotNull(nameof(_cancelMfaTcs), nameof(_selectMfaTcs))]
    private void SetMfaMethods(MfaMethod[] methods, string status)
    {
        ClearMfaMethods();

        foreach (var method in methods)
            EnabledMfaMethods.Add(new EnabledMfaMethod(method.GetName(), method, ReactiveCommand.Create(() => SelectMfaMethod(method))));

        _selectMfaTcs = new TaskCompletionSource<MfaMethod>();
        _cancelMfaTcs = new TaskCompletionSource<bool>();

        MfaStatus = status;
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
