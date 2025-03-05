// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Reactive;
using System.Threading;
using System.Threading.Tasks;
using OneOf;
using OpenQA.Selenium;
using OpenQA.Selenium.Chrome;
using OpenQA.Selenium.Support.UI;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Duo;
using PasswordManagerAccess.LastPass;
using PasswordManagerAccess.LastPass.Ui;
using ReactiveUI;
using Platform = PasswordManagerAccess.LastPass.Platform;

namespace LastPassAvalonia;

public class MainWindowViewModel : ViewModelBase, IAsyncUi
{
    private static readonly bool UseBrowserPersistence = false;

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

    public async Task<OneOf<Otp, MfaMethod, Canceled>> ProvideMicrosoftAuthPasscode(
        int attempt,
        MfaMethod[] otherMethods,
        CancellationToken cancellationToken
    )
    {
        try
        {
            IsMicrosoftAuthEnabled = true;
            SetMfaMethods(otherMethods, "Please enter Microsoft Authenticator code", attempt);

            _approveMicrosoftAuthTcs = new TaskCompletionSource<bool>();
            var done = await WhenAnyWithCancellation(cancellationToken, _approveMicrosoftAuthTcs.Task, _selectMfaTcs.Task, _cancelMfaTcs.Task);

            if (done == _selectMfaTcs.Task)
                return _selectMfaTcs.Task.Result;

            if (done == _cancelMfaTcs.Task)
                return new Canceled("User cancelled");

            return new Otp(MicrosoftAuthPasscode, RememberMe);
        }
        finally
        {
            ClearMfaMethods();
            IsMicrosoftAuthEnabled = false;
            _approveMicrosoftAuthTcs = null;
        }
    }

    public async Task<OneOf<Otp, MfaMethod, Canceled>> ProvideYubikeyPasscode(
        int attempt,
        MfaMethod[] otherMethods,
        CancellationToken cancellationToken
    )
    {
        try
        {
            IsYubiKeyEnabled = true;
            SetMfaMethods(otherMethods, "Please enter YubiKey passcode", attempt);

            _approveYubiKeyTcs = new TaskCompletionSource<bool>();
            var done = await WhenAnyWithCancellation(cancellationToken, _approveYubiKeyTcs.Task, _selectMfaTcs.Task, _cancelMfaTcs.Task);

            if (done == _selectMfaTcs.Task)
                return _selectMfaTcs.Task.Result;

            if (done == _cancelMfaTcs.Task)
                return new Canceled("User cancelled");

            return new Otp(YubiKeyPasscode, RememberMe);
        }
        finally
        {
            ClearMfaMethods();
            IsYubiKeyEnabled = false;
            _approveYubiKeyTcs = null;
        }
    }

    public async Task<OneOf<Otp, WaitForOutOfBand, MfaMethod, Canceled>> ApproveLastPassAuth(
        int attempt,
        MfaMethod[] otherMethods,
        CancellationToken cancellationToken
    )
    {
        try
        {
            IsLastPassAuthEnabled = true;
            SetMfaMethods(otherMethods, "Please enter LastPass Authenticator passcode or choose to push to mobile", attempt);

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
                return new Canceled("User cancelled");

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

    public async Task<OneOf<string, Canceled>> PerformSsoLogin(string url, string expectedRedirectUrl, CancellationToken cancellationToken)
    {
        return await Task.Run<OneOf<string, Canceled>>(
            () =>
            {
                var options = new ChromeOptions();

                // Enable this to make a persistent profile to save the login state
                if (UseBrowserPersistence)
                {
                    // Get a temporary directory path for the Chrome profile
                    var tempPath = Path.GetTempPath();
                    var chromeProfilePath = Path.Combine(tempPath, "lastpass-chrome-profile");

                    // Ensure the directory exists
                    if (!Directory.Exists(chromeProfilePath))
                        Directory.CreateDirectory(chromeProfilePath);

                    options.AddArgument($"--user-data-dir={chromeProfilePath}");
                    options.AddArgument("--profile-directory=Default");
                }

                using var driver = new ChromeDriver(options);
                var timedOut = false;

                driver.Navigate().GoToUrl(url);

                try
                {
                    // Wait for the redirect to happen
                    new WebDriverWait(driver, TimeSpan.FromMinutes(2)).Until(
                        d => d.WindowHandles.Count == 0 || d.Url.StartsWith(expectedRedirectUrl),
                        cancellationToken
                    );
                }
                catch (WebDriverTimeoutException)
                {
                    timedOut = true;
                }

                // Timed out or the user closed the window
                if (timedOut || driver.WindowHandles.Count == 0)
                    return new Canceled("User cancelled");

                // We should be ok here
                return driver.Url;
            },
            cancellationToken
        );
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
