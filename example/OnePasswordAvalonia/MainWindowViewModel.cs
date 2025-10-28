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
using PasswordManagerAccess.OnePassword;
using PasswordManagerAccess.OnePassword.Ui;
using ReactiveUI;

namespace OnePasswordAvalonia;

public class MainWindowViewModel : ViewModelBase, IAsyncUi
{
    private static bool UseBrowserPersistence => true;

    private string _username = "dmitry@downhillpro.xyz";
    public string Username
    {
        get => _username;
        set
        {
            this.RaiseAndSetIfChanged(ref _username, value);
            this.RaisePropertyChanged(nameof(IsLoginEnabled));
        }
    }

    private string _password = "-";
    public string Password
    {
        get => _password;
        set
        {
            this.RaiseAndSetIfChanged(ref _password, value);
            this.RaisePropertyChanged(nameof(IsLoginEnabled));
        }
    }

    private string _accountKey = "A3-B24CMZ-X84BZJ-266SM-J8WXE-6HZXW-SZMAH";
    public string AccountKey
    {
        get => _accountKey;
        set
        {
            this.RaiseAndSetIfChanged(ref _accountKey, value);
            this.RaisePropertyChanged(nameof(IsLoginEnabled));
        }
    }

    private string _deviceId = "gvcwm2onr66yune47arn4qhq4z";
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
        !string.IsNullOrEmpty(Username)
        && !string.IsNullOrEmpty(Password)
        && !string.IsNullOrEmpty(AccountKey)
        && !string.IsNullOrEmpty(DeviceId)
        && !_isLoggingIn;

    public bool IsCancelEnabled => _isLoggingIn;

    private CancellationTokenSource? _loginCancellationTokenSource;

    // TODO: Make this a permanent storage
    private readonly AsyncPlainStorage _storage = new();

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
                _storage,
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
    // SSO Enrollment
    //

    private bool _isEnrollmentActive = false;
    public bool IsEnrollmentActive
    {
        get => _isEnrollmentActive;
        set => this.RaiseAndSetIfChanged(ref _isEnrollmentActive, value);
    }

    private string _enrollmentStatus = "";
    public string EnrollmentStatus
    {
        get => _enrollmentStatus;
        set => this.RaiseAndSetIfChanged(ref _enrollmentStatus, value);
    }

    private string _verificationCode = "";
    public string VerificationCode
    {
        get => _verificationCode;
        set => this.RaiseAndSetIfChanged(ref _verificationCode, value);
    }

    private bool _isVerificationCodeEnabled = false;
    public bool IsVerificationCodeEnabled
    {
        get => _isVerificationCodeEnabled;
        set => this.RaiseAndSetIfChanged(ref _isVerificationCodeEnabled, value);
    }

    private TaskCompletionSource<bool>? _submitVerificationCodeTcs;
    private TaskCompletionSource<bool>? _cancelEnrollmentTcs;

    public void SubmitVerificationCode()
    {
        _submitVerificationCodeTcs?.SetResult(true);
    }

    public void CancelEnrollment()
    {
        _cancelEnrollmentTcs?.SetResult(true);
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

    public async Task<string> PerformSsoLogin(string ssoLoginUrl, string redirectTo, CancellationToken cancellationToken)
    {
        return await Task.Run(
            () =>
            {
                var options = new ChromeOptions();

                // Enable this to make a persistent profile to save the login state
                if (UseBrowserPersistence)
                {
                    // Get a temporary directory path for the Chrome profile
                    var tempPath = Path.GetTempPath();
                    var chromeProfilePath = Path.Combine(tempPath, "onepassword-chrome-profile");

                    // Ensure the directory exists
                    if (!Directory.Exists(chromeProfilePath))
                        Directory.CreateDirectory(chromeProfilePath);

                    options.AddArgument($"--user-data-dir={chromeProfilePath}");
                    options.AddArgument("--profile-directory=Default");
                }

                using var driver = new ChromeDriver(options);
                var timedOut = false;

                driver.Navigate().GoToUrl(ssoLoginUrl);

                try
                {
                    // Wait for the redirect to happen
                    new WebDriverWait(driver, TimeSpan.FromMinutes(2)).Until(
                        d => d.WindowHandles.Count == 0 || d.Url.StartsWith(redirectTo),
                        cancellationToken
                    );
                }
                catch (WebDriverTimeoutException)
                {
                    timedOut = true;
                }

                // Timed out or the user closed the window
                if (timedOut || driver.WindowHandles.Count == 0)
                    throw new CanceledSsoLoginException("User cancelled SSO login");

                // We should be ok here
                return driver.Url;
            },
            cancellationToken
        );
    }

    public Task<ISsoEnrollmentContext> BeginSsoEnrollment(CancellationToken cancellationToken)
    {
        // Show the enrollment UI
        IsEnrollmentActive = true;
        EnrollmentStatus = "Starting device enrollment...";

        // Create and return the context
        var context = new SsoEnrollmentContext(this, cancellationToken);
        return Task.FromResult<ISsoEnrollmentContext>(context);
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

    //
    // SSO Enrollment Context
    //

    private class SsoEnrollmentContext : ISsoEnrollmentContext
    {
        private readonly MainWindowViewModel _vm;
        private readonly CancellationTokenSource _internalCancellation;
        private readonly CancellationTokenSource _linkedCancellation;

        public SsoEnrollmentContext(MainWindowViewModel vm, CancellationToken externalCancellation)
        {
            _vm = vm;
            _internalCancellation = new CancellationTokenSource();

            // Link external cancellation (from library/login) with internal (from UI cancel button)
            _linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(externalCancellation, _internalCancellation.Token);

            // Set up the cancel button to trigger internal cancellation
            _vm._cancelEnrollmentTcs = new TaskCompletionSource<bool>();
            _vm._cancelEnrollmentTcs.Task.ContinueWith(
                _ =>
                {
                    _internalCancellation.Cancel();
                },
                TaskScheduler.Default
            );
        }

        public CancellationToken Token => _linkedCancellation.Token;

        public Task UpdateStatus(EnrollmentStatus status, string message, CancellationToken cancellationToken)
        {
            // Update UI based on status
            // TODO: This is not necessarily coming on the UI thread. Forward it to the UI thread.
            _vm.EnrollmentStatus = status switch
            {
                PasswordManagerAccess.OnePassword.Ui.EnrollmentStatus.WaitingForApproval =>
                    $"{message}\nPlease check your enrolled devices and approve this device.",
                PasswordManagerAccess.OnePassword.Ui.EnrollmentStatus.VerificationCodeNeeded =>
                    $"{message}\nA verification code should now be displayed on your enrolled device.",
                PasswordManagerAccess.OnePassword.Ui.EnrollmentStatus.ExchangingCredentials => $"{message}\nSecurely exchanging credentials...",
                PasswordManagerAccess.OnePassword.Ui.EnrollmentStatus.Completing => $"{message}\nFinalizing enrollment...",
                _ => message,
            };

            return Task.CompletedTask;
        }

        public async Task<OneOf<string, EnrollmentCanceled>> ProvideVerificationCode(CancellationToken cancellationToken)
        {
            try
            {
                // Enable the verification code input
                _vm.IsVerificationCodeEnabled = true;
                _vm.VerificationCode = "";
                _vm._submitVerificationCodeTcs = new TaskCompletionSource<bool>();

                // Wait for either:
                // 1. User submits code
                // 2. User cancels enrollment
                // 3. External cancellation (login timeout, etc.)
                var done = await WhenAnyWithCancellation(
                    _linkedCancellation.Token,
                    _vm._submitVerificationCodeTcs.Task,
                    _vm._cancelEnrollmentTcs!.Task
                );

                if (done == _vm._cancelEnrollmentTcs.Task)
                    return new EnrollmentCanceled("User clicked cancel");

                if (_linkedCancellation.Token.IsCancellationRequested)
                    return new EnrollmentCanceled("Operation was canceled");

                // User submitted the code
                var code = _vm.VerificationCode;
                if (string.IsNullOrWhiteSpace(code))
                    return new EnrollmentCanceled("No verification code provided");

                return code.Trim();
            }
            finally
            {
                _vm.IsVerificationCodeEnabled = false;
                _vm._submitVerificationCodeTcs = null;
            }
        }

        public Task EndEnrollment(SsoEnrollmentResult result, CancellationToken cancellationToken)
        {
            // Clean up UI
            _vm.IsEnrollmentActive = false;
            _vm.EnrollmentStatus = result switch
            {
                SsoEnrollmentResult.Success => "Device enrollment completed successfully.",
                SsoEnrollmentResult.Canceled => "Device enrollment was canceled by the user.",
                SsoEnrollmentResult.Denied => "Device enrollment was denied from the enrolled device.",
                SsoEnrollmentResult.Failed => "Device enrollment failed due to an error.",
                _ => throw new ArgumentOutOfRangeException(nameof(result)),
            };

            // Clean up resources
            _vm._cancelEnrollmentTcs = null;
            _linkedCancellation.Dispose();
            _internalCancellation.Dispose();

            return Task.CompletedTask;
        }

        private static async Task<Task> WhenAnyWithCancellation(CancellationToken cancellationToken, params Task[] tasks)
        {
            var cancelTcs = new TaskCompletionSource<object>();
            await using (cancellationToken.Register(() => cancelTcs.TrySetCanceled(cancellationToken)))
            {
                var completedTask = await Task.WhenAny(tasks.Append(cancelTcs.Task)).ConfigureAwait(false);

                if (completedTask == cancelTcs.Task)
                    await completedTask.ConfigureAwait(false);

                return completedTask;
            }
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
