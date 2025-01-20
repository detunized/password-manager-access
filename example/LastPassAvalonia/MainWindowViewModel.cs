// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Threading.Tasks;
using ReactiveUI;

namespace LastPassAvalonia;

public class MainWindowViewModel : ViewModelBase
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

    public async Task Login()
    {
        _isLoggingIn = true;
        this.RaisePropertyChanged(nameof(IsLoginEnabled));

        try
        {
            Status = "Logging in...";
            await Task.Delay(1000);
            Status = "Done";
        }
        finally
        {
            _isLoggingIn = false;
            this.RaisePropertyChanged(nameof(IsLoginEnabled));
        }
    }
}
