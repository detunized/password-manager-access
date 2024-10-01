using PasswordManagerAccess.Example.Common;
using PasswordManagerAccess.ZohoVault;
using PasswordManagerAccess.ZohoVault.Ui;

namespace ZohoVaultMaui;

public partial class MainPage : ContentPage
{
    public MainPage()
    {
        InitializeComponent();
    }

    private async void OnCounterClicked(object sender, EventArgs e)
    {
        try
        {
            CounterBtn.Text = "...";

            var config = await LoadConfig();
            var vault = Vault.Open(
                new Credentials(username: config["username"], password: config["password"], passphrase: config["passphrase"]),
                new Settings { KeepSession = true },
                new InvisibleUi(config["google-auth-totp-secret"]),
                new PrefStorage()
            );

            CounterBtn.Text = $"Got {vault.Accounts.Length} accounts";
        }
        catch (Exception ex)
        {
            CounterBtn.Text = ex.Message;
        }
    }

    private async Task<Dictionary<string, string>> LoadConfig()
    {
        await using var stream = await FileSystem.OpenAppPackageFileAsync("config.yaml").ConfigureAwait(false);
        using var reader = new StreamReader(stream);
        var contents = await reader.ReadToEndAsync().ConfigureAwait(false);
        return Util.ParseConfig(contents);
    }

    private class InvisibleUi(string totpSecret) : BaseUi, IUi
    {
        public Passcode ProvideGoogleAuthPasscode() => new(Util.CalculateGoogleAuthTotp(totpSecret), false);
    }

    private class PrefStorage : PasswordManagerAccess.Common.ISecureStorage
    {
        public string? LoadString(string key) => Preferences.Get(key, null);

        public void StoreString(string key, string? value)
        {
            if (value == null)
                Preferences.Remove(key);
            else
                Preferences.Set(key, value);
        }
    }
}
