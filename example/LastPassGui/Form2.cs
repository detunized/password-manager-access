using System;
using System.Threading.Tasks;
using System.Windows.Forms;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.LastPass;
using PasswordManagerAccess.LastPass.Ui;

namespace LastPassGui
{
    public partial class Form2 : Form, IUi
    {
        public Vault Vault { get; private set; }

        private string _deviceId;
        private string _description;

        public Form2()
        {
            InitializeComponent();
        }

        public void SetDefaults(string username, string password, string deviceId, string description)
        {
            usernameInput.Text = username;
            passwordInput.Text = password;
            _deviceId = deviceId;
            _description = description;
        }

        private async Task Login(string username, string password)
        {
            DisableUi();
            try
            {
                var vault = await Vault.Open(usernameInput.Text,
                                             passwordInput.Text,
                                             new ClientInfo(Platform.Desktop, _deviceId, _description),
                                             this);

                messageLabel.Text = $"Open the vault with {vault.Accounts.Length} accounts";
                Vault = vault;
            }
            catch (BaseException e)
            {
                messageLabel.Text = e.Message;
                EnableUi();
            }
        }

        private void EnableUi(bool enable = true)
        {
            usernameInput.Enabled = enable;
            passwordInput.Enabled = enable;
            loginButton.Enabled = enable;
        }

        private void DisableUi() => EnableUi(false);

        //
        // LastPass.IUi
        //

        public Task<OobResult> ApproveDuo()
        {
            throw new NotImplementedException();
        }

        public Task<OobResult> ApproveLastPassAuth()
        {
            throw new NotImplementedException();
        }

        public Task<DuoChoice> ChooseDuoFactor(DuoDevice[] devices)
        {
            throw new NotImplementedException();
        }

        public Task<string> ProvideDuoPasscode(DuoDevice device)
        {
            throw new NotImplementedException();
        }

        public Task<OtpResult> ProvideGoogleAuthPasscode()
        {
            throw new NotImplementedException();
        }

        public Task<OtpResult> ProvideMicrosoftAuthPasscode()
        {
            throw new NotImplementedException();
        }

        public Task<OtpResult> ProvideYubikeyPasscode()
        {
            throw new NotImplementedException();
        }

        public Task UpdateDuoStatus(DuoStatus status, string text)
        {
            throw new NotImplementedException();
        }

        //
        // UI
        //

        private async void loginButton_Click(object sender, EventArgs e)
        {
            await Login(usernameInput.Text, passwordInput.Text);
            if (Vault == null)
                return;

            await Task.Delay(3000);
            Close();
        }
    }
}
