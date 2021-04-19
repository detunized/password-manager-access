using System;
using System.Linq;
using System.Threading;
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

            duoDevicePanel.Visible = false;
            lastPassAuthPanel.Visible = false;
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

        public async Task<OobResult> ApproveLastPassAuth()
        {
            using var cancelSemaphore = new SemaphoreSlim(0, 1);
            using var continueSemaphore = new SemaphoreSlim(0, 1);

            void cancelHandler(object s, EventArgs e) => cancelSemaphore.Release();
            void continueHandler(object s, EventArgs e) => continueSemaphore.Release();

            lastPassAuthCancel.Click += cancelHandler;
            lastPassAuthContinue.Click += continueHandler;
            lastPassAuthPanel.Visible = true;

            var cancelTask = cancelSemaphore.WaitAsync();
            var continueTask = continueSemaphore.WaitAsync();

            var completedTask = await Task.WhenAny(new[] { cancelTask, continueTask });

            lastPassAuthPanel.Visible = false;
            lastPassAuthCancel.Click -= cancelHandler;
            lastPassAuthContinue.Click -= continueHandler;

            if (completedTask == cancelTask)
            {
                return OobResult.Cancel;
            }

            if (completedTask == continueTask)
                return OobResult.ContinueWithPasscode(lastPassAuthPasscodeInput.Text, lastPassAuthRememberMeCheck.Checked);

            throw new InvalidOperationException("Invalid task?!");
        }

        public async Task<DuoChoice> ChooseDuoFactor(DuoDevice[] devices)
        {
            using var semaphore = new SemaphoreSlim(0, 1);

            duoDevicePick.Items.Clear();
            duoDevicePick.Items.AddRange(devices.Select(x => x.Name).ToArray());
            duoContinue.Enabled = false;
            
            var selectedDevice = devices[0];
            var selectedFactor = selectedDevice.Factors[0];

            EventHandler deviceHandler = (s, e) =>
            {
                selectedDevice = devices[duoDevicePick.SelectedIndex];

                duoFactorPick.Items.Clear();
                duoFactorPick.Items.AddRange(selectedDevice.Factors.Select(x => x.ToString()).ToArray());
                duoFactorPick.SelectedIndex = -1;
                duoFactorPick.ResetText();
                duoContinue.Enabled = false;
            };

            EventHandler factorHandler = (s, e) =>
            {
                selectedFactor = selectedDevice.Factors[duoFactorPick.SelectedIndex];
                duoContinue.Enabled = true;
            };


            EventHandler continueHandler = (s, e) =>
            {
                semaphore.Release();
            };

            duoDevicePick.SelectedIndexChanged += deviceHandler;
            duoFactorPick.SelectedIndexChanged += factorHandler;
            duoContinue.Click += continueHandler;
            duoDevicePanel.Visible = true;

            await semaphore.WaitAsync();

            duoDevicePanel.Visible = false;
            duoDevicePick.SelectedIndexChanged -= deviceHandler;
            duoFactorPick.SelectedIndexChanged -= factorHandler;
            duoContinue.Click -= continueHandler;

            return new DuoChoice(selectedDevice, selectedFactor, duoRememberMeCheck.Checked);
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
            messageLabel.Text = text;
            return Task.CompletedTask;
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
