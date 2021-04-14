
namespace LastPassGui
{
    partial class Form2
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.usernameInput = new System.Windows.Forms.TextBox();
            this.passwordInput = new System.Windows.Forms.TextBox();
            this.loginButton = new System.Windows.Forms.Button();
            this.messageLabel = new System.Windows.Forms.Label();
            this.label1 = new System.Windows.Forms.Label();
            this.duoDevicePick = new System.Windows.Forms.ComboBox();
            this.duoContinue = new System.Windows.Forms.Button();
            this.duoDevicePanel = new System.Windows.Forms.Panel();
            this.duoRememberMeCheck = new System.Windows.Forms.CheckBox();
            this.label2 = new System.Windows.Forms.Label();
            this.duoFactorPick = new System.Windows.Forms.ComboBox();
            this.duoDevicePanel.SuspendLayout();
            this.SuspendLayout();
            // 
            // usernameInput
            // 
            this.usernameInput.Location = new System.Drawing.Point(13, 13);
            this.usernameInput.Name = "usernameInput";
            this.usernameInput.Size = new System.Drawing.Size(497, 23);
            this.usernameInput.TabIndex = 0;
            // 
            // passwordInput
            // 
            this.passwordInput.Location = new System.Drawing.Point(13, 43);
            this.passwordInput.Name = "passwordInput";
            this.passwordInput.Size = new System.Drawing.Size(497, 23);
            this.passwordInput.TabIndex = 1;
            // 
            // loginButton
            // 
            this.loginButton.Location = new System.Drawing.Point(435, 222);
            this.loginButton.Name = "loginButton";
            this.loginButton.Size = new System.Drawing.Size(75, 23);
            this.loginButton.TabIndex = 2;
            this.loginButton.Text = "Login";
            this.loginButton.UseVisualStyleBackColor = true;
            this.loginButton.Click += new System.EventHandler(this.loginButton_Click);
            // 
            // messageLabel
            // 
            this.messageLabel.AutoSize = true;
            this.messageLabel.Location = new System.Drawing.Point(13, 73);
            this.messageLabel.Name = "messageLabel";
            this.messageLabel.Size = new System.Drawing.Size(16, 15);
            this.messageLabel.TabIndex = 3;
            this.messageLabel.Text = "...";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(0, 24);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(69, 15);
            this.label1.TabIndex = 4;
            this.label1.Text = "Duo device:";
            // 
            // duoDevicePick
            // 
            this.duoDevicePick.FormattingEnabled = true;
            this.duoDevicePick.Location = new System.Drawing.Point(75, 24);
            this.duoDevicePick.Name = "duoDevicePick";
            this.duoDevicePick.Size = new System.Drawing.Size(191, 23);
            this.duoDevicePick.TabIndex = 5;
            // 
            // duoContinue
            // 
            this.duoContinue.Location = new System.Drawing.Point(191, 83);
            this.duoContinue.Name = "duoContinue";
            this.duoContinue.Size = new System.Drawing.Size(75, 23);
            this.duoContinue.TabIndex = 6;
            this.duoContinue.Text = "Continue";
            this.duoContinue.UseVisualStyleBackColor = true;
            // 
            // duoDevicePanel
            // 
            this.duoDevicePanel.Controls.Add(this.duoRememberMeCheck);
            this.duoDevicePanel.Controls.Add(this.label2);
            this.duoDevicePanel.Controls.Add(this.label1);
            this.duoDevicePanel.Controls.Add(this.duoContinue);
            this.duoDevicePanel.Controls.Add(this.duoFactorPick);
            this.duoDevicePanel.Controls.Add(this.duoDevicePick);
            this.duoDevicePanel.Location = new System.Drawing.Point(13, 91);
            this.duoDevicePanel.Name = "duoDevicePanel";
            this.duoDevicePanel.Size = new System.Drawing.Size(497, 125);
            this.duoDevicePanel.TabIndex = 7;
            // 
            // duoRememberMeCheck
            // 
            this.duoRememberMeCheck.AutoSize = true;
            this.duoRememberMeCheck.Location = new System.Drawing.Point(75, 83);
            this.duoRememberMeCheck.Name = "duoRememberMeCheck";
            this.duoRememberMeCheck.Size = new System.Drawing.Size(104, 19);
            this.duoRememberMeCheck.TabIndex = 7;
            this.duoRememberMeCheck.Text = "Remember me";
            this.duoRememberMeCheck.UseVisualStyleBackColor = true;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(3, 57);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(66, 15);
            this.label2.TabIndex = 4;
            this.label2.Text = "Duo factor:";
            // 
            // duoFactorPick
            // 
            this.duoFactorPick.FormattingEnabled = true;
            this.duoFactorPick.Location = new System.Drawing.Point(75, 54);
            this.duoFactorPick.Name = "duoFactorPick";
            this.duoFactorPick.Size = new System.Drawing.Size(191, 23);
            this.duoFactorPick.TabIndex = 5;
            // 
            // Form2
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(522, 254);
            this.Controls.Add(this.duoDevicePanel);
            this.Controls.Add(this.messageLabel);
            this.Controls.Add(this.loginButton);
            this.Controls.Add(this.passwordInput);
            this.Controls.Add(this.usernameInput);
            this.Name = "Form2";
            this.Text = "Login";
            this.duoDevicePanel.ResumeLayout(false);
            this.duoDevicePanel.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.TextBox usernameInput;
        private System.Windows.Forms.TextBox passwordInput;
        private System.Windows.Forms.Button loginButton;
        private System.Windows.Forms.Label messageLabel;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.ComboBox duoDevicePick;
        private System.Windows.Forms.Button duoContinue;
        private System.Windows.Forms.Panel duoDevicePanel;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.ComboBox comboBox1;
        private System.Windows.Forms.ComboBox duoFactorPick;
        private System.Windows.Forms.CheckBox duoRememberMeCheck;
    }
}
