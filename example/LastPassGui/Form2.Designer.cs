
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
            this.loginButton.Location = new System.Drawing.Point(435, 254);
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
            // Form2
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(522, 289);
            this.Controls.Add(this.messageLabel);
            this.Controls.Add(this.loginButton);
            this.Controls.Add(this.passwordInput);
            this.Controls.Add(this.usernameInput);
            this.Name = "Form2";
            this.Text = "Login";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.TextBox usernameInput;
        private System.Windows.Forms.TextBox passwordInput;
        private System.Windows.Forms.Button loginButton;
        private System.Windows.Forms.Label messageLabel;
    }
}
