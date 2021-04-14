using System;
using System.Windows.Forms;

namespace LastPassGui
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();

            listView1.Columns.Add("Name");
            listView1.Columns.Add("Username");
            listView1.Columns.Add("Password");
            listView1.Columns.Add("Url");
        }

        protected override void OnActivated(EventArgs e)
        {
            base.OnActivated(e);

            if (!_loggedIn)
            {
                var loginUi = new Form2();
                loginUi.SetDefaults("username", "pazzword");
                loginUi.ShowDialog(this);

                _loggedIn = true;

                var v = loginUi.Vault;
                if (v != null)
                {
                    foreach (var a in v.Accounts)
                    {
                        listView1.Items.Add(new ListViewItem(new[]
                        {
                            a.Name,
                            a.Username,
                            a.Password,
                            a.Url,
                        }));
                    }
                }

            }
        }

        //
        // Data
        //

        private bool _loggedIn = false;
    }
}
