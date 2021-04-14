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
                MessageBox.Show(this, "Please login");
                _loggedIn = true;

                listView1.Items.Add("test");
            }
        }

        //
        // Data
        //

        private bool _loggedIn = false;
    }
}
