using System;

namespace DropboxPasswordsUi;

public partial class MainPage : ContentPage
{
	//int count = 0;

	public MainPage()
	{
		InitializeComponent();

		Console.WriteLine("Blah");

		Browser.Navigating += (s, e) => {
			Console.WriteLine(s);
			Console.WriteLine(e.Url);
		};
	}

	private void OnCounterClicked(object sender, EventArgs e)
	{
		//count++;
		//CounterLabel.Text = $"Current count: {count}";

		//SemanticScreenReader.Announce(CounterLabel.Text);
	}
}

