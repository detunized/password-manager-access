//using Xamarin.Forms;

namespace DropboxPasswordsUi;

public partial class App : Application
{
	public App()
	{
		InitializeComponent();

		//MainPage = new MainPage();
		MainPage = new ContentPage {
			Content = new WebView {
				Source = "https://bing.com"
			},
		};
	}
}
