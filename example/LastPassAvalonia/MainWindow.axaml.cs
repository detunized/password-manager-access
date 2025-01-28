using System.Threading.Tasks;
using Avalonia.Controls;

namespace LastPassAvalonia;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();

        // For some reason the widnow often opens in the background. Bring it to the front!
        Opened += async (_, _) =>
        {
            await Task.Delay(1000);
            Activate();
        };
    }
}
