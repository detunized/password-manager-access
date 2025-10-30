// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Threading.Tasks;
using Avalonia.Controls;

namespace OnePasswordAvalonia;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();

        // For some reason the window often opens in the background. Bring it to the front!
        Opened += async (_, _) =>
        {
            await Task.Delay(1000);
            Activate();
        };
    }
}
