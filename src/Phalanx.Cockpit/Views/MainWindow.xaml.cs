using System.Windows;
using Phalanx.Cockpit.ViewModels;

namespace Phalanx.Cockpit.Views;

/// <summary>
/// MainWindow.xaml에 대한 상호 작용 논리
/// </summary>
public partial class MainWindow : Window
{
    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }
}
