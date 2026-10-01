using System.Windows;
using System.Windows.Input;
using Phalanx.Cockpit.ViewModels;

namespace Phalanx.Cockpit.Views;

public partial class SettingsWindow : Window
{
    public SettingsWindow()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
        Closed += OnWindowClosed;
    }

    private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (e.OldValue is SettingsViewModel oldVm)
        {
            oldVm.RequestClose -= OnRequestClose;
        }
        if (e.NewValue is SettingsViewModel newVm)
        {
            newVm.RequestClose += OnRequestClose;
        }
    }

    private void OnWindowClosed(object? sender, EventArgs e)
    {
        if (DataContext is SettingsViewModel vm)
        {
            vm.RequestClose -= OnRequestClose;
        }
        DataContext = null;
    }

    private void OnRequestClose()
    {
        Close();
    }

    private void Window_MouseDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton == MouseButton.Left && e.ButtonState == MouseButtonState.Pressed)
        {
            DragMove();
        }
    }

    private void MinimizeButton_Click(object sender, RoutedEventArgs e)
    {
        WindowState = WindowState.Minimized;
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }
}
