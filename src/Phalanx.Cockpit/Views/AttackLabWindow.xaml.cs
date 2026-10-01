using System.Windows;
using Phalanx.Cockpit.ViewModels;

namespace Phalanx.Cockpit.Views;

/// <summary>
/// AttackLabWindow.xaml에 대한 상호 작용 논리
/// 독립된 보조 컴패니언 창으로 동작하여 메인 관제 화면과 나란히 띄워두고 공격을 주입하고 실시간 모니터링합니다.
/// </summary>
public partial class AttackLabWindow : Window
{
    public AttackLabWindow()
    {
        InitializeComponent();
    }

    private void MinimizeButton_Click(object sender, RoutedEventArgs e)
    {
        SystemCommands.MinimizeWindow(this);
    }

    private void MaximizeButton_Click(object sender, RoutedEventArgs e)
    {
        if (WindowState == WindowState.Maximized)
        {
            SystemCommands.RestoreWindow(this);
        }
        else
        {
            SystemCommands.MaximizeWindow(this);
        }
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }

    private void ToggleTopmost_Click(object sender, RoutedEventArgs e)
    {
        Topmost = !Topmost;
        if (sender is System.Windows.Controls.Button btn)
        {
            btn.Content = Topmost ? "PINNED (항상 위)" : "PIN (항상 위 고정)";
        }
    }
}
