using System;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace Phalanx.Cockpit.Helpers;

/// <summary>
/// Windows DWM API를 활용하여 윈도우 창 프레임, 드롭 섀도우 및 시스템 메뉴(Alt+Space)를
/// 심층 다크 모드(Immersive Dark Mode)로 일체화하는 Attached Behavior
/// </summary>
public static class WindowTitleBarBehavior
{
    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

    // DWM 속성 상수
    private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;     // Win 10 20H1+ 및 Win 11 다크 모드 강제
    private const int DWMWA_USE_IMMERSIVE_DARK_MODE_OLD = 19; // Win 10 1809 - 1909 호환

    public static readonly DependencyProperty EnableDarkTitleBarProperty =
        DependencyProperty.RegisterAttached(
            "EnableDarkTitleBar",
            typeof(bool),
            typeof(WindowTitleBarBehavior),
            new PropertyMetadata(false, OnEnableDarkTitleBarChanged));

    public static bool GetEnableDarkTitleBar(DependencyObject obj) => (bool)obj.GetValue(EnableDarkTitleBarProperty);
    public static void SetEnableDarkTitleBar(DependencyObject obj, bool value) => obj.SetValue(EnableDarkTitleBarProperty, value);

    private static void OnEnableDarkTitleBarChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is Window window && (bool)e.NewValue)
        {
            if (window.IsLoaded)
            {
                ApplyDarkThemeTitleBar(window);
            }
            else
            {
                window.SourceInitialized += (s, ev) => ApplyDarkThemeTitleBar(window);
            }
        }
    }

    public static void ApplyDarkThemeTitleBar(Window window)
    {
        try
        {
            var helper = new WindowInteropHelper(window);
            var hwnd = helper.Handle;

            if (hwnd == IntPtr.Zero) return;

            // 창 전체 심층 다크 모드 활성화 (Alt+Space 시스템 메뉴, DWM 창 그림자, 스냅 가이드 다크 렌더링)
            int useImmersiveDarkMode = 1;
            if (DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ref useImmersiveDarkMode, sizeof(int)) != 0)
            {
                DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_OLD, ref useImmersiveDarkMode, sizeof(int));
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[WindowTitleBarBehavior] DWM 다크 모드 적용 실패: {ex.Message}");
        }
    }
}
