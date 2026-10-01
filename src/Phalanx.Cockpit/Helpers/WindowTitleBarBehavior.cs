using System;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace Phalanx.Cockpit.Helpers;

/// <summary>
/// Windows DWM API를 활용하여 윈도우 타이틀바를 앱 테마와 일체화(Seamless)하는 Attached Behavior
/// </summary>
public static class WindowTitleBarBehavior
{
    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

    // DWM 속성 상수
    private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;     // Win 10 20H1+ 및 Win 11 다크 모드 강제
    private const int DWMWA_USE_IMMERSIVE_DARK_MODE_OLD = 19; // Win 10 1809 - 1909 호환
    private const int DWMWA_CAPTION_COLOR = 35;               // Win 11 빌드 22000+ 타이틀바 배경색 (BGR)
    private const int DWMWA_TEXT_COLOR = 36;                  // Win 11 빌드 22000+ 타이틀바 텍스트색 (BGR)

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

            // 1. 창 전체 다크 모드 활성화 (비활성 시에도 흰색으로 풀리지 않도록 방지)
            int useImmersiveDarkMode = 1;
            if (DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ref useImmersiveDarkMode, sizeof(int)) != 0)
            {
                DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_OLD, ref useImmersiveDarkMode, sizeof(int));
            }

            // 2. 타이틀바 배경색: Phalanx SurfaceBrush(#13161F) -> BGR(0x001F1613)
            int captionColor = 0x001F1613;
            DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, ref captionColor, sizeof(int));

            // 3. 타이틀바 텍스트색: Phalanx TextPrimaryBrush(#F1F5F9) -> BGR(0x00F9F5F1)
            int textColor = 0x00F9F5F1;
            DwmSetWindowAttribute(hwnd, DWMWA_TEXT_COLOR, ref textColor, sizeof(int));
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[WindowTitleBarBehavior] DWM 타이틀바 테마 적용 실패: {ex.Message}");
        }
    }
}
