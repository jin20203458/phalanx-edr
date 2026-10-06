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
            new PropertyMetadata(false, OnEnableThemeTitleBarChanged));

    public static bool GetEnableDarkTitleBar(DependencyObject obj) => (bool)obj.GetValue(EnableDarkTitleBarProperty);
    public static void SetEnableDarkTitleBar(DependencyObject obj, bool value) => obj.SetValue(EnableDarkTitleBarProperty, value);

    private static void OnEnableThemeTitleBarChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is Window window && (bool)e.NewValue)
        {
            if (window.IsLoaded)
            {
                ApplyCurrentThemeTitleBar(window);
            }
            else
            {
                window.SourceInitialized += (s, ev) => ApplyCurrentThemeTitleBar(window);
            }
        }
    }

    /// <summary>
    /// 현재 활성화된 테마 상태(ThemeManager.IsDark)에 맞춰 DWM 타이틀바 모드 적용
    /// </summary>
    public static void ApplyCurrentThemeTitleBar(Window window)
    {
        try
        {
            bool isDark = Services.ThemeManager.Instance.IsDark;
            UpdateImmersiveDarkMode(window, isDark);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[WindowTitleBarBehavior] ApplyCurrentThemeTitleBar 실패: {ex.Message}");
        }
    }

    /// <summary>
    /// 지정된 윈도우의 DWM 심층 다크 모드 속성 동적 갱신 (다크: 1, 라이트: 0)
    /// </summary>
    public static void UpdateImmersiveDarkMode(Window window, bool isDark)
    {
        try
        {
            var helper = new WindowInteropHelper(window);
            var hwnd = helper.Handle;

            if (hwnd == IntPtr.Zero) return;

            // 창 전체 심층 다크/라이트 모드 토글 (Alt+Space 시스템 메뉴, DWM 창 그림자, 스냅 가이드 렌더링)
            int useImmersiveDarkMode = isDark ? 1 : 0;
            if (DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ref useImmersiveDarkMode, sizeof(int)) != 0)
            {
                DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_OLD, ref useImmersiveDarkMode, sizeof(int));
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[WindowTitleBarBehavior] DWM 모드 갱신 실패: {ex.Message}");
        }
    }
}
