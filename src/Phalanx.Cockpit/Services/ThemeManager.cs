using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows;
using Microsoft.Win32;
using Phalanx.Cockpit.Config;
using Phalanx.Cockpit.Helpers;

namespace Phalanx.Cockpit.Services;

/// <summary>
/// 애플리케이션 테마 모드 열거형
/// </summary>
public enum AppThemeMode
{
    System = 0,
    Dark = 1,
    Light = 2
}

/// <summary>
/// Phalanx Cockpit 실시간 동적 테마 관리자 (Singleton)
/// - OS 테마 실시간 추적(SystemEvents.UserPreferenceChanged)
/// - UI 스레드 안전 Dispatcher 마샬링
/// - Palettes (DarkPalette.xaml / LightPalette.xaml) 초고속 0ms 스왑
/// - DWM Immersive Dark Mode 동적 연동 및 Headless 방어
/// </summary>
public sealed class ThemeManager : IDisposable
{
    private static readonly Lazy<ThemeManager> _lazyInstance = new(() => new ThemeManager());
    public static ThemeManager Instance => _lazyInstance.Value;

    private const string RegistryKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";
    private const string RegistryValueName = "AppsUseLightTheme";

    private bool _isDisposed;
    private AppThemeMode _currentMode = AppThemeMode.System;
    private bool _isDark = true;

    public AppThemeMode CurrentMode => _currentMode;
    public bool IsDark => _isDark;

    public event Action<AppThemeMode, bool>? ThemeChanged;

    private ThemeManager()
    {
        try
        {
            // Windows OS 테마 변경 브로드캐스트 이벤트 구독
            SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[ThemeManager] SystemEvents 구독 실패: {ex.Message}");
        }
    }

    /// <summary>
    /// 앱 기동 시 저장된 설정 파일로부터 테마 복원 및 초기화
    /// </summary>
    public void Initialize()
    {
        var savedMode = LoadSavedThemeMode();
        ApplyTheme(savedMode);
    }

    /// <summary>
    /// 테마 모드 적용 (System, Dark, Light)
    /// </summary>
    public void ApplyTheme(AppThemeMode mode)
    {
        _currentMode = mode;
        bool targetIsDark = mode switch
        {
            AppThemeMode.Dark => true,
            AppThemeMode.Light => false,
            _ => GetSystemIsDark()
        };

        ApplyThemeInternal(targetIsDark);
    }

    private void ApplyThemeInternal(bool targetIsDark)
    {
        _isDark = targetIsDark;

        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher != null && dispatcher.Thread.IsAlive && !dispatcher.HasShutdownStarted)
        {
            if (dispatcher.CheckAccess())
            {
                ExecutePaletteSwap(targetIsDark);
            }
            else
            {
                dispatcher.InvokeAsync(() => ExecutePaletteSwap(targetIsDark));
            }
        }
        else
        {
            // Headless / 단위 테스트 환경 (Dispatcher 스레드가 없거나 이미 종료됨)
            ThemeChanged?.Invoke(_currentMode, _isDark);
        }
    }

    private void ExecutePaletteSwap(bool targetIsDark)
    {
        try
        {
            var mergedDictionaries = Application.Current?.Resources?.MergedDictionaries;
            if (mergedDictionaries != null && mergedDictionaries.Count > 0)
            {
                string palettePath = targetIsDark
                    ? "pack://application:,,,/Phalanx.Cockpit;component/Themes/Palettes/DarkPalette.xaml"
                    : "pack://application:,,,/Phalanx.Cockpit;component/Themes/Palettes/LightPalette.xaml";

                var newPalette = new ResourceDictionary
                {
                    Source = new Uri(palettePath, UriKind.Absolute)
                };

                // Index 0에 위치한 활성 팔레트 교체 (Order Contract)
                mergedDictionaries[0] = newPalette;

                // 모든 열린 윈도우의 DWM 속성 동기화
                UpdateAllWindowsTitleBar(targetIsDark);
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[ThemeManager] 팔레트 스왑 실패: {ex.Message}");
        }
        finally
        {
            ThemeChanged?.Invoke(_currentMode, _isDark);
        }
    }

    /// <summary>
    /// OS 레지스트리를 조회하여 Windows 시스템 테마가 다크 모드인지 확인
    /// </summary>
    public bool GetSystemIsDark()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RegistryKeyPath);
            var registryValue = key?.GetValue(RegistryValueName);

            if (registryValue is int value)
            {
                // 0: Dark, 1: Light
                return value == 0;
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[ThemeManager] 레지스트리 조회 실패: {ex.Message}");
        }

        // 기본값: 보안 관제 콘솔 특성상 안전하게 다크 모드로 폴백
        return true;
    }

    private void OnUserPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
    {
        if (e.Category == UserPreferenceCategory.General || e.Category == UserPreferenceCategory.Color)
        {
            // 시스템 연동 모드일 때만 실시간 반응
            if (_currentMode == AppThemeMode.System)
            {
                var dispatcher = Application.Current?.Dispatcher;
                if (dispatcher != null && dispatcher.Thread.IsAlive && !dispatcher.HasShutdownStarted)
                {
                    dispatcher.InvokeAsync(() =>
                    {
                        if (_currentMode == AppThemeMode.System)
                        {
                            ApplyThemeInternal(GetSystemIsDark());
                        }
                    });
                }
            }
        }
    }

    /// <summary>
    /// 열려 있는 모든 창의 DWM 타이틀바 테마를 실시간 갱신
    /// </summary>
    public void UpdateAllWindowsTitleBar(bool isDark)
    {
        try
        {
            if (Application.Current?.Windows == null) return;

            foreach (Window window in Application.Current.Windows)
            {
                if (window.IsLoaded)
                {
                    WindowTitleBarBehavior.UpdateImmersiveDarkMode(window, isDark);
                }
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[ThemeManager] DWM 타이틀바 갱신 실패: {ex.Message}");
        }
    }

    private static AppThemeMode LoadSavedThemeMode()
    {
        try
        {
            var themeStr = PhalanxConfigurationManager.Current.Theme;
            if (!string.IsNullOrWhiteSpace(themeStr) && Enum.TryParse<AppThemeMode>(themeStr, true, out var mode))
            {
                return mode;
            }
        }
        catch
        {
            // 파싱 실패 시 기본 시스템 설정 유지
        }

        return AppThemeMode.System;
    }

    public void Dispose()
    {
        if (!_isDisposed)
        {
            _isDisposed = true;
            try
            {
                SystemEvents.UserPreferenceChanged -= OnUserPreferenceChanged;
            }
            catch { }
            GC.SuppressFinalize(this);
        }
    }
}
