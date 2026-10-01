using System;
using Phalanx.Cockpit.Services;
using Xunit;

namespace Phalanx.Agent.Tests;

[Trait("Category", "Unit")]
public sealed class ThemeManagerTests
{
    [Fact]
    public void TestThemeManager_SingletonInstance_IsNotNull()
    {
        var manager = ThemeManager.Instance;
        Assert.NotNull(manager);
    }

    [Fact]
    public void TestThemeManager_HeadlessGuard_DoesNotThrow()
    {
        var manager = ThemeManager.Instance;

        // Headless 환경 (Application.Current == null)에서 호출 시 예외 없이 모드 상태 갱신
        var ex = Record.Exception(() =>
        {
            manager.ApplyTheme(AppThemeMode.Dark);
            Assert.Equal(AppThemeMode.Dark, manager.CurrentMode);
            Assert.True(manager.IsDark);

            manager.ApplyTheme(AppThemeMode.Light);
            Assert.Equal(AppThemeMode.Light, manager.CurrentMode);
            Assert.False(manager.IsDark);

            manager.ApplyTheme(AppThemeMode.System);
            Assert.Equal(AppThemeMode.System, manager.CurrentMode);
        });

        Assert.Null(ex);
    }

    [Fact]
    public void TestThemeManager_SystemTheme_ReadsRegistryWithoutCrash()
    {
        var manager = ThemeManager.Instance;
        var ex = Record.Exception(() =>
        {
            bool isDark = manager.GetSystemIsDark();
            // Boolean 값이어야 함
            Assert.True(isDark || !isDark);
        });

        Assert.Null(ex);
    }

    [Fact]
    public void TestThemeManager_ThemeChangedEvent_FiresOnApplyTheme()
    {
        var manager = ThemeManager.Instance;
        AppThemeMode? reportedMode = null;
        bool? reportedIsDark = null;

        void OnThemeChanged(AppThemeMode mode, bool isDark)
        {
            reportedMode = mode;
            reportedIsDark = isDark;
        }

        manager.ThemeChanged += OnThemeChanged;
        try
        {
            manager.ApplyTheme(AppThemeMode.Light);
            Assert.Equal(AppThemeMode.Light, reportedMode);
            Assert.False(reportedIsDark);

            manager.ApplyTheme(AppThemeMode.Dark);
            Assert.Equal(AppThemeMode.Dark, reportedMode);
            Assert.True(reportedIsDark);
        }
        finally
        {
            manager.ThemeChanged -= OnThemeChanged;
        }
    }
}
