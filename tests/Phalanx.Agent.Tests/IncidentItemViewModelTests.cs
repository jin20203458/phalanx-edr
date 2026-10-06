using System;
using System.Collections.Generic;
using Phalanx.Cockpit.ViewModels;
using Xunit;

namespace Phalanx.Agent.Tests;

[Trait("Category", "Unit")]
public class IncidentItemViewModelTests
{
    [Fact]
    public void RelativeTime_UtcTimestamp_Recent_ReturnsJustNow()
    {
        var vm = new IncidentItemViewModel
        {
            Timestamp = DateTime.UtcNow.AddSeconds(-20)
        };

        Assert.Equal("방금 전", vm.RelativeTime);
    }

    [Fact]
    public void RelativeTime_UtcTimestamp_MinutesAgo_ReturnsMinutesAgo()
    {
        var vm = new IncidentItemViewModel
        {
            Timestamp = DateTime.UtcNow.AddMinutes(-15)
        };

        Assert.Equal("15분 전", vm.RelativeTime);
    }

    [Fact]
    public void RelativeTime_UtcTimestamp_HoursAgo_ReturnsHoursAgo()
    {
        var vm = new IncidentItemViewModel
        {
            Timestamp = DateTime.UtcNow.AddHours(-3)
        };

        Assert.Equal("3시간 전", vm.RelativeTime);
    }

    [Fact]
    public void RelativeTime_UtcTimestamp_DaysAgo_ReturnsDaysAgo()
    {
        var vm = new IncidentItemViewModel
        {
            Timestamp = DateTime.UtcNow.AddDays(-2)
        };

        Assert.Equal("2일 전", vm.RelativeTime);
    }

    [Fact]
    public void RelativeTime_LocalTimestampFromDb_HoursAgo_ReturnsHoursAgo()
    {
        // LiteDB 역직렬화 시 발생하는 DateTimeKind.Local 시나리오
        var localThreeHoursAgo = DateTime.Now.AddHours(-3);
        Assert.Equal(DateTimeKind.Local, localThreeHoursAgo.Kind);

        var vm = new IncidentItemViewModel
        {
            Timestamp = localThreeHoursAgo
        };

        // 기존 버그에서는 DateTime.UtcNow와 빼서 음수(-330분 등)가 되어 "방금 전"을 반환했음
        // ToUniversalTime() 정규화로 올바르게 "3시간 전"이 계산되어야 함
        Assert.Equal("3시간 전", vm.RelativeTime);
    }

    [Fact]
    public void RelativeTime_LocalTimestampFromDb_MinutesAgo_ReturnsMinutesAgo()
    {
        var localMinutesAgo = DateTime.Now.AddMinutes(-25);
        Assert.Equal(DateTimeKind.Local, localMinutesAgo.Kind);

        var vm = new IncidentItemViewModel
        {
            Timestamp = localMinutesAgo
        };

        Assert.Equal("25분 전", vm.RelativeTime);
    }

    [Fact]
    public void RelativeTime_FutureTimestampClockSkew_ReturnsJustNow()
    {
        // 미세 클럭 오차로 약간 미래 시간(음수 Ticks)이 들어오는 엣지 케이스 방어
        var futureTime = DateTime.UtcNow.AddSeconds(10);

        var vm = new IncidentItemViewModel
        {
            Timestamp = futureTime
        };

        Assert.Equal("방금 전", vm.RelativeTime);
    }

    [Fact]
    public void FormattedTime_LocalConversion_ReturnsFormattedString()
    {
        var testTime = new DateTime(2026, 10, 4, 15, 30, 0, DateTimeKind.Utc);
        var expectedLocal = testTime.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");

        var vm = new IncidentItemViewModel
        {
            Timestamp = testTime
        };

        Assert.Equal(expectedLocal, vm.FormattedTime);
    }

    [Fact]
    public void TimestampPropertyChange_NotifiesFormattedTimeAndRelativeTime()
    {
        var vm = new IncidentItemViewModel();
        var changedProps = new List<string>();
        vm.PropertyChanged += (s, e) =>
        {
            if (e.PropertyName != null)
                changedProps.Add(e.PropertyName);
        };

        vm.Timestamp = DateTime.UtcNow.AddHours(-5);

        Assert.Contains(nameof(IncidentItemViewModel.Timestamp), changedProps);
        Assert.Contains(nameof(IncidentItemViewModel.FormattedTime), changedProps);
        Assert.Contains(nameof(IncidentItemViewModel.RelativeTime), changedProps);
    }
}
