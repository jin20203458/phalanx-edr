using Xunit;

// WPF UI 요소(Application.Current, ThemeManager, WindowChrome 등)의 전역 상태 격리를 위해 단위 테스트 직렬 실행 보장
[assembly: CollectionBehavior(DisableTestParallelization = true)]
