using CommunityToolkit.Mvvm.ComponentModel;

namespace Phalanx.Cockpit.ViewModels;

/// <summary>
/// Gemini 자율 수사관의 단일 ReAct 턴(Thought -> Action -> Observation) 감사 뷰모델
/// </summary>
public partial class ReActStepViewModel : ObservableObject
{
    [ObservableProperty]
    private int _stepNumber;

    [ObservableProperty]
    private string _actionTool = string.Empty;

    [ObservableProperty]
    private string _thought = string.Empty;

    [ObservableProperty]
    private string _actionArgsJson = string.Empty;

    [ObservableProperty]
    private string _observation = string.Empty;

    public string FormattedStep => $"PHASE {StepNumber:D2} : {ActionTool.ToUpperInvariant()}";
}
