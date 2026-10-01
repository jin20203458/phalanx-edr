using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using Phalanx.Cockpit.ViewModels;

namespace Phalanx.Cockpit.Views;

public partial class ProcessGraphView : UserControl
{
    public ProcessGraphView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (e.OldValue is MainViewModel oldVm)
        {
            oldVm.PropertyChanged -= OnViewModelPropertyChanged;
        }
        if (e.NewValue is MainViewModel newVm)
        {
            newVm.PropertyChanged += OnViewModelPropertyChanged;
        }
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainViewModel.SelectedProcessNode) &&
            DataContext is MainViewModel vm &&
            vm.SelectedProcessNode != null)
        {
            ProcessListView.ScrollIntoView(vm.SelectedProcessNode);
        }
    }
}
