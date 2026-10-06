using System.Collections.Specialized;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Phalanx.Cockpit.ViewModels;

namespace Phalanx.Cockpit.Views;

public partial class ProcessGraphView : UserControl
{
    private bool _isScrollPending;

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
            oldVm.VisibleProcesses.CollectionChanged -= OnVisibleProcessesChanged;
        }
        if (e.NewValue is MainViewModel newVm)
        {
            newVm.PropertyChanged += OnViewModelPropertyChanged;
            newVm.VisibleProcesses.CollectionChanged += OnVisibleProcessesChanged;
        }
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainViewModel.SelectedProcessNode) &&
            DataContext is MainViewModel vm &&
            vm.SelectedProcessNode != null)
        {
            AnchorSelectedNode(vm);
        }
    }

    private void OnVisibleProcessesChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (!IsVisible) return;

        if (DataContext is MainViewModel vm &&
            vm.IsSelectionPinned &&
            vm.SelectedProcessNode != null &&
            vm.VisibleProcesses.Contains(vm.SelectedProcessNode))
        {
            AnchorSelectedNode(vm);
        }
    }

    private void AnchorSelectedNode(MainViewModel vm)
    {
        if (_isScrollPending) return;
        _isScrollPending = true;

        Dispatcher.BeginInvoke(DispatcherPriority.Background, () =>
        {
            _isScrollPending = false;
            if (vm.IsSelectionPinned && vm.SelectedProcessNode != null && vm.VisibleProcesses.Contains(vm.SelectedProcessNode))
            {
                ProcessListView.ScrollIntoView(vm.SelectedProcessNode);
            }
        });
    }
}
