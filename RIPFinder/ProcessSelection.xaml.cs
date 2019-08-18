using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.Diagnostics;

namespace RIPFinder
{
    /// <summary>
    /// ProcessSelection.xaml の相互作用ロジック
    /// </summary>
    public partial class ProcessSelection : Window
    {
        List<ProcessModel> ProcessList { get; set; }
        public Process SelectedProcess { get; set; }
        public ProcessSelection()
        {
            InitializeComponent();
            ProcessList = new List<ProcessModel>();
            var processes = Process.GetProcesses().Where(p => p.MainWindowTitle.Length != 0);
            foreach (var process in processes)
            {


                ProcessList.Add(new ProcessModel
                {
                    Name = process.ProcessName,
                    Process = process
                });
            }
            ListBox_Processes.DataContext = ProcessList;
        }

        private void Button_OpenThisProcess_Click(object sender, RoutedEventArgs e)
        {
            if (ListBox_Processes.SelectedItems.Count == 1)
            {
                var p = ListBox_Processes.SelectedItems[0] as ProcessModel;
                this.SelectedProcess = p.Process;
                DialogResult = true;
            }
        }
    }

    class ProcessModel
    {
        public string Name { get; set; }
        public Process Process { get; set; }
    }
}
