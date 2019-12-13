using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;

namespace RIPFinder
{
    /// <summary>
    /// MainWindow.xaml の相互作用ロジック
    /// </summary>
    public partial class MainWindow : Window
    {
        Process TargetProcess { get; set; }
        public MainWindow()
        {
            InitializeComponent();
        }

        private void Button_SelectProcess_Click(object sender, RoutedEventArgs e)
        {
            ProcessSelection processSelection = new ProcessSelection();
            Nullable<bool> dialogResult = processSelection.ShowDialog();
            if (dialogResult == true)
            {
                if (processSelection.SelectedProcess != null)
                {
                    TargetProcess = processSelection.SelectedProcess;
                    TextBox_ProcessName.Text = processSelection.SelectedProcess.ProcessName;
                    DataGrid_RIP.ItemsSource = null;
                    TextBox_Log.Clear();
                }
            }
        }

        private async void Button_StartScan_Click(object sender, RoutedEventArgs e)
        {
            if (TargetProcess == null) { return; }

            List<RIPEntry> entries = new List<RIPEntry>();
            Stopwatch stopwatch = new Stopwatch();
            TextBox_Log.Clear();

            Button_SelectProcess.IsEnabled = false;
            Button_StartScan.IsEnabled = false;
            TextBox_FilterString.IsEnabled = false;
            CheckBox_AllModules.IsEnabled = false;
            Button_SaveDump.IsEnabled = false;
            Button_ExportResults.IsEnabled = false;

            List<string> filters = new List<string>();
            if (!string.IsNullOrWhiteSpace(TextBox_FilterString.Text))
            {
                filters.Add(TextBox_FilterString.Text);
                filters.Add(TextBox_FilterString.Text.PadLeft(16, '0'));

                if (Int64.TryParse(TextBox_FilterString.Text, out Int64 out1))
                {
                    filters.Add(out1.ToString());
                }
                if (Int64.TryParse(TextBox_FilterString.Text, NumberStyles.HexNumber, new CultureInfo("en-US"), out Int64 out2))
                {
                    filters.Add(out2.ToString());
                }
            }

            foreach (var f in filters)
            {
                TextBox_Log.AppendText($"filter: {f}" + "\r\n");
            }

            bool searchFromAllModules = CheckBox_AllModules.IsChecked ?? false;

            List<ProcessModule> ProcessModules = new List<ProcessModule>();

            if (searchFromAllModules)
            {
                foreach (ProcessModule m in TargetProcess.Modules)
                {
                    ProcessModules.Add(m);
                }

            }
            else
            {
                ProcessModules.Add(TargetProcess.MainModule);
            }


            var task = Task.Run(() =>
            {
                foreach (var m in ProcessModules)
                {
                    int moduleMemorySize = m.ModuleMemorySize;
                    IntPtr startAddres = m.BaseAddress;
                    IntPtr endAddres = new IntPtr(m.BaseAddress.ToInt64() + moduleMemorySize);

                    this.Dispatcher.Invoke((Action)(() =>
                    {
                        TextBox_Log.AppendText($"----------------------------------------------------" + "\r\n");

                        TextBox_Log.AppendText($"Module Name: {m.ModuleName}" + "\r\n");
                        TextBox_Log.AppendText($"File Name: {m.FileName}" + "\r\n");
                        TextBox_Log.AppendText($"Module Size: {moduleMemorySize.ToString("#,0")} Byte" + "\r\n");
                        TextBox_Log.AppendText($"Start Address: {startAddres.ToInt64().ToString("X2")} + ({startAddres.ToInt64()})" + "\r\n");
                        TextBox_Log.AppendText($"End Address  : {endAddres.ToInt64().ToString("X2")} + ({endAddres.ToInt64()})" + "\r\n");
                        TextBox_Log.AppendText($"Scan started. Please wait..." + "  ");

                    }));

                    stopwatch.Start();

                    IntPtr currentAddress = startAddres;
                    int bufferSize = 1 * 1024 * 1024;
                    byte[] buffer = new byte[bufferSize];

                    while (currentAddress.ToInt64() < endAddres.ToInt64())
                    {

                        // size
                        IntPtr nSize = new IntPtr(bufferSize);

                        // if remaining memory size is less than splitSize, change nSize to remaining size
                        if (IntPtr.Add(currentAddress, bufferSize).ToInt64() > endAddres.ToInt64())
                        {
                            nSize = (IntPtr)(endAddres.ToInt64() - currentAddress.ToInt64());
                        }

                        IntPtr numberOfBytesRead = IntPtr.Zero;
                        if (Helper.ReadProcessMemory(TargetProcess.Handle, currentAddress, buffer, nSize, ref numberOfBytesRead))
                        {

                            for (int i = 0; i < numberOfBytesRead.ToInt64() - 4; i++)
                            {
                                var entry = new RIPEntry();
                                entry.Address = new IntPtr(currentAddress.ToInt64() + i);
                                entry.AddressValueInt64 = BitConverter.ToInt32(buffer, i);
                                entry.TargetAddress = new IntPtr(entry.Address.ToInt64() + entry.AddressValueInt64 + 4);


                                if (entry.TargetAddress.ToInt64() < startAddres.ToInt64() || entry.TargetAddress.ToInt64() > endAddres.ToInt64())
                                {
                                    continue;
                                }

                                entry.AddressRelativeString = m.ModuleName + "+0x" + (entry.Address.ToInt64() - startAddres.ToInt64()).ToString("X2");
                                entry.TargetAddressRelativeString = m.ModuleName + "+0x" + (entry.TargetAddress.ToInt64() - startAddres.ToInt64()).ToString("X2");

                                entry.TargetAddressValue = Helper.GetByteArray(TargetProcess, entry.TargetAddress, 8);

                                if (filters.Any() &&
                                !filters.Any(x => x == entry.TargetAddressString) &&
                                !filters.Any(x => x == entry.TargetAddressValueHexString))
                                {
                                    continue;
                                }

                                entries.Add(entry);

                            }
                        }
                        if ((currentAddress.ToInt64() + numberOfBytesRead.ToInt64()) == endAddres.ToInt64())
                        {
                            currentAddress = new IntPtr(currentAddress.ToInt64() + numberOfBytesRead.ToInt64());
                        }
                        else
                        {
                            currentAddress = new IntPtr(currentAddress.ToInt64() + numberOfBytesRead.ToInt64() - 4);
                        }
                    }

                    stopwatch.Stop();

                    this.Dispatcher.Invoke((Action)(() =>
                    {
                        DataGrid_RIP.ItemsSource = entries;

                        TextBox_Log.AppendText($"Complete." + "\r\n");
                        TextBox_Log.AppendText($"Result Count: {entries.Count.ToString("#,0")}" + "\r\n");
                        TextBox_Log.AppendText($"Scan Time: {stopwatch.ElapsedMilliseconds}ms" + "\r\n");
                    }));
                }

            });

            await task;

            Button_SelectProcess.IsEnabled = true;
            Button_StartScan.IsEnabled = true;
            TextBox_FilterString.IsEnabled = true;
            CheckBox_AllModules.IsEnabled = true;
            Button_SaveDump.IsEnabled = true;
            Button_ExportResults.IsEnabled = true;
        }

        private void DataGrid_RIP_CopyAddress(object sender, RoutedEventArgs e)
        {
            RIPEntry entry = this.DataGrid_RIP.SelectedItem as RIPEntry;
            if (entry != null)
            {
                try
                {
                    Clipboard.SetDataObject(entry.AddressString);
                }
                catch
                { }
            }
        }

        private async void Button_SaveDump_Click(object sender, RoutedEventArgs e)
        {
            if (TargetProcess == null) { return; }

            var dialog = new SaveFileDialog();
            dialog.Filter = "binary file (*.bin)|*.bin|all files (*.*)|*.*";
            if (dialog.ShowDialog() == true)
            {
                Button_SelectProcess.IsEnabled = false;
                Button_StartScan.IsEnabled = false;
                TextBox_FilterString.IsEnabled = false;
                CheckBox_AllModules.IsEnabled = false;
                Button_SaveDump.IsEnabled = false;
                Button_ExportResults.IsEnabled = false;

                var task = Task.Run(() =>
                {

                    var binFile = dialog.FileName;
                    System.IO.FileStream binFs = new System.IO.FileStream(binFile, System.IO.FileMode.Create, System.IO.FileAccess.Write);
                    System.IO.StreamWriter txt128Sr = new System.IO.StreamWriter(binFile + ".128.txt", false, System.Text.Encoding.ASCII);

                    int moduleMemorySize = TargetProcess.MainModule.ModuleMemorySize;
                    IntPtr startAddres = TargetProcess.MainModule.BaseAddress;
                    IntPtr endAddres = new IntPtr(TargetProcess.MainModule.BaseAddress.ToInt64() + moduleMemorySize);

                    IntPtr currentAddress = startAddres;
                    int bufferSize = 1 * 1024 * 1024;
                    byte[] buffer = new byte[bufferSize];


                    while (currentAddress.ToInt64() < endAddres.ToInt64())
                    {
                        // size
                        IntPtr nSize = new IntPtr(bufferSize);

                        // if remaining memory size is less than splitSize, change nSize to remaining size
                        if (IntPtr.Add(currentAddress, bufferSize).ToInt64() > endAddres.ToInt64())
                        {
                            nSize = (IntPtr)(endAddres.ToInt64() - currentAddress.ToInt64());
                        }

                        IntPtr numberOfBytesRead = IntPtr.Zero;
                        if (Helper.ReadProcessMemory(TargetProcess.Handle, currentAddress, buffer, nSize, ref numberOfBytesRead))
                        {
                            binFs.Write(buffer, 0, numberOfBytesRead.ToInt32());

                            byte[] b = new byte[numberOfBytesRead.ToInt32()];
                            Array.Copy(buffer, 0, b, 0, numberOfBytesRead.ToInt32());
                            var t = System.Text.RegularExpressions.Regex.Replace(BitConverter.ToString(b).Replace("-", ""), @"(?<=\G.{128})(?!$)", Environment.NewLine);
                            txt128Sr.Write(t);


                        }


                        currentAddress = new IntPtr(currentAddress.ToInt64() + numberOfBytesRead.ToInt64());
                    }
                    binFs.Close();
                    txt128Sr.Close();
                });

                await task;

                MessageBox.Show("Complete.");

                Button_SelectProcess.IsEnabled = true;
                Button_StartScan.IsEnabled = true;
                TextBox_FilterString.IsEnabled = true;
                CheckBox_AllModules.IsEnabled = true;
                Button_SaveDump.IsEnabled = true;
                Button_ExportResults.IsEnabled = true;

            }
        }

        private async void Button_ExportResults_Click(object sender, RoutedEventArgs e)
        {
            if (this.DataGrid_RIP == null) { return; }
            if (this.DataGrid_RIP.Items == null) { return; }

            var dialog = new SaveFileDialog();
            dialog.Filter = "txt file (*.txt)|*.txt|all files (*.*)|*.*";
            if (dialog.ShowDialog() == true)
            {
                Button_SelectProcess.IsEnabled = false;
                Button_StartScan.IsEnabled = false;
                TextBox_FilterString.IsEnabled = false;
                CheckBox_AllModules.IsEnabled = false;
                Button_SaveDump.IsEnabled = false;
                Button_ExportResults.IsEnabled = false;

                var task = Task.Run(() =>
                {
                    var file = dialog.FileName;
                    System.IO.StreamWriter sr = new System.IO.StreamWriter(file, false, System.Text.Encoding.ASCII);

                    foreach (var item in this.DataGrid_RIP.Items)
                    {
                        RIPEntry entry = item as RIPEntry;
                        string csv = "";
                        csv += String.Format("{0, -30}", entry.AddressRelativeString) + " ";
                        csv += String.Format("{0, -20}", entry.AddressString) + " ";
                        csv += String.Format("{0, -30}", entry.TargetAddressRelativeString) + " ";
                        csv += String.Format("{0, -20}", entry.TargetAddressString) + " ";
                        csv += String.Format("{0, 20}", entry.TargetAddressValueHexString) + Environment.NewLine;
                        sr.Write(csv);
                    }

                    sr.Close();
                });

                await task;
                MessageBox.Show("Complete.");
                Button_SelectProcess.IsEnabled = true;
                Button_StartScan.IsEnabled = true;
                TextBox_FilterString.IsEnabled = true;
                CheckBox_AllModules.IsEnabled = true;
                Button_SaveDump.IsEnabled = true;
                Button_ExportResults.IsEnabled = true;
            }
        }
    }

    public class Module
    {
        public IntPtr startAddres { get; set; } = IntPtr.Zero;
        public IntPtr endAddres { get; set; } = IntPtr.Zero;
    }
    public class RIPEntry
    {
        public IntPtr Address { get; set; } = IntPtr.Zero;
        public string AddressString => Address.ToInt64().ToString("X2");
        public string AddressRelativeString { get; set; }
        public Int64 AddressValueInt64 { get; set; } = 0;
        public IntPtr TargetAddress { get; set; } = IntPtr.Zero;
        public string TargetAddressString => TargetAddress.ToInt64().ToString("X2");
        public string TargetAddressRelativeString { get; set; }
        public byte[] TargetAddressValue { get; set; } = null;
        public string TargetAddressValueHexString => BitConverter.ToString(TargetAddressValue).Replace("-", "");

    }
}
