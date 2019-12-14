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

        private void SetUI(bool isEnabled)
        {
            Button_SelectProcess.IsEnabled = isEnabled;
            Button_StartScan.IsEnabled = isEnabled;
            TextBox_FilterString.IsEnabled = isEnabled;
            CheckBox_AllModules.IsEnabled = isEnabled;
            Button_SaveDump.IsEnabled = isEnabled;
            Button_ExportResults.IsEnabled = isEnabled;
            TextBox_Signature.IsEnabled = isEnabled;
            TextBox_Offset1.IsEnabled = isEnabled;
            TextBox_LogScan.IsEnabled = isEnabled;
            Button_SignatureScan.IsEnabled = isEnabled;
            
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

            SetUI(false);

            List<string> filters = new List<string>();
            if (!string.IsNullOrWhiteSpace(TextBox_FilterString.Text))
            {
                var filterStrings = TextBox_FilterString.Text.Split(',');
                foreach (var filterString in filterStrings)
                {
                    var str = filterString.Trim();
                    filters.Add(str);

                    if (Int64.TryParse(str, out Int64 out1))
                    {
                        filters.Add(out1.ToString("X"));
                    }

                    if (Int64.TryParse(str, NumberStyles.HexNumber, new CultureInfo("en-US"), out Int64 out2))
                    {
                        filters.Add(out2.ToString("X"));
                        filters.Add(out2.ToString("X").PadLeft(16, '0'));
                    }
                }
            }

            filters = filters.Distinct().ToList();

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
                        TextBox_Log.AppendText($"Start Address: {startAddres.ToInt64().ToString("X2")} ({startAddres.ToInt64()})" + "\r\n");
                        TextBox_Log.AppendText($"End Address  : {endAddres.ToInt64().ToString("X2")} ({endAddres.ToInt64()})" + "\r\n");
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

                                var offsetString1 = (entry.Address.ToInt64() - startAddres.ToInt64()).ToString("X");
                                if (offsetString1.Length % 2 == 1) offsetString1 = "0" + offsetString1;
                                entry.AddressRelativeString = '"' + m.ModuleName + '"' + "+" + offsetString1;

                                var offsetString2 = (entry.TargetAddress.ToInt64() - startAddres.ToInt64()).ToString("X");
                                if (offsetString2.Length % 2 == 1) offsetString2 = "0" + offsetString2;
                                entry.TargetAddressRelativeString = '"' + m.ModuleName + '"' + "+" + offsetString2;

                                if (filters.Any() &&
                                !filters.Any(x => x == entry.TargetAddressString) &&
                                !filters.Any(x => x == entry.TargetAddressRelativeString))
                                {
                                    continue;
                                }

                                // Signature
                                int bufferSize2 = 64;
                                byte[] buffer2 = new byte[bufferSize2];
                                IntPtr nSize2 = new IntPtr(bufferSize2);
                                IntPtr numberOfBytesRead2 = IntPtr.Zero;
                                if (Helper.ReadProcessMemory(TargetProcess.Handle, new IntPtr(entry.Address.ToInt64() - bufferSize2), buffer2, nSize2, ref numberOfBytesRead2))
                                {
                                    if (numberOfBytesRead2.ToInt64() == bufferSize2)
                                    {
                                        entry.Signature = BitConverter.ToString(buffer2).Replace("-", "");
                                    }
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

            SetUI(true);
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
                SetUI(false);

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

                SetUI(true);
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
                SetUI(false);

                var task = Task.Run(() =>
                {
                    var file = dialog.FileName;
                    System.IO.StreamWriter sr = new System.IO.StreamWriter(file, false, System.Text.Encoding.ASCII);

                    foreach (var item in this.DataGrid_RIP.Items)
                    {
                        RIPEntry entry = item as RIPEntry;
                        string csv = "";
                        csv += String.Format("{0, -30}", entry.AddressRelativeString) + " ";
                        csv += String.Format("{0, -16}", entry.AddressString) + " ";
                        csv += String.Format("{0, -30}", entry.TargetAddressRelativeString) + " ";
                        csv += String.Format("{0, -16}", entry.TargetAddressString) + " ";
                        csv += String.Format("{0, -64}", entry.Signature) + Environment.NewLine;
                        sr.Write(csv);
                    }

                    sr.Close();
                });

                await task;
                MessageBox.Show("Complete.");
                SetUI(true);
            }
        }

        private async void Button_SignatureScan_Click(object sender, RoutedEventArgs e)
        {
            if (TargetProcess == null) return;
            if (TargetProcess.HasExited) return;
            if (string.IsNullOrEmpty(TextBox_Signature.Text)) return;


            SetUI(false);
            TextBox_LogScan.Clear();

            if (int.TryParse(TextBox_Offset1.Text, out int offset1) == false)
            {
                offset1 = 0;
            }

            var module = TargetProcess.MainModule;
            var baseAddress = TargetProcess.MainModule.BaseAddress;
            var endAddress = new IntPtr(TargetProcess.MainModule.BaseAddress.ToInt64() + TargetProcess.MainModule.ModuleMemorySize);



            Memory memory = new Memory(TargetProcess);
            var pointers = memory.SigScan(TextBox_Signature.Text, offset1, true);


            TextBox_LogScan.Text += "FileName= " + TargetProcess.MainModule.FileName + Environment.NewLine;
            TextBox_LogScan.Text += "MainModule= " + TargetProcess.MainModule.ModuleName + Environment.NewLine;
            TextBox_LogScan.Text += "BaseAddress= " + ((baseAddress.ToInt64().ToString("X").Length % 2 == 1) ? "0" + baseAddress.ToInt64().ToString("X") : baseAddress.ToInt64().ToString("X")) + Environment.NewLine;
            TextBox_LogScan.Text += "ModuleMemorySize= " + TargetProcess.MainModule.ModuleMemorySize.ToString() + Environment.NewLine;

            TextBox_LogScan.Text += "Signature= " + TextBox_Signature.Text + Environment.NewLine;
            TextBox_LogScan.Text += "Offset= " + TextBox_Signature.Text + Environment.NewLine;
            TextBox_LogScan.Text += "pointes.Count()= " + pointers.Count() + Environment.NewLine;
            TextBox_LogScan.Text += "Scan started. Please wait..." + Environment.NewLine;
            TextBox_LogScan.Text += "==================" + Environment.NewLine;

            string pString = "";
            var task = Task.Run(() =>
            {
                foreach (var p in pointers)
                {
                    if (p.ToInt64() >= baseAddress.ToInt64() && p.ToInt64() <= endAddress.ToInt64())
                    {
                        var r = p.ToInt64() - baseAddress.ToInt64();
                        pString += "p: \"" + TargetProcess.MainModule.ModuleName + "\"+" +
                            ((r.ToString("X").Length % 2 == 1) ? "0" + r.ToString("X") : r.ToString("X")) + " (" +
                            ((p.ToInt64().ToString("X").Length % 2 == 1) ? "0" + p.ToInt64().ToString("X") : p.ToInt64().ToString("X")) + ")" + Environment.NewLine;
                    }
                    else
                    {
                        pString += "p: " + ((p.ToInt64().ToString("X").Length % 2 == 1) ? "0" + p.ToInt64().ToString("X") : p.ToInt64().ToString("X")) + Environment.NewLine;
                    }
                }
            });
            await task;
            TextBox_LogScan.Text += pString;
            SetUI(true);

        }
    }

    public class Module
    {
        public IntPtr startAddres { get; set; } = IntPtr.Zero;
        public IntPtr endAddres { get; set; } = IntPtr.Zero;
    }
    public class RIPEntry
    {
        public string Signature { get; set; }

        public IntPtr Address { get; set; } = IntPtr.Zero;
        public string AddressString => (Address.ToInt64().ToString("X").Length % 2 == 1) ? "0" + Address.ToInt64().ToString("X") : Address.ToInt64().ToString("X");
        public string AddressRelativeString { get; set; }
        public Int64 AddressValueInt64 { get; set; } = 0;

        public IntPtr TargetAddress { get; set; } = IntPtr.Zero;
        public string TargetAddressString => (TargetAddress.ToInt64().ToString("X").Length % 2 == 1) ? "0" + TargetAddress.ToInt64().ToString("X") : TargetAddress.ToInt64().ToString("X");
        public string TargetAddressRelativeString { get; set; }

    }
}
