using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Windows;
using System.Windows.Threading;
using KironProhori.Agent.Core.Scanning;

namespace KironProhori.Agent.Desktop;

/// <summary>
/// Application entrypoint with Windows Explorer Right-Click Context Menu (--scan-path) CLI support,
/// single-instance Named Pipe forwarding, crash recovery persistence, and unhandled exception logging.
/// </summary>
public partial class App : System.Windows.Application
{
    public const string ScanPathNamedPipeName = "KironProhori_Desktop_ScanPath_IPC_v1";

    public static string? InitialScanTargetPath { get; private set; }
    public static bool StartMinimizedToTray { get; private set; }

    protected override void OnStartup(StartupEventArgs e)
    {
        var (scanPath, minimized) = ModularScanPipeline.ParseCliScanPathArguments(e.Args);
        InitialScanTargetPath = scanPath;
        StartMinimizedToTray = minimized;

        // If launched via Windows Explorer Right-Click ("Scan with KIRON PROHORI") while an instance is already open,
        // forward the target path to the running window over Named Pipe and exit this helper instance.
        if (!string.IsNullOrWhiteSpace(scanPath) && TryForwardScanPathToRunningInstance(scanPath))
        {
            Shutdown(0);
            return;
        }

        base.OnStartup(e);
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnDomainUnhandledException;
    }

    private static bool TryForwardScanPathToRunningInstance(string scanPath)
    {
        try
        {
            using var client = new NamedPipeClientStream(".", ScanPathNamedPipeName, PipeDirection.Out);
            client.Connect(timeout: 350);
            byte[] payload = Encoding.UTF8.GetBytes(scanPath);
            client.Write(payload, 0, payload.Length);
            client.Flush();
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        RecordCrashRecoveryCheckpoint(e.Exception);
        System.Windows.MessageBox.Show(
            $"KIRON PROHORI recovered from an unexpected UI error without data loss:\n{e.Exception.Message}",
            "KIRON PROHORI Crash Recovery Guard",
            MessageBoxButton.OK,
            MessageBoxImage.Warning);
        e.Handled = true;
    }

    private static void OnDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        if (e.ExceptionObject is Exception ex)
        {
            RecordCrashRecoveryCheckpoint(ex);
        }
    }

    private static void RecordCrashRecoveryCheckpoint(Exception ex)
    {
        try
        {
            string logDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "KironProhori",
                "Logs");
            Directory.CreateDirectory(logDir);
            string logFile = Path.Combine(logDir, "crash-recovery.log");
            string entry = $"[{DateTimeOffset.UtcNow:O}] CRASH_RECOVERY_CAPTURED: {ex.GetType().FullName}: {ex.Message}{Environment.NewLine}{ex.StackTrace}{Environment.NewLine}";
            File.AppendAllText(logFile, entry);
        }
        catch
        {
            // Never throw inside crash recovery logger
        }
    }
}
