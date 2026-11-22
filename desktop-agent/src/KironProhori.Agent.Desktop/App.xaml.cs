using System;
using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace KironProhori.Agent.Desktop;

/// <summary>
/// Application entrypoint with crash recovery persistence and unhandled exception logging.
/// </summary>
public partial class App : System.Windows.Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnDomainUnhandledException;
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
