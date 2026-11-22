using System;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using KironProhori.Agent.Core.BrowserProtection;
using KironProhori.Agent.Core.Diagnostics;
using KironProhori.Agent.Core.Exclusions;
using KironProhori.Agent.Core.Models;
using KironProhori.Agent.Core.Notifications;
using KironProhori.Agent.Core.Performance;
using KironProhori.Agent.Core.Quarantine;
using KironProhori.Agent.Core.Realtime;
using KironProhori.Agent.Core.Scanning;
using KironProhori.Agent.Core.Scheduling;
using KironProhori.Agent.Core.Updates;
using KironProhori.Agent.Core.WindowsSecurity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace KironProhori.Agent.Service;

/// <summary>
/// KIRON PROHORI Windows Background Service (Service Name: KironProhoriSecurityService).
/// Runs on Windows 10 / Windows 11 x64 with delayed auto-start and crash-recovery configuration.
/// Responsibilities:
/// 1. Hosts Local Security Engine, Real-Time User-Mode File Protection Monitor, Scheduled Scan Coordinator,
///    Quarantine Vault, Exclusion Manager, and Cryptographic Update Manager.
/// 2. Hosts a local-only Named Pipe IPC server ("KironProhori.SecurityService.Ipc.v1") restricted to authenticated
///    local interactive users and administrators so the Desktop UI and Native Messaging Host can query live status.
/// 3. Strictly enforces coexistence: never disables or modifies Microsoft Defender or Windows Firewall.
/// 4. Strictly enforces privacy: zero telemetry by default, zero automatic sample uploads.
/// </summary>
public static class Program
{
    public const string WindowsServiceName = "KironProhoriSecurityService";
    public const string WindowsServiceDisplayName = "KIRON PROHORI Windows Security Service";
    public const string LocalNamedPipeName = "KironProhori.SecurityService.Ipc.v1";

    public static async Task Main(string[] args)
    {
        IHost host = Host.CreateDefaultBuilder(args)
            .UseWindowsService(options =>
            {
                options.ServiceName = WindowsServiceName;
            })
            .ConfigureServices((hostContext, services) =>
            {
                services.AddSingleton<ExclusionManager>();
                services.AddSingleton<QuarantineManager>();
                services.AddSingleton<SmartNotificationManager>();
                services.AddSingleton<PerformanceProtectionGuard>();
                services.AddSingleton<ModularScanPipeline>();
                services.AddSingleton<RealTimeFileProtectionMonitor>();
                services.AddSingleton<NativeMessagingDownloadGuard>();
                services.AddSingleton<SecureUpdateManager>();
                services.AddSingleton<ScheduledScanCoordinator>();
                services.AddSingleton<WindowsSecurityMonitor>();
                services.AddSingleton<ErrorDiagnosticsManager>();
                services.AddHostedService<KironProhoriBackgroundWorker>();
            })
            .Build();

        await host.RunAsync().ConfigureAwait(false);
    }
}

public sealed class KironProhoriBackgroundWorker : BackgroundService
{
    private readonly ILogger<KironProhoriBackgroundWorker> _logger;
    private readonly ModularScanPipeline _scanPipeline;
    private readonly RealTimeFileProtectionMonitor _realTimeMonitor;
    private readonly NativeMessagingDownloadGuard _browserGuard;
    private readonly QuarantineManager _quarantineManager;
    private readonly ExclusionManager _exclusionManager;
    private readonly SecureUpdateManager _updateManager;
    private readonly WindowsSecurityMonitor _windowsSecurityMonitor;
    private readonly ErrorDiagnosticsManager _diagnostics;
    private DateTimeOffset _serviceStartedAtUtc;

    public KironProhoriBackgroundWorker(
        ILogger<KironProhoriBackgroundWorker> logger,
        ModularScanPipeline scanPipeline,
        RealTimeFileProtectionMonitor realTimeMonitor,
        NativeMessagingDownloadGuard browserGuard,
        QuarantineManager quarantineManager,
        ExclusionManager exclusionManager,
        SecureUpdateManager updateManager,
        WindowsSecurityMonitor windowsSecurityMonitor,
        ErrorDiagnosticsManager diagnostics)
    {
        _logger = logger;
        _scanPipeline = scanPipeline;
        _realTimeMonitor = realTimeMonitor;
        _browserGuard = browserGuard;
        _quarantineManager = quarantineManager;
        _exclusionManager = exclusionManager;
        _updateManager = updateManager;
        _windowsSecurityMonitor = windowsSecurityMonitor;
        _diagnostics = diagnostics;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _serviceStartedAtUtc = DateTimeOffset.UtcNow;
        _logger.LogInformation(
            "{Product} Background Service v{Version} by {Developer} starting on {OS} (Privacy: {Privacy})",
            AboutBrandMetadata.ProductName,
            AboutBrandMetadata.ProductVersion,
            AboutBrandMetadata.DeveloperName,
            Environment.OSVersion,
            AboutBrandMetadata.PrivacyPolicyDefault);

        // 1. Run self-healing startup check on configuration & quarantine metadata
        DiagnosticHealthReport health = await _diagnostics.RunSelfDiagnosticAndRepairAsync().ConfigureAwait(false);
        _logger.LogInformation("Startup configuration health check completed: {Status}", health.Status);

        // 2. Start User-Mode Real-Time File Protection Monitor on Downloads, Temp, and Startup folders
        _realTimeMonitor.StartDefaultUserModeWatchers();
        _logger.LogInformation(
            "User-Mode Real-Time File Protection started across {Count} monitored directories.",
            _realTimeMonitor.GetMonitoredDirectories().Count);

        // 3. Run Local Named Pipe IPC loop for Desktop UI and Native Messaging Host status synchronization
        Task ipcTask = RunLocalNamedPipeServerLoopAsync(stoppingToken);

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Normal service shutdown
        }
        finally
        {
            _realTimeMonitor.StopAllWatchers();
            await ipcTask.ConfigureAwait(false);
            _logger.LogInformation("{Service} stopped cleanly.", Program.WindowsServiceName);
        }
    }

    private async Task RunLocalNamedPipeServerLoopAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var pipeServer = new NamedPipeServerStream(
                    Program.LocalNamedPipeName,
                    PipeDirection.InOut,
                    maxNumberOfServerInstances: 4,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);

                await pipeServer.WaitForConnectionAsync(stoppingToken).ConfigureAwait(false);

                using var reader = new StreamReader(pipeServer, Encoding.UTF8, leaveOpen: true);
                using var writer = new StreamWriter(pipeServer, new UTF8Encoding(false), leaveOpen: true)
                {
                    AutoFlush = true
                };

                string? commandLine = await reader.ReadLineAsync(stoppingToken).ConfigureAwait(false);
                if (!string.IsNullOrWhiteSpace(commandLine))
                {
                    string responseJson = HandleIpcCommand(commandLine.Trim());
                    await writer.WriteLineAsync(responseJson.AsMemory(), stoppingToken).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Local IPC named pipe connection transient error.");
                await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken).ConfigureAwait(false);
            }
        }
    }

    public string HandleIpcCommand(string command)
    {
        var statusPayload = new
        {
            serviceName = Program.WindowsServiceName,
            product = AboutBrandMetadata.ProductName,
            version = AboutBrandMetadata.ProductVersion,
            developer = AboutBrandMetadata.DeveloperName,
            uptimeSeconds = Math.Round((DateTimeOffset.UtcNow - _serviceStartedAtUtc).TotalSeconds, 1),
            realTimeMonitoringActive = _realTimeMonitor.IsMonitoringActive,
            monitoredDirectories = _realTimeMonitor.GetMonitoredDirectories(),
            quarantinedCount = _quarantineManager.GetActiveEntries().Count,
            exclusionsCount = _exclusionManager.GetExclusions().Count,
            webProtectionRuleCount = NativeMessagingDownloadGuard.GetVerifiedWebProtectionRules().Count,
            telemetryEnabled = false,
            commandReceived = command,
            respondedAtUtc = DateTimeOffset.UtcNow
        };

        return JsonSerializer.Serialize(statusPayload);
    }
}
