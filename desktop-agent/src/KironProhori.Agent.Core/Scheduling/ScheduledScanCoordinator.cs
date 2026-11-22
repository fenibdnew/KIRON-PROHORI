using System;
using KironProhori.Agent.Core.Models;

namespace KironProhori.Agent.Core.Scheduling;

/// <summary>
/// User-mode Scheduled Scan Coordinator (Experimental Phase 7A User-Mode feature).
/// Generates standard non-elevated Windows Task Scheduler (schtasks.exe) command definitions
/// without silently modifying system tasks without user consent.
/// </summary>
public sealed class ScheduledScanCoordinator
{
    public FeatureMaturityTier MaturityTier => FeatureMaturityTier.ExperimentalUserMode;

    public string BuildWindowsTaskSchedulerCommand(
        string scheduleCadence, // DAILY or WEEKLY
        string time24Hour,      // e.g. "13:00"
        string agentExecutablePath)
    {
        string safeCadence = scheduleCadence.Equals("WEEKLY", StringComparison.OrdinalIgnoreCase)
            ? "WEEKLY"
            : "DAILY";

        return $"schtasks /Create /SC {safeCadence} /TN \"KironProhori_UserMode_QuickScan\" /TR \"\\\"{agentExecutablePath}\\\" --quick-scan\" /ST {time24Hour} /RL LIMITED /F";
    }
}
