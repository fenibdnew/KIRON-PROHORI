using System.Collections.Generic;

namespace KironProhori.Agent.Core.Localization;

/// <summary>
/// Bilingual (English &amp; Bengali / বাংলা) UI string catalog for the 13 desktop views.
/// </summary>
public static class BilingualStrings
{
    public static readonly IReadOnlyDictionary<string, (string En, string Bn)> Catalog =
        new Dictionary<string, (string En, string Bn)>
        {
            ["BrandTitle"] = ("KIRON PROHORI — Windows Security Agent", "কিরণ প্রহরী — উইন্ডোজ সিকিউরিটি এজেন্ট"),
            ["PhaseBadge"] = ("PHASE 7A USER-MODE MVP · $0 ZERO-COST", "ফেজ ৭এ ইউজার-মোড এমভিপি · $০ বাজেট"),
            ["Nav_Overview"] = ("01. Security Overview", "০১. সিকিউরিটি ওভারভিউ"),
            ["Nav_QuickScan"] = ("02. Quick Scan", "০২. কুইক স্ক্যান"),
            ["Nav_FullScan"] = ("03. Full Scan", "০৩. ফুল স্ক্যান"),
            ["Nav_CustomScan"] = ("04. Custom Scan", "০৪. কাস্টম ফোল্ডার স্ক্যান"),
            ["Nav_UsbScan"] = ("05. USB Drive Scan", "০৫. ইউএসবি ড্রাইভ স্ক্যান"),
            ["Nav_ProtectionStatus"] = ("06. Protection Status", "০৬. সুরক্ষা অবস্থা"),
            ["Nav_ThreatHistory"] = ("07. Threat History", "০৭. থ্রেট ইতিহাস"),
            ["Nav_Quarantine"] = ("08. Quarantine Vault", "০৮. কোয়ারেন্টাইন ভল্ট"),
            ["Nav_Firewall"] = ("09. Firewall Status", "০৯. ফায়ারওয়াল অবস্থা"),
            ["Nav_WindowsSecurity"] = ("10. Windows Security", "১০. উইন্ডোজ সিকিউরিটি"),
            ["Nav_Updates"] = ("11. Signature Updates", "১১. সিগনেচার আপডেট"),
            ["Nav_Reports"] = ("12. Scan Reports", "১২. স্ক্যান রিপোর্ট"),
            ["Nav_Settings"] = ("13. Agent Settings", "১৩. এজেন্ট সেটিংস"),
            ["CoexistenceBanner"] = (
                "Cooperative User-Mode Mode: Never disables Microsoft Defender or Windows Firewall. Never installs unsigned kernel drivers.",
                "সহযোগী ইউজার-মোড: কখনোই Microsoft Defender বা Windows Firewall বন্ধ করে না। আনসাইনড কার্নেল ড্রাইভার ইনস্টল করে না।"
            ),
            ["QuarantineConfirmPrompt"] = (
                "Confirm Quarantine: Isolate selected file in non-executable .kpq vault?",
                "কোয়ারেন্টাইন নিশ্চিতকরণ: নির্বাচিত ফাইলটি কি নিরাপদ .kpq ভল্টে আলাদা করতে চান?"
            )
        };

    public static string Get(string key, bool isBengali) =>
        Catalog.TryGetValue(key, out var pair)
            ? (isBengali ? pair.Bn : pair.En)
            : key;
}
