using System;
using System.Collections.Generic;
using KironProhori.Agent.Core.Models;

namespace KironProhori.Agent.Core.Localization;

/// <summary>
/// Bilingual (English &amp; Bengali / বাংলা) UI string catalog for all desktop navigation views and Developer About metadata.
/// </summary>
public static class BilingualStrings
{
    public static readonly IReadOnlyDictionary<string, (string En, string Bn)> Catalog =
        new Dictionary<string, (string En, string Bn)>(StringComparer.OrdinalIgnoreCase)
        {
            // Canonical Phase 7A catalog keys
            ["BrandTitle"] = ("KIRON PROHORI — Windows Security & Antivirus", "কিরণ প্রহরী — উইন্ডোজ সিকিউরিটি ও অ্যান্টিভাইরাস"),
            ["DeveloperCredit"] = ("Developer: ARIFUZZAMAN", "ডেভেলপার: ARIFUZZAMAN"),
            ["PhaseBadge"] = ("PHASE 7A · PRIVACY-FIRST (NO TELEMETRY) · $0 BUDGET", "ফেজ ৭এ · প্রাইভেসি-ফার্স্ট (নো টেলিমেট্রি) · $০ বাজেট"),
            ["Nav_01_Overview"] = ("01. Security Overview", "০১. সিকিউরিটি ওভারভিউ"),
            ["Nav_02_QuickScan"] = ("02. Quick Scan", "০২. কুইক স্ক্যান"),
            ["Nav_03_FullScan"] = ("03. Full Scan", "০৩. ফুল স্ক্যান"),
            ["Nav_04_CustomScan"] = ("04. Custom Scan", "০৪. কাস্টম ফোল্ডার স্ক্যান"),
            ["Nav_05_UsbScan"] = ("05. USB Scan", "০৫. ইউএসবি ড্রাইভ স্ক্যান"),
            ["Nav_06_RealTime"] = ("06. Real-Time Monitoring", "০৬. রিয়েল-টাইম মনিটরিং"),
            ["Nav_07_ThreatHistory"] = ("07. Threat History", "০৭. থ্রেট ইতিহাস"),
            ["Nav_08_Quarantine"] = ("08. Quarantine", "০৮. কোয়ারেন্টাইন ভল্ট"),
            ["Nav_09_Exclusions"] = ("09. Exclusions", "০৯. এক্সক্লুশন ম্যানেজার"),
            ["Nav_10_Defender"] = ("10. Windows Defender Status", "১০. উইন্ডোজ ডিফেন্ডার স্ট্যাটাস"),
            ["Nav_11_Firewall"] = ("11. Firewall Status", "১১. ফায়ারওয়াল অবস্থা"),
            ["Nav_12_Updates"] = ("12. Updates", "১২. সিকিউরিটি আপডেট"),
            ["Nav_13_Notifications"] = ("13. Notifications", "১৩. স্মার্ট নোটিফিকেশন"),
            ["Nav_14_Settings"] = ("14. Settings", "১৪. সেটিংস ও পারফরম্যান্স"),
            ["Nav_15_About"] = ("15. About", "১৫. পরিচিতি (About)"),
            ["AboutMessage"] = (
                AboutBrandMetadata.OfficialAboutMessage,
                "কিরণ প্রহরী একটি স্বতন্ত্র সিকিউরিটি অ্যাপ্লিকেশন, যা ইন্টেলিজেন্ট থ্রেট ডিটেকশন, ম্যালওয়্যার স্ক্যানিং এবং সিকিউরিটি মনিটরিংয়ের মাধ্যমে উইন্ডোজ কম্পিউটার সুরক্ষিত রাখতে সহায়তা করে।\n\nকিরণ প্রহরী বেছে নেওয়ার জন্য আপনাকে ধন্যবাদ।\n\nআপনার গোপনীয়তা গুরুত্বপূর্ণ। আপনার নিরাপত্তা গুরুত্বপূর্ণ। আপনার আস্থা গুরুত্বপূর্ণ।\n\nএকটি নিরাপদ ডিজিটাল বিশ্বের জন্য যত্নসহকারে নির্মিত।"
            ),
            ["NonAffiliationNotice"] = (
                AboutBrandMetadata.NonAffiliationNotice,
                "কিরণ প্রহরী ARIFUZZAMAN কর্তৃক নির্মিত একটি স্বতন্ত্র পণ্য এবং এটি Microsoft বা অন্য কোনো অ্যান্টিভাইরাস প্রতিষ্ঠানের সাথে সম্পর্কিত নয়।"
            ),
            ["CoexistenceBanner"] = (
                "Privacy-First Companion Mode: No Telemetry by Default. Never disables Microsoft Defender or Windows Firewall. Not registered as a primary WSC Antivirus replacement.",
                "প্রাইভেসি-ফার্স্ট কম্প্যানিয়ন মোড: ডিফল্টভাবে কোনো টেলিমেট্রি নেই। কখনোই Microsoft Defender বা Windows Firewall বন্ধ করে না।"
            ),

            // V1.0 Desktop UI navigation & header keys
            ["app.title"] = ("KIRON PROHORI", "কিরণ প্রহরী"),
            ["app.subtitle"] = ("Windows Security & Antivirus V1.0", "উইন্ডোজ সিকিউরিটি ও অ্যান্টিভাইরাস V1.0"),
            ["nav.overview"] = ("Security Overview", "সিকিউরিটি ওভারভিউ"),
            ["nav.quick_scan"] = ("Quick Scan", "কুইক স্ক্যান"),
            ["nav.full_scan"] = ("Full Scan", "ফুল স্ক্যান"),
            ["nav.custom_scan"] = ("Custom Scan", "কাস্টম ফোল্ডার স্ক্যান"),
            ["nav.usb_scan"] = ("USB Scan", "ইউএসবি ড্রাইভ স্ক্যান"),
            ["nav.web_protection"] = ("Web Protection (Chrome/Edge)", "ওয়েব সুরক্ষা (Chrome/Edge)"),
            ["nav.download_protection"] = ("Download Protection", "ডাউনলোড সুরক্ষা"),
            ["nav.realtime"] = ("Real-Time Protection", "রিয়েল-টাইম সুরক্ষা"),
            ["nav.history"] = ("Threat History", "থ্রেট ইতিহাস"),
            ["nav.quarantine"] = ("Quarantine", "কোয়ারেন্টাইন ভল্ট"),
            ["nav.exclusions"] = ("Exclusions", "এক্সক্লুশন ম্যানেজার"),
            ["nav.security_intel"] = ("Security Intelligence", "সিকিউরিটি ইন্টেলিজেন্স"),
            ["nav.defender"] = ("Microsoft Defender Status", "মাইক্রোসফট ডিফেন্ডার স্ট্যাটাস"),
            ["nav.firewall"] = ("Firewall Status", "ফায়ারওয়াল অবস্থা"),
            ["nav.updates"] = ("Updates", "সিকিউরিটি আপডেট"),
            ["nav.notifications"] = ("Notifications", "স্মার্ট নোটিফিকেশন"),
            ["nav.settings"] = ("Settings", "সেটিংস ও পারফরম্যান্স"),
            ["nav.about"] = ("About", "পরিচিতি (About)"),
            ["status.honest_disclosure"] = (
                "User-Mode Windows Companion · Coexists with Microsoft Defender · No Automatic File Upload · No Telemetry by Default",
                "ইউজার-মোড উইন্ডোজ কম্প্যানিয়ন · Microsoft Defender-এর সাথে সহাবস্থান করে · স্বয়ংক্রিয় ফাইল আপলোড নেই · ডিফল্টভাবে কোনো টেলিমেট্রি নেই"
            )
        };

    public static string Get(string key, bool isBengali) =>
        Catalog.TryGetValue(key, out var pair)
            ? (isBengali ? pair.Bn : pair.En)
            : key;
}
