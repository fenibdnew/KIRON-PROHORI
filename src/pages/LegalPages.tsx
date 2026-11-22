import React from 'react';
import { Info, Lock, Scale, AlertOctagon, Shield } from 'lucide-react';
import { LegalPageId } from '../types/navigation';
import { useApp } from '../context/AppContext';

interface LegalPageProps {
  pageId: LegalPageId;
}

export const LegalPages: React.FC<LegalPageProps> = ({ pageId }) => {
  const { language, setActiveRoute, t } = useApp();
  const isBn = language === 'bn';

  const navTabs: { id: LegalPageId; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
    { id: 'about', label: t.legalPages.about, icon: Info },
    { id: 'privacy', label: t.legalPages.privacy, icon: Lock },
    { id: 'terms', label: t.legalPages.terms, icon: Scale },
    { id: 'security-disclaimer', label: t.legalPages.disclaimer, icon: AlertOctagon },
  ];

  return (
    <div className="space-y-6">
      {/* Legal & Identity Navigation Tabs */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[#1E2D4A] pb-4">
        <div className="flex flex-wrap items-center gap-1.5 rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-1">
          {navTabs.map((tab) => {
            const IconComp = tab.icon;
            const active = pageId === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveRoute(tab.id)}
                className={`inline-flex items-center gap-2 rounded-md px-3.5 py-2 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                  active
                    ? 'bg-blue-600 text-white'
                    : 'text-slate-300 hover:bg-[#141F38] hover:text-white'
                }`}
              >
                <IconComp className="h-3.5 w-3.5" aria-hidden="true" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        <span className="font-mono text-xs text-slate-400">
          KIRON PROHORI · v0.1.0
        </span>
      </div>

      {/* ABOUT PAGE */}
      {pageId === 'about' && (
        <article className="space-y-6 rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-6 sm:p-8">
          <div className="border-b border-[#1E2D4A] pb-5">
            <div className="font-mono text-xs text-blue-400">
              {isBn ? 'স্বতন্ত্র প্ল্যাটফর্ম পরিচিতি' : 'INDEPENDENT PLATFORM IDENTITY'}
            </div>
            <h1 className="mt-1 text-2xl font-bold text-slate-100 sm:text-3xl">
              {isBn
                ? 'কিরণ প্রহরী (KIRON PROHORI) সম্পর্কে'
                : 'About KIRON PROHORI'}
            </h1>
            <p className="mt-2 max-w-3xl text-sm leading-relaxed text-slate-300">
              {isBn
                ? 'কিরণ প্রহরী একটি স্বতন্ত্র, প্রতিরক্ষামূলক সাইবার থ্রেট ইন্টেলিজেন্স প্ল্যাটফর্ম যার লক্ষ্য আইটি টেকনিশিয়ান, নিরাপত্তা গবেষক, ক্ষুদ্র ব্যবসা এবং সাধারণ ব্যবহারকারীদের পাবলিকলি নথিভুক্ত সফটওয়্যার দুর্বলতা, ম্যালওয়্যার ইন্ডিকেটর এবং অনলাইন স্ক্যাম বুঝতে সহায়তা করা।'
                : 'KIRON PROHORI is an independent, defensive cyber threat intelligence platform built to help IT technicians, security researchers, small businesses, and ordinary users understand publicly documented cybersecurity threats, software vulnerabilities, malware distribution indicators, and online scams.'}
            </p>
          </div>

          <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
            <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-5 space-y-2">
              <h2 className="text-base font-semibold text-slate-100">
                {isBn
                  ? 'স্বতন্ত্র পরিচয় ও অননুমোদন ঘোষণা'
                  : 'Independent Product & Non-Affiliation Declaration'}
              </h2>
              <p className="text-xs leading-relaxed text-slate-300">
                {isBn
                  ? 'এই প্ল্যাটফর্মটি একটি সম্পূর্ণ স্বতন্ত্র পণ্য। এটি CISA (Cybersecurity and Infrastructure Security Agency), NIST (National Institute of Standards and Technology), MITRE/CVE, FIRST, Google কিংবা বাংলাদেশ বা অন্য কোনো দেশের সরকারি সংস্থার সাথে সম্পর্কিত, অনুমোদিত বা তাদের দ্বারা পরিচালিত নয়।'
                  : 'KIRON PROHORI is an independent product. It is not affiliated with, endorsed by, or operated by CISA, NIST, CVE, FIRST, Google, or any government organization.'}
              </p>
            </div>

            <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-5 space-y-2">
              <h2 className="text-base font-semibold text-slate-100">
                {isBn
                  ? 'কঠোর $০ বাজেট ও উন্মুক্ত ডেটা দর্শন'
                  : 'Strict $0 Budget & Open-Intelligence Architecture'}
              </h2>
              <p className="text-xs leading-relaxed text-slate-300">
                {isBn
                  ? 'কিরণ প্রহরী কোনো পেইড ক্লাউড বিলিং, পেইড এপিআই বা রানটাইম পেইড এআই ইনফারেন্স ব্যবহার করে না। এটি শুধুমাত্র উন্মুক্ত পাবলিক ডেটা উৎস, ব্রাউজার-ভিত্তিক লোকাল ক্যালকুলেশন (যেমন WebCrypto SHA-256 ও লেক্সিকাল URL বিশ্লেষণ) এবং ম্যানুয়াল রিফ্রেশের ওপর ভিত্তি করে নির্মিত।'
                  : 'KIRON PROHORI operates under a strict $0 budget policy. It requires zero paid cloud billing, zero paid API keys, and zero paid AI inference at runtime. All capabilities rely on public open-data feeds, deterministic local browser calculations, and user-initiated manual refreshes.'}
              </p>
            </div>
          </div>

          <div className="space-y-3 border-t border-[#1E2D4A] pt-5">
            <h2 className="text-base font-semibold text-slate-100">
              {isBn ? 'যাদের জন্য নির্মিত' : 'Who We Serve'}
            </h2>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4 text-xs">
              <div className="rounded-md border border-[#1E2D4A] bg-[#080D1A] p-4">
                <div className="font-semibold text-slate-200">
                  {isBn ? '১. আইটি টেকনিশিয়ান' : '1. IT Technicians'}
                </div>
                <p className="mt-1 text-slate-400">
                  {isBn
                    ? 'দ্রুত CVE ও CISA KEV প্যাচ অগ্রাধিকার যাচাই এবং সিস্টেম হার্ডেনিং চেকলিস্ট।'
                    : 'Rapid CVE and CISA KEV patch prioritization and practical system hardening checklists.'}
                </p>
              </div>
              <div className="rounded-md border border-[#1E2D4A] bg-[#080D1A] p-4">
                <div className="font-semibold text-slate-200">
                  {isBn ? '২. নিরাপত্তা গবেষক' : '2. Security Researchers'}
                </div>
                <p className="mt-1 text-slate-400">
                  {isBn
                    ? 'ডিফ্যাংড ম্যালওয়্যার ইন্ডিকেটর, লোকাল SHA-256 হ্যাশ যাচাই এবং CVSS ভেক্টর বিশ্লেষণ।'
                    : 'Defanged malware indicators, zero-upload local SHA-256 hashing, and CVSS vector inspection.'}
                </p>
              </div>
              <div className="rounded-md border border-[#1E2D4A] bg-[#080D1A] p-4">
                <div className="font-semibold text-slate-200">
                  {isBn ? '৩. ক্ষুদ্র ও মাঝারি ব্যবসা' : '3. Small Businesses'}
                </div>
                <p className="mt-1 text-slate-400">
                  {isBn
                    ? 'ব্যয়বহুল এন্টারপ্রাইজ লাইসেন্স ছাড়াই র‍্যানসমওয়্যার ও ফিশিং প্রতিরোধের নির্দেশনা।'
                    : 'Accessible ransomware and invoice-fraud resilience without expensive enterprise SOC licenses.'}
                </p>
              </div>
              <div className="rounded-md border border-[#1E2D4A] bg-[#080D1A] p-4">
                <div className="font-semibold text-slate-200">
                  {isBn ? '৪. সাধারণ ব্যবহারকারী' : '4. Ordinary Users'}
                </div>
                <p className="mt-1 text-slate-400">
                  {isBn
                    ? 'সহজ বাংলা ও ইংরেজিতে সন্দেহজনক লিংক, ওটিপি স্ক্যাম ও ফিশিং চেনার উপায়।'
                    : 'Plain-language bilingual (English & Bengali) guidance to spot phishing links and online scams.'}
                </p>
              </div>
            </div>
          </div>
        </article>
      )}

      {/* PRIVACY POLICY PAGE */}
      {pageId === 'privacy' && (
        <article className="space-y-6 rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-6 sm:p-8">
          <div className="border-b border-[#1E2D4A] pb-5">
            <div className="font-mono text-xs text-blue-400">
              {isBn ? 'ডেটা ও গোপনীয়তা নীতি' : 'LOCAL-FIRST PRIVACY ARCHITECTURE'}
            </div>
            <h1 className="mt-1 text-2xl font-bold text-slate-100 sm:text-3xl">
              {t.legalPages.privacy}
            </h1>
            <p className="mt-2 max-w-3xl text-sm text-slate-300">
              {isBn
                ? 'কার্যকর তারিখ: সংস্করণ ০.১.০ (ফাউন্ডেশন রিলিজ) · কিরণ প্রহরী ব্যবহারকারীর গোপনীয়তা ও লোকাল ডেটা সুরক্ষাকে সর্বোচ্চ অগ্রাধিকার দেয়।'
                : 'Effective Version: v0.1.0 Foundation Release · KIRON PROHORI is engineered around local-first data minimization.'}
            </p>
          </div>

          <div className="space-y-4 text-xs leading-relaxed text-slate-300">
            <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-5">
              <h2 className="text-sm font-semibold text-slate-100">
                {isBn
                  ? '১. লোকাল-ফার্স্ট স্টোরেজ ও শূন্য ট্র্যাকিং'
                  : '1. Local-First Browser Storage & Zero Third-Party Tracking'}
              </h2>
              <p className="mt-1.5 text-slate-400">
                {isBn
                  ? 'আপনার ভাষা নির্বাচন (ইংরেজি/বাংলা), ওয়াচলিস্ট এবং চেকলিস্টের অগ্রগতি সরাসরি আপনার ব্রাউজারের localStorage-এ সংরক্ষিত থাকে। আমরা কোনো পেইড মার্কেটিং পিক্সেল, বিজ্ঞাপন ট্র্যাকার বা তৃতীয় পক্ষের অ্যানালিটিক্স ব্যবহার করি না।'
                  : 'Your interface language preference (English/Bengali), custom watchlists, and security checklist progress are stored locally in your browser via localStorage/IndexedDB. We do not embed advertising trackers, marketing pixels, or paid behavioral analytics.'}
              </p>
            </div>

            <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-5">
              <h2 className="text-sm font-semibold text-slate-100">
                {isBn
                  ? '২. ফাইল হ্যাশিং ও ইউআরএল পরিদর্শনের গোপনীয়তা'
                  : '2. Zero-Upload File Hashing & Local URL Inspection'}
              </h2>
              <p className="mt-1.5 text-slate-400">
                {isBn
                  ? 'হ্যাশ লুকআপ মডিউলে কোনো ফাইল নির্বাচন করলে তার SHA-256 হ্যাশ আপনার ব্রাউজারের নিজস্ব WebCrypto এপিআই দিয়ে আপনার ডিভাইসেই তৈরি হয়—মূল ফাইলটি কখনোই কোনো সার্ভারে আপলোড করা হয় না।'
                  : 'When calculating file digests in the Hash Lookup module, cryptographic hashing (SHA-256) executes locally inside your browser using the W3C WebCrypto API. Raw files are never uploaded to external servers.'}
              </p>
            </div>

            <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-5">
              <h2 className="text-sm font-semibold text-slate-100">
                {isBn
                  ? '৩. পাবলিক ডেটা উৎস ব্যবহারের সতর্কতা'
                  : '3. Public Threat Feed Queries'}
              </h2>
              <p className="mt-1.5 text-slate-400">
                {isBn
                  ? 'পাবলিক থ্রেট ফিড (যেমন NVD বা CISA KEV) ম্যানুয়ালি রিফ্রেশ করার সময় স্ট্যান্ডার্ড HTTP রিকোয়েস্ট ব্যবহৃত হয়। কখনোই ব্যক্তিগত পাসওয়ার্ড, গোপন টোকেন বা সংবেদনশীল অভ্যন্তরীণ URL পাবলিক সার্চ বক্সে প্রদান করবেন না।'
                  : 'When manual feed synchronization is triggered in future phases, standard HTTPS requests retrieve public JSON catalogs (such as NVD or CISA KEV). Users should never paste confidential passwords, secret API tokens, or private internal URLs into public lookup fields.'}
              </p>
            </div>
          </div>
        </article>
      )}

      {/* TERMS OF USE PAGE */}
      {pageId === 'terms' && (
        <article className="space-y-6 rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-6 sm:p-8">
          <div className="border-b border-[#1E2D4A] pb-5">
            <div className="font-mono text-xs text-blue-400">
              {isBn ? 'প্রতিরক্ষামূলক ব্যবহারের নীতিমালা' : 'DEFENSIVE USE & GOVERNANCE TERMS'}
            </div>
            <h1 className="mt-1 text-2xl font-bold text-slate-100 sm:text-3xl">
              {t.legalPages.terms}
            </h1>
            <p className="mt-2 max-w-3xl text-sm text-slate-300">
              {isBn
                ? 'কিরণ প্রহরী প্ল্যাটফর্মটি শুধুমাত্র বৈধ প্রতিরক্ষামূলক সাইবার নিরাপত্তা, গবেষণা এবং শিক্ষামূলক উদ্দেশ্যে ব্যবহারের জন্য।'
                : 'By accessing KIRON PROHORI, you agree to use this platform strictly for defensive cybersecurity awareness, vulnerability remediation, and educational research.'}
            </p>
          </div>

          <div className="space-y-4 text-xs leading-relaxed text-slate-300">
            <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-5">
              <h2 className="text-sm font-semibold text-slate-100">
                {isBn
                  ? '১. শুধুমাত্র প্রতিরক্ষামূলক ও বৈধ ব্যবহার'
                  : '1. Authorized Defensive & Educational Purpose Only'}
              </h2>
              <p className="mt-1.5 text-slate-400">
                {isBn
                  ? 'এই প্ল্যাটফর্মের কোনো তথ্য বা টুল অননুমোদিত আক্রমণ, এক্সপ্লয়টেশন বা কোনো সিস্টেমের ক্ষতি করার উদ্দেশ্যে ব্যবহার করা সম্পূর্ণ নিষিদ্ধ।'
                  : 'KIRON PROHORI provides visibility into publicly documented vulnerabilities and threat indicators solely to assist defenders in securing systems. Using any information from this application for unauthorized exploitation or offensive activity is strictly prohibited.'}
              </p>
            </div>

            <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-5">
              <h2 className="text-sm font-semibold text-slate-100">
                {isBn
                  ? '২. পাবলিক ডেটা ক্যাটালগের মেধাস্বত্ব ও অ্যাট্রিবিউশন'
                  : '2. Upstream Public Data Attribution'}
              </h2>
              <p className="mt-1.5 text-slate-400">
                {isBn
                  ? 'পাবলিকলি প্রকাশিত CVE, KEV এবং ম্যালওয়্যার ইন্ডিকেটরগুলোর কৃতিত্ব সংশ্লিষ্ট পাবলিক ডেটাবেসের (যেমন NIST NVD, CISA, MITRE, OSV.dev, abuse.ch)। কিরণ প্রহরী কোনো সরকারি সংস্থার প্রতিনিধিত্ব করে না।'
                  : 'Public vulnerability identifiers and catalogs referenced by the platform remain the work of their respective public maintainers (including NIST NVD, CISA, MITRE, OSV.dev, and abuse.ch). Attribution is provided for transparency without implying endorsement.'}
              </p>
            </div>

            <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-5">
              <h2 className="text-sm font-semibold text-slate-100">
                {isBn
                  ? '৩. শূন্য-খরচ সেবা ও ওপেন-ইন্টেলিজেন্স সীমা'
                  : '3. Zero-Cost Service Availability'}
              </h2>
              <p className="mt-1.5 text-slate-400">
                {isBn
                  ? 'কিরণ প্রহরী সম্পূর্ণ বিনামূল্যে ($০ বাজেটে) প্রদান করা হয় এবং পাবলিক এপিআইয়ের রেট-লিমিটের ওপর নির্ভরশীল।'
                  : 'Because KIRON PROHORI operates at $0 cost using public rate-limited endpoints and local browser computation, feed availability depends on upstream public repositories.'}
              </p>
            </div>
          </div>
        </article>
      )}

      {/* SECURITY DISCLAIMER PAGE */}
      {pageId === 'security-disclaimer' && (
        <article className="space-y-6 rounded-lg border border-amber-800/70 bg-[#0E1628] p-6 sm:p-8">
          <div className="border-b border-[#1E2D4A] pb-5">
            <div className="font-mono text-xs text-amber-300">
              {isBn ? 'গুরুত্বপূর্ণ নিরাপত্তা ডিসক্লেইমার' : 'ADVISORY & OPERATIONAL RISK DISCLAIMER'}
            </div>
            <h1 className="mt-1 text-2xl font-bold text-slate-100 sm:text-3xl">
              {t.legalPages.disclaimer}
            </h1>
            <p className="mt-2 max-w-3xl text-sm text-slate-300">
              {isBn
                ? 'কিরণ প্রহরী কোনো অ্যান্টিভাইরাস, ফায়ারওয়াল বা ২৪/৭ ম্যানেজড সিকিউরিটি সার্ভিস (SOC) নয়। কোনো সিদ্ধান্ত নেওয়ার আগে নিচের সতর্কতাগুলো মনোযোগ দিয়ে পড়ুন।'
                : 'Please read this operational security disclaimer carefully before relying on threat indicators, URL analysis, or checklists displayed in KIRON PROHORI.'}
            </p>
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 text-xs leading-relaxed">
            <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-5 space-y-2">
              <h2 className="text-sm font-semibold text-slate-100">
                {isBn
                  ? '১. থ্রেট ফিডের অনুপস্থিতি মানেই নিরাপদ নয়'
                  : '1. Absence of an Indicator Does Not Guarantee Safety'}
              </h2>
              <p className="text-slate-400">
                {isBn
                  ? 'কোনো URL বা ফাইল হ্যাশ পাবলিক ব্লকলিস্টে না থাকার অর্থ এই নয় যে সেটি ১০০% নিরাপদ। নতুন ফিশিং ডোমেইন এবং জিরো-ডে ম্যালওয়্যার পাবলিক তালিকায় আসতে সময় নিতে পারে।'
                  : 'If a URL, domain, IP address, or file hash does not appear in a public feed, it does NOT guarantee that the resource is benign. Newly registered phishing domains and polymorphic malware frequently predate public community feeds.'}
              </p>
            </div>

            <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-5 space-y-2">
              <h2 className="text-sm font-semibold text-slate-100">
                {isBn
                  ? '২. অফিশিয়াল ভেন্ডর অ্যাডভাইজরি যাচাই করুন'
                  : '2. Always Verify Vendor Advisories Before Patching'}
              </h2>
              <p className="text-slate-400">
                {isBn
                  ? 'প্রোডাকশন সার্ভারে কোনো প্যাচ বা পরিবর্তন প্রয়োগ করার আগে সর্বদা মূল সফটওয়্যার নির্মাতার অফিশিয়াল সিকিউরিটি বুলেটিন এবং রিলিজ নোট যাচাই করুন।'
                  : 'Before applying emergency patches or configuration changes to production systems, IT administrators must verify the primary vendor security bulletin and test changes in a staging environment.'}
              </p>
            </div>

            <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-5 space-y-2">
              <h2 className="text-sm font-semibold text-slate-100">
                {isBn
                  ? '৩. ডিফ্যাংড ইন্ডিকেটর সতর্কতার সাথে ব্যবহার করুন'
                  : '3. Safe Handling of Defanged Indicators (hxxps://)'}
              </h2>
              <p className="text-slate-400">
                {isBn
                  ? 'কিরণ প্রহরীতে প্রদর্শিত ক্ষতিকর লিংকগুলো দুর্ঘটনাবশত ক্লিক রোধ করতে ডিফ্যাং (যেমন hxxps://example[.]com) করা হয়। অনিরাপদ ডিভাইসে কখনোই এই লিংকগুলো ব্রাউজারে ওপেন করবেন না।'
                  : 'KIRON PROHORI defangs malicious URLs and IP addresses (e.g., hxxps://example[.]invalid) by default. Never refang or visit reported malware or phishing URLs on a production or personal device.'}
              </p>
            </div>

            <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-5 space-y-2">
              <h2 className="text-sm font-semibold text-slate-100">
                {isBn
                  ? '৪. পেশাদার ইনসিডেন্ট রেসপন্সের বিকল্প নয়'
                  : '4. No Warranty & Not a Substitute for Incident Response'}
              </h2>
              <p className="text-slate-400">
                {isBn
                  ? 'এই প্ল্যাটফর্মটি কোনো ওয়ারেন্টি ছাড়াই "যেমন আছে" ভিত্তিতে প্রদান করা হয়। সক্রিয় সাইবার আক্রমণের শিকার হলে অবিলম্বে পেশাদার ইনসিডেন্ট রেসপন্স টিমের সহায়তা নিন।'
                  : 'This software is provided "AS IS" without warranty of any kind. It is an informational decision-support tool and does not replace certified forensic incident response or legal counsel.'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-4 text-xs text-slate-300">
            <Shield className="h-5 w-5 text-blue-400 shrink-0" aria-hidden="true" />
            <span>{t.independentNoticeFull}</span>
          </div>
        </article>
      )}
    </div>
  );
};
