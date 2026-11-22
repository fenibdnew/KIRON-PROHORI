import { Language, NavGroupKey } from '../types/navigation';

export interface UIStrings {
  appName: string;
  appSubtitle: string;
  independentNoticeShort: string;
  independentNoticeFull: string;
  zeroCostPledge: string;
  versionLabel: string;
  searchModulesPlaceholder: string;
  languageLabel: string;
  stateInspectorLabel: string;
  stateNotConnected: string;
  stateDemoSchema: string;
  stateLoading: string;
  stateErrorTest: string;
  statusNotConnected: string;
  statusDemo: string;
  statusLocalReady: string;
  manualRefreshBtn: string;
  refreshingLabel: string;
  lastCheckedNever: string;
  noFakeStatsTitle: string;
  noFakeStatsDesc: string;
  plannedDataSource: string;
  refreshCadence: string;
  costGuardrail: string;
  moduleSpecHeading: string;
  phase2Heading: string;
  tableSchemaPreviewHeading: string;
  tableFilterPlaceholder: string;
  emptyModuleHeading: string;
  emptyModuleDescription: string;
  previewSchemaAction: string;
  returnToHonestEmptyAction: string;
  triggerLoadingPreviewAction: string;
  chartPlaceholderTitle: string;
  chartPlaceholderSubtitle: string;
  navGroups: Record<NavGroupKey, string>;
  legalNavHeading: string;
  legalPages: {
    about: string;
    privacy: string;
    terms: string;
    disclaimer: string;
  };
  errorBoundary: {
    title: string;
    subtitle: string;
    resetButton: string;
    technicalDetails: string;
  };
}

export const TRANSLATIONS: Record<Language, UIStrings> = {
  en: {
    appName: 'KIRON PROHORI',
    appSubtitle: 'Independent Cyber Threat Intelligence Platform',
    independentNoticeShort:
      'Independent platform · Not affiliated with CISA, NIST, CVE, FIRST, Google, or any government entity.',
    independentNoticeFull:
      'KIRON PROHORI is an independent defensive cybersecurity product. It is not affiliated with, endorsed by, or operated by CISA, NIST, MITRE/CVE, FIRST, Google, or any government agency.',
    zeroCostPledge: 'Strict $0 Budget Mode · Public Feeds & Local Analysis Only',
    versionLabel: 'v0.1.0 Foundation',
    searchModulesPlaceholder: 'Filter modules (e.g. CVE, KEV, Phishing)...',
    languageLabel: 'Language',
    stateInspectorLabel: 'Foundation State View',
    stateNotConnected: 'Not Connected (Honest Default)',
    stateDemoSchema: 'Schema Preview (Marked DEMO)',
    stateLoading: 'Loading Skeleton State',
    stateErrorTest: 'Error Boundary Test',
    statusNotConnected: 'NOT CONNECTED',
    statusDemo: 'DEMO SCHEMA',
    statusLocalReady: 'SHELL READY',
    manualRefreshBtn: 'Test Manual Refresh',
    refreshingLabel: 'Checking Feed Connector...',
    lastCheckedNever: 'Feed Sync: Not Connected in v0.1.0',
    noFakeStatsTitle: 'Strict Integrity Rule: Zero Fabricated Threat Metrics',
    noFakeStatsDesc:
      'This module is currently in Phase 1 (Foundation Shell). No live external feeds are connected yet, and KIRON PROHORI never generates synthetic or misleading threat counters. Switch to "Schema Preview (Marked DEMO)" to inspect table structures and column bindings.',
    plannedDataSource: 'Planned Public Data Source',
    refreshCadence: 'Ingestion & Refresh Mechanism',
    costGuardrail: 'Zero-Cost Compliance ($0.00)',
    moduleSpecHeading: 'Module Architecture & Data Contract',
    phase2Heading: 'Planned Phase 2 Implementation Scope',
    tableSchemaPreviewHeading: 'Data Table Contract & Column Schema',
    tableFilterPlaceholder: 'Search within schema columns...',
    emptyModuleHeading: 'Public Intelligence Feed Not Connected',
    emptyModuleDescription:
      'External public threat feeds are intentionally unlinked in the v0.1.0 foundation build. All numeric indicators remain unset until verified public connectors are enabled.',
    previewSchemaAction: 'Inspect Table Schema (DEMO)',
    returnToHonestEmptyAction: 'Return to Not Connected State',
    triggerLoadingPreviewAction: 'Preview Loading Skeleton',
    chartPlaceholderTitle: 'Telemetry Visualization Canvas (NOT CONNECTED)',
    chartPlaceholderSubtitle:
      'Chart baseline verifies Recharts responsive container geometry. Values shown in DEMO mode are structural placeholders only.',
    navGroups: {
      intelligence_feeds: 'Threat Intelligence & Advisories',
      defensive_tools: 'Inspection & Defensive Tools',
      user_workspace: 'Operations & Watchlist',
      platform_governance: 'Platform, Sources & Help',
    },
    legalNavHeading: 'Identity, Legal & Trust',
    legalPages: {
      about: 'About Platform',
      privacy: 'Privacy Policy',
      terms: 'Terms of Use',
      disclaimer: 'Security Disclaimer',
    },
    errorBoundary: {
      title: 'Module Render Exception Caught by Error Boundary',
      subtitle:
        'The application shell isolated a runtime error within this module viewport. Navigation and global settings remain operational.',
      resetButton: 'Restore Module Viewport',
      technicalDetails: 'Diagnostic Exception Trace',
    },
  },
  bn: {
    appName: 'কিরণ প্রহরী (KIRON PROHORI)',
    appSubtitle: 'স্বতন্ত্র সাইবার থ্রেট ইন্টেলিজেন্স প্ল্যাটফর্ম',
    independentNoticeShort:
      'স্বতন্ত্র পণ্য · CISA, NIST, CVE, FIRST, Google বা কোনো সরকারি সংস্থার সাথে সম্পর্কিত নয়।',
    independentNoticeFull:
      'কিরণ প্রহরী (KIRON PROHORI) একটি সম্পূর্ণ স্বতন্ত্র প্রতিরক্ষামূলক সাইবার নিরাপত্তা প্ল্যাটফর্ম। এটি CISA, NIST, CVE, FIRST, Google বা কোনো সরকারি সংস্থার দ্বারা পরিচালিত, অনুমোদিত বা সম্পর্কিত নয়।',
    zeroCostPledge: 'কঠোর $০ বাজেট নীতি · শুধুমাত্র পাবলিক ডেটা ও লোকাল বিশ্লেষণ',
    versionLabel: 'ভার্সন ০.১.০ (ফাউন্ডেশন)',
    searchModulesPlaceholder: 'মডিউল খুঁজুন (যেমন CVE, KEV, ফিশিং)...',
    languageLabel: 'ভাষা',
    stateInspectorLabel: 'ফাউন্ডেশন স্টেট ভিউ',
    stateNotConnected: 'সংযুক্ত নয় (ডিফল্ট)',
    stateDemoSchema: 'স্কিমা প্রিভিউ (DEMO চিহ্নিত)',
    stateLoading: 'লোডিং স্কেলিটন স্টেট',
    stateErrorTest: 'এরর বাউন্ডারি টেস্ট',
    statusNotConnected: 'NOT CONNECTED · সংযুক্ত নয়',
    statusDemo: 'DEMO · ডেমো স্কিমা',
    statusLocalReady: 'SHELL READY · শেল প্রস্তুত',
    manualRefreshBtn: 'ম্যানুয়াল রিফ্রেশ পরীক্ষা',
    refreshingLabel: 'ফিড কানেক্টর পরীক্ষা করা হচ্ছে...',
    lastCheckedNever: 'ফিড সিঙ্ক: v0.1.0-এ সংযুক্ত নয়',
    noFakeStatsTitle: 'তথ্য সততা নীতি: কোনো কাল্পনিক থ্রেট পরিসংখ্যান ব্যবহৃত হয়নি',
    noFakeStatsDesc:
      'এই মডিউলটি বর্তমানে ধাপ ১ (ফাউন্ডেশন শেল)-এ রয়েছে। এখনো কোনো লাইভ পাবলিক ফিড সংযুক্ত করা হয়নি এবং কিরণ প্রহরী কখনোই ভুয়া বা কাল্পনিক থ্রেট সংখ্যা প্রদর্শন করে না। টেবিলের গঠন দেখতে "স্কিমা প্রিভিউ (DEMO)" নির্বাচন করুন।',
    plannedDataSource: 'পরিকল্পিত পাবলিক ডেটা উৎস',
    refreshCadence: 'ডেটা গ্রহণ ও রিফ্রেশ পদ্ধতি',
    costGuardrail: 'শূন্য-খরচ নীতি ($0.00)',
    moduleSpecHeading: 'মডিউল আর্কিটেকচার ও ডেটা চুক্তি',
    phase2Heading: 'পরিকল্পিত ধাপ ২-এর কার্যপরিধি',
    tableSchemaPreviewHeading: 'ডেটা টেবিল কাঠামো ও কলাম স্কিমা',
    tableFilterPlaceholder: 'স্কিমা কলামের মধ্যে খুঁজুন...',
    emptyModuleHeading: 'পাবলিক ইন্টেলিজেন্স ফিড সংযুক্ত নয় (NOT CONNECTED)',
    emptyModuleDescription:
      'v0.1.0 ফাউন্ডেশন সংস্করণে বাহ্যিক থ্রেট ফিডগুলো ইচ্ছাকৃতভাবে অসংযুক্ত রাখা হয়েছে। যাচাইকৃত পাবলিক ডেটা কানেক্টর চালু না হওয়া পর্যন্ত সকল সূচক ফাঁকা থাকবে।',
    previewSchemaAction: 'টেবিল স্কিমা দেখুন (DEMO)',
    returnToHonestEmptyAction: 'সংযুক্ত নয় (Not Connected) অবস্থায় ফিরুন',
    triggerLoadingPreviewAction: 'লোডিং স্কেলিটন দেখুন',
    chartPlaceholderTitle: 'টেলিমেট্রি ভিজ্যুয়ালাইজেশন ক্যানভাস (NOT CONNECTED)',
    chartPlaceholderSubtitle:
      'এই চার্ট কন্টেইনারটি Recharts-এর রেসপন্সিভ লেআউট যাচাই করে। DEMO মোডে প্রদর্শিত মানগুলো শুধুমাত্র কাঠামোগত উদাহরণ।',
    navGroups: {
      intelligence_feeds: 'থ্রেট ইন্টেলিজেন্স ও অ্যাডভাইজরি',
      defensive_tools: 'পরিদর্শন ও প্রতিরক্ষামূলক টুলস',
      user_workspace: 'অপারেশন ও ওয়াচলিস্ট',
      platform_governance: 'প্ল্যাটফর্ম, ডেটা উৎস ও সহায়তা',
    },
    legalNavHeading: 'পরিচিতি, নীতিমালা ও ডিসক্লেইমার',
    legalPages: {
      about: 'প্ল্যাটফর্ম পরিচিতি (About)',
      privacy: 'গোপনীয়তা নীতি (Privacy)',
      terms: 'ব্যবহারের শর্তাবলী (Terms)',
      disclaimer: 'নিরাপত্তা ডিসক্লেইমার',
    },
    errorBoundary: {
      title: 'এরর বাউন্ডারি দ্বারা মডিউল ত্রুটি শনাক্ত হয়েছে',
      subtitle:
        'অ্যাপ্লিকেশন শেল এই মডিউলের একটি রানটাইম ত্রুটি বিচ্ছিন্ন করেছে। নেভিগেশন এবং অন্যান্য সেটিংস সম্পূর্ণ সচল রয়েছে।',
      resetButton: 'মডিউল ভিউপোর্ট পুনরুদ্ধার করুন',
      technicalDetails: 'ডায়াগনস্টিক ত্রুটির বিবরণ',
    },
  },
};
