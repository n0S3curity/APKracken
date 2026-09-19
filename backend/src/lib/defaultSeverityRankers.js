import { prisma } from '../db.js';

export const ANDROID_SEVERITY_RANKER_NAME = 'Android mobile security triage';
// Dedicated rankers for the two device-verifying research flows. Seeded like the
// defaults, but deliberately kept OUT of DEFAULT_SEVERITY_RANKER_NAMES so they are not
// auto-selected on the general repo tab — they are the pre-selected default only on the
// Android pentest / Samsung tabs (see CreateScan).
export const ANDROID_RESEARCH_SEVERITY_RANKER_NAME = 'Android on-device exploit impact';
export const SAMSUNG_RESEARCH_SEVERITY_RANKER_NAME = 'Samsung system-app impact';

export const DEFAULT_SEVERITY_RANKERS = [
  {
    name: 'Blockchain security triage',
    description: 'A conservative production-impact ranker suitable for a first scan.',
    content: `Rank only findings with a concrete, externally reachable production trigger.

- Critical: consensus or integrity corruption, network-wide persistent outage, or unauthorized asset creation, destruction, or theft.
- High: realistic remote input causing a prolonged service outage, consensus safety/liveness failure, authentication bypass, or substantial asset impact.
- Medium: bounded availability, authorization, or integrity impact with meaningful prerequisites or limited blast radius.
- Low: defense-in-depth issues with a concrete but minor production impact.
- Informational: hardening opportunities without demonstrated security impact.

Prefer end-to-end evidence, reachable default or supplied configuration, and reproducible triggers. Demote theoretical, test-only, privileged-local, brute-force, race-dependent, non-default, and unverified findings. Rank likely false positives last.`,
  },
  {
    name: ANDROID_SEVERITY_RANKER_NAME,
    description: 'Real-world Android/APK impact ranker: weighs reachability (exported vs chain-only) and user data.',
    content: `Rank Android/APK findings by real-world, externally reachable impact on a shipped app on a default install. Weigh HOW the component is reached: directly exported (adb / another app hits it) > chain-only (needs a URI grant, intent redirection, or setResult from another component) > internal-only (in-process). An exported, directly-reachable issue outranks the same issue on a non-exported, chain-only component.

- Critical: remote code execution or full account/device takeover with little or no user interaction — an exported component or deep link that loads attacker-controlled code/URL into a WebView with a JavaScript bridge or file access; an exported ContentProvider allowing arbitrary app-private file read/write, path traversal, or SQL injection; or hardcoded PRODUCTION credentials/API keys/signing secrets granting real server-side or account access.
- High: theft of user credentials, session tokens, or sensitive PII reachable by another installed app or a crafted intent/deep link; authentication or authorization bypass; an exported component performing a privileged action on attacker-controlled input; cleartext or disabled-TLS traffic carrying secrets; PendingIntent hijack; or a verified exploit CHAIN that reaches any of the above.
- Medium: sensitive-data exposure gated by meaningful prerequisites (physical/adb device access, an already-granted URI, a non-default configuration); task hijacking or tapjacking; weak cryptography protecting real user data; an over-broad FileProvider exploitable only via a chain; or an exported component with limited, lower-value impact.
- Low: defense-in-depth gaps with concrete but minor impact — debuggable or allowBackup-enabled release builds, verbose logging of non-secret data, missing non-critical permissions, insecure-but-unused configuration.
- Informational: hardening opportunities with no demonstrated impact — best-practice deviations, exported flags on components that expose nothing sensitive, and noise inside bundled third-party SDKs.

Prefer findings with a concrete, runnable trigger on a default install (an adb/intent PoC or a malicious-app snippet) and real vulnerable code. Demote theoretical, internal-only, root/privileged-local, test/debug-only, and third-party-library findings, and rank likely false positives last.`,
  },
];

// Research-flow rankers. Weigh PROVEN-on-device impact above static reasoning, matching the
// device-verifying workflows (dynamic_verified findings are demonstrated, not hypothesised).
export const MOBILE_RESEARCH_SEVERITY_RANKERS = [
  {
    name: ANDROID_RESEARCH_SEVERITY_RANKER_NAME,
    description: 'On-device exploit research ranker: proven-on-device impact outranks static-only reasoning.',
    content: `Rank Android findings from the on-device exploit-research workflow by DEMONSTRATED, externally reachable impact on a default install. A finding reproduced live on the device/emulator (dynamic_verified) is proven, not hypothetical — rank it above an otherwise-identical static-only finding, and never rank a device-proven finding as a false positive. Weigh reachability: directly exported / deep-linkable (adb or another app triggers it) > chain-only (needs a URI grant, intent redirection, or a setResult hop) > internal-only.

- Critical: device-proven remote code execution or full account/device takeover with little or no user interaction — attacker code/URL reaching a WebView JS bridge or file access; an exported ContentProvider giving arbitrary app-private read/write, path traversal, or SQL injection; or hardcoded PRODUCTION secrets granting real server-side/account access. A runtime-guard bypass (SSL unpinning, root/emulator-detection defeat) that unlocked the exploit raises confidence, not lowers it.
- High: device-proven theft of credentials, session tokens, or sensitive PII reachable by another installed app or a crafted intent/deep link; authentication/authorization bypass; an exported component taking a privileged action on attacker input; PendingIntent hijack; or a verified exploit CHAIN reaching any of the above.
- Medium: impact gated by meaningful prerequisites (physical/adb access, an already-granted URI, a non-default config); task hijacking/tapjacking; weak crypto over real user data; an over-broad FileProvider exploitable only via a chain; or a plausible static finding not yet reproduced on device.
- Low: defense-in-depth gaps with concrete but minor impact — debuggable/allowBackup release builds, verbose non-secret logging, insecure-but-unused configuration.
- Informational: hardening with no demonstrated impact, exported flags exposing nothing sensitive, and noise inside bundled third-party SDKs.

Strongly prefer findings carrying on-device evidence (screenshots, an observed effect, a reproduced adb/Frida trigger). Demote theoretical, internal-only, root/privileged-local, and test/debug-only findings; rank unreproduced, evidence-contradicted, or likely-false-positive findings last.`,
  },
  {
    name: SAMSUNG_RESEARCH_SEVERITY_RANKER_NAME,
    description: 'Samsung system-app ranker (com.samsung.*/com.sec.*): weighs privileged/system reach + SVE-style impact.',
    content: `Rank findings in Samsung pre-installed / system apps (com.samsung.*, com.sec.*) by real-world impact reachable by an UNPRIVILEGED third-party app or a physically-present actor on a default retail Samsung device, in the spirit of the Samsung Mobile Security Rewards Program (SVE). These apps often hold system/signature or privileged permissions, so the pivotal question is whether an outside caller crosses a privilege boundary. Weigh caller verification: a privileged action reachable from an unprivileged/exported entry with NO caller permission/signature check is the core Samsung bug class — rank it highest. A finding reproduced live on a Samsung device is proven; rank it above a static-only equivalent.

- Critical: unprivileged local app gains code execution, a system/privileged capability, or persistent device compromise through a Samsung system app — an exported system component performing a privileged operation on attacker input with no caller check; a privileged Knox/DevicePolicy/settings surface reachable from a third-party app; or arbitrary read/write of another app's or system data via an exported/grantUri provider.
- High: unprivileged app or crafted intent/deep link extracts sensitive user or account data (SSO/Samsung account tokens, Pay/health/contacts/PII), bypasses authentication/authorization, or abuses a custom permission that is downgraded (normal/dangerous instead of signature) to reach a protected action.
- Medium: impact gated by meaningful prerequisites (physical access, an already-granted URI, a non-default or enterprise-only config); information disclosure of lower-value data; a privileged surface reachable only via a chain.
- Low: defense-in-depth gaps with concrete but minor impact on the system app.
- Informational: hardening opportunities, exported flags exposing nothing sensitive, and issues confined to bundled third-party SDKs shipped inside the Samsung app.

Prefer findings with a concrete unprivileged trigger (a malicious-app snippet or an adb/intent PoC) that crosses a privilege boundary, plus on-device evidence where available. Demote issues requiring system/signature permission the attacker cannot obtain, root/privileged-local-only findings, and likely false positives — rank those last.`,
  },
];

export const DEFAULT_SEVERITY_RANKER_NAMES = DEFAULT_SEVERITY_RANKERS.map((ranker) => ranker.name);

export function isDefaultSeverityRankerName(name) {
  return DEFAULT_SEVERITY_RANKER_NAMES.includes(name);
}

export async function ensureDefaultSeverityRankers(client = prisma) {
  return client.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext('open-kritt-default-severity-rankers'))`;

    const installed = [];
    for (const ranker of [...DEFAULT_SEVERITY_RANKERS, ...MOBILE_RESEARCH_SEVERITY_RANKERS]) {
      const existing = await tx.severityRanker.findFirst({
        where: { name: ranker.name },
        orderBy: { insertedAt: 'asc' },
        select: { id: true },
      });
      if (existing) continue;
      await tx.severityRanker.create({ data: ranker });
      installed.push(ranker.name);
    }
    return installed;
  });
}
