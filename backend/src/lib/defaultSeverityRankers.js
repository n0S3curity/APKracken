import { prisma } from '../db.js';

export const ANDROID_SEVERITY_RANKER_NAME = 'Android mobile security triage';

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

export const DEFAULT_SEVERITY_RANKER_NAMES = DEFAULT_SEVERITY_RANKERS.map((ranker) => ranker.name);

export function isDefaultSeverityRankerName(name) {
  return DEFAULT_SEVERITY_RANKER_NAMES.includes(name);
}

export async function ensureDefaultSeverityRankers(client = prisma) {
  return client.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext('open-kritt-default-severity-rankers'))`;

    const installed = [];
    for (const ranker of DEFAULT_SEVERITY_RANKERS) {
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
