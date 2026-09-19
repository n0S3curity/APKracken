"""General source-code security agent skills — OWASP Top 10 + common code-bug classes.

Unlike the Android specialists (which run in the APK investigation phase), these are editable
agent skills the user attaches to ANY scan (local repo, remote repo). Their content is injected
into the scan prompt (native_agent_skills_prompt → agent_skills_prompt for the local harness), so
they steer the tool-using agent toward specific vulnerability classes. Seeded insert-if-missing so
UI edits are preserved.
"""

from __future__ import annotations

import logging

LOGGER = logging.getLogger("open_kritt_engine")

_SLUG_PREFIX = "sec-"

# (selector, name, description, content)
_SECURITY_SKILLS: list[tuple[str, str, str, str]] = [
    (
        "injection",
        "Injection (SQL / NoSQL / OS Command / LDAP / XPath)",
        "Attacker-controlled input reaching a query/command interpreter without parameterisation.",
        "Hunt INJECTION: attacker-controlled input concatenated into an interpreter instead of being parameterised. "
        "SQL/HQL/JPQL (Statement + string concat, `createQuery(\"... \"+x)`, `rawQuery`, `.append(userInput)`), "
        "NoSQL (Mongo `$where`, JSON query built from input), OS command (`Runtime.exec`, `ProcessBuilder`, "
        "`os.system`, backticks with user data), LDAP filters, XPath, and expression languages. Trace the tainted "
        "value from its source (HTTP param/header/body, message, file) to the sink; note any escaping/validation and "
        "whether it is bypassable. Report the exact sink file:line, the tainted path, and a concrete payload.",
    ),
    (
        "broken-access-control",
        "Broken Access Control (AuthZ / IDOR)",
        "Missing or bypassable authorization: IDOR, forced browsing, privilege escalation, path-based access.",
        "Hunt BROKEN ACCESS CONTROL: endpoints/handlers/RPCs that act on a resource without verifying the caller is "
        "authorized for THAT resource. Look for IDOR (an id/path/key from the request used to fetch or mutate data "
        "with no ownership/role check), missing `@PreAuthorize`/role guards, admin functions reachable without admin, "
        "client-side-only checks, and access decisions made on attacker-controlled fields. Read the auth filter/"
        "interceptor and confirm which routes it actually covers. Report the unprotected action, who can reach it, "
        "and what they can read/change.",
    ),
    (
        "cryptographic-failures",
        "Cryptographic Failures",
        "Weak/misused crypto, hardcoded keys, plaintext secrets, weak hashing, bad TLS.",
        "Hunt CRYPTOGRAPHIC FAILURES: hardcoded keys/passwords/IVs, ECB mode, static/predictable IVs, weak algorithms "
        "(DES, RC4, MD5/SHA1 for security), `Random`/`Math.random` for secrets/tokens, unsalted or fast password "
        "hashing, disabled certificate/hostname verification (custom TrustManager, `verify(){return true}`), and "
        "secrets in config/source. Quote the exact key/algorithm/transformation and state what an attacker can "
        "decrypt, forge, or predict as a result.",
    ),
    (
        "insecure-deserialization",
        "Insecure Deserialization (Object Injection → RCE)",
        "Deserialising untrusted data (Java/Python/PHP/.NET, YAML, XML) enabling gadget-chain RCE or tampering.",
        "Hunt INSECURE DESERIALIZATION: untrusted bytes fed to a deserializer. Java `ObjectInputStream.readObject`, "
        "`XMLDecoder`, `readUnshared`; unsafe YAML (`SnakeYaml new Yaml()` with a permissive constructor), "
        "Kryo/XStream without a type allowlist, JSON with polymorphic type handling (Jackson `enableDefaultTyping` / "
        "`@JsonTypeInfo`), Python `pickle`/`yaml.load`. Trace where the serialized data originates (request body, "
        "cache, queue, file) and whether a type allowlist / lookahead filter exists. Report the sink, the untrusted "
        "source, whether a gadget chain is plausible (libraries on the classpath), and the impact (RCE / DoS / "
        "tampering).",
    ),
    (
        "xxe",
        "XML External Entity (XXE)",
        "XML parsers that resolve external entities/DTDs on untrusted input → file read / SSRF / DoS.",
        "Hunt XXE: XML parsers created without disabling DTDs/external entities on attacker-supplied XML. Java "
        "`DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `SAXReader`, `TransformerFactory`, "
        "`Unmarshaller` — check whether `disallow-doctype-decl` / `external-general-entities` / `external-parameter-"
        "entities` are set to false, or `XMLConstants.FEATURE_SECURE_PROCESSING` / `setExpandEntityReferences(false)`. "
        "If not hardened and the input is untrusted, report file-read (`file://`), SSRF (`http://`), and billion-laughs "
        "DoS, with the parser file:line and a sample malicious XML.",
    ),
    (
        "ssrf",
        "Server-Side Request Forgery (SSRF)",
        "Server makes a request to an attacker-controlled URL/host (cloud metadata, internal services).",
        "Hunt SSRF: the server issues an outbound request to a URL/host derived from user input. HTTP clients "
        "(`HttpURLConnection`, `RestTemplate`, `WebClient`, `OkHttp`, `HttpClient`, `URL.openConnection`), fetch-by-url "
        "features, webhooks, PDF/image/URL previewers, and XML/SVG loaders. Check for an allowlist of hosts/schemes "
        "and whether redirects, DNS rebinding, `file://`/`gopher://`, or `169.254.169.254` (cloud metadata) bypass it. "
        "Report the request sink, the tainted URL source, and what internal resource the attacker reaches.",
    ),
    (
        "path-traversal",
        "Path Traversal & Arbitrary File Access (Zip Slip)",
        "User input reaching a filesystem path → read/write/delete outside the intended directory.",
        "Hunt PATH TRAVERSAL: request/message data used to build a filesystem path. `new File(base, userName)`, "
        "`Files.newInputStream`, `FileInputStream`, `Paths.get`, static-file handlers, download/upload endpoints, and "
        "archive extraction (Zip Slip: `zipEntry.getName()` joined to an output dir without canonicalisation). Check "
        "for `../` handling, absolute-path acceptance, null bytes, and whether the canonicalised path is confined to "
        "the base dir. Report the sink, the traversal payload, and whether it enables read, overwrite, or delete.",
    ),
    (
        "race-condition",
        "Race Conditions & TOCTOU",
        "Check-then-use / concurrent access to shared state an attacker can win the race on.",
        "Hunt RACE CONDITIONS: attacker-triggerable time-of-check/time-of-use and unsynchronised shared state. "
        "Check-then-act on files/paths/permissions (verify then open a world-writable/temp path; symlink swaps), "
        "shared mutable state (static/singleton fields, caches, counters, balances) mutated from concurrent request "
        "handlers without locking/atomics, double-spend / limit-bypass via parallel requests, and non-atomic "
        "get-then-set. Identify who triggers the race, the window, and the consequence (auth bypass, data corruption, "
        "double-spend). These are hard to prove dynamically — judge from the code pattern and set confidence honestly.",
    ),
    (
        "xss",
        "Cross-Site Scripting (XSS)",
        "Untrusted data rendered into HTML/JS without contextual encoding (reflected/stored/DOM).",
        "Hunt XSS: untrusted data written into an HTML/JS/attribute/URL context without contextual output encoding. "
        "Server-rendered templates with raw/unescaped output (`<%= %>`, `{{{ }}}`, `th:utext`, `| safe`, `dangerouslySet"
        "InnerHTML`, `innerHTML`, `document.write`), reflected request params, and stored values later rendered. "
        "Distinguish reflected vs stored vs DOM. Check the template engine's auto-escaping and whether it is disabled "
        "for the sink. Report the source, the sink file:line, the context, and a payload.",
    ),
    (
        "ssti",
        "Server-Side Template Injection (SSTI)",
        "User input concatenated into a template that is then evaluated → RCE / data disclosure.",
        "Hunt SSTI: attacker-controlled input placed into a template STRING that the engine then evaluates (not just "
        "passed as data). Freemarker, Velocity, Thymeleaf (expression preprocessing), Jinja2/Twig, Handlebars, "
        "`Runtime`-capable engines, and any `engine.process(userControlledTemplate)`. Confirm the input reaches the "
        "template body (not a bound variable) and whether the engine exposes objects enabling RCE. Report the sink, "
        "the tainted template source, and an evaluation payload.",
    ),
    (
        "authentication-failures",
        "Authentication & Session Failures",
        "Broken login, weak/guessable credentials, flawed session/token handling, missing MFA on sensitive flows.",
        "Hunt AUTH & SESSION FAILURES: default/hardcoded credentials, missing rate-limiting/lockout on login, weak "
        "password policy, credential logging, predictable/long-lived tokens, JWTs with `alg:none`/weak secret/no "
        "signature verification, session fixation (id not rotated on login), missing session invalidation on logout, "
        "and insecure 'remember me'/reset-token flows. Read the auth + token code and report the concrete weakness "
        "and what it lets an attacker do (account takeover, bypass).",
    ),
    (
        "security-misconfiguration",
        "Security Misconfiguration",
        "Dangerous defaults, permissive CORS, verbose errors, exposed admin/actuator/debug endpoints.",
        "Hunt SECURITY MISCONFIGURATION: debug/dev mode in production, verbose stack traces returned to clients, "
        "permissive CORS (`Access-Control-Allow-Origin: *` with credentials, reflected Origin), disabled CSRF where "
        "it matters, exposed management/admin/actuator/metrics/H2-console endpoints, directory listing, default "
        "accounts, over-broad file permissions, and secrets in config committed to the repo. Read config files "
        "(application.yml/properties, web.xml, nginx, docker) and report the exposure + impact.",
    ),
    (
        "sensitive-data-exposure",
        "Sensitive Data Exposure & Logging",
        "Secrets / PII / tokens leaked via logs, errors, responses, or insecure storage.",
        "Hunt SENSITIVE DATA EXPOSURE: credentials/tokens/PII/card/health data written to logs (`log.info(password)`, "
        "full request/response dumps), returned in error messages or API responses beyond what's needed, stored "
        "unencrypted, or transmitted over cleartext. Grep for `password`, `secret`, `token`, `apikey`, `authorization` "
        "near logging/serialisation. Report what sensitive value is exposed, where, and who can see it.",
    ),
    (
        "unsafe-reflection-rce",
        "Unsafe Reflection / Dynamic Code Execution",
        "Attacker input choosing classes/methods/code to load or execute → RCE.",
        "Hunt UNSAFE REFLECTION / DYNAMIC EXECUTION: user input selecting a class/method/handler to load or invoke. "
        "`Class.forName(userInput)`, `.getMethod(userInput).invoke`, `ClassLoader`, `ScriptEngine.eval`, `GroovyShell`, "
        "`Nashorn`, `eval`/`exec`, plugin loaders, and JNDI lookups (`InitialContext.lookup(userInput)` — Log4Shell-"
        "style). Confirm the input controls the target and whether an allowlist constrains it. Report the sink and how "
        "it reaches attacker-controlled code execution.",
    ),
    (
        "open-redirect",
        "Open Redirect & URL Validation",
        "Unvalidated user-controlled redirect/forward target enabling phishing/token theft.",
        "Hunt OPEN REDIRECT: a redirect/forward whose target comes from user input without a strict allowlist. "
        "`sendRedirect(userUrl)`, `Location` header set from a param, `RedirectView`, `res.redirect(req.query.next)`, "
        "and OAuth `redirect_uri` handling. Test bypasses of any allowlist (`//evil.com`, `https:evil.com`, `@`, "
        "backslashes, sub-domain/prefix tricks). Report the redirect sink, the tainted source, and the phishing / "
        "OAuth-token-theft impact.",
    ),
    (
        "vulnerable-components",
        "Vulnerable & Outdated Components",
        "Known-vulnerable or outdated dependencies with a reachable, exploitable code path.",
        "Hunt VULNERABLE COMPONENTS: read the dependency manifests (pom.xml, build.gradle, package.json, requirements"
        ".txt, go.mod) and flag libraries/versions with well-known CVEs (e.g. Log4j <2.17, Jackson-databind gadget "
        "versions, Spring, Struts, Fastjson, commons-collections). Only report as exploitable when the app actually "
        "uses the affected feature on attacker-reachable data; otherwise note it as a lower-confidence dependency "
        "risk. Report the component, version, CVE class, and the reachable usage.",
    ),
]


def security_skill_defs() -> list[dict[str, str]]:
    return [
        {"slug": _SLUG_PREFIX + selector, "selector": selector, "name": name, "description": desc, "content": content}
        for (selector, name, desc, content) in _SECURITY_SKILLS
    ]


def ensure_security_skills(conn) -> int:
    """Seed the OWASP / code-bug agent skills (insert-if-missing). Returns count newly added."""
    installed = 0
    for skill in security_skill_defs():
        cur = conn.execute(
            """
            INSERT INTO public.agent_skills (slug, name, description, content)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (slug) DO NOTHING
            """,
            (skill["slug"], skill["name"], skill["description"], skill["content"]),
        )
        installed += cur.rowcount or 0
    conn.commit()
    return installed
