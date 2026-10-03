from flask import g, request, url_for
from .acl import has_permission


def nav_for_request():
    org = getattr(g, "organization", None)
    org_id = (org or {}).get("syntal_org_id")
    endpoint = request.endpoint or ""
    category = "overview"
    if endpoint.startswith("diagnostics."):category="access" if endpoint.endswith("inspector") else "applications"
    if endpoint.startswith("organizations."):
        category = "organization"
    elif endpoint.startswith("applications."):
        category = "applications"
    elif endpoint.startswith("access."):
        category = "access"
    elif endpoint.startswith("billing."):
        category = "billing"
    elif endpoint.startswith("auth."):
        category = "settings"

    def orgurl(endpoint_name, **kwargs):
        return url_for(endpoint_name, org_id=org_id, **kwargs) if org_id else url_for("organizations.index")

    primary = [
        {"key":"overview","label":"Overview","href":url_for("organizations.dashboard"),"visible":True},
        {"key":"organization","label":"Organization","href":orgurl("organizations.overview"),"visible":bool(org_id)},
        {"key":"applications","label":"Applications","href":orgurl("applications.index"),"visible":bool(org_id) and (has_permission("syntal.org_apps.read") or has_permission("syntal.apps.manage"))},
        {"key":"access","label":"Access","href":orgurl("access.roles"),"visible":bool(org_id) and has_permission("syntal.roles.read")},
        {"key":"billing","label":"Billing","href":orgurl("billing.overview"),"visible":bool(org_id) and has_permission("syntal.billing.read")},
        {"key":"settings","label":"Settings","href":orgurl("organizations.settings") if org_id else url_for("auth.account"),"visible":True},
    ]
    secondary = {
        "overview": [
            ("dashboard","Dashboard",url_for("organizations.dashboard"),True),
            ("activity","Activity",orgurl("access.audit_log"),bool(org_id) and has_permission("syntal.audit.read")),
        ],
        "organization": [
            ("overview","Overview",orgurl("organizations.overview"),True),
            ("people","People",orgurl("organizations.people"),True),
            ("invitations","Invitations",orgurl("organizations.invitations"),has_permission("syntal.members.invite") or has_permission("syntal.members.read")),
            ("teams","Teams",orgurl("organizations.teams"),True),
            ("organizations","Organizations",url_for("organizations.index"),True),
        ],
        "applications": [
            ("applications","Applications",orgurl("applications.index"),True),
            ("diagnostics","Integration diagnostics",orgurl("diagnostics.integrations"),has_permission("syntal.org_apps.manage")),
            ("assignments","Access assignments",orgurl("access.matrix"),has_permission("syntal.roles.read")),
            ("developers","Developer applications",url_for("applications.developers"),has_permission("syntal.org_apps.manage")),
            ("security","Security policy",orgurl("applications.security"),has_permission("syntal.org_apps.manage")),
        ],
        "access": [
            ("roles","Roles",orgurl("access.roles"),True),
            ("permissions","Permissions",orgurl("access.permissions"),True),
            ("inspector","Member access inspector",orgurl("diagnostics.inspector"),has_permission("syntal.members.read")),
            ("matrix","Access matrix",orgurl("access.matrix"),True),
            ("decisions","Authorization decisions",orgurl("access.decisions"),has_permission("syntal.audit.read")),
            ("audit","Audit log",orgurl("access.audit_log"),has_permission("syntal.audit.read")),
        ],
        "billing": [
            ("overview","Overview",orgurl("billing.overview"),True),
            ("subscriptions","Subscriptions",orgurl("billing.subscriptions"),True),
            ("usage","Usage",orgurl("billing.usage"),True),
            ("invoices","Invoices",orgurl("billing.invoices"),True),
            ("profile","Billing profile",orgurl("billing.profile"),has_permission("syntal.billing.manage") or has_permission("syntal.billing.read")),
        ],
        "settings": [
            ("organization","Organization",orgurl("organizations.settings"),bool(org_id)),
            ("security","Security",orgurl("applications.security"),bool(org_id) and has_permission("syntal.org_apps.manage")),
            ("ownership","Ownership",orgurl("organizations.ownership"),bool(org_id)),
            ("lifecycle","Lifecycle",orgurl("organizations.lifecycle"),bool(org_id)),
            ("account","My account",url_for("auth.account"),True),
            ("sessions","Your sessions",url_for("auth.sessions"),True),
        ],
    }
    active = active_secondary(endpoint)
    return {
        "primary": [x for x in primary if x["visible"]],
        "secondary": [{"key":k,"label":l,"href":h} for k,l,h,v in secondary.get(category,[]) if v],
        "category": category,
        "active": active,
    }


def active_secondary(endpoint):
    mapping = {
        "organizations.dashboard":"dashboard","organizations.index":"organizations","organizations.overview":"overview","organizations.people":"people","organizations.person_detail":"people","organizations.invitations":"invitations","organizations.teams":"teams","organizations.team_detail":"teams","organizations.settings":"organization","organizations.ownership":"ownership","organizations.lifecycle":"lifecycle",
        "applications.index":"applications","applications.detail":"applications","applications.app_overview":"applications","applications.app_configuration":"applications","applications.app_permissions":"applications","applications.app_roles":"applications","applications.app_members":"applications","applications.app_oauth":"applications","applications.app_secrets":"applications","applications.developers":"developers","applications.security":"security",
        "access.roles":"roles","access.role_detail":"roles","access.permissions":"permissions","access.matrix":"matrix","access.decisions":"decisions","access.audit_log":"audit",
        "billing.overview":"overview","billing.subscriptions":"subscriptions","billing.usage":"usage","billing.invoices":"invoices","billing.invoice_detail":"invoices","billing.profile":"profile",
        "auth.account":"account","auth.sessions":"sessions","diagnostics.inspector":"inspector","diagnostics.integrations":"diagnostics",
    }
    return mapping.get(endpoint, "dashboard")
