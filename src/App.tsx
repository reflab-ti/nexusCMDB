import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Cloud,
  GitBranch,
  HardDrive,
  HelpCircle,
  History,
  Image as ImageIcon,
  Layers3,
  LogOut,
  Pencil,
  Play,
  Plus,
  RefreshCw,
  Save,
  Search,
  Server,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  Trash2,
  Users,
  Workflow,
  X,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

type Section = "dashboard" | "active-directory" | "nutanix" | "mappings" | "syncs" | "settings" | "admin" | "branding";
type SourceKind = "AD" | "Nutanix";
type SourcePage = "ad" | "nutanix";
type ADEntity = "Usuarios" | "Grupos" | "Equipos";
type SyncStatus = "Correcta" | "Aviso" | "Error" | "Ejecutando";
type AdTestStatus = "idle" | "testing" | "success" | "error";
type OuNode = {
  dn: string;
  name: string;
  children?: OuNode[];
};
type JiraSchemaInfo = {
  id?: string;
  name: string;
  objectTypes: Array<string | JiraObjectTypeInfo>;
};
type JiraObjectTypeInfo = {
  id?: string;
  name: string;
  attributes?: Array<string | JiraAttributeInfo>;
};
type JiraAttributeInfo = {
  id?: string;
  name: string;
  editable?: boolean;
  system?: boolean;
  required?: boolean;
  label?: boolean;
  type?: string;
};
type AttributeOption = string | {
  name: string;
  description: string;
};
type SourceConfig = {
  ad: {
    name: string;
    domain: string;
    url: string;
    bindUser: string;
    bindPassword?: string;
    hasBindPassword?: boolean;
    connected?: boolean;
    testedAt?: string;
    domainTree?: OuNode[];
    enabled: Record<ADEntity, boolean>;
    ous: Record<ADEntity, string[]>;
    attributes: Record<ADEntity, string[]>;
  };
  nutanix: {
    name: string;
    prismUrl: string;
    username: string;
    password?: string;
    hasPassword?: boolean;
    connected?: boolean;
    testedAt?: string;
    selectedClusters: string[];
    attributes: string[];
  };
  jira: {
    url: string;
    cloudId: string;
    workspaceId: string;
    email: string;
    apiToken?: string;
    hasApiToken?: boolean;
    connected?: boolean;
    testedAt?: string;
    schemas?: JiraSchemaInfo[];
  };
};

type Mapping = {
  id: string;
  name: string;
  source: SourceKind;
  entity: ADEntity | "VMs";
  sourceScope: string[];
  jiraSchema: string;
  objectType: string;
  automatic: boolean;
  frequency: string;
  fields: MappingField[];
  statusConfig?: {
    enabled: boolean;
    jiraAttribute: string;
    activeValue: string;
    inactiveValue: string;
    disabledValue?: string;
  };
  lastSync: string;
  status: SyncStatus;
};

type MappingField = {
  sourceAttribute: string;
  jiraAttribute: string;
  key: boolean;
  kind?: "attribute" | "jiraObject";
  reference?: {
    schema: string;
    objectType: string;
    matchAttribute: string;
  };
};

type AppRoute = {
  section: Section;
  sourcePage: SourcePage;
  mappingPageId?: string;
};

type AuthUser = {
  id: string;
  email: string;
  role: string;
  active: boolean;
  expirationPolicy: PasswordExpirationPolicy;
  passwordChangedAt?: string | null;
  passwordExpiresAt?: string | null;
  createdAt?: string;
  updatedAt?: string;
};

type PasswordExpirationPolicy = "never" | "6months" | "1year";
type BrandingSettings = {
  logoDataUrl: string;
  faviconDataUrl: string;
  appTitle: string;
};

const defaultBranding: BrandingSettings = {
  logoDataUrl: "",
  faviconDataUrl: "",
  appTitle: "Nexus CMDB",
};

type SyncLog = {
  id: string;
  mappingName: string;
  startedAt: string;
  status: SyncStatus;
  created: number;
  updated: number;
  unchanged: number;
  errors: number;
  changes: Array<{ object: string; action: string; detail: string }>;
  done?: boolean;
};

const adAttributes: Record<ADEntity, AttributeOption[]> = {
  Usuarios: [
    { name: "objectSid", description: "ID unico AD" },
    { name: "objectGUID", description: "GUID objeto" },
    { name: "objectClass", description: "Clases objeto" },
    { name: "objectCategory", description: "Categoria objeto" },
    { name: "distinguishedName", description: "Ruta LDAP" },
    { name: "canonicalName", description: "Ruta canonica" },
    { name: "name", description: "Nombre objeto" },
    { name: "cn", description: "Nombre comun" },
    { name: "displayName", description: "Nombre visible" },
    { name: "givenName", description: "Nombre" },
    { name: "sn", description: "Apellidos" },
    { name: "initials", description: "Iniciales" },
    { name: "description", description: "Descripcion" },
    { name: "employeeID", description: "ID empleado" },
    { name: "employeeNumber", description: "Numero empleado" },
    { name: "employeeType", description: "Tipo empleado" },
    { name: "userPrincipalName", description: "UPN login" },
    { name: "sAMAccountName", description: "Cuenta SAM" },
    { name: "sAMAccountType", description: "Tipo SAM" },
    { name: "userAccountControl", description: "Flags cuenta" },
    { name: "accountExpires", description: "Caduca cuenta" },
    { name: "adminCount", description: "Cuenta admin" },
    { name: "badPwdCount", description: "Fallos password" },
    { name: "badPasswordTime", description: "Ultimo fallo" },
    { name: "codePage", description: "Pagina codigo" },
    { name: "countryCode", description: "Codigo pais" },
    { name: "lastLogoff", description: "Ultimo logoff" },
    { name: "lastLogon", description: "Logon DC" },
    { name: "lastLogonTimestamp", description: "Ultimo logon" },
    { name: "lockoutTime", description: "Bloqueo" },
    { name: "logonCount", description: "Num logons" },
    { name: "pwdLastSet", description: "Cambio password" },
    { name: "msDS-UserPasswordExpiryTimeComputed", description: "Caduca password" },
    { name: "msDS-User-Account-Control-Computed", description: "Flags calculados" },
    { name: "primaryGroupID", description: "Grupo primario" },
    { name: "memberOf", description: "Grupos" },
    { name: "tokenGroups", description: "SID grupos" },
    { name: "tokenGroupsGlobalAndUniversal", description: "SID G/U" },
    { name: "mail", description: "Correo" },
    { name: "proxyAddresses", description: "Alias correo" },
    { name: "targetAddress", description: "Direccion destino" },
    { name: "mailNickname", description: "Alias mail" },
    { name: "department", description: "Departamento" },
    { name: "title", description: "Cargo" },
    { name: "company", description: "Empresa" },
    { name: "division", description: "Division" },
    { name: "manager", description: "Manager" },
    { name: "directReports", description: "Reportes" },
    { name: "physicalDeliveryOfficeName", description: "Oficina" },
    { name: "telephoneNumber", description: "Telefono" },
    { name: "mobile", description: "Movil" },
    { name: "facsimileTelephoneNumber", description: "Fax" },
    { name: "homePhone", description: "Telefono casa" },
    { name: "ipPhone", description: "Telefono IP" },
    { name: "pager", description: "Busca" },
    { name: "streetAddress", description: "Direccion" },
    { name: "postOfficeBox", description: "Apartado postal" },
    { name: "l", description: "Ciudad" },
    { name: "st", description: "Provincia" },
    { name: "postalCode", description: "Codigo postal" },
    { name: "co", description: "Pais" },
    { name: "c", description: "Codigo pais" },
    { name: "preferredLanguage", description: "Idioma" },
    { name: "wWWHomePage", description: "Web" },
    { name: "url", description: "URLs" },
    { name: "info", description: "Notas" },
    { name: "personalTitle", description: "Tratamiento" },
    { name: "displayNamePrintable", description: "Nombre impreso" },
    { name: "legacyExchangeDN", description: "DN Exchange" },
    { name: "homeDirectory", description: "Home dir" },
    { name: "homeDrive", description: "Unidad home" },
    { name: "profilePath", description: "Perfil" },
    { name: "scriptPath", description: "Script login" },
    { name: "userWorkstations", description: "PCs login" },
    { name: "logonHours", description: "Horario login" },
    { name: "unixHomeDirectory", description: "Home Unix" },
    { name: "uid", description: "UID Unix" },
    { name: "uidNumber", description: "UID numero" },
    { name: "gidNumber", description: "GID numero" },
    { name: "loginShell", description: "Shell Unix" },
    { name: "msSFU30Name", description: "SFU nombre" },
    { name: "msSFU30NisDomain", description: "Dominio NIS" },
    { name: "whenCreated", description: "Fecha alta" },
    { name: "whenChanged", description: "Ultimo cambio" },
    { name: "createTimeStamp", description: "Timestamp alta" },
    { name: "modifyTimeStamp", description: "Timestamp cambio" },
    { name: "uSNCreated", description: "USN alta" },
    { name: "uSNChanged", description: "USN cambio" },
    { name: "dSCorePropagationData", description: "Propagacion DS" },
    { name: "isDeleted", description: "Eliminado" },
    { name: "isCriticalSystemObject", description: "Objeto critico" },
    { name: "nTSecurityDescriptor", description: "ACL objeto" },
    { name: "instanceType", description: "Tipo instancia" },
  ],
  Grupos: [
    { name: "objectSid", description: "ID unico AD" },
    { name: "objectGUID", description: "GUID objeto" },
    { name: "objectClass", description: "Clases objeto" },
    { name: "objectCategory", description: "Categoria objeto" },
    { name: "distinguishedName", description: "Ruta LDAP" },
    { name: "canonicalName", description: "Ruta canonica" },
    { name: "name", description: "Nombre objeto" },
    { name: "displayName", description: "Nombre visible" },
    { name: "cn", description: "Nombre comun" },
    { name: "sAMAccountName", description: "Cuenta SAM" },
    { name: "sAMAccountType", description: "Tipo SAM" },
    { name: "description", description: "Descripcion" },
    { name: "info", description: "Notas" },
    { name: "mail", description: "Correo" },
    { name: "proxyAddresses", description: "Alias correo" },
    { name: "mailNickname", description: "Alias mail" },
    { name: "groupType", description: "Tipo grupo" },
    { name: "groupMembershipSAM", description: "Miembros SAM" },
    { name: "managedBy", description: "Responsable" },
    { name: "member", description: "Miembros" },
    { name: "memberOf", description: "Grupos padre" },
    { name: "primaryGroupToken", description: "Token grupo" },
    { name: "adminCount", description: "Grupo admin" },
    { name: "whenCreated", description: "Fecha alta" },
    { name: "whenChanged", description: "Ultimo cambio" },
    { name: "createTimeStamp", description: "Timestamp alta" },
    { name: "modifyTimeStamp", description: "Timestamp cambio" },
    { name: "uSNCreated", description: "USN alta" },
    { name: "uSNChanged", description: "USN cambio" },
    { name: "dSCorePropagationData", description: "Propagacion DS" },
    { name: "isDeleted", description: "Eliminado" },
    { name: "isCriticalSystemObject", description: "Objeto critico" },
    { name: "nTSecurityDescriptor", description: "ACL objeto" },
    { name: "instanceType", description: "Tipo instancia" },
  ],
  Equipos: [
    { name: "objectSid", description: "ID unico AD" },
    { name: "objectGUID", description: "GUID objeto" },
    { name: "objectClass", description: "Clases objeto" },
    { name: "objectCategory", description: "Categoria objeto" },
    { name: "distinguishedName", description: "Ruta LDAP" },
    { name: "canonicalName", description: "Ruta canonica" },
    { name: "name", description: "Nombre objeto" },
    { name: "displayName", description: "Nombre visible" },
    { name: "cn", description: "Nombre comun" },
    { name: "dNSHostName", description: "Nombre DNS" },
    { name: "servicePrincipalName", description: "SPNs" },
    { name: "operatingSystemServicePack", description: "Service pack" },
    { name: "operatingSystemHotfix", description: "Hotfix SO" },
    { name: "operatingSystem", description: "Sistema operativo" },
    { name: "operatingSystemVersion", description: "Version SO" },
    { name: "lastLogon", description: "Logon DC" },
    { name: "lastLogonTimestamp", description: "Ultimo logon" },
    { name: "lastLogoff", description: "Ultimo logoff" },
    { name: "logonCount", description: "Num logons" },
    { name: "pwdLastSet", description: "Cambio password" },
    { name: "accountExpires", description: "Caduca cuenta" },
    { name: "userAccountControl", description: "Flags cuenta" },
    { name: "sAMAccountName", description: "Cuenta SAM" },
    { name: "sAMAccountType", description: "Tipo SAM" },
    { name: "primaryGroupID", description: "Grupo primario" },
    { name: "memberOf", description: "Grupos" },
    { name: "managedBy", description: "Responsable" },
    { name: "location", description: "Ubicacion" },
    { name: "description", description: "Descripcion" },
    { name: "localPolicyFlags", description: "Flags politica" },
    { name: "msDS-SupportedEncryptionTypes", description: "Cifrado Kerberos" },
    { name: "msDS-AdditionalDnsHostName", description: "DNS extra" },
    { name: "msDS-AllowedToDelegateTo", description: "Delegacion" },
    { name: "msDS-AllowedToActOnBehalfOfOtherIdentity", description: "RBCD" },
    { name: "msDS-KeyCredentialLink", description: "Key trust" },
    { name: "ms-Mcs-AdmPwdExpirationTime", description: "Caduca LAPS" },
    { name: "msLAPS-PasswordExpirationTime", description: "Caduca LAPS2" },
    { name: "whenCreated", description: "Fecha alta" },
    { name: "whenChanged", description: "Ultimo cambio" },
    { name: "createTimeStamp", description: "Timestamp alta" },
    { name: "modifyTimeStamp", description: "Timestamp cambio" },
    { name: "uSNCreated", description: "USN alta" },
    { name: "uSNChanged", description: "USN cambio" },
    { name: "dSCorePropagationData", description: "Propagacion DS" },
    { name: "isDeleted", description: "Eliminado" },
    { name: "isCriticalSystemObject", description: "Objeto critico" },
    { name: "nTSecurityDescriptor", description: "ACL objeto" },
    { name: "instanceType", description: "Tipo instancia" },
  ],
};

const nutanixAttributes: AttributeOption[] = [
  { name: "vmUuid", description: "ID de VM" },
  { name: "name", description: "Nombre VM" },
  { name: "description", description: "Descripcion" },
  { name: "powerState", description: "Estado energia" },
  { name: "numSockets", description: "Sockets CPU" },
  { name: "numVcpusPerSocket", description: "vCPU/socket" },
  { name: "numVcpus", description: "vCPU total" },
  { name: "numThreadsPerCore", description: "Hilos/core" },
  { name: "memoryMb", description: "RAM MB" },
  { name: "memoryGiB", description: "RAM GiB" },
  { name: "clusterUuid", description: "ID cluster" },
  { name: "clusterName", description: "Nombre cluster" },
  { name: "hostUuid", description: "ID host" },
  { name: "hostName", description: "Nombre host" },
  { name: "hypervisorType", description: "Tipo hipervisor" },
  { name: "machineType", description: "Tipo maquina" },
  { name: "guestOsName", description: "SO invitado" },
  { name: "guestOsVersion", description: "Version SO" },
  { name: "ngtInstalled", description: "NGT instalado" },
  { name: "ngtEnabled", description: "NGT activo" },
  { name: "ngtVersion", description: "Version NGT" },
  { name: "ipAddresses", description: "IPs VM" },
  { name: "macAddresses", description: "MACs VM" },
  { name: "nics", description: "Tarjetas red" },
  { name: "disks", description: "Discos VM" },
  { name: "diskSizeBytes", description: "Disco bytes" },
  { name: "diskSizeGb", description: "Disco GB" },
  { name: "categories", description: "Categorias" },
  { name: "projectName", description: "Proyecto" },
  { name: "projectUuid", description: "ID proyecto" },
  { name: "owner", description: "Propietario" },
  { name: "creationTime", description: "Fecha creacion" },
  { name: "lastUpdateTime", description: "Ultima actualizacion" },
  { name: "protectionType", description: "Proteccion" },
  { name: "availabilityZone", description: "Zona" },
  { name: "subnets", description: "Subredes" },
  { name: "vpc", description: "VPC" },
  { name: "clusterExternalIp", description: "IP externa cluster" },
  { name: "clusterVirtualIp", description: "IP virtual cluster" },
  { name: "timezone", description: "Zona horaria" },
  { name: "hypervisorTypes", description: "Hipervisores" },
  { name: "redundancyFactor", description: "Factor RF" },
  { name: "nodesCount", description: "Numero nodos" },
  { name: "storageCapacityBytes", description: "Storage total" },
  { name: "storageUsageBytes", description: "Storage usado" },
  { name: "cpuCapacityHz", description: "CPU total" },
  { name: "cpuUsageHz", description: "CPU usada" },
  { name: "memoryCapacityBytes", description: "RAM total" },
  { name: "memoryUsageBytes", description: "RAM usada" },
  { name: "aosVersion", description: "Version AOS" },
  { name: "nccVersion", description: "Version NCC" },
];

const initialConfig: SourceConfig = {
  ad: {
    name: "Active Directory corporativo",
    domain: "",
    url: "",
    bindUser: "",
    bindPassword: "",
    connected: false,
    testedAt: undefined,
    domainTree: [],
    enabled: { Usuarios: true, Grupos: true, Equipos: true },
    ous: {
      Usuarios: [],
      Grupos: [],
      Equipos: [],
    },
    attributes: {
      Usuarios: [],
      Grupos: [],
      Equipos: [],
    },
  },
  nutanix: {
    name: "Nutanix Prism Central",
    prismUrl: "",
    username: "",
    password: "",
    hasPassword: false,
    connected: false,
    testedAt: undefined,
    selectedClusters: [],
    attributes: [],
  },
  jira: {
    url: "",
    cloudId: "",
    workspaceId: "",
    email: "",
    apiToken: "",
    hasApiToken: false,
    connected: false,
    testedAt: undefined,
    schemas: [],
  },
};

const initialMappings: Mapping[] = [];

const initialLogs: SyncLog[] = [];

const sections = [
  { id: "dashboard" as const, label: "Panel de control", group: "paneles", icon: Activity },
  { id: "active-directory" as const, label: "Active Directory", group: "Fuentes", icon: Users },
  { id: "nutanix" as const, label: "Nutanix", group: "Fuentes", icon: Cloud },
  { id: "mappings" as const, label: "Mapeos", group: "gestion", icon: Workflow },
  { id: "syncs" as const, label: "Sincronizaciones", group: "cumplimiento", icon: History },
  { id: "settings" as const, label: "Jira Assets", group: "administracion", icon: Settings },
  { id: "admin" as const, label: "Usuarios", group: "administracion", icon: Users },
  { id: "branding" as const, label: "Logotipo", group: "administracion", icon: ImageIcon },
];

function App() {
  const [auth, setAuth] = useState<{ loading: boolean; setupRequired: boolean; user: AuthUser | null }>({ loading: true, setupRequired: false, user: null });
  const [branding, setBranding] = useState<BrandingSettings>(defaultBranding);

  const refreshAuth = async () => {
    try {
      const response = await fetch("/api/auth/status");
      const result = await response.json();
      setAuth({ loading: false, setupRequired: Boolean(result.setupRequired), user: result.user ?? null });
    } catch {
      setAuth({ loading: false, setupRequired: false, user: null });
    }
  };

  useEffect(() => {
    clearLegacyLocalState();
    void refreshAuth();
    void refreshBranding().then(setBranding).catch(() => undefined);
  }, []);

  useEffect(() => {
    document.title = branding.appTitle || defaultBranding.appTitle;
    if (branding.faviconDataUrl) {
      let favicon = document.querySelector<HTMLLinkElement>('link[rel="icon"]');
      if (!favicon) {
        favicon = document.createElement("link");
        favicon.rel = "icon";
        document.head.appendChild(favicon);
      }
      favicon.type = "image/png";
      favicon.href = branding.faviconDataUrl;
    }
  }, [branding]);

  if (auth.loading) return <AuthShell title="Nexus CMDB" subtitle="Cargando sesion..." branding={branding} />;
  if (auth.setupRequired) return <SetupPortal branding={branding} onReady={(user) => setAuth({ loading: false, setupRequired: false, user })} />;
  if (!auth.user) return <LoginPortal branding={branding} onReady={(user) => setAuth({ loading: false, setupRequired: false, user })} />;
  return <AuthenticatedApp currentUser={auth.user} branding={branding} setBranding={setBranding} onLogout={() => setAuth({ loading: false, setupRequired: false, user: null })} />;
}

function AuthenticatedApp({ currentUser, branding, setBranding, onLogout }: { currentUser: AuthUser; branding: BrandingSettings; setBranding: (branding: BrandingSettings) => void; onLogout: () => void }) {
  const initialRoute = getRouteFromLocation();
  const [section, setSection] = useState<Section>(initialRoute.section);
  const [mappingPageId, setMappingPageId] = useState<string | undefined>(initialRoute.mappingPageId);
  const [config, setConfig] = usePersistedState<SourceConfig>("config", initialConfig);
  const [mappings, setMappings] = usePersistedState<Mapping[]>("mappings", initialMappings);
  const [logs, setLogs] = usePersistedState<SyncLog[]>("logs", initialLogs);
  const [runningJobs, setRunningJobs] = useState<Record<string, string>>({});

  const kpis = useMemo(
    () => [
      { label: "Mapeos activos", value: mappings.length.toString(), note: `${mappings.filter((m) => m.automatic).length} automaticos`, icon: Workflow, tone: "blue" },
      { label: "Objetos sin cambios", value: logs[0]?.unchanged.toString() ?? "0", note: "Ultima sincronizacion", icon: CheckCircle2, tone: "emerald" },
      { label: "Cambios registrados", value: logs.reduce((sum, log) => sum + log.created + log.updated, 0).toString(), note: "Altas y actualizaciones", icon: GitBranch, tone: "violet" },
      { label: "Errores abiertos", value: logs.reduce((sum, log) => sum + log.errors, 0).toString(), note: "Requieren revision", icon: AlertTriangle, tone: "amber" },
    ],
    [logs, mappings]
  );

  const runSync = async (mapping: Mapping) => {
    const now = new Date();
    const stamp = formatDate(now);
    setMappings((current) => current.map((item) => (item.id === mapping.id ? { ...item, lastSync: "Ejecutando", status: "Ejecutando" } : item)));
    try {
      const response = await fetch("/api/sync/run", {
        method: "POST",
        headers: secureJsonHeaders(),
        body: JSON.stringify({ mapping }),
      });
      const text = await response.text();
      const result = parseSyncResponse(text) as SyncLog & { detail?: string; error?: string };
      if (!response.ok) throw new Error(result.detail || result.error || "Error al sincronizar mapeo.");
      setLogs((current) => upsertSyncLog(current, result));
      setRunningJobs((current) => ({ ...current, [mapping.id]: result.id }));
      setMappings((current) => current.map((item) => (item.id === mapping.id ? { ...item, lastSync: result.startedAt, status: result.status } : item)));
      if (result.status === "Ejecutando" && !result.done) {
        void pollSyncJob(result.id, mapping);
      }
    } catch (error) {
      const newLog: SyncLog = {
        id: createClientId(),
        mappingName: mapping.name,
        startedAt: stamp,
        status: "Error",
        created: 0,
        updated: 0,
        unchanged: 0,
        errors: 1,
        changes: [{ object: mapping.objectType, action: "Error", detail: error instanceof Error ? error.message : "Error al sincronizar mapeo." }],
      };
      setLogs((current) => [newLog, ...current]);
      setRunningJobs((current) => {
        const next = { ...current };
        delete next[mapping.id];
        return next;
      });
      setMappings((current) => current.map((item) => (item.id === mapping.id ? { ...item, lastSync: stamp, status: "Error" } : item)));
    }
  };

  const pollSyncJob = async (jobId: string, mapping: Mapping) => {
    try {
      const response = await fetch(`/api/sync/jobs/${encodeURIComponent(jobId)}`);
      const text = await response.text();
      const result = parseSyncResponse(text) as SyncLog & { detail?: string; error?: string };
      if (!response.ok) throw new Error(result.detail || result.error || "No se pudo consultar el progreso de la sincronizacion.");
      setLogs((current) => upsertSyncLog(current, result));
      setMappings((current) => current.map((item) => (item.id === mapping.id ? { ...item, lastSync: result.status === "Ejecutando" ? "Ejecutando" : result.startedAt, status: result.status } : item)));
      if (result.status === "Ejecutando" && !result.done) {
        window.setTimeout(() => void pollSyncJob(jobId, mapping), 2000);
      } else {
        setRunningJobs((current) => {
          const next = { ...current };
          delete next[mapping.id];
          return next;
        });
      }
    } catch (error) {
      const failedLog: SyncLog = {
        id: jobId,
        mappingName: mapping.name,
        startedAt: formatDate(new Date()),
        status: "Error",
        created: 0,
        updated: 0,
        unchanged: 0,
        errors: 1,
        changes: [{ object: mapping.objectType, action: "Error", detail: error instanceof Error ? error.message : "Error al consultar el progreso de sincronizacion." }],
      };
      setLogs((current) => upsertSyncLog(current, failedLog));
      setRunningJobs((current) => {
        const next = { ...current };
        delete next[mapping.id];
        return next;
      });
      setMappings((current) => current.map((item) => (item.id === mapping.id ? { ...item, lastSync: failedLog.startedAt, status: "Error" } : item)));
    }
  };

  const stopSync = async (mapping: Mapping) => {
    const jobId = runningJobs[mapping.id];
    if (!jobId) return;
    try {
      const response = await fetch(`/api/sync/jobs/${encodeURIComponent(jobId)}/cancel`, { method: "POST", headers: csrfHeaders() });
      const text = await response.text();
      const result = parseSyncResponse(text) as SyncLog & { detail?: string; error?: string };
      if (!response.ok) throw new Error(result.detail || result.error || "No se pudo detener la sincronizacion.");
      setLogs((current) => upsertSyncLog(current, result));
    } catch (error) {
      setLogs((current) => upsertSyncLog(current, {
        id: jobId,
        mappingName: mapping.name,
        startedAt: formatDate(new Date()),
        status: "Aviso",
        created: 0,
        updated: 0,
        unchanged: 0,
        errors: 1,
        changes: [{ object: mapping.objectType, action: "Error", detail: error instanceof Error ? error.message : "Error al detener la sincronizacion." }],
      }));
    }
  };

  const purgeOldLogs = () => {
    setLogs((current) => current.filter((log) => !isLogOlderThanDays(log, 30)));
  };

  useEffect(() => {
    const syncRoute = () => {
      const route = getRouteFromLocation();
      setSection(route.section);
      setMappingPageId(route.mappingPageId);
      replaceLegacyUsersPath();
    };
    replaceLegacyUsersPath();
    window.addEventListener("popstate", syncRoute);
    return () => window.removeEventListener("popstate", syncRoute);
  }, []);

  useEffect(() => {
    const refreshScheduledSyncState = async () => {
      const [storedMappings, storedLogs] = await Promise.all([
        fetchPersistedState<Mapping[]>("mappings", initialMappings),
        fetchPersistedState<SyncLog[]>("logs", initialLogs),
      ]);
      setMappings(storedMappings);
      setLogs(storedLogs);
    };
    const timer = window.setInterval(() => {
      void refreshScheduledSyncState().catch(() => undefined);
    }, 15000);
    return () => window.clearInterval(timer);
  }, [setLogs, setMappings]);

  const navigateToSection = (nextSection: Section) => {
    setSection(nextSection);
    setMappingPageId(undefined);
    setLocationPath(nextSection);
  };

  const navigateToCreateMapping = () => {
    setSection("mappings");
    setMappingPageId("new");
    setLocationPath("mappings", undefined, "new");
  };

  const navigateToEditMapping = (mapping: Mapping) => {
    setSection("mappings");
    setMappingPageId(mapping.id);
    setLocationPath("mappings", undefined, mapping.id);
  };

  const navigateToMappingsList = () => {
    setSection("mappings");
    setMappingPageId(undefined);
    setLocationPath("mappings");
  };

  const saveMapping = (mapping: Mapping) => {
    setMappings((current) => (current.some((item) => item.id === mapping.id) ? current.map((item) => (item.id === mapping.id ? mapping : item)) : [mapping, ...current]));
    navigateToMappingsList();
  };

  const logout = async () => {
    await fetch("/api/auth/logout", { method: "POST", headers: csrfHeaders() }).catch(() => undefined);
    onLogout();
  };

  const editingMapping = mappingPageId && mappingPageId !== "new" ? mappings.find((mapping) => mapping.id === mappingPageId) ?? null : null;

  return (
    <div className="h-screen w-full bg-slate-50 text-slate-900 font-sans overflow-hidden">
      <div className="flex h-full w-full overflow-hidden">
        <Sidebar active={section} onSelect={navigateToSection} currentUser={currentUser} branding={branding} onLogout={logout} />
        <div className="flex-1 flex flex-col bg-slate-50 overflow-hidden">
          <MobileNav active={section} onSelect={navigateToSection} branding={branding} />
          <main className="flex-1 overflow-y-auto p-6 md:p-8">
            {section === "dashboard" && <Dashboard kpis={kpis} mappings={mappings} logs={logs} onRunSync={runSync} onStopSync={stopSync} runningJobs={runningJobs} onCreateMapping={navigateToCreateMapping} />}
            {section === "active-directory" && <Sources config={config} setConfig={setConfig} sourcePage="ad" />}
            {section === "nutanix" && <Sources config={config} setConfig={setConfig} sourcePage="nutanix" />}
            {section === "mappings" && !mappingPageId && <Mappings mappings={mappings} setMappings={setMappings} onRunSync={runSync} onStopSync={stopSync} runningJobs={runningJobs} onCreate={navigateToCreateMapping} onEdit={navigateToEditMapping} />}
            {section === "mappings" && mappingPageId && (
              mappingPageId !== "new" && !editingMapping ? (
                <MappingNotFoundPage onClose={navigateToMappingsList} />
              ) : (
                <MappingEditorPage
                  config={config}
                  setConfig={setConfig}
                  initialMapping={mappingPageId === "new" ? null : editingMapping}
                  onClose={navigateToMappingsList}
                  onSave={saveMapping}
                />
              )
            )}
            {section === "syncs" && <Syncs logs={logs} mappings={mappings} onRunSync={runSync} onPurgeOldLogs={purgeOldLogs} />}
            {section === "settings" && <JiraSettings config={config} setConfig={setConfig} />}
            {section === "admin" && <Administration currentUser={currentUser} />}
            {section === "branding" && <BrandingAdmin branding={branding} onBrandingChange={setBranding} />}
          </main>
        </div>
      </div>
    </div>
  );
}

function Sidebar({ active, onSelect, currentUser, branding, onLogout }: { active: Section; onSelect: (section: Section) => void; currentUser: AuthUser; branding: BrandingSettings; onLogout: () => void }) {
  const grouped = groupSections();
  return (
    <aside className="hidden md:flex w-64 shrink-0 bg-[#0b1329] text-slate-100 border-r border-[#1e293b] sticky top-0 h-full flex-col">
      <div className="px-5 py-5 border-b border-slate-800">
        {branding.logoDataUrl ? (
          <div className="w-full h-20 flex items-center justify-center">
            <img src={branding.logoDataUrl} alt={branding.appTitle} className="max-h-20 max-w-full object-contain" />
          </div>
        ) : (
          <div className="h-12 w-12 bg-blue-600 flex items-center justify-center mx-auto">
            <ShieldCheck className="h-5 w-5 text-white" />
          </div>
        )}
      </div>
      <nav className="flex-1 overflow-y-auto px-3 py-5 space-y-6">
        {Object.entries(grouped).map(([group, items]) => (
          <div key={group}>
            <div className="px-3 mb-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">{group}</div>
            <div className="space-y-1">
              {items.map((item) => {
                const Icon = item.icon;
                const isActive = active === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => onSelect(item.id)}
                    className={`w-full h-10 px-3 flex items-center gap-3 text-sm text-left rounded-none ${
                      isActive ? "bg-[#1c2c54]/60 text-blue-400 font-bold" : "text-slate-400 hover:bg-[#1c2c54]/20 hover:text-slate-200"
                    }`}
                  >
                    <Icon className="h-4 w-4 shrink-0" />
                    <span className="truncate">{item.label}</span>
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </nav>
      <div className="border-t border-slate-800 p-3">
        <div className="px-3 py-2 text-xs text-slate-400 truncate">{currentUser.email}</div>
        <button onClick={onLogout} className="w-full h-9 px-3 flex items-center gap-2 text-sm text-slate-300 hover:bg-[#1c2c54]/40">
          <LogOut className="h-4 w-4" />
          Cerrar sesion
        </button>
      </div>
    </aside>
  );
}

function MobileNav({ active, onSelect, branding }: { active: Section; onSelect: (section: Section) => void; branding: BrandingSettings }) {
  return (
    <header className="md:hidden bg-white border-b border-slate-200 sticky top-0 z-30">
      <div className="h-14 px-4 flex items-center gap-3">
        {branding.logoDataUrl ? <img src={branding.logoDataUrl} alt={branding.appTitle} className="h-8 w-8 object-contain" /> : <ShieldCheck className="h-5 w-5 text-blue-600" />}
        <div className="font-extrabold text-sm uppercase tracking-wider">{branding.appTitle || "Nexus CMDB"}</div>
      </div>
      <nav className="flex overflow-x-auto border-t border-slate-200">
        {sections.map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.id}
              onClick={() => onSelect(item.id)}
              className={`h-11 px-4 shrink-0 inline-flex items-center gap-2 text-xs font-bold uppercase ${
                active === item.id ? "text-blue-600 border-b-2 border-blue-600" : "text-slate-500"
              }`}
            >
              <Icon className="h-4 w-4" />
              {item.label}
            </button>
          );
        })}
      </nav>
    </header>
  );
}

function Dashboard({
  kpis,
  mappings,
  logs,
  onRunSync,
  onStopSync,
  runningJobs,
  onCreateMapping,
}: {
  kpis: Array<{ label: string; value: string; note: string; icon: typeof Activity; tone: string }>;
  mappings: Mapping[];
  logs: SyncLog[];
  onRunSync: (mapping: Mapping) => void;
  onStopSync: (mapping: Mapping) => void;
  runningJobs: Record<string, string>;
  onCreateMapping: () => void;
}) {
  return (
    <div className="space-y-6">
      <SectionHeader
        title="Panel de sincronizacion CMDB"
        description="Control operativo de fuentes, mapeos, ejecuciones y cambios enviados a Jira Assets."
        actions={
          <>
            <button onClick={onCreateMapping} className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-none text-sm font-semibold shadow-sm">
              <Plus className="h-4 w-4" />
              Nuevo mapeo
            </button>
          </>
        }
      />
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        {kpis.map((kpi) => (
          <Kpi key={kpi.label} {...kpi} />
        ))}
      </div>
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <MappingsTable mappings={mappings.slice(0, 5)} onRunSync={onRunSync} onStopSync={onStopSync} runningJobs={runningJobs} compact />
        <LogsTable logs={logs.slice(0, 5)} compact />
      </div>
    </div>
  );
}

function Sources({
  config,
  setConfig,
  sourcePage,
}: {
  config: SourceConfig;
  setConfig: (config: SourceConfig) => void;
  sourcePage: SourcePage;
}) {
  const [adTestStatus, setAdTestStatus] = useState<AdTestStatus>("idle");
  const [adTestMessage, setAdTestMessage] = useState("");
  const [nutanixTestStatus, setNutanixTestStatus] = useState<AdTestStatus>("idle");
  const [nutanixTestMessage, setNutanixTestMessage] = useState("");
  const adConnected = config.ad.connected === true;
  const nutanixConnected = config.nutanix.connected === true;

  const markAdDisconnected = (ad: SourceConfig["ad"]) => ({
    ...ad,
    connected: false,
    testedAt: undefined,
    domainTree: [],
    ous: { Usuarios: [], Grupos: [], Equipos: [] },
  });

  const markNutanixDisconnected = (nutanix: SourceConfig["nutanix"]) => ({
    ...nutanix,
    connected: false,
    testedAt: undefined,
  });

  const testAdConnection = async () => {
    if (!config.ad.domain.trim() || !config.ad.url.trim() || !config.ad.bindUser.trim()) {
      setAdTestStatus("error");
      setAdTestMessage("Completa dominio, URL LDAPS y usuario bind antes de probar la conexion.");
      setConfig({ ...config, ad: markAdDisconnected(config.ad) });
      return;
    }

    setAdTestStatus("testing");
    setAdTestMessage("Conectando con Active Directory y leyendo unidades organizativas.");

    try {
      const response = await fetch("/api/ad/test", {
        method: "POST",
        headers: secureJsonHeaders(),
        body: JSON.stringify({
          domain: config.ad.domain,
          url: config.ad.url,
          bindUser: config.ad.bindUser,
          bindPassword: config.ad.bindPassword,
        }),
      });
      const result = (await response.json()) as { tree?: OuNode[]; error?: string; detail?: string };

      if (!response.ok || !result.tree?.length) {
        throw new Error(result.detail || result.error || "No se pudo descubrir el arbol del dominio.");
      }

      setConfig({
        ...config,
        ad: {
          ...config.ad,
          bindPassword: undefined,
          hasBindPassword: true,
          connected: true,
          testedAt: formatDate(new Date()),
          domainTree: result.tree,
        },
      });
      setAdTestStatus("success");
      setAdTestMessage("Conexion validada. OUs disponibles para seleccionar en los mapeos.");
    } catch (error) {
      setAdTestStatus("error");
      setAdTestMessage(error instanceof Error ? error.message : "Error al conectar con Active Directory.");
      setConfig({ ...config, ad: markAdDisconnected(config.ad) });
    }
  };

  const testNutanixConnection = async () => {
    if (!config.nutanix.prismUrl.trim() || !config.nutanix.username.trim()) {
      setNutanixTestStatus("error");
      setNutanixTestMessage("Completa Prism Central y usuario antes de conectar con Nutanix.");
      setConfig({ ...config, nutanix: markNutanixDisconnected(config.nutanix) });
      return;
    }

    setNutanixTestStatus("testing");
    setNutanixTestMessage("Conectando con Nutanix Prism Central.");

    try {
      const response = await fetch("/api/nutanix/test", {
        method: "POST",
        headers: secureJsonHeaders(),
        body: JSON.stringify({
          prismUrl: config.nutanix.prismUrl,
          username: config.nutanix.username,
          password: config.nutanix.password,
        }),
      });
      const result = (await response.json()) as { status?: string; detail?: string; clusters?: string[]; endpoint?: string };
      if (!response.ok) throw new Error(result.detail || "No se pudo conectar con Nutanix.");

      const detectedClusters = result.clusters ?? [];
      setConfig({
        ...config,
        nutanix: {
          ...config.nutanix,
          password: undefined,
          hasPassword: true,
          connected: true,
          testedAt: formatDate(new Date()),
          selectedClusters: config.nutanix.selectedClusters.length ? config.nutanix.selectedClusters : detectedClusters,
        },
      });
      setNutanixTestStatus("success");
      setNutanixTestMessage(detectedClusters.length ? `Conexion validada. Clusters detectados: ${detectedClusters.join(", ")}.` : "Conexion validada con Nutanix Prism Central.");
    } catch (error) {
      setNutanixTestStatus("error");
      setNutanixTestMessage(error instanceof Error ? error.message : "Error al conectar con Nutanix.");
      setConfig({ ...config, nutanix: markNutanixDisconnected(config.nutanix) });
    }
  };
  const pageTitle = sourcePage === "ad" ? "Active Directory" : "Nutanix";
  const pageDescription = sourcePage === "ad"
    ? "Configuracion LDAP para validar acceso al dominio. Las OUs y atributos se seleccionan desde cada mapeo."
    : "Configuracion de Prism Central, clusters y atributos disponibles para maquinas virtuales.";

  return (
    <div className="space-y-6">
      <SectionHeader
        title={pageTitle}
        description={pageDescription}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {sourcePage === "ad" ? (
              <button
                onClick={testAdConnection}
                disabled={adTestStatus === "testing"}
                className="inline-flex items-center gap-2 px-4 py-2 bg-slate-900 hover:bg-slate-800 disabled:bg-slate-400 text-white rounded-none text-sm font-semibold shadow-sm"
              >
                <RefreshCw className={`h-4 w-4 ${adTestStatus === "testing" ? "animate-spin" : ""}`} />
                Conectar AD
              </button>
            ) : (
              <button
                onClick={testNutanixConnection}
                disabled={nutanixTestStatus === "testing"}
                className="inline-flex items-center gap-2 px-4 py-2 bg-slate-900 hover:bg-slate-800 disabled:bg-slate-400 text-white rounded-none text-sm font-semibold shadow-sm"
              >
                <RefreshCw className={`h-4 w-4 ${nutanixTestStatus === "testing" ? "animate-spin" : ""}`} />
                Conectar NTX
              </button>
            )}
            <button className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-none text-sm font-semibold shadow-sm">
              <Save className="h-4 w-4" />
              Guardar
            </button>
          </div>
        }
      />
      <div>
        {sourcePage === "ad" ? (
        <div className="bg-white border border-slate-200 shadow-sm">
          <div className="p-5 grid grid-cols-1 sm:grid-cols-2 gap-4 border-b border-slate-200">
            <TextInput label="Nombre" value={config.ad.name} onChange={(name) => setConfig({ ...config, ad: markAdDisconnected({ ...config.ad, name }) })} />
            <TextInput label="Dominio" value={config.ad.domain} onChange={(domain) => setConfig({ ...config, ad: markAdDisconnected({ ...config.ad, domain }) })} />
            <TextInput label="URL LDAPS" value={config.ad.url} onChange={(url) => setConfig({ ...config, ad: markAdDisconnected({ ...config.ad, url }) })} />
            <TextInput label="Usuario bind" value={config.ad.bindUser} onChange={(bindUser) => setConfig({ ...config, ad: markAdDisconnected({ ...config.ad, bindUser }) })} />
            <TextInput label="Contrasena bind" type="password" value={config.ad.bindPassword ?? ""} onChange={(bindPassword) => setConfig({ ...config, ad: markAdDisconnected({ ...config.ad, bindPassword }) })} />
            {config.ad.hasBindPassword && !config.ad.bindPassword ? (
              <div className="sm:col-span-2 text-xs text-slate-500">
                Hay una password bind guardada cifrada en la BBDD. Deja el campo vacio para reutilizarla o escribe una nueva para reemplazarla.
              </div>
            ) : null}
          </div>
          <div className="px-5 py-3 border-b border-slate-200">
            {adConnected ? (
              <div className="flex items-center gap-2 bg-emerald-50 text-emerald-800 border border-emerald-100 px-3 py-2 text-sm">
                <CheckCircle2 className="h-4 w-4 shrink-0" />
                <span className="truncate">Conexion validada {config.ad.testedAt ? `el ${formatDisplayDateTime(config.ad.testedAt)}` : ""}. Las OUs se seleccionan desde cada mapeo.</span>
              </div>
            ) : (
              <div className="flex items-center gap-2 bg-amber-50 text-amber-800 border border-amber-100 px-3 py-2 text-sm">
                <AlertTriangle className="h-4 w-4 shrink-0" />
                <span>{adTestStatus === "error" ? adTestMessage : "Prueba la conexion para validar el acceso al dominio. Las OUs se mostraran al crear mapeos."}</span>
              </div>
            )}
          </div>
          <div className="p-5 space-y-5">
            {(["Usuarios", "Grupos", "Equipos"] as ADEntity[]).map((entityName) => (
              <AttributePicker
                key={entityName}
                label={`Atributos de ${entityName}`}
                attributes={adAttributes[entityName]}
                selected={config.ad.attributes[entityName] ?? []}
                onToggle={(attribute) => {
                  const selected = config.ad.attributes[entityName] ?? [];
                  const next = selected.includes(attribute) ? selected.filter((item) => item !== attribute) : [...selected, attribute];
                  setConfig({
                    ...config,
                    ad: {
                      ...config.ad,
                      attributes: {
                        ...config.ad.attributes,
                        [entityName]: next,
                      },
                    },
                  });
                }}
              />
            ))}
          </div>
        </div>
        ) : null}
        {sourcePage === "nutanix" ? (
        <div className="bg-white border border-slate-200 shadow-sm">
          <PanelTitle icon={Cloud} title="Nutanix" subtitle="Conexion Prism Central y seleccion de atributos de maquinas virtuales." />
          <div className="p-5 grid grid-cols-1 sm:grid-cols-2 gap-4 border-b border-slate-200">
            <TextInput label="Nombre" value={config.nutanix.name} onChange={(name) => setConfig({ ...config, nutanix: markNutanixDisconnected({ ...config.nutanix, name }) })} />
            <TextInput label="Prism Central" value={config.nutanix.prismUrl} onChange={(prismUrl) => setConfig({ ...config, nutanix: markNutanixDisconnected({ ...config.nutanix, prismUrl }) })} placeholder="https://prism.empresa.local:9440" />
            <TextInput label="Usuario" value={config.nutanix.username} onChange={(username) => setConfig({ ...config, nutanix: markNutanixDisconnected({ ...config.nutanix, username }) })} />
            <TextInput label="Contrasena" type="password" value={config.nutanix.password ?? ""} onChange={(password) => setConfig({ ...config, nutanix: markNutanixDisconnected({ ...config.nutanix, password }) })} />
            {config.nutanix.hasPassword && !config.nutanix.password ? (
              <div className="sm:col-span-2 text-xs text-slate-500">
                Hay una contrasena de Nutanix guardada cifrada en la BBDD. Deja el campo vacio para reutilizarla o escribe una nueva para reemplazarla.
              </div>
            ) : null}
            <div className="sm:col-span-2">
              <TextInput label="Clusters" value={config.nutanix.selectedClusters.join(", ")} onChange={(value) => setConfig({ ...config, nutanix: { ...config.nutanix, selectedClusters: splitList(value) } })} />
            </div>
          </div>
          <div className="px-5 py-3 border-b border-slate-200">
            {nutanixConnected ? (
              <div className="flex items-center gap-2 bg-emerald-50 text-emerald-800 border border-emerald-100 px-3 py-2 text-sm">
                <CheckCircle2 className="h-4 w-4 shrink-0" />
                <span className="truncate">Conexion validada {config.nutanix.testedAt ? `el ${formatDisplayDateTime(config.nutanix.testedAt)}` : ""}.</span>
              </div>
            ) : (
              <div className="flex items-center gap-2 bg-amber-50 text-amber-800 border border-amber-100 px-3 py-2 text-sm">
                <AlertTriangle className="h-4 w-4 shrink-0" />
                <span>{nutanixTestStatus === "error" ? nutanixTestMessage : "Pulsa Conectar NTX para validar el acceso a Prism Central."}</span>
              </div>
            )}
          </div>
          <div className="p-5">
            <AttributePicker
              label="Atributos de VMs"
              attributes={nutanixAttributes}
              selected={config.nutanix.attributes}
              onToggle={(attribute) => {
                const selected = config.nutanix.attributes;
                const next = selected.includes(attribute) ? selected.filter((item) => item !== attribute) : [...selected, attribute];
                setConfig({ ...config, nutanix: { ...config.nutanix, attributes: next } });
              }}
            />
          </div>
        </div>
        ) : null}
      </div>
    </div>
  );
}

function AuthShell({ title, subtitle, branding, children }: { title: string; subtitle: string; branding: BrandingSettings; children?: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-slate-50 flex items-center justify-center p-6">
      <div className="w-full max-w-md bg-white text-slate-900 border border-slate-200 shadow-xl rounded-2xl p-7 space-y-5">
        <div className="space-y-2 text-center">
          {branding.logoDataUrl ? (
            <img src={branding.logoDataUrl} alt={branding.appTitle} className="max-h-16 max-w-[220px] object-contain mx-auto" />
          ) : (
            <div className="mx-auto text-sm font-black text-slate-900 tracking-wide">{branding.appTitle || "Nexus CMDB"}</div>
          )}
          <h1 className="text-xl font-black text-slate-900">{title}</h1>
          <p className="text-xs text-slate-500 leading-relaxed">{subtitle}</p>
        </div>
        {children}
      </div>
    </div>
  );
}

function SetupPortal({ branding, onReady }: { branding: BrandingSettings; onReady: (user: AuthUser) => void }) {
  return <AuthForm mode="setup" branding={branding} onReady={onReady} />;
}

function LoginPortal({ branding, onReady }: { branding: BrandingSettings; onReady: (user: AuthUser) => void }) {
  return <AuthForm mode="login" branding={branding} onReady={onReady} />;
}

function AuthForm({ mode, branding, onReady }: { mode: "setup" | "login"; branding: BrandingSettings; onReady: (user: AuthUser) => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [expirationPolicy, setExpirationPolicy] = useState<PasswordExpirationPolicy>("never");
  const [message, setMessage] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const isSetup = mode === "setup";

  const submit = async () => {
    setMessage("");
    if (isSetup) {
      const validation = validatePasswordClient(password);
      if (validation) {
        setMessage(validation);
        return;
      }
    }
    setSubmitting(true);
    try {
      const response = await fetch(isSetup ? "/api/auth/setup" : "/api/auth/login", {
        method: "POST",
        headers: secureJsonHeaders(),
        body: JSON.stringify(isSetup ? { email, password, expirationPolicy } : { email, password }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || "No se pudo completar la operacion.");
      onReady(result.user);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "No se pudo completar la operacion.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AuthShell title={isSetup ? "Crear primer administrador" : `Acceso ${branding.appTitle || "Nexus CMDB"}`} subtitle={isSetup ? "No hay usuarios configurados. El primer usuario se creara con rol administrador." : "Introduce tu correo y contrasena para acceder a la aplicacion."} branding={branding}>
      <div className="space-y-4">
        <TextInput label="Correo electronico" value={email} onChange={setEmail} placeholder="admin@empresa.local" />
        <TextInput label="Contrasena" type="password" value={password} onChange={setPassword} />
        {isSetup ? (
          <>
            <ExpirationSelect label="Caducidad de contrasena" value={expirationPolicy} onChange={setExpirationPolicy} />
            <PasswordPolicyHint />
          </>
        ) : null}
        {message ? <div className="border border-red-200 bg-red-50 text-red-800 p-3 rounded-lg text-xs flex items-start gap-2"><AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />{message}</div> : null}
        <button onClick={submit} disabled={submitting} className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-slate-300 text-white px-4 py-2 rounded-lg text-sm font-bold uppercase tracking-wider">
          {submitting ? "Procesando..." : isSetup ? "Crear administrador" : "Iniciar sesion"}
        </button>
      </div>
    </AuthShell>
  );
}

function Administration({ currentUser }: { currentUser: AuthUser }) {
  const [users, setUsers] = useState<AuthUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState("");
  const [newUser, setNewUser] = useState({ email: "", password: "", expirationPolicy: "never" as PasswordExpirationPolicy });
  const [passwordDrafts, setPasswordDrafts] = useState<Record<string, string>>({});

  const loadUsers = async () => {
    setLoading(true);
    try {
      const response = await fetch("/api/admin/users");
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || "No se pudieron leer los usuarios.");
      setUsers(result.users ?? []);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "No se pudieron leer los usuarios.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadUsers();
  }, []);

  const createUser = async () => {
    const validation = validatePasswordClient(newUser.password);
    if (validation) {
      setMessage(validation);
      return;
    }
    await adminRequest("/api/admin/users", {
      method: "POST",
      body: JSON.stringify(newUser),
    }, async () => {
      setNewUser({ email: "", password: "", expirationPolicy: "never" });
      await loadUsers();
    }, setMessage);
  };

  const updateUser = async (user: AuthUser, patch: Record<string, unknown>) => {
    await adminRequest(`/api/admin/users/${encodeURIComponent(user.id)}`, {
      method: "PUT",
      body: JSON.stringify(patch),
    }, loadUsers, setMessage);
  };

  const resetPassword = async (user: AuthUser) => {
    const password = passwordDrafts[user.id] ?? "";
    const validation = validatePasswordClient(password);
    if (validation) {
      setMessage(validation);
      return;
    }
    await updateUser(user, { password });
    setPasswordDrafts((current) => ({ ...current, [user.id]: "" }));
  };

  return (
    <div className="space-y-6">
      <SectionHeader title="Usuarios" description="Gestion de usuarios locales, caducidad y cambio de contrasenas de la aplicacion." />
      <div className="bg-white border border-slate-200 shadow-sm">
        <PanelTitle icon={Users} title="Nuevo usuario" subtitle="El usuario debe ser un correo electronico y la contrasena debe cumplir complejidad." />
        <div className="p-5 grid grid-cols-1 md:grid-cols-4 gap-4">
          <TextInput label="Correo" value={newUser.email} onChange={(email) => setNewUser({ ...newUser, email })} />
          <TextInput label="Contrasena" type="password" value={newUser.password} onChange={(password) => setNewUser({ ...newUser, password })} />
          <ExpirationSelect label="Caducidad" value={newUser.expirationPolicy} onChange={(expirationPolicy) => setNewUser({ ...newUser, expirationPolicy })} />
          <button onClick={createUser} className="h-10 self-end bg-blue-600 hover:bg-blue-700 text-white font-semibold">Crear</button>
        </div>
        <div className="px-5 pb-5"><PasswordPolicyHint /></div>
      </div>
      {message ? <div className="border border-amber-100 bg-amber-50 text-amber-800 p-3 text-sm">{message}</div> : null}
      <div className="bg-white border border-slate-200 shadow-sm overflow-x-auto">
        <table className="w-full text-left border-collapse min-w-[980px]">
          <thead>
            <tr className="bg-slate-50 border-b border-slate-200 text-xs font-bold uppercase text-slate-500">
              <th className="px-4 py-3">Usuario</th>
              <th className="px-4 py-3">Estado</th>
              <th className="px-4 py-3">Caducidad</th>
              <th className="px-4 py-3">Vence</th>
              <th className="px-4 py-3">Nueva contrasena</th>
              <th className="px-4 py-3">Acciones</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200 text-sm">
            {loading ? (
              <tr><td className="px-4 py-8 text-slate-500" colSpan={6}>Cargando usuarios...</td></tr>
            ) : users.map((user) => (
              <tr key={user.id} className="align-top">
                <td className="px-4 py-3 font-semibold text-slate-900">{user.email}<div className="text-xs text-slate-500">{user.role}</div></td>
                <td className="px-4 py-3"><Badge status={user.active ? "Correcta" : "Aviso"} text={user.active ? "Activo" : "Inactivo"} /></td>
                <td className="px-4 py-3">
                  <select value={user.expirationPolicy} onChange={(event) => updateUser(user, { expirationPolicy: event.target.value })} className="h-9 border border-slate-300 bg-white px-2 text-sm">
                    {passwordExpirationOptions.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
                  </select>
                </td>
                <td className="px-4 py-3 text-slate-600">{user.passwordExpiresAt ? formatDisplayDateTime(user.passwordExpiresAt) : "Nunca"}</td>
                <td className="px-4 py-3">
                  <input type="password" value={passwordDrafts[user.id] ?? ""} onChange={(event) => setPasswordDrafts({ ...passwordDrafts, [user.id]: event.target.value })} className="h-9 w-full border border-slate-300 px-2 text-sm" />
                </td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-2">
                    <button onClick={() => resetPassword(user)} className="px-3 py-2 border border-slate-300 bg-white hover:bg-slate-50 text-xs font-semibold">Cambiar</button>
                    <button
                      onClick={() => updateUser(user, { active: !user.active })}
                      disabled={user.id === currentUser.id}
                      className="px-3 py-2 border border-slate-300 bg-white hover:bg-slate-50 disabled:opacity-50 text-xs font-semibold"
                    >
                      {user.active ? "Desactivar" : "Activar"}
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function BrandingAdmin({ branding, onBrandingChange }: { branding: BrandingSettings; onBrandingChange: (branding: BrandingSettings) => void }) {
  const [form, setForm] = useState<BrandingSettings>(branding);
  const [message, setMessage] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setForm(branding);
  }, [branding]);

  const handleFile = async (field: "logoDataUrl" | "faviconDataUrl", file?: File) => {
    setMessage("");
    if (!file) return;
    if (!isPngFile(file)) {
      setMessage("Solo se permiten ficheros PNG para el logotipo y el favicon.");
      return;
    }
    try {
      const dataUrl = await fileToDataUrl(file);
      setForm((current) => ({ ...current, [field]: dataUrl }));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "No se pudo cargar el fichero PNG.");
    }
  };

  const saveBranding = async () => {
    setMessage("");
    setSaving(true);
    try {
      const payload: BrandingSettings = {
        logoDataUrl: form.logoDataUrl,
        faviconDataUrl: form.faviconDataUrl,
        appTitle: form.appTitle.trim() || defaultBranding.appTitle,
      };
      const response = await fetch("/api/settings/branding", {
        method: "PUT",
        headers: secureJsonHeaders(),
        body: JSON.stringify({ value: payload }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || result.error || "No se pudo guardar la marca de la aplicacion.");
      onBrandingChange(normalizeBranding(result.value));
      setMessage("Logotipo, favicon y nombre de la web actualizados correctamente.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "No se pudo guardar la marca de la aplicacion.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Logotipo"
        description="Configura el logotipo, favicon y nombre visible de la plataforma."
        actions={
          <button onClick={saveBranding} disabled={saving} className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-400 text-white rounded-none text-sm font-semibold shadow-sm">
            <Save className="h-4 w-4" />
            {saving ? "Guardando..." : "Guardar marca"}
          </button>
        }
      />

      {message ? <div className="border border-amber-100 bg-amber-50 text-amber-800 p-3 text-sm">{message}</div> : null}

      <div className="bg-white border border-slate-200 shadow-sm p-5">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="border border-slate-200 p-4 space-y-3">
            <label className="block text-xs font-bold uppercase text-slate-600">Logotipo web PNG</label>
            <div className="h-20 border border-dashed border-slate-300 bg-slate-50 flex items-center justify-center p-3">
              {form.logoDataUrl ? <img src={form.logoDataUrl} alt="Logotipo actual" className="max-h-full max-w-full object-contain" /> : <span className="text-xs text-slate-400 font-semibold">Sin logotipo</span>}
            </div>
            <input type="file" accept="image/png,.png" onChange={(event) => void handleFile("logoDataUrl", event.target.files?.[0])} className="w-full text-xs file:mr-3 file:px-3 file:py-1.5 file:border-0 file:bg-blue-600 file:text-white file:font-bold file:cursor-pointer" />
            {form.logoDataUrl ? <button type="button" onClick={() => setForm({ ...form, logoDataUrl: "" })} className="text-xs font-semibold text-slate-600 hover:text-slate-900">Quitar logotipo</button> : null}
          </div>

          <div className="border border-slate-200 p-4 space-y-3">
            <label className="block text-xs font-bold uppercase text-slate-600">Favicon PNG</label>
            <div className="h-20 border border-dashed border-slate-300 bg-slate-50 flex items-center justify-center p-3">
              {form.faviconDataUrl ? <img src={form.faviconDataUrl} alt="Favicon actual" className="max-h-12 max-w-12 object-contain" /> : <span className="text-xs text-slate-400 font-semibold">Sin favicon</span>}
            </div>
            <input type="file" accept="image/png,.png" onChange={(event) => void handleFile("faviconDataUrl", event.target.files?.[0])} className="w-full text-xs file:mr-3 file:px-3 file:py-1.5 file:border-0 file:bg-blue-600 file:text-white file:font-bold file:cursor-pointer" />
            {form.faviconDataUrl ? <button type="button" onClick={() => setForm({ ...form, faviconDataUrl: "" })} className="text-xs font-semibold text-slate-600 hover:text-slate-900">Quitar favicon</button> : null}
          </div>

          <div className="border border-slate-200 p-4 space-y-3">
            <TextInput label="Nombre de la web" value={form.appTitle} onChange={(appTitle) => setForm({ ...form, appTitle })} maxWidthClassName="max-w-md" />
            <p className="text-[10px] text-slate-400">Aparece en el login, el menú lateral y la pestaña del navegador.</p>
          </div>
        </div>
      </div>
    </div>
  );
}

async function adminRequest(url: string, init: RequestInit, onSuccess: () => void | Promise<void>, setMessage: (message: string) => void) {
  try {
    setMessage("");
    const response = await fetch(url, { ...init, headers: secureJsonHeaders() });
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail || "Operacion no completada.");
    await onSuccess();
  } catch (error) {
    setMessage(error instanceof Error ? error.message : "Operacion no completada.");
  }
}

const passwordExpirationOptions: Array<{ value: PasswordExpirationPolicy; label: string }> = [
  { value: "never", label: "Nunca caduca" },
  { value: "6months", label: "Caduca a los 6 meses" },
  { value: "1year", label: "Caduca a 1 ano" },
];

function PasswordPolicyHint() {
  return <div className="text-xs text-slate-500">Minimo 12 caracteres con mayuscula, minuscula, numero y simbolo. No se pueden reutilizar las ultimas 5 contrasenas.</div>;
}

function validatePasswordClient(password: string) {
  if (password.length < 12) return "La contrasena debe tener al menos 12 caracteres.";
  if (!/[a-z]/.test(password)) return "La contrasena debe incluir al menos una minuscula.";
  if (!/[A-Z]/.test(password)) return "La contrasena debe incluir al menos una mayuscula.";
  if (!/\d/.test(password)) return "La contrasena debe incluir al menos un numero.";
  if (!/[^A-Za-z0-9]/.test(password)) return "La contrasena debe incluir al menos un simbolo.";
  return "";
}

function Mappings({
  mappings,
  setMappings,
  onRunSync,
  onStopSync,
  runningJobs,
  onCreate,
  onEdit,
}: {
  mappings: Mapping[];
  setMappings: (mappings: Mapping[]) => void;
  onRunSync: (mapping: Mapping) => void;
  onStopSync: (mapping: Mapping) => void;
  runningJobs: Record<string, string>;
  onCreate: () => void;
  onEdit: (mapping: Mapping) => void;
}) {
  const [query, setQuery] = useState("");
  const visible = mappings.filter((mapping) => mapping.name.toLowerCase().includes(query.toLowerCase()) || mapping.objectType.toLowerCase().includes(query.toLowerCase()));
  return (
    <div className="space-y-6">
      <SectionHeader
        title="Mapeos de atributos"
        description="Relaciona cada origen y ambito con un esquema, tipo de objeto y atributos de Jira Assets."
        actions={
          <button onClick={onCreate} className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-none text-sm font-semibold shadow-sm">
            <Plus className="h-4 w-4" />
            Nuevo
          </button>
        }
      />
      <Toolbar query={query} setQuery={setQuery} count={visible.length} />
      <MappingsTable mappings={visible} onRunSync={onRunSync} onStopSync={onStopSync} runningJobs={runningJobs} onEdit={onEdit} onDelete={(id) => setMappings(mappings.filter((mapping) => mapping.id !== id))} />
    </div>
  );
}

function Syncs({ logs, mappings, onRunSync, onPurgeOldLogs }: { logs: SyncLog[]; mappings: Mapping[]; onRunSync: (mapping: Mapping) => void; onPurgeOldLogs: () => void }) {
  const [selectedLog, setSelectedLog] = useState<SyncLog | null>(null);
  const [statusFilter, setStatusFilter] = useState<"Todas" | "Errores">("Todas");
  const oldLogsCount = logs.filter((log) => isLogOlderThanDays(log, 30)).length;
  const visibleLogs = statusFilter === "Errores" ? logs.filter((log) => log.status === "Error" || log.errors > 0) : logs;

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Registro de sincronizaciones"
        description="Auditoria de ejecuciones, objetos creados, atributos modificados y errores de sincronizacion."
        actions={
          <div className="flex flex-col sm:flex-row gap-2">
            <button
              onClick={onPurgeOldLogs}
              disabled={!oldLogsCount}
              className="inline-flex items-center justify-center gap-2 h-10 px-3 border border-slate-300 bg-white text-slate-700 hover:bg-slate-50 disabled:bg-slate-100 disabled:text-slate-400 rounded-none text-sm font-semibold"
            >
              <Trash2 className="h-4 w-4" />
              Eliminar &gt;30 dias
            </button>
            <select
              onChange={(event) => {
                const mapping = mappings.find((item) => item.id === event.target.value);
                if (mapping) onRunSync(mapping);
                event.target.value = "";
              }}
              className="h-10 border border-slate-300 bg-white px-3 text-sm focus:outline-none focus:border-blue-500"
              defaultValue=""
            >
              <option value="" disabled>
                Sincronizar mapeo
              </option>
              {mappings.map((mapping) => (
                <option key={mapping.id} value={mapping.id}>
                  {mapping.name}
                </option>
              ))}
            </select>
          </div>
        }
      />
      <div className="bg-white border border-slate-200 shadow-sm px-4 py-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <div className="text-sm font-bold text-slate-900">Filtro de sincronizaciones</div>
          <div className="text-xs text-slate-500">{visibleLogs.length} de {logs.length} sincronizaciones visibles</div>
        </div>
        <select
          value={statusFilter}
          onChange={(event) => setStatusFilter(event.target.value as "Todas" | "Errores")}
          className="h-10 border border-slate-300 bg-white px-3 text-sm focus:outline-none focus:border-blue-500"
        >
          <option value="Todas">Todas</option>
          <option value="Errores">Solo con error</option>
        </select>
      </div>
      <LogsTable logs={visibleLogs} onOpen={setSelectedLog} />
      {selectedLog ? <SyncLogDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} /> : null}
    </div>
  );
}

function JiraSettings({ config, setConfig }: { config: SourceConfig; setConfig: (config: SourceConfig) => void }) {
  const [showHelp, setShowHelp] = useState(false);
  const [testStatus, setTestStatus] = useState<AdTestStatus>("idle");
  const [testMessage, setTestMessage] = useState("");
  const jiraSchemas = config.jira.schemas ?? [];

  const testJiraConnection = async () => {
    if (!config.jira.url.trim() || !config.jira.cloudId.trim() || !config.jira.workspaceId.trim() || !config.jira.email.trim()) {
      setTestStatus("error");
      setTestMessage("Completa URL Jira, Cloud ID, Workspace ID y Correo API antes de probar la conexion.");
      return;
    }

    setTestStatus("testing");
    setTestMessage("Conectando con Jira Assets y leyendo esquemas reales.");

    try {
      const response = await fetch("/api/jira/test", {
        method: "POST",
        headers: secureJsonHeaders(),
        body: JSON.stringify({
          url: config.jira.url,
          cloudId: config.jira.cloudId,
          workspaceId: config.jira.workspaceId,
          email: config.jira.email,
          apiToken: config.jira.apiToken,
        }),
      });
      const result = (await response.json()) as { schemas?: JiraSchemaInfo[]; hasApiToken?: boolean; detail?: string; error?: string };
      if (!response.ok) throw new Error(result.detail || result.error || "No se pudo conectar con Jira Assets.");

      setConfig({
        ...config,
        jira: {
          ...config.jira,
          apiToken: undefined,
          hasApiToken: result.hasApiToken ?? true,
          connected: true,
          testedAt: formatDate(new Date()),
          schemas: result.schemas ?? [],
        },
      });
      setTestStatus("success");
      setTestMessage(`Conexion validada. ${result.schemas?.length ?? 0} esquemas reales cargados desde Jira Assets.`);
    } catch (error) {
      setTestStatus("error");
      setTestMessage(error instanceof Error ? error.message : "Error al conectar con Jira Assets.");
      setConfig({
        ...config,
        jira: {
          ...config.jira,
          connected: false,
          testedAt: undefined,
          schemas: [],
        },
      });
    }
  };

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Conexion Jira Assets"
        description="Parametros para crear y actualizar objetos mediante la API de Jira Assets."
        actions={
          <>
            <button
              onClick={() => setShowHelp(true)}
              className="inline-flex items-center gap-2 px-4 py-2 bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 rounded-none text-sm font-semibold shadow-sm"
            >
              <HelpCircle className="h-4 w-4" />
              Ayuda configuracion
            </button>
            <button
              onClick={testJiraConnection}
              disabled={testStatus === "testing"}
              className="inline-flex items-center gap-2 px-4 py-2 bg-slate-900 hover:bg-slate-800 disabled:bg-slate-400 text-white rounded-none text-sm font-semibold shadow-sm"
            >
              <RefreshCw className={`h-4 w-4 ${testStatus === "testing" ? "animate-spin" : ""}`} />
              Probar conexion
            </button>
          </>
        }
      />
      <div className="bg-white border border-slate-200 shadow-sm">
        <div className="p-5 grid grid-cols-1 md:grid-cols-2 gap-4">
          <TextInput label="URL Jira" value={config.jira.url} onChange={(url) => setConfig({ ...config, jira: { ...config.jira, url } })} />
          <TextInput label="Cloud ID" value={config.jira.cloudId} onChange={(cloudId) => setConfig({ ...config, jira: { ...config.jira, cloudId } })} />
          <TextInput label="Workspace ID" value={config.jira.workspaceId} onChange={(workspaceId) => setConfig({ ...config, jira: { ...config.jira, workspaceId } })} />
          <TextInput label="Correo API" value={config.jira.email} onChange={(email) => setConfig({ ...config, jira: { ...config.jira, email } })} />
          <div>
            <TextInput
              label="API token"
              type="password"
              maxWidthClassName="max-w-md"
              value={config.jira.apiToken ?? ""}
              placeholder={config.jira.hasApiToken && !config.jira.apiToken ? "•••••••••••••••• token guardado" : "Pega el API token"}
              onChange={(apiToken) => setConfig({ ...config, jira: { ...config.jira, apiToken } })}
            />
            {config.jira.hasApiToken && !config.jira.apiToken ? (
              <div className="mt-1 text-xs text-slate-500">API token guardado cifrado en la BBDD. Se reutilizara automaticamente; escribe uno nuevo solo si quieres reemplazarlo.</div>
            ) : null}
          </div>
        </div>
        <div className="px-5 py-3 border-t border-slate-200">
          {config.jira.connected ? (
            <div className="flex items-center gap-2 bg-emerald-50 text-emerald-800 border border-emerald-100 px-3 py-2 text-sm">
              <CheckCircle2 className="h-4 w-4 shrink-0" />
              <span className="truncate">Conexion validada {config.jira.testedAt ? `el ${formatDisplayDateTime(config.jira.testedAt)}` : ""}. Esquemas cargados desde Jira Assets.</span>
            </div>
          ) : (
            <div className="flex items-center gap-2 bg-amber-50 text-amber-800 border border-amber-100 px-3 py-2 text-sm">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              <span>{testStatus === "error" ? testMessage : "Ejecuta la prueba para cargar los esquemas reales de Jira Assets."}</span>
            </div>
          )}
        </div>
      </div>
      <div className="bg-white border border-slate-200 shadow-sm overflow-x-auto">
        <div className="px-4 py-3 border-b border-slate-200 text-sm font-bold text-slate-900">
          Listado de esquemas disponibles
        </div>
        <table className="w-full text-left border-collapse min-w-[760px]">
          <tbody className="divide-y divide-slate-200 text-sm">
            {jiraSchemas.length ? jiraSchemas.map((schema) => (
              <tr key={schema.name} className="hover:bg-slate-50/50">
                <td className="px-4 py-3 font-semibold text-slate-800">{schema.name}</td>
                <td className="px-4 py-3 text-slate-600">{schema.objectTypes.length ? schema.objectTypes.map(getJiraObjectTypeName).join(", ") : "Sin tipos de objeto detectados"}</td>
                <td className="px-4 py-3"><Badge status="Correcta" text="Disponible" /></td>
              </tr>
            )) : (
              <tr>
                <td className="px-4 py-6 text-sm text-slate-500" colSpan={3}>
                  No hay esquemas cargados. Ejecuta `Probar conexion` para consultar Jira Assets y refrescar este listado.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {showHelp ? <JiraAssetsHelpModal onClose={() => setShowHelp(false)} /> : null}
    </div>
  );
}

function JiraAssetsHelpModal({ onClose }: { onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 bg-slate-900/50 backdrop-blur-xs p-4 overflow-y-auto">
      <div role="dialog" aria-modal="true" className="bg-white border border-slate-200 border-l-4 border-l-blue-600 shadow-xl w-full max-w-3xl mx-auto my-8">
        <div className="h-14 px-5 border-b border-slate-200 flex items-center justify-between">
          <div className="min-w-0">
            <h3 className="text-base font-bold text-slate-900">Configurar Jira Assets</h3>
            <p className="text-xs text-slate-500">Datos necesarios para autenticar y localizar el workspace de Assets.</p>
          </div>
          <button onClick={onClose} aria-label="Cerrar ayuda" className="h-9 w-9 inline-flex items-center justify-center border border-slate-300 bg-white hover:bg-slate-50">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="p-5 space-y-5 text-sm text-slate-700">
          <div className="bg-slate-50 border border-slate-200 p-4">
            <div className="text-xs font-bold uppercase text-slate-600 mb-2">Campos de conexion</div>
            <table className="w-full text-left text-sm">
              <tbody className="divide-y divide-slate-200">
                <tr>
                  <td className="py-2 pr-4 font-semibold text-slate-900 whitespace-nowrap">URL Jira</td>
                  <td className="py-2">URL base de tu sitio Atlassian, por ejemplo <span className="font-mono text-xs">https://empresa.atlassian.net</span>.</td>
                </tr>
                <tr>
                  <td className="py-2 pr-4 font-semibold text-slate-900 whitespace-nowrap">Workspace ID</td>
                  <td className="py-2">Identificador de Assets devuelto por el endpoint de workspaces.</td>
                </tr>
                <tr>
                  <td className="py-2 pr-4 font-semibold text-slate-900 whitespace-nowrap">Correo API</td>
                  <td className="py-2">Email de la cuenta Atlassian o cuenta de servicio que ejecutara la sincronizacion.</td>
                </tr>
                <tr>
                  <td className="py-2 pr-4 font-semibold text-slate-900 whitespace-nowrap">API token</td>
                  <td className="py-2">Token API de Atlassian. Se guarda cifrado en la BBDD y nunca debe copiarse en documentacion ni logs.</td>
                </tr>
              </tbody>
            </table>
          </div>

          <div>
            <div className="text-xs font-bold uppercase text-slate-600 mb-2">Generar token API</div>
            <ol className="list-decimal list-inside space-y-1">
              <li>Accede con la cuenta que usara la integracion a <a className="text-blue-700 font-semibold hover:underline" href="https://id.atlassian.com/manage-profile/security/api-tokens" target="_blank" rel="noreferrer">id.atlassian.com/manage-profile/security/api-tokens</a>.</li>
              <li>Crea un token API con scopes y caducidad controlada. Si usas un token sin scopes, la autenticacion es mas amplia y menos restrictiva.</li>
              <li>Selecciona los scopes de Jira Service Management y Assets indicados en el siguiente apartado.</li>
              <li>Copia el token una sola vez y guardalo en el gestor de secretos que uses para el despliegue.</li>
            </ol>
          </div>

          <div className="bg-slate-50 border border-slate-200 p-4">
            <div className="text-xs font-bold uppercase text-slate-600 mb-2">Scopes necesarios</div>
            <p className="mb-3">Para tokens con scopes, Atlassian exige llamar por <span className="font-mono text-xs">api.atlassian.com/ex/jira/&#123;cloudId&#125;</span>. Esta aplicacion prueba ese modo automaticamente. Configura estos scopes:</p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="bg-white border border-slate-200 p-3">
                <div className="text-[11px] font-bold uppercase text-slate-500 mb-2">Objetos de Assets</div>
                <ul className="space-y-1 font-mono text-xs text-slate-800">
                  <li>read:cmdb-object:jira</li>
                  <li>write:cmdb-object:jira</li>
                  <li>delete:cmdb-object:jira</li>
                </ul>
              </div>
              <div className="bg-white border border-slate-200 p-3">
                <div className="text-[11px] font-bold uppercase text-slate-500 mb-2">Lectura de estructura</div>
                <ul className="space-y-1 font-mono text-xs text-slate-800">
                  <li>read:cmdb-schema:jira</li>
                  <li>read:cmdb-type:jira</li>
                  <li>read:cmdb-attribute:jira</li>
                  <li>read:cmdb-icon:jira</li>
                </ul>
              </div>
              <div className="bg-white border border-slate-200 p-3 md:col-span-2">
                <div className="text-[11px] font-bold uppercase text-slate-500 mb-2">Jira Service Management</div>
                <ul className="space-y-1 font-mono text-xs text-slate-800">
                  <li>read:servicedesk-request</li>
                  <li>read:servicedesk:jira-service-management</li>
                  <li>read:user:jira</li>
                </ul>
                <p className="mt-2 text-xs text-slate-500">El endpoint de Workspace ID documenta <span className="font-mono text-xs">read:servicedesk-request</span>. Los scopes adicionales ayudan con tokens granulares y cuentas de servicio cuando Atlassian valida acceso a Jira Service Management.</p>
              </div>
            </div>
            <div className="mt-3 border border-amber-100 bg-amber-50 text-amber-800 p-3 text-xs">
              Si tu token no permite leer configuracion de Assets, informa manualmente en cada mapeo los campos ID estado Alta, ID estado Baja e ID estado Deshabilitado. Solo anade scopes de escritura o borrado de schemas, object types o atributos si la aplicacion va a modificar la estructura de Assets: write/delete:cmdb-schema:jira, write/delete:cmdb-type:jira y write/delete:cmdb-attribute:jira. Para sincronizar elementos existentes no son necesarios.
            </div>
          </div>

          <div>
            <div className="text-xs font-bold uppercase text-slate-600 mb-2">Obtener Jira Cloud ID</div>
            <pre className="bg-slate-900 text-slate-100 p-3 overflow-x-auto text-xs"><code>{`https://tunombredetenant.atlassian.net/_edge/tenant_info`}</code></pre>
          </div>

          <div>
            <div className="text-xs font-bold uppercase text-slate-600 mb-2">Obtener Workspace ID de Assets</div>
            <p className="mb-2">Accede en el navegador a esta URL:</p>
            <pre className="bg-slate-900 text-slate-100 p-3 overflow-x-auto text-xs"><code>{`https://tunombredetenant.atlassian.net/rest/servicedeskapi/assets/workspace`}</code></pre>
            <p className="mt-2">En esta web encontraras el valor <span className="font-mono text-xs">workspaceId</span>. Copialo y pegalo en el campo Workspace ID.</p>
          </div>

          <div>
            <div className="text-xs font-bold uppercase text-slate-600 mb-2">Ruta base para sincronizar Assets</div>
            <pre className="bg-slate-900 text-slate-100 p-3 overflow-x-auto text-xs"><code>{`https://api.atlassian.com/ex/jira/{cloudId}/jsm/assets/workspace/{workspaceId}/v1/...`}</code></pre>
            <p className="mt-2">Sustituye <span className="font-mono text-xs">cloudId</span> por el ID obtenido en <span className="font-mono text-xs">/_edge/tenant_info</span> y <span className="font-mono text-xs">workspaceId</span> por el ID devuelto por el endpoint de workspaces de Assets.</p>
          </div>
        </div>
        <div className="px-5 py-4 border-t border-slate-200 flex justify-end">
          <button onClick={onClose} className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-white rounded-none text-sm font-semibold">Cerrar</button>
        </div>
      </div>
    </div>
  );
}

function getJiraObjectTypeName(objectType: string | JiraObjectTypeInfo) {
  return typeof objectType === "string" ? objectType : objectType.name;
}

function normalizeJiraObjectTypes(objectTypes: Array<string | JiraObjectTypeInfo>) {
  return objectTypes
    .map((objectType) => (typeof objectType === "string" ? { name: objectType, attributes: [] } : { ...objectType, attributes: normalizeJiraAttributes(objectType.attributes ?? []) }))
    .filter((objectType) => objectType.name);
}

function normalizeJiraAttributes(attributes: Array<string | JiraAttributeInfo>) {
  return attributes
    .map((attribute) => (typeof attribute === "string" ? { name: attribute } : attribute))
    .filter((attribute) => attribute.name);
}

function normalizeJiraAttributeNames(attributes: Array<string | JiraAttributeInfo>) {
  return normalizeJiraAttributes(attributes).map((attribute) => attribute.name).filter(Boolean);
}

function isWritableJiraAttribute(attribute: JiraAttributeInfo) {
  return attribute.editable !== false && !attribute.system && !["key", "created", "updated"].includes(attribute.name.toLowerCase());
}

function getDefaultJiraAttribute(attributes: JiraAttributeInfo[], source: SourceKind) {
  if (!attributes.length) return "";
  if (source === "AD") {
    const objectSid = attributes.find((attribute) => attribute.name.toLowerCase() === "objectsid");
    if (objectSid) return objectSid.name;
  }
  const label = attributes.find((attribute) => attribute.label);
  if (label) return label.name;
  const requiredName = attributes.find((attribute) => attribute.required && (attribute.name.toLowerCase() === "nombre" || attribute.name.toLowerCase() === "name"));
  if (requiredName) return requiredName.name;
  const name = attributes.find((attribute) => attribute.name.toLowerCase() === "nombre" || attribute.name.toLowerCase() === "name");
  return name?.name ?? attributes[0].name;
}

function createInitialMappingFields({ source, attrs, jiraAttributes }: { source: SourceKind; attrs: string[]; jiraAttributes: JiraAttributeInfo[] }) {
  const keySourceAttribute = source === "AD" ? (attrs.find((attribute) => attribute.toLowerCase() === "objectsid") ?? attrs[0] ?? "objectSid") : (attrs[0] ?? "name");
  const fields: MappingField[] = [{ sourceAttribute: keySourceAttribute, jiraAttribute: getDefaultJiraAttribute(jiraAttributes, source), key: true, kind: "attribute" }];
  const requiredLabel = jiraAttributes.find((attribute) => attribute.label || (attribute.required && ["nombre", "name"].includes(attribute.name.toLowerCase())));
  const sourceNameAttribute = attrs.find((attribute) => ["name", "cn", "displayName"].includes(attribute));
  if (requiredLabel?.name && sourceNameAttribute && requiredLabel.name !== fields[0].jiraAttribute && sourceNameAttribute !== fields[0].sourceAttribute) {
    fields.push({ sourceAttribute: sourceNameAttribute, jiraAttribute: requiredLabel.name, key: false, kind: "attribute" });
  }
  return fields;
}

function normalizeMappingFields(fields: MappingField[] = []) {
  return fields.map((field) => ({ ...field, kind: field.kind ?? "attribute" }));
}

function MappingNotFoundPage({ onClose }: { onClose: () => void }) {
  return (
    <div className="space-y-6">
      <SectionHeader
        title="Mapeo no encontrado"
        description="El mapeo solicitado no existe o se ha eliminado."
        actions={<button onClick={onClose} className="px-4 py-2 bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 rounded-none text-sm font-semibold">Volver a mapeos</button>}
      />
    </div>
  );
}

function getDefaultStatusAttribute(attributes: JiraAttributeInfo[]) {
  return attributes.find((attribute) => ["estado", "status"].includes(attribute.name.toLowerCase()))?.name
    ?? attributes.find((attribute) => ["estado", "status"].includes(String(attribute.type ?? "").toLowerCase()))?.name
    ?? "";
}

function getAvailableAttributesForRow(attributes: string[], selected: string[], current: string) {
  return [...new Set([current, ...attributes].filter(Boolean))].filter((attribute) => attribute === current || !selected.includes(attribute));
}

const mappingScheduleOptions = ["Nunca", "Cada 1 hora", "Cada 6 horas", "Cada 24 horas"];

function normalizeMappingSchedule(mapping?: Mapping | null) {
  if (!mapping?.automatic) return "Nunca";
  if (mapping.frequency === "Cada hora") return "Cada 1 hora";
  return mappingScheduleOptions.includes(mapping.frequency) ? mapping.frequency : "Cada 6 horas";
}

function MappingEditorPage({
  config,
  setConfig,
  initialMapping,
  onClose,
  onSave,
}: {
  config: SourceConfig;
  setConfig: (value: SourceConfig | ((current: SourceConfig) => SourceConfig)) => void;
  initialMapping?: Mapping | null;
  onClose: () => void;
  onSave: (mapping: Mapping) => void;
}) {
  const isEditing = Boolean(initialMapping);
  const skipFieldReset = useRef(Boolean(initialMapping));
  const preserveFieldsOnJiraSync = useRef(false);
  const [name, setName] = useState(initialMapping?.name ?? "");
  const [source, setSource] = useState<SourceKind>(initialMapping?.source ?? "AD");
  const [entity, setEntity] = useState<ADEntity | "VMs">(initialMapping?.entity ?? "Usuarios");
  const availableJiraSchemas = config.jira.schemas ?? [];
  const [schema, setSchema] = useState(initialMapping?.jiraSchema ?? availableJiraSchemas[0]?.name ?? "");
  const objectTypes = useMemo(
    () => normalizeJiraObjectTypes(availableJiraSchemas.find((item) => item.name === schema)?.objectTypes ?? []),
    [availableJiraSchemas, schema]
  );
  const [objectType, setObjectType] = useState(initialMapping?.objectType ?? objectTypes[0]?.name ?? "");
  const jiraAttributeDefinitions = useMemo(() => normalizeJiraAttributes(objectTypes.find((item) => item.name === objectType)?.attributes ?? []).filter(isWritableJiraAttribute), [objectTypes, objectType]);
  const jiraAttributes = useMemo(() => normalizeJiraAttributeNames(jiraAttributeDefinitions), [jiraAttributeDefinitions]);
  const requiredJiraAttributes = useMemo(() => jiraAttributeDefinitions.filter((attribute) => attribute.required || attribute.label).map((attribute) => attribute.name), [jiraAttributeDefinitions]);
  const attrs = source === "AD" && entity !== "VMs" ? (config.ad.attributes[entity] ?? []) : config.nutanix.attributes;
  const [selectedOus, setSelectedOus] = useState<string[]>(initialMapping?.source === "AD" ? initialMapping.sourceScope : []);
  const scope = source === "AD" ? selectedOus : config.nutanix.selectedClusters;
  const adTreeAvailable = Boolean(config.ad.connected && config.ad.domainTree?.length);
  const [fields, setFields] = useState<MappingField[]>([
    ...(initialMapping?.fields.length ? normalizeMappingFields(initialMapping.fields) : createInitialMappingFields({ source, attrs, jiraAttributes: jiraAttributeDefinitions })),
  ]);
  const [statusConfig, setStatusConfig] = useState({
    enabled: initialMapping?.statusConfig?.enabled ?? true,
    jiraAttribute: initialMapping?.statusConfig?.jiraAttribute ?? getDefaultStatusAttribute(jiraAttributeDefinitions),
    activeValue: initialMapping?.statusConfig?.activeValue ?? "",
    inactiveValue: initialMapping?.statusConfig?.inactiveValue ?? "",
    disabledValue: initialMapping?.statusConfig?.disabledValue ?? "",
  });
  const [schedule, setSchedule] = useState(normalizeMappingSchedule(initialMapping));
  const [validationMessage, setValidationMessage] = useState("");
  const [adSyncStatus, setAdSyncStatus] = useState<AdTestStatus>("idle");
  const [adSyncMessage, setAdSyncMessage] = useState("");
  const [jiraSyncStatus, setJiraSyncStatus] = useState<AdTestStatus>("idle");
  const [jiraSyncMessage, setJiraSyncMessage] = useState("");
  const statusAttributeManaged = source === "AD" && entity === "Usuarios" && statusConfig.enabled && Boolean(statusConfig.jiraAttribute);
  const jiraAttributesForFields = useMemo(
    () => statusAttributeManaged ? jiraAttributes.filter((attribute) => attribute !== statusConfig.jiraAttribute) : jiraAttributes,
    [jiraAttributes, statusAttributeManaged, statusConfig.jiraAttribute]
  );
  const availableSourceForNewField = attrs.find((attr) => !fields.some((field) => field.sourceAttribute === attr)) ?? "";
  const availableJiraForNewField = jiraAttributesForFields.find((attribute) => !fields.some((field) => field.jiraAttribute === attribute)) ?? "";

  useEffect(() => {
    if (source === "Nutanix") setEntity("VMs");
    if (source === "AD" && entity === "VMs") setEntity("Usuarios");
  }, [source, entity]);

  useEffect(() => {
    if (!availableJiraSchemas.length) {
      setSchema("");
      return;
    }
    if (!availableJiraSchemas.some((item) => item.name === schema)) {
      setSchema(availableJiraSchemas[0].name);
    }
  }, [availableJiraSchemas, schema]);

  useEffect(() => {
    if (!objectTypes.length) {
      setObjectType("");
      return;
    }
    if (!objectTypes.some((item) => item.name === objectType)) {
      setObjectType(objectTypes[0].name);
    }
  }, [objectTypes, objectType]);

  useEffect(() => {
    if (skipFieldReset.current) return;
    setSelectedOus([]);
    setValidationMessage("");
  }, [source, entity]);

  useEffect(() => {
    if (skipFieldReset.current) {
      skipFieldReset.current = false;
      return;
    }
    if (preserveFieldsOnJiraSync.current) {
      preserveFieldsOnJiraSync.current = false;
      setStatusConfig((current) => ({
        ...current,
        jiraAttribute: current.jiraAttribute && jiraAttributes.includes(current.jiraAttribute) ? current.jiraAttribute : getDefaultStatusAttribute(jiraAttributeDefinitions),
      }));
      setValidationMessage("");
      return;
    }
    setFields(createInitialMappingFields({ source, attrs, jiraAttributes: jiraAttributeDefinitions }));
    setStatusConfig((current) => ({ ...current, jiraAttribute: getDefaultStatusAttribute(jiraAttributeDefinitions) }));
    setValidationMessage("");
  }, [source, entity, objectType, jiraAttributeDefinitions, jiraAttributes, attrs]);

  useEffect(() => {
    if (!statusAttributeManaged) return;
    setFields((current) => current.filter((field) => field.jiraAttribute !== statusConfig.jiraAttribute));
  }, [statusAttributeManaged, statusConfig.jiraAttribute]);

  const syncAdOus = async () => {
    setAdSyncStatus("testing");
    setAdSyncMessage("");
    try {
      const response = await fetch("/api/ad/test", {
        method: "POST",
        headers: secureJsonHeaders(),
        body: JSON.stringify({
          domain: config.ad.domain,
          url: config.ad.url,
          bindUser: config.ad.bindUser,
        }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || "No se pudo sincronizar Active Directory.");
      const nextTree = result.tree ?? [];
      setConfig((current) => ({
        ...current,
        ad: {
          ...current.ad,
          connected: true,
          testedAt: formatDate(new Date()),
          domainTree: nextTree,
        },
      }));
      setSelectedOus((current) => current.filter((dn) => ouTreeContainsDn(nextTree, dn)));
      setAdSyncStatus("success");
      setAdSyncMessage(`OUs actualizadas desde Active Directory. Detectadas: ${result.organizationalUnits ?? nextTree.length}.`);
    } catch (error) {
      setAdSyncStatus("error");
      setAdSyncMessage(error instanceof Error ? error.message : "No se pudo sincronizar Active Directory.");
    }
  };

  const syncJiraCatalog = async () => {
    setJiraSyncStatus("testing");
    setJiraSyncMessage("");
    try {
      const response = await fetch("/api/jira/test", {
        method: "POST",
        headers: secureJsonHeaders(),
        body: JSON.stringify({
          url: config.jira.url,
          cloudId: config.jira.cloudId,
          workspaceId: config.jira.workspaceId,
          email: config.jira.email,
        }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || "No se pudo sincronizar Jira Assets.");
      const nextSchemas = result.schemas ?? [];
      preserveFieldsOnJiraSync.current = true;
      setConfig((current) => ({
        ...current,
        jira: {
          ...current.jira,
          connected: true,
          testedAt: formatDate(new Date()),
          schemas: nextSchemas,
          hasApiToken: result.hasApiToken ?? current.jira.hasApiToken,
        },
      }));
      setJiraSyncStatus("success");
      setJiraSyncMessage(`Jira Assets actualizado. Esquemas detectados: ${nextSchemas.length}.`);
    } catch (error) {
      setJiraSyncStatus("error");
      setJiraSyncMessage(error instanceof Error ? error.message : "No se pudo sincronizar Jira Assets.");
    }
  };

  const save = () => {
    const mappingName = name.trim() || `${entity} ${source} a ${schema}`;
    if (source === "AD" && selectedOus.length === 0) {
      setValidationMessage("Selecciona al menos una OU de Active Directory para guardar el mapeo.");
      return;
    }
    if (source === "AD" && entity !== "VMs" && !attrs.length) {
      setValidationMessage(`Selecciona atributos de ${entity} en Fuentes > Active Directory antes de guardar el mapeo.`);
      return;
    }
    if (source === "Nutanix" && !attrs.length) {
      setValidationMessage("Selecciona atributos de VMs en Fuentes > Nutanix antes de guardar el mapeo.");
      return;
    }
    if (!schema) {
      setValidationMessage("Selecciona un esquema de Jira Assets.");
      return;
    }
    if (!objectTypes.length || !objectType) {
      setValidationMessage("Selecciona un tipo de objeto de Jira Assets.");
      return;
    }
    if (!jiraAttributes.length) {
      setValidationMessage("Este tipo de objeto no tiene atributos cargados. Ejecuta `Probar conexion` en Jira Assets para refrescar esquemas, tipos y atributos.");
      return;
    }
    if (!fields.length || fields.some((field) => !field.sourceAttribute || !field.jiraAttribute)) {
      setValidationMessage("Completa todos los pares de atributos origen y Jira antes de guardar.");
      return;
    }
    if (fields.some((field) => field.kind === "jiraObject" && (!field.reference?.schema || !field.reference?.objectType || !field.reference?.matchAttribute))) {
      setValidationMessage("Completa esquema, tipo de objeto y atributo de conexion en todas las referencias Objeto Jira.");
      return;
    }
    if (new Set(fields.map((field) => field.sourceAttribute)).size !== fields.length || new Set(fields.map((field) => field.jiraAttribute)).size !== fields.length) {
      setValidationMessage("No se pueden repetir atributos origen ni atributos Jira dentro del mismo mapeo.");
      return;
    }
    const missingRequired = requiredJiraAttributes.filter((attribute) => {
      if (statusAttributeManaged && attribute === statusConfig.jiraAttribute) return false;
      return !fields.some((field) => field.jiraAttribute === attribute);
    });
    if (missingRequired.length) {
      setValidationMessage(`Anade los atributos obligatorios de Jira antes de guardar: ${missingRequired.join(", ")}.`);
      return;
    }
    if (!fields.some((field) => field.key)) {
      setValidationMessage("Marca al menos un atributo como clave para poder identificar el objeto en Jira.");
      return;
    }
    if (source === "AD" && entity === "Usuarios" && statusConfig.enabled && (!statusConfig.jiraAttribute || !statusConfig.activeValue.trim() || !statusConfig.inactiveValue.trim() || !statusConfig.disabledValue.trim())) {
      setValidationMessage("Completa la configuracion de Estado del mapeo: atributo Estado, valor Alta, valor Baja y valor Deshabilitado.");
      return;
    }
    const mapping: Mapping = {
      id: initialMapping?.id ?? createClientId(),
      name: mappingName,
      source,
      entity,
      sourceScope: scope,
      jiraSchema: schema,
      objectType: objectType || "Objeto",
      automatic: schedule !== "Nunca",
      frequency: schedule,
      fields,
      statusConfig: source === "AD" && entity === "Usuarios" ? {
        enabled: statusConfig.enabled,
        jiraAttribute: statusConfig.jiraAttribute,
        activeValue: statusConfig.activeValue.trim(),
        inactiveValue: statusConfig.inactiveValue.trim(),
        disabledValue: statusConfig.disabledValue.trim(),
      } : undefined,
      lastSync: initialMapping?.lastSync ?? "Pendiente",
      status: initialMapping?.status ?? "Aviso",
    };
    onSave(mapping);
    onClose();
  };

  return (
    <div className="space-y-6">
      <SectionHeader
        title={isEditing ? "Editar mapeo" : "Nuevo mapeo"}
        description="Configura origen, ambito, destino Jira Assets, atributos, estado y referencias a otros objetos."
        actions={
          <div className="flex gap-2">
            <button onClick={onClose} className="px-4 py-2 bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 rounded-none text-sm font-semibold">Volver</button>
            <button onClick={save} className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-none text-sm font-semibold">
              <Save className="h-4 w-4" />
              {isEditing ? "Guardar cambios" : "Crear mapeo"}
            </button>
          </div>
        }
      />
      <div className="bg-white border border-slate-200 shadow-sm">
        <div className="p-5 space-y-5">
          <div className="bg-white border border-slate-200">
            <div className="px-4 py-3 border-b border-slate-200 bg-slate-50">
              <div className="text-sm font-bold text-slate-900">Origen</div>
              <div className="text-xs text-slate-500">Define la fuente, el elemento y las OUs que alimentan este mapeo.</div>
            </div>
            <div className="p-4 space-y-4">
              <TextInput label="Nombre del mapeo" value={name} onChange={setName} placeholder={`${entity} ${source} a ${schema || "Jira Assets"}`} />
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <SelectInput label="Origen" value={source} onChange={(value) => setSource(value as SourceKind)} options={["AD", "Nutanix"]} />
                <SelectInput label="Elemento" value={entity} onChange={(value) => setEntity(value as ADEntity | "VMs")} options={source === "AD" ? ["Usuarios", "Grupos", "Equipos"] : ["VMs"]} />
              </div>
              {source === "AD" ? (
                <div className="border border-slate-200">
                  <div className="px-4 py-3 border-b border-slate-200 flex items-center justify-between gap-3">
                    <div>
                      <div className="text-xs font-bold uppercase text-slate-600">OUs de Active Directory</div>
                      <div className="text-xs text-slate-500">Selecciona las unidades organizativas que alimentaran este mapeo de {entity}.</div>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={syncAdOus}
                        disabled={adSyncStatus === "testing"}
                        className="inline-flex items-center gap-2 px-3 py-2 border border-slate-300 bg-white text-slate-700 hover:bg-slate-50 disabled:opacity-60 rounded-none text-xs font-semibold"
                      >
                        <RefreshCw className={`h-4 w-4 ${adSyncStatus === "testing" ? "animate-spin" : ""}`} />
                        AD Sync
                      </button>
                      <Badge status={adTreeAvailable ? "Correcta" : "Aviso"} text={adTreeAvailable ? `${selectedOus.length} OUs seleccionadas` : "Prueba AD pendiente"} />
                    </div>
                  </div>
                  <div className="p-4">
                    {adSyncMessage ? (
                      <div className={`mb-3 border p-3 text-sm ${adSyncStatus === "error" ? "border-red-100 bg-red-50 text-red-700" : "border-emerald-100 bg-emerald-50 text-emerald-700"}`}>
                        {adSyncMessage}
                      </div>
                    ) : null}
                    {adTreeAvailable ? (
                      <OuTree
                        tree={config.ad.domainTree ?? []}
                        selected={selectedOus}
                        onChange={setSelectedOus}
                      />
                    ) : (
                      <div className="border border-amber-100 bg-amber-50 text-amber-800 p-4 text-sm">
                        Ejecuta correctamente la prueba AD en Fuentes antes de crear mapeos de Active Directory.
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="border border-slate-200 bg-slate-50 p-4 text-sm text-slate-600">
                  Este mapeo usara los clusters Nutanix configurados en Fuentes.
                </div>
              )}
            </div>
          </div>

          <div className="bg-white border border-slate-200">
            <div className="px-4 py-3 border-b border-slate-200 bg-slate-50 flex items-center justify-between gap-3">
              <div>
                <div className="text-sm font-bold text-slate-900">Destino</div>
                <div className="text-xs text-slate-500">Selecciona el esquema y el tipo de objeto en Jira Assets.</div>
              </div>
              <button
                onClick={syncJiraCatalog}
                disabled={jiraSyncStatus === "testing"}
                className="inline-flex items-center gap-2 px-3 py-2 border border-slate-300 bg-white text-slate-700 hover:bg-slate-50 disabled:opacity-60 rounded-none text-xs font-semibold"
              >
                <RefreshCw className={`h-4 w-4 ${jiraSyncStatus === "testing" ? "animate-spin" : ""}`} />
                Jira Sync
              </button>
            </div>
            <div className="p-4 space-y-4">
              {jiraSyncMessage ? (
                <div className={`border p-3 text-sm ${jiraSyncStatus === "error" ? "border-red-100 bg-red-50 text-red-700" : "border-emerald-100 bg-emerald-50 text-emerald-700"}`}>
                  {jiraSyncMessage}
                </div>
              ) : null}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <SelectInput label="Esquema Jira" value={schema} onChange={setSchema} options={availableJiraSchemas.map((item) => item.name)} />
                <SelectInput label="Tipo objeto" value={objectType} onChange={setObjectType} options={objectTypes.map((item) => item.name)} />
              </div>
              {!availableJiraSchemas.length ? (
                <div className="border border-amber-100 bg-amber-50 text-amber-800 p-4 text-sm">
                  Ejecuta correctamente `Probar conexion` en Jira Assets antes de crear mapeos. Los esquemas y tipos de objeto deben venir de Jira, no de datos de demo.
                </div>
              ) : null}
              {source === "AD" && entity === "Usuarios" ? (
                <div className="border border-slate-200">
                  <div className="px-4 py-3 border-b border-slate-200 flex items-center justify-between gap-3">
                    <div>
                      <div className="text-xs font-bold uppercase text-slate-600">Control de estado</div>
                      <div className="text-xs text-slate-500">
                        Para controlar el estado hay que identificar con el ID los estados de Alta, Baja y Deshabilitado, sigue la documentacion oficial para encontrar el ID de estado o crearlo.{" "}
                        <a className="text-blue-700 font-semibold hover:underline" href="https://support.atlassian.com/assets/docs/add-a-status/" target="_blank" rel="noreferrer">https://support.atlassian.com/assets/docs/add-a-status/</a>
                      </div>
                    </div>
                    <label className="inline-flex items-center gap-2 text-xs font-semibold text-slate-700">
                      <input type="checkbox" checked={statusConfig.enabled} onChange={(event) => setStatusConfig({ ...statusConfig, enabled: event.target.checked })} className="h-4 w-4 accent-blue-600" />
                      Gestionar
                    </label>
                  </div>
                  {statusConfig.enabled ? (
                    <div className="p-4 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                      <SelectInput label="Atributo Estado" value={statusConfig.jiraAttribute} onChange={(jiraAttribute) => setStatusConfig({ ...statusConfig, jiraAttribute })} options={jiraAttributes} />
                      <TextInput label="Valor Alta" value={statusConfig.activeValue} onChange={(activeValue) => setStatusConfig({ ...statusConfig, activeValue })} placeholder="Alta o ID del estado" />
                      <TextInput label="Valor Baja" value={statusConfig.inactiveValue} onChange={(inactiveValue) => setStatusConfig({ ...statusConfig, inactiveValue })} placeholder="Baja o ID del estado" />
                      <TextInput label="Valor Deshabilitado" value={statusConfig.disabledValue} onChange={(disabledValue) => setStatusConfig({ ...statusConfig, disabledValue })} placeholder="Deshabilitado o ID del estado" />
                    </div>
                  ) : null}
                </div>
              ) : null}
            </div>
          </div>

          <div className="bg-white border border-slate-200">
            <div className="px-4 py-3 border-b border-slate-200 bg-slate-50">
              <div className="text-sm font-bold text-slate-900">Atributos</div>
              <div className="text-xs text-slate-500">Listado de atributos que se sincronizaran entre el origen y Jira Assets.</div>
            </div>
            <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse min-w-[980px]">
              <thead>
                <tr className="bg-slate-50 border-b border-slate-200 text-xs font-bold uppercase text-slate-500 tracking-wider">
                  <th className="px-4 py-3">Atributo origen</th>
                  <th className="px-4 py-3">Tipo</th>
                  <th className="px-4 py-3">Atributo Jira</th>
                  <th className="px-4 py-3">Clave</th>
                  <th className="px-4 py-3 w-14"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 text-sm">
                {fields.map((field, index) => (
                  <tr key={`${field.sourceAttribute}-${index}`}>
                    <td className="px-4 py-3">
                      <select
                        value={field.sourceAttribute}
                        onChange={(event) => setFields(fields.map((item, itemIndex) => (itemIndex === index ? { ...item, sourceAttribute: event.target.value } : item)))}
                        className="w-full h-9 border border-slate-300 bg-white px-2 text-sm focus:outline-none focus:border-blue-500"
                      >
                        {getAvailableAttributesForRow(attrs, fields.map((item) => item.sourceAttribute), field.sourceAttribute).map((attr) => (
                          <option key={attr} value={attr}>{attr}</option>
                        ))}
                      </select>
                    </td>
                    <td className="px-4 py-3 align-top">
                      <select
                        value={field.kind ?? "attribute"}
                        onChange={(event) => {
                          const kind = event.target.value as "attribute" | "jiraObject";
                          const defaultSchema = availableJiraSchemas[0]?.name ?? "";
                          const defaultTypes = normalizeJiraObjectTypes(availableJiraSchemas.find((item) => item.name === defaultSchema)?.objectTypes ?? []);
                          const defaultType = defaultTypes[0]?.name ?? "";
                          const defaultAttrs = normalizeJiraAttributeNames(defaultTypes[0]?.attributes ?? []);
                          setFields(fields.map((item, itemIndex) => (itemIndex === index ? {
                            ...item,
                            kind,
                            key: kind === "jiraObject" ? false : item.key,
                            reference: kind === "jiraObject" ? (item.reference ?? { schema: defaultSchema, objectType: defaultType, matchAttribute: defaultAttrs[0] ?? "" }) : undefined,
                          } : item)));
                        }}
                        className="w-full h-9 border border-slate-300 bg-white px-2 text-sm focus:outline-none focus:border-blue-500"
                      >
                        <option value="attribute">Atributo</option>
                        <option value="jiraObject">Objeto Jira</option>
                      </select>
                    </td>
                    <td className="px-4 py-3">
                      <select
                        value={field.jiraAttribute}
                        onChange={(event) => setFields(fields.map((item, itemIndex) => (itemIndex === index ? { ...item, jiraAttribute: event.target.value } : item)))}
                        className="w-full h-9 border border-slate-300 bg-white px-2 text-sm focus:outline-none focus:border-blue-500"
                      >
                        {!jiraAttributes.length ? <option value="">Sin atributos cargados</option> : null}
                        {getAvailableAttributesForRow(jiraAttributesForFields, fields.map((item) => item.jiraAttribute), field.jiraAttribute).map((attribute) => (
                          <option key={attribute} value={attribute}>{attribute}</option>
                        ))}
                      </select>
                      {(field.kind ?? "attribute") === "jiraObject" ? (
                        <ReferenceMappingControls
                          schemas={availableJiraSchemas}
                          value={field.reference}
                          onChange={(reference) => setFields(fields.map((item, itemIndex) => (itemIndex === index ? { ...item, reference } : item)))}
                        />
                      ) : null}
                    </td>
                    <td className="px-4 py-3">
                      <input
                        type="checkbox"
                        checked={field.key}
                        disabled={(field.kind ?? "attribute") === "jiraObject"}
                        onChange={(event) => setFields(fields.map((item, itemIndex) => (itemIndex === index ? { ...item, key: event.target.checked } : item)))}
                        className="h-4 w-4 accent-blue-600"
                      />
                    </td>
                    <td className="px-4 py-3">
                      <button aria-label="Eliminar atributo" onClick={() => setFields(fields.filter((_, itemIndex) => itemIndex !== index))} className="h-8 w-8 inline-flex items-center justify-center border border-slate-300 hover:bg-slate-50">
                        <Trash2 className="h-4 w-4 text-rose-600" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>
          </div>
          <button
            onClick={() => {
              if (!availableSourceForNewField || !availableJiraForNewField) return;
              setFields([...fields, { sourceAttribute: availableSourceForNewField, jiraAttribute: availableJiraForNewField, key: false, kind: "attribute" }]);
            }}
            disabled={!availableSourceForNewField || !availableJiraForNewField}
            className="inline-flex items-center gap-2 px-3 py-2 bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 disabled:bg-slate-100 disabled:text-slate-400 rounded-none text-sm font-semibold"
          >
            <Plus className="h-4 w-4" />
            Anadir atributo
          </button>

          <div className="bg-white border border-slate-200">
            <div className="px-4 py-3 border-b border-slate-200 bg-slate-50">
              <div className="text-sm font-bold text-slate-900">Programación</div>
              <div className="text-xs text-slate-500">Define si este mapeo se ejecutara de forma automatica y cada cuanto tiempo.</div>
            </div>
            <div className="p-4 max-w-sm">
              <SelectInput label="Frecuencia" value={schedule} onChange={setSchedule} options={mappingScheduleOptions} />
            </div>
          </div>

          {validationMessage ? (
            <div className="border border-amber-100 bg-amber-50 text-amber-800 p-3 text-sm">
              {validationMessage}
            </div>
          ) : null}
        </div>
          <div className="px-5 py-4 -mx-5 -mb-5 border-t border-slate-200 flex justify-end gap-2 bg-slate-50">
          <button onClick={onClose} className="px-4 py-2 bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 rounded-none text-sm font-semibold">Cancelar</button>
          <button
            onClick={save}
            className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-none text-sm font-semibold"
          >
            <Save className="h-4 w-4" />
            {isEditing ? "Guardar cambios" : "Crear mapeo"}
          </button>
          </div>
        </div>
    </div>
  );
}

function MappingsTable({
  mappings,
  onRunSync,
  onStopSync,
  runningJobs = {},
  onEdit,
  onDelete,
  compact = false,
}: {
  mappings: Mapping[];
  onRunSync: (mapping: Mapping) => void;
  onStopSync?: (mapping: Mapping) => void;
  runningJobs?: Record<string, string>;
  onEdit?: (mapping: Mapping) => void;
  onDelete?: (id: string) => void;
  compact?: boolean;
}) {
  return (
    <div className="bg-white border border-slate-200 shadow-sm overflow-x-auto">
      <table className="w-full text-left border-collapse min-w-[980px]">
        <thead>
          <tr className="bg-slate-50 border-b border-slate-200 text-xs font-bold uppercase text-slate-500 tracking-wider">
            <th className="px-4 py-3">Mapeo</th>
            <th className="px-4 py-3">Origen</th>
            <th className="px-4 py-3">Destino Jira</th>
            <th className="px-4 py-3">Atributos</th>
            <th className="px-4 py-3">Automatica</th>
            <th className="px-4 py-3">Ultima sincronizacion</th>
            <th className="px-4 py-3 w-36">Acciones</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-200 text-sm">
          {mappings.map((mapping) => (
            <tr key={mapping.id} className="hover:bg-slate-50/50">
              <td className="px-4 py-3">
                <div className="font-semibold text-slate-900 truncate max-w-[260px]">{mapping.name}</div>
                <div className="text-xs text-slate-500 truncate max-w-[260px]">{mapping.sourceScope.join(" | ")}</div>
              </td>
              <td className="px-4 py-3"><SourceBadge source={mapping.source} entity={mapping.entity} /></td>
              <td className="px-4 py-3">
                <div className="font-semibold text-slate-800">{mapping.jiraSchema}</div>
                <div className="text-xs text-slate-500">{mapping.objectType}</div>
              </td>
              <td className="px-4 py-3 text-slate-600">{mapping.fields.length} atributos</td>
              <td className="px-4 py-3">{mapping.automatic ? <Badge status="Correcta" text={mapping.frequency} /> : <Badge status="Neutro" text="Manual" />}</td>
              <td className="px-4 py-3"><Badge status={mapping.status} text={formatSyncDateLabel(mapping.lastSync)} /></td>
              <td className="px-4 py-3">
                <div className="flex items-center gap-2">
                  {runningJobs[mapping.id] || mapping.status === "Ejecutando" ? (
                    <button onClick={() => onStopSync?.(mapping)} aria-label="Detener sincronizacion" className="h-8 w-8 inline-flex items-center justify-center bg-rose-600 hover:bg-rose-700 text-white">
                      <X className="h-4 w-4" />
                    </button>
                  ) : (
                    <button onClick={() => onRunSync(mapping)} aria-label="Sincronizar" className="h-8 w-8 inline-flex items-center justify-center bg-blue-600 hover:bg-blue-700 text-white">
                      <Play className="h-4 w-4" />
                    </button>
                  )}
                  {onEdit && !compact && (
                    <button onClick={() => onEdit(mapping)} aria-label="Editar" className="h-8 w-8 inline-flex items-center justify-center border border-slate-300 hover:bg-slate-50">
                      <Pencil className="h-4 w-4 text-slate-700" />
                    </button>
                  )}
                  {onDelete && !compact && (
                    <button onClick={() => onDelete(mapping.id)} aria-label="Eliminar" className="h-8 w-8 inline-flex items-center justify-center border border-slate-300 hover:bg-slate-50">
                      <Trash2 className="h-4 w-4 text-rose-600" />
                    </button>
                  )}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ReferenceMappingControls({
  schemas,
  value,
  onChange,
}: {
  schemas: JiraSchemaInfo[];
  value?: MappingField["reference"];
  onChange: (value: NonNullable<MappingField["reference"]>) => void;
}) {
  const schema = value?.schema || schemas[0]?.name || "";
  const objectTypes = normalizeJiraObjectTypes(schemas.find((item) => item.name === schema)?.objectTypes ?? []);
  const objectType = value?.objectType && objectTypes.some((item) => item.name === value.objectType) ? value.objectType : objectTypes[0]?.name ?? "";
  const attributes = normalizeJiraAttributeNames(objectTypes.find((item) => item.name === objectType)?.attributes ?? []);
  const matchAttribute = value?.matchAttribute && attributes.includes(value.matchAttribute) ? value.matchAttribute : attributes[0] ?? "";

  const setReference = (next: Partial<NonNullable<MappingField["reference"]>>) => {
    const nextSchema = next.schema ?? schema;
    const nextTypes = normalizeJiraObjectTypes(schemas.find((item) => item.name === nextSchema)?.objectTypes ?? []);
    const nextObjectType = next.objectType ?? (nextTypes.some((item) => item.name === objectType) ? objectType : nextTypes[0]?.name ?? "");
    const nextAttributes = normalizeJiraAttributeNames(nextTypes.find((item) => item.name === nextObjectType)?.attributes ?? []);
    onChange({
      schema: nextSchema,
      objectType: nextObjectType,
      matchAttribute: next.matchAttribute ?? (nextAttributes.includes(matchAttribute) ? matchAttribute : nextAttributes[0] ?? ""),
    });
  };

  return (
    <div className="mt-2 grid grid-cols-1 md:grid-cols-3 gap-2">
      <select value={schema} onChange={(event) => setReference({ schema: event.target.value })} className="w-full h-9 border border-slate-300 bg-white px-2 text-xs focus:outline-none focus:border-blue-500">
        {schemas.map((item) => <option key={item.name} value={item.name}>{item.name}</option>)}
      </select>
      <select value={objectType} onChange={(event) => setReference({ objectType: event.target.value })} className="w-full h-9 border border-slate-300 bg-white px-2 text-xs focus:outline-none focus:border-blue-500">
        {objectTypes.map((item) => <option key={item.name} value={item.name}>{item.name}</option>)}
      </select>
      <select value={matchAttribute} onChange={(event) => setReference({ matchAttribute: event.target.value })} className="w-full h-9 border border-slate-300 bg-white px-2 text-xs focus:outline-none focus:border-blue-500">
        {attributes.map((item) => <option key={item} value={item}>{item}</option>)}
      </select>
    </div>
  );
}

function LogsTable({ logs, compact = false, onOpen }: { logs: SyncLog[]; compact?: boolean; onOpen?: (log: SyncLog) => void }) {
  return (
    <div className="bg-white border border-slate-200 shadow-sm overflow-x-auto">
      <table className="w-full text-left border-collapse min-w-[920px]">
        <thead>
          <tr className="bg-slate-50 border-b border-slate-200 text-xs font-bold uppercase text-slate-500 tracking-wider">
            <th className="px-4 py-3">Ejecucion</th>
            <th className="px-4 py-3">Estado</th>
            <th className="px-4 py-3">Creados</th>
            <th className="px-4 py-3">Actualizados</th>
            <th className="px-4 py-3">Sin cambios</th>
            <th className="px-4 py-3">Cambios registrados</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-200 text-sm">
          {logs.length ? logs.map((log) => (
            <tr key={log.id} className="hover:bg-slate-50/50 align-top">
              <td className="px-4 py-3">
                {onOpen ? (
                  <button
                    type="button"
                    onClick={() => onOpen(log)}
                    className="font-semibold text-blue-700 hover:text-blue-900 hover:underline truncate max-w-[260px] text-left block"
                  >
                    {log.mappingName}
                  </button>
                ) : (
                  <div className="font-semibold text-slate-900 truncate max-w-[260px]">{log.mappingName}</div>
                )}
                <div className="text-xs text-slate-500">{formatDisplayDateTime(log.startedAt)}</div>
              </td>
              <td className="px-4 py-3"><Badge status={log.status} text={log.status} /></td>
              <td className="px-4 py-3 font-semibold text-slate-800">{log.created}</td>
              <td className="px-4 py-3 font-semibold text-slate-800">{log.updated}</td>
              <td className="px-4 py-3 text-slate-600">{log.unchanged}</td>
              <td className="px-4 py-3">
                <div className="space-y-1">
                  {log.changes.slice(0, compact ? 2 : 5).map((change) => (
                    <div key={`${log.id}-${change.object}-${change.detail}`} className="text-xs text-slate-600">
                      <span className="font-bold text-slate-800">{change.object}</span> · {change.action}: {change.detail}
                    </div>
                  ))}
                </div>
              </td>
            </tr>
          )) : (
            <tr>
              <td colSpan={6} className="px-4 py-8 text-center text-sm text-slate-500">
                No hay sincronizaciones para mostrar.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function SyncLogDetailModal({ log, onClose }: { log: SyncLog; onClose: () => void }) {
  const [query, setQuery] = useState("");
  const [actionFilter, setActionFilter] = useState("Todas");
  const normalizedQuery = query.trim().toLowerCase();
  const actionOptions = useMemo(() => ["Todas", ...Array.from(new Set(log.changes.map((change) => change.action))).sort((a, b) => a.localeCompare(b, "es"))], [log.changes]);
  const visibleChanges = log.changes.filter((change) => {
    const matchesAction = actionFilter === "Todas" || change.action === actionFilter;
    const matchesQuery = !normalizedQuery || [change.object, change.action, change.detail].some((value) => value.toLowerCase().includes(normalizedQuery));
    return matchesAction && matchesQuery;
  });

  return (
    <div className="fixed inset-0 z-50 bg-slate-900/50 backdrop-blur-xs p-4 overflow-y-auto">
      <div role="dialog" aria-modal="true" className="bg-white border border-slate-200 border-l-4 border-l-blue-600 shadow-xl w-full max-w-5xl mx-auto my-8 max-h-[86vh] flex flex-col">
        <div className="h-14 px-5 border-b border-slate-200 flex items-center justify-between gap-3 shrink-0">
          <div className="min-w-0">
            <h3 className="text-base font-bold text-slate-900 truncate">{log.mappingName}</h3>
            <p className="text-xs text-slate-500">{formatDisplayDateTime(log.startedAt)}</p>
          </div>
          <button onClick={onClose} aria-label="Cerrar detalle" className="h-9 w-9 inline-flex items-center justify-center border border-slate-300 bg-white hover:bg-slate-50 shrink-0">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="p-5 border-b border-slate-200 shrink-0 space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <KpiMini label="Estado" value={log.status} />
            <KpiMini label="Creados" value={log.created.toString()} />
            <KpiMini label="Actualizados" value={log.updated.toString()} />
            <KpiMini label="Sin cambios" value={log.unchanged.toString()} />
            <KpiMini label="Errores" value={log.errors.toString()} />
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-[1fr_220px] gap-3">
            <label className="relative block">
              <Search className="h-4 w-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Buscar por usuario, objeto, atributo o detalle"
                className="w-full h-10 pl-9 pr-3 border border-slate-300 bg-white text-sm focus:outline-none focus:border-blue-500"
              />
            </label>
            <select
              value={actionFilter}
              onChange={(event) => setActionFilter(event.target.value)}
              className="w-full h-10 border border-slate-300 bg-white px-3 text-sm focus:outline-none focus:border-blue-500"
              aria-label="Filtrar por accion"
            >
              {actionOptions.map((action) => <option key={action} value={action}>{action === "Todas" ? "Todas las acciones" : action}</option>)}
            </select>
          </div>
          <div>
            <span className="text-xs text-slate-500">{visibleChanges.length} de {log.changes.length} registros visibles</span>
          </div>
        </div>
        <div className="overflow-auto">
          <table className="w-full text-left border-collapse min-w-[820px]">
            <thead className="sticky top-0 z-10">
              <tr className="bg-slate-50 border-b border-slate-200 text-xs font-bold uppercase text-slate-500 tracking-wider">
                <th className="px-4 py-3">Objeto</th>
                <th className="px-4 py-3">Accion</th>
                <th className="px-4 py-3">Detalle</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 text-sm">
              {visibleChanges.length ? visibleChanges.map((change, index) => (
                <tr key={`${log.id}-${change.object}-${change.action}-${index}`} className="hover:bg-slate-50/50 align-top">
                  <td className="px-4 py-3 font-semibold text-slate-900">{change.object}</td>
                  <td className="px-4 py-3"><Badge status={change.action === "Error" ? "Error" : change.action === "Creado" || change.action === "Actualizado" ? "Correcta" : "Neutro"} text={change.action} /></td>
                  <td className="px-4 py-3 text-slate-600 whitespace-pre-wrap">{change.detail}</td>
                </tr>
              )) : (
                <tr>
                  <td className="px-4 py-8 text-sm text-slate-500" colSpan={3}>No hay cambios que coincidan con los filtros.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function KpiMini({ label, value }: { label: string; value: string }) {
  return (
    <div className="border border-slate-200 bg-slate-50 px-3 py-2">
      <div className="text-[11px] font-bold uppercase text-slate-500">{label}</div>
      <div className="text-base font-bold text-slate-900 truncate">{value}</div>
    </div>
  );
}

function getOuSubtreeDns(node: OuNode): string[] {
  return [node.dn, ...(node.children ?? []).flatMap(getOuSubtreeDns)];
}

function ouTreeContainsDn(tree: OuNode[], dn: string): boolean {
  return tree.some((node) => node.dn === dn || ouTreeContainsDn(node.children ?? [], dn));
}

function getOuLevelClass(level: number) {
  return `ou-tree-level-${Math.min(Math.max(level, 0), 12)}`;
}

function OuTree({ tree, selected, onChange }: { tree: OuNode[]; selected: string[]; onChange: (selected: string[]) => void }) {
  const [expandedDns, setExpandedDns] = useState<Set<string>>(new Set());

  useEffect(() => {
    setExpandedDns(new Set());
  }, [tree]);

  const toggleExpanded = (dn: string) => {
    setExpandedDns((current) => {
      const next = new Set(current);
      if (next.has(dn)) {
        next.delete(dn);
      } else {
        next.add(dn);
      }
      return next;
    });
  };

  const toggleNode = (node: OuNode) => {
    const nodeDns = getOuSubtreeDns(node);
    if (selected.includes(node.dn)) {
      const removeDns = new Set(nodeDns);
      onChange(selected.filter((dn) => !removeDns.has(dn)));
      return;
    }

    onChange(Array.from(new Set([...selected, ...nodeDns])));
  };

  return (
    <div className="border border-slate-200 bg-slate-50 p-3 max-h-[360px] overflow-y-auto">
      {tree.map((node) => (
        <TreeNode key={node.dn} node={node} selected={selected} expandedDns={expandedDns} onToggle={toggleNode} onToggleExpanded={toggleExpanded} level={0} />
      ))}
    </div>
  );
}

function TreeNode({
  node,
  selected,
  expandedDns,
  onToggle,
  onToggleExpanded,
  level,
}: {
  node: OuNode;
  selected: string[];
  expandedDns: Set<string>;
  onToggle: (node: OuNode) => void;
  onToggleExpanded: (dn: string) => void;
  level: number;
}) {
  const hasChildren = Boolean(node.children?.length);
  const isExpanded = expandedDns.has(node.dn);
  const subtreeDns = getOuSubtreeDns(node);
  const isChecked = selected.includes(node.dn);
  const isIndeterminate = !isChecked && subtreeDns.some((dn) => selected.includes(dn));
  const checkboxRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (checkboxRef.current) checkboxRef.current.indeterminate = isIndeterminate;
  }, [isIndeterminate]);

  return (
    <div>
      <div className={`ou-tree-row h-8 flex items-center gap-2 text-sm text-slate-700 min-w-0 ${getOuLevelClass(level)}`}>
        {hasChildren ? (
          <button
            type="button"
            aria-label={isExpanded ? `Comprimir ${node.name}` : `Expandir ${node.name}`}
            onClick={() => onToggleExpanded(node.dn)}
            className="h-5 w-5 inline-flex items-center justify-center text-slate-500 hover:text-slate-900 hover:bg-white border border-transparent hover:border-slate-200"
          >
            <ChevronRight className={`h-3.5 w-3.5 transition-transform ${isExpanded ? "rotate-90" : ""}`} />
          </button>
        ) : (
          <span className="w-5 shrink-0" />
        )}
        <input ref={checkboxRef} type="checkbox" checked={isChecked} onChange={() => onToggle(node)} className="h-4 w-4 accent-blue-600" />
        <button type="button" onClick={() => hasChildren && onToggleExpanded(node.dn)} className="truncate text-left min-w-0 hover:text-slate-900">
          {node.name}
        </button>
      </div>
      {hasChildren && isExpanded
        ? node.children?.map((child) => (
            <TreeNode key={child.dn} node={child} selected={selected} expandedDns={expandedDns} onToggle={onToggle} onToggleExpanded={onToggleExpanded} level={level + 1} />
          ))
        : null}
    </div>
  );
}

function AttributePicker({ label, attributes, selected, onToggle }: { label: string; attributes: AttributeOption[]; selected: string[]; onToggle: (attribute: string) => void }) {
  const [query, setQuery] = useState("");
  const normalizedQuery = query.trim().toLowerCase();
  const visibleAttributes = attributes
    .map(normalizeAttributeOption)
    .filter((attribute) => !normalizedQuery || `${attribute.name} ${attribute.description}`.toLowerCase().includes(normalizedQuery))
    .sort((left, right) => {
      const leftSelected = selected.includes(left.name);
      const rightSelected = selected.includes(right.name);
      if (leftSelected !== rightSelected) return leftSelected ? -1 : 1;
      return left.name.localeCompare(right.name, "es");
    });

  return (
    <div>
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-3 gap-2">
        <div>
          <label className="text-xs font-bold uppercase text-slate-600">{label}</label>
          <div className="text-xs text-slate-500">{selected.length} seleccionados · {visibleAttributes.length} visibles</div>
        </div>
        <div className="relative w-full sm:w-72">
          <Search className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Buscar atributo"
            className="h-9 w-full border border-slate-300 bg-white pl-9 pr-3 text-sm focus:outline-none focus:border-blue-500"
          />
        </div>
      </div>
      <div className="border border-slate-200 bg-slate-50 p-3 grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-[360px] overflow-y-auto">
        {visibleAttributes.length ? visibleAttributes.map((option) => (
          <label key={option.name} className="min-h-8 flex items-start gap-2 text-sm text-slate-700 min-w-0 py-1">
            <input type="checkbox" checked={selected.includes(option.name)} onChange={() => onToggle(option.name)} className="h-4 w-4 accent-blue-600 shrink-0 mt-0.5" />
            <span className="min-w-0 truncate leading-tight">
              <span className="font-semibold text-slate-800">{option.name}</span>
              {option.description ? <span className="text-xs text-slate-500"> - {option.description}</span> : null}
            </span>
          </label>
        )) : (
          <div className="sm:col-span-2 px-3 py-6 text-center text-sm text-slate-500">
            No hay atributos que coincidan con la busqueda.
          </div>
        )}
      </div>
    </div>
  );
}

function normalizeAttributeOption(attribute: AttributeOption) {
  return typeof attribute === "string" ? { name: attribute, description: "" } : attribute;
}

function SectionHeader({ title, description, actions }: { title: string; description: string; actions?: React.ReactNode }) {
  return (
    <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center bg-white p-6 rounded-none border border-slate-200 border-l-4 border-l-blue-600 shadow-sm gap-4">
      <div className="min-w-0">
        <h2 className="text-xl font-bold text-slate-900 tracking-tight">{title}</h2>
        <p className="text-sm text-slate-500 mt-0.5">{description}</p>
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

function PanelTitle({ icon: Icon, title, subtitle, actions }: { icon: typeof Activity; title: string; subtitle: string; actions?: React.ReactNode }) {
  return (
    <div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between gap-3">
      <div className="flex items-center gap-3 min-w-0">
        <div className="h-9 w-9 bg-blue-50 text-blue-700 border border-blue-100 flex items-center justify-center shrink-0">
          <Icon className="h-4 w-4" />
        </div>
        <div className="min-w-0">
          <h3 className="font-bold text-slate-900 truncate">{title}</h3>
          <p className="text-xs text-slate-500 truncate">{subtitle}</p>
        </div>
      </div>
      {actions && <div className="shrink-0">{actions}</div>}
    </div>
  );
}

function Kpi({ label, value, note, icon: Icon, tone }: { label: string; value: string; note: string; icon: typeof Activity; tone: string }) {
  const toneClass = tone === "emerald" ? "bg-emerald-50 text-emerald-700 border-emerald-100" : tone === "violet" ? "bg-violet-50 text-violet-700 border-violet-100" : tone === "amber" ? "bg-amber-50 text-amber-700 border-amber-100" : "bg-blue-50 text-blue-700 border-blue-100";
  return (
    <div className="bg-slate-50 p-4 border border-slate-200 flex items-center gap-4">
      <div className={`h-11 w-11 flex items-center justify-center border ${toneClass}`}>
        <Icon className="h-5 w-5" />
      </div>
      <div className="min-w-0">
        <div className="text-[10px] font-bold uppercase text-slate-500 tracking-wider truncate">{label}</div>
        <div className="text-2xl font-extrabold text-slate-800 leading-tight">{value}</div>
        <div className="text-xs text-slate-500 truncate">{note}</div>
      </div>
    </div>
  );
}

function Toolbar({ query, setQuery, count }: { query: string; setQuery: (query: string) => void; count: number }) {
  return (
    <div className="bg-white p-5 border border-slate-200 shadow-sm flex flex-col sm:flex-row sm:items-center gap-4">
      <div className="relative flex-1 min-w-[220px]">
        <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
        <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Buscar por mapeo, destino o tipo de objeto" className="w-full h-10 pl-9 pr-3 border border-slate-300 bg-white text-sm focus:outline-none focus:border-blue-500" />
      </div>
      <div className="inline-flex items-center gap-2 text-sm text-slate-600">
        <SlidersHorizontal className="h-4 w-4" />
        Mostrando {count} resultados
      </div>
    </div>
  );
}

function TextInput({
  label,
  value,
  onChange,
  type = "text",
  maxWidthClassName = "",
  placeholder = "",
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  type?: string;
  maxWidthClassName?: string;
  placeholder?: string;
}) {
  return (
    <label className="block">
      <span className="block text-xs font-bold uppercase text-slate-600 mb-1.5">{label}</span>
      <input type={type} value={value} placeholder={placeholder} onChange={(event) => onChange(event.target.value)} className={`w-full h-10 border border-slate-300 bg-white px-3 text-sm focus:outline-none focus:border-blue-500 ${maxWidthClassName}`} />
    </label>
  );
}

function SelectInput({ label, value, options, onChange }: { label: string; value: string; options: string[]; onChange: (value: string) => void }) {
  return (
    <label className="block">
      <span className="block text-xs font-bold uppercase text-slate-600 mb-1.5">{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value)} className="w-full h-10 border border-slate-300 bg-white px-3 text-sm focus:outline-none focus:border-blue-500">
        {options.map((option) => (
          <option key={option} value={option}>{option}</option>
        ))}
      </select>
    </label>
  );
}

function ExpirationSelect({ label, value, onChange }: { label: string; value: PasswordExpirationPolicy; onChange: (value: PasswordExpirationPolicy) => void }) {
  return (
    <label className="block">
      <span className="block text-xs font-bold uppercase text-slate-600 mb-1.5">{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value as PasswordExpirationPolicy)} className="w-full h-10 border border-slate-300 bg-white px-3 text-sm focus:outline-none focus:border-blue-500">
        {passwordExpirationOptions.map((option) => (
          <option key={option.value} value={option.value}>{option.label}</option>
        ))}
      </select>
    </label>
  );
}

function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (checked: boolean) => void }) {
  return (
    <label className="inline-flex items-center gap-2 text-xs font-bold uppercase text-slate-600">
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} className="h-4 w-4 accent-blue-600" />
      {label}
    </label>
  );
}

function Badge({ status, text }: { status: SyncStatus | "Neutro"; text: string }) {
  const cls =
    status === "Correcta"
      ? "bg-emerald-50 text-emerald-800 border-emerald-100"
      : status === "Aviso"
        ? "bg-amber-50 text-amber-800 border-amber-100"
        : status === "Error"
          ? "bg-red-50 text-red-800 border-red-100"
          : status === "Ejecutando"
            ? "bg-blue-50 text-blue-800 border-blue-100"
            : "bg-slate-50 text-slate-700 border-slate-200";
  return <span className={`inline-flex items-center px-2 py-1 border text-xs font-bold whitespace-nowrap ${cls}`}>{text}</span>;
}

function SourceBadge({ source, entity }: { source: SourceKind; entity: ADEntity | "VMs" }) {
  const Icon = source === "AD" ? Server : HardDrive;
  return (
    <span className="inline-flex items-center gap-2 px-2 py-1 border border-slate-200 bg-slate-50 text-xs font-bold text-slate-700 whitespace-nowrap">
      <Icon className="h-3.5 w-3.5" />
      {source} · {entity}
    </span>
  );
}

function groupSections() {
  return sections.reduce<Record<string, typeof sections>>((acc, item) => {
    acc[item.group] = acc[item.group] ?? [];
    acc[item.group].push(item);
    return acc;
  }, {});
}

function getRouteFromLocation(): AppRoute {
  const path = window.location.pathname.replace(/^\/+|\/+$/g, "");
  const legacyHash = window.location.hash.replace(/^#\/?/, "");
  const raw = path || legacyHash;
  const [sectionPart, sourcePart, thirdPart] = raw.split("/");
  const section = sectionFromSlug(sectionPart, sourcePart);
  const sourcePage = sourcePageFromSlug(sourcePart);
  const mappingPageId = section === "mappings" && sourcePart ? sourcePart : undefined;
  return { section, sourcePage, mappingPageId: thirdPart ? undefined : mappingPageId };
}

function setLocationPath(section: Section, _sourcePage?: SourcePage, mappingPageId?: string) {
  const nextPath = mappingPageId
    ? `/mappings/${encodeURIComponent(mappingPageId)}`
    : `/${sectionSlug(section)}`;
  if (window.location.pathname !== nextPath) window.history.pushState(null, "", nextPath);
}

function replaceLegacyUsersPath() {
  const path = window.location.pathname.replace(/^\/+|\/+$/g, "");
  if (path === "administration" || path === "admin") {
    window.history.replaceState(null, "", "/users");
  }
}

function sectionSlug(section: Section) {
  if (section === "active-directory") return "sources/active-directory";
  if (section === "nutanix") return "sources/nutanix";
  if (section === "syncs") return "synchronizations";
  if (section === "settings") return "jira-assets";
  if (section === "admin") return "users";
  if (section === "branding") return "branding";
  return section;
}

function sectionFromSlug(value: string, sourcePart?: string): Section {
  if (value === "sources") return sourcePageFromSlug(sourcePart) === "nutanix" ? "nutanix" : "active-directory";
  if (value === "active-directory" || value === "ad") return "active-directory";
  if (value === "nutanix") return "nutanix";
  if (value === "synchronizations" || value === "syncs") return "syncs";
  if (value === "jira-assets" || value === "settings") return "settings";
  if (value === "users" || value === "administration" || value === "admin") return "admin";
  if (value === "branding" || value === "logo" || value === "logotipo") return "branding";
  if (value === "mappings") return "mappings";
  return "dashboard";
}

function sourcePageFromSlug(value?: string): SourcePage {
  if (value === "nutanix") return "nutanix";
  return "ad";
}

function csrfHeaders() {
  return { "X-Nexus-CMDB-Request": "same-origin" };
}

function secureJsonHeaders() {
  return { "Content-Type": "application/json", ...csrfHeaders() };
}

async function refreshBranding() {
  const response = await fetch("/api/public/branding");
  if (!response.ok) throw new Error(`API ${response.status}`);
  return normalizeBranding(await response.json());
}

function normalizeBranding(value: Partial<BrandingSettings> | null | undefined): BrandingSettings {
  return {
    logoDataUrl: typeof value?.logoDataUrl === "string" ? value.logoDataUrl : "",
    faviconDataUrl: typeof value?.faviconDataUrl === "string" ? value.faviconDataUrl : "",
    appTitle: typeof value?.appTitle === "string" && value.appTitle.trim() ? value.appTitle.trim().slice(0, 80) : defaultBranding.appTitle,
  };
}

function isPngFile(file: File) {
  return file.type === "image/png" && file.name.toLowerCase().endsWith(".png");
}

function fileToDataUrl(file: File) {
  return new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ""));
    reader.onerror = () => reject(new Error("No se pudo leer el fichero PNG."));
    reader.readAsDataURL(file);
  });
}

async function fetchPersistedState<T>(key: string, initialValue: T) {
  const response = await fetch(`/api/data/${key}`);
  if (response.status === 404) return initialValue;
  if (!response.ok) throw new Error(`API ${response.status}`);
  const value = await response.json() as T;
  return normalizePersistedValue(key, value, initialValue);
}

function usePersistedState<T>(key: string, initialValue: T) {
  const [state, setState] = useState<T>(initialValue);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetchPersistedState<T>(key, initialValue)
      .then((value) => {
        if (!cancelled) setState(value);
      })
      .catch(() => undefined)
      .finally(() => {
        if (!cancelled) setLoaded(true);
      });
    return () => {
      cancelled = true;
    };
  }, [key, initialValue]);

  useEffect(() => {
    if (!loaded) return;
    fetch(`/api/data/${key}`, {
      method: "PUT",
      headers: secureJsonHeaders(),
      body: JSON.stringify(state),
    }).catch(() => undefined);
  }, [key, loaded, state]);

  return [state, setState] as const;
}

function clearLegacyLocalState() {
  try {
    ["config", "mappings", "logs"].forEach((key) => {
      localStorage.removeItem(`nexus-cmdb-${key}`);
    });
  } catch {
    // El navegador puede bloquear localStorage; la BBDD sigue siendo la fuente persistente.
  }
}

function normalizePersistedValue<T>(key: string, value: T, initialValue: T): T {
  if (key === "mappings" && Array.isArray(value)) {
    return value.filter((mapping) => !["map-users", "map-vms"].includes(String((mapping as Mapping).id))) as T;
  }
  if (key === "logs" && Array.isArray(value)) {
    return value.filter((log) => !["log-1", "log-2"].includes(String((log as SyncLog).id))) as T;
  }
  if (key !== "config") return value;
  const current = value as SourceConfig;
  const initial = initialValue as SourceConfig;
  return {
    ...initial,
    ...current,
    ad: {
      ...initial.ad,
      ...(current.ad ?? {}),
      enabled: {
        ...initial.ad.enabled,
        ...(current.ad?.enabled ?? {}),
      },
      ous: {
        ...initial.ad.ous,
        ...(current.ad?.ous ?? {}),
      },
      attributes: {
        ...initial.ad.attributes,
        ...(current.ad?.attributes ?? {}),
      },
      domainTree: current.ad?.domainTree ?? initial.ad.domainTree ?? [],
    },
    nutanix: {
      ...initial.nutanix,
      ...(current.nutanix ?? {}),
      selectedClusters: current.nutanix?.selectedClusters ?? initial.nutanix.selectedClusters,
      attributes: current.nutanix?.attributes ?? initial.nutanix.attributes,
      hasPassword: Boolean(current.nutanix?.hasPassword),
      connected: Boolean(current.nutanix?.connected),
    },
    jira: {
      ...initial.jira,
      ...(current.jira ?? {}),
      cloudId: current.jira?.cloudId ?? "",
      workspaceId: current.jira?.workspaceId ?? "",
      connected: current.jira?.connected ?? false,
      schemas: current.jira?.schemas ?? [],
    },
  } as T;
}

function splitList(value: string) {
  return value.split(",").map((item) => item.trim()).filter(Boolean);
}

function parseSyncResponse(text: string) {
  if (!text.trim()) return {};
  try {
    return JSON.parse(text);
  } catch {
    const detail = text.replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 240);
    return {
      error: "Respuesta no JSON",
      detail: `La sincronizacion recibio una respuesta no JSON del servidor o proxy. Esto suele indicar timeout o error intermedio de Nginx/Atlassian. Detalle: ${detail || "sin contenido"}`,
    };
  }
}

function upsertSyncLog(logs: SyncLog[], log: SyncLog) {
  return logs.some((item) => item.id === log.id) ? logs.map((item) => (item.id === log.id ? log : item)) : [log, ...logs];
}

function formatDate(date: Date) {
  return formatDisplayDateTime(date);
}

function formatSyncDateLabel(value: string) {
  if (!value || ["Pendiente", "Ejecutando", "Manual", "Nunca"].includes(value)) return value;
  return formatDisplayDateTime(value);
}

function formatDisplayDateTime(value: string | Date) {
  const date = value instanceof Date ? value : parseDateTimeValue(value);
  if (!date) return String(value);
  const pad = (value: number) => value.toString().padStart(2, "0");
  return `${pad(date.getDate())}/${pad(date.getMonth() + 1)}/${date.getFullYear()} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function isLogOlderThanDays(log: SyncLog, days: number) {
  const timestamp = parseLogTimestamp(log.startedAt);
  if (!timestamp) return false;
  return timestamp.getTime() < Date.now() - days * 24 * 60 * 60 * 1000;
}

function parseLogTimestamp(value: string) {
  return parseDateTimeValue(value);
}

function parseDateTimeValue(value: string) {
  const trimmed = String(value ?? "").trim();
  const spanishMatch = trimmed.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})(?:\s+(\d{1,2}):(\d{2}))?$/);
  if (spanishMatch) {
    const [, day, month, year, hour = "0", minute = "0"] = spanishMatch;
    const date = new Date(Number(year), Number(month) - 1, Number(day), Number(hour), Number(minute));
    return Number.isNaN(date.getTime()) ? null : date;
  }
  const normalized = trimmed.includes("T") ? trimmed : trimmed.replace(" ", "T");
  const date = new Date(normalized);
  return Number.isNaN(date.getTime()) ? null : date;
}

function createClientId() {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

export default App;
