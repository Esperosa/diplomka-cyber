// Rozpoznani typu zarizeni (z aktiv, sluzeb, nazvu, vyrobce) a sada vlastnich ikon.
// Ikony jsou stavene z kruhu, kruhovych oblouku a zaoblenych obdelniku (24x24, cara 1.8, kulate konce),
// aby seděly k organickym bublinam mapy. Zadna cizi ikonova sada.
import type { Host, NetworkAsset, Report } from "./types";

export type DeviceKind =
  | "internet"
  | "router"
  | "switch"
  | "ap"
  | "server"
  | "database"
  | "web"
  | "mail"
  | "files"
  | "dns"
  | "workstation"
  | "mobile"
  | "printer"
  | "camera"
  | "iot"
  | "plc"
  | "hmi"
  | "medical"
  | "voip"
  | "vpn"
  | "container"
  | "unknown";

export type DeviceClass = {
  kind: DeviceKind;
  /** high = z aktiva nebo jednoznacne sluzby, medium = z nazvu/dalsich znaku, low = jen odhad */
  confidence: "high" | "medium" | "low";
  /** lidsky srozumitelne duvody ("proc si to myslime") */
  reasons: string[];
};

export const KIND_LABEL: Record<DeviceKind, string> = {
  internet: "Internet",
  router: "Router / brána",
  switch: "Switch",
  ap: "Wi-Fi AP",
  server: "Server",
  database: "Databáze",
  web: "Webový server",
  mail: "Poštovní server",
  files: "Souborový server",
  dns: "DNS server",
  workstation: "Pracovní stanice",
  mobile: "Mobilní zařízení",
  printer: "Tiskárna",
  camera: "Kamera",
  iot: "IoT zařízení",
  plc: "Průmyslový automat (PLC)",
  hmi: "Operátorský panel (HMI)",
  medical: "Zdravotnické zařízení",
  voip: "VoIP telefon",
  vpn: "VPN brána",
  container: "Kontejner / služba",
  unknown: "Neznámé zařízení",
};

/** Poradi skupin v filtrech (nejdulezitejsi infrastruktura nahore). */
export const KIND_ORDER: DeviceKind[] = [
  "router",
  "switch",
  "ap",
  "vpn",
  "server",
  "web",
  "database",
  "mail",
  "files",
  "dns",
  "container",
  "workstation",
  "mobile",
  "voip",
  "printer",
  "camera",
  "iot",
  "plc",
  "hmi",
  "medical",
  "unknown",
];

const ASSET_KIND: Record<string, DeviceKind> = {
  router: "router",
  gateway: "router",
  firewall: "router",
  switch: "switch",
  "access-point": "ap",
  "wireless-client": "mobile",
  printer: "printer",
  camera: "camera",
  phone: "voip",
};

const NAME_RULES: Array<[RegExp, DeviceKind, string]> = [
  [/(^|[-_.])(gw|gateway|router|brana)([-_.]|\d|$)/i, "router", "název odpovídá bráně"],
  [/(^|[-_.])(sw|switch)([-_.]|\d|$)/i, "switch", "název odpovídá switchi"],
  [/(^|[-_.])(ap|wifi|wlan|aruba|unifi)([-_.]|\d|$)/i, "ap", "název odpovídá Wi-Fi AP"],
  [/print|tisk|mfp|jetdirect/i, "printer", "název obsahuje tiskárnu"],
  [/(^|[-_.])(cam|camera|kamera|nvr|dvr)([-_.]|\d|$)/i, "camera", "název obsahuje kameru"],
  [/(^|[-_.])(plc|scada)([-_.]|\d|$)/i, "plc", "název obsahuje PLC"],
  [/(^|[-_.])hmi([-_.]|\d|$)/i, "hmi", "název obsahuje HMI"],
  [/(^|[-_.])(db|sql|mysql|postgres|mongo)([-_.]|\d|$)/i, "database", "název obsahuje databázi"],
  [/(^|[-_.])(mail|smtp|imap|mx)([-_.]|\d|$)/i, "mail", "název obsahuje poštu"],
  [/(^|[-_.])(files|nas|smb|bak|backup)([-_.]|\d|$)/i, "files", "název obsahuje úložiště"],
  [/(^|[-_.])(dns|ldap|ad)([-_.]|\d|$)/i, "dns", "název obsahuje adresářovou službu"],
  [/(^|[-_.])(vpn)([-_.]|\d|$)/i, "vpn", "název obsahuje VPN"],
  [/(^|[-_.])(web|www|proxy|git|ci|wiki)([-_.]|\d|$)/i, "web", "název obsahuje webovou službu"],
  [/(^|[-_.])(voip|phone|sip)([-_.]|\d|$)/i, "voip", "název obsahuje telefon"],
  [/(^|[-_.])(ws|nb|pc|laptop|desktop)([-_.]|\d|$)/i, "workstation", "název obsahuje pracovní stanici"],
  [/(^|[-_.])(iot|sensor|hvac)([-_.]|\d|$)/i, "iot", "název obsahuje IoT zařízení"],
];

type PortRule = { ports: number[]; kind: DeviceKind; label: string; strong: boolean };
const PORT_RULES: PortRule[] = [
  { ports: [9100, 515, 631], kind: "printer", label: "tiskový protokol", strong: true },
  { ports: [554, 8554], kind: "camera", label: "RTSP (video)", strong: true },
  { ports: [502, 102, 44818, 20000], kind: "plc", label: "průmyslový protokol", strong: true },
  { ports: [104, 2575], kind: "medical", label: "DICOM / HL7", strong: true },
  { ports: [5060, 5061], kind: "voip", label: "SIP", strong: true },
  { ports: [1194, 500, 4500, 1701], kind: "vpn", label: "VPN protokol", strong: true },
  { ports: [6443, 2375, 2376, 10250], kind: "container", label: "orchestrace kontejnerů", strong: true },
  { ports: [3306, 5432, 1433, 27017, 1521, 6379], kind: "database", label: "databázový port", strong: true },
  { ports: [25, 465, 587, 143, 993, 110, 995], kind: "mail", label: "poštovní protokol", strong: true },
  { ports: [445, 139, 2049, 21], kind: "files", label: "sdílení souborů", strong: false },
  { ports: [53], kind: "dns", label: "DNS", strong: true },
  { ports: [1883, 8883, 5683], kind: "iot", label: "IoT protokol (MQTT/CoAP)", strong: true },
  { ports: [80, 443, 8080, 8443], kind: "web", label: "webový port", strong: false },
  { ports: [3389, 5900], kind: "workstation", label: "vzdálená plocha", strong: false },
];

const PRODUCT_HINTS: Array<[RegExp, DeviceKind, string]> = [
  [/jetdirect|cups|hp embedded/i, "printer", "produkt tiskárny"],
  [/live555|hikvision|dahua|goahead/i, "camera", "produkt kamery"],
  [/modicon|siemens|rockwell|wincc/i, "plc", "produkt průmyslového řízení"],
  [/mosquitto|boa/i, "iot", "produkt IoT zařízení"],
  [/asterisk|freepbx/i, "voip", "produkt telefonie"],
  [/openvpn|strongswan/i, "vpn", "produkt VPN"],
  [/dropbear/i, "ap", "produkt síťového prvku (Dropbear)"],
  [/mysql|postgres|mariadb|mongo|mssql/i, "database", "produkt databáze"],
  [/postfix|dovecot|exim/i, "mail", "produkt pošty"],
  [/samba|vsftpd/i, "files", "produkt sdílení souborů"],
  [/dnsmasq|bind|unbound/i, "dns", "produkt DNS"],
];

export function assetOf(report: Report, host: Host): NetworkAsset | undefined {
  return (report.networkAssets ?? []).find((a) => a.linked_host_key === host.host_key || (a.ip && a.ip === host.ip));
}

export function classifyHost(report: Report, host: Host): DeviceClass {
  const reasons: string[] = [];
  const asset = assetOf(report, host);
  if (asset) {
    const kind = ASSET_KIND[asset.asset_type];
    if (kind) {
      reasons.push(`zdroj ${asset.source} ho vede jako „${asset.asset_type}“${asset.model ? ` (${asset.model})` : ""}`);
      return { kind, confidence: "high", reasons };
    }
  }
  const votes = new Map<DeviceKind, { score: number; why: string[] }>();
  const vote = (kind: DeviceKind, score: number, why: string) => {
    const entry = votes.get(kind) ?? { score: 0, why: [] };
    entry.score += score;
    entry.why.push(why);
    votes.set(kind, entry);
  };
  if (asset?.asset_type === "endpoint") vote("workstation", 0.8, `zdroj ${asset.source} ho vede jen jako koncový bod`);
  const ports = new Set(host.services.filter((s) => s.port_state === "open" || !s.port_state).map((s) => s.port));
  for (const rule of PORT_RULES) {
    const hit = rule.ports.filter((p) => ports.has(p));
    if (hit.length) vote(rule.kind, rule.strong ? 3 : 1.2, `${rule.label} (port ${hit.join(", ")})`);
  }
  for (const service of host.services) {
    const text = `${service.inventory.product ?? ""} ${service.inventory.service_name ?? ""}`;
    for (const [re, kind, why] of PRODUCT_HINTS) if (re.test(text)) vote(kind, 2.2, `${why} (${service.inventory.product ?? service.inventory.service_name})`);
  }
  const name = host.hostname ?? "";
  if (name) for (const [re, kind, why] of NAME_RULES) if (re.test(name)) vote(kind, 2, `${why} („${name}“)`);
  if (/\.1$/.test(host.ip)) vote("router", 1, "adresa končí na .1 (typicky brána)");
  if (host.vendor) {
    if (/hp|brother|canon|epson|xerox|ricoh|kyocera/i.test(host.vendor)) vote("printer", 1.2, `výrobce ${host.vendor}`);
    if (/aruba|ubiquiti|ruckus|cisco meraki|tp-link/i.test(host.vendor)) vote("ap", 1, `výrobce ${host.vendor}`);
    if (/hikvision|axis|dahua|reolink/i.test(host.vendor)) vote("camera", 2, `výrobce ${host.vendor}`);
  }
  if (!votes.size) {
    if (!host.services.length) return { kind: "unknown", confidence: "low", reasons: ["žádná otevřená služba ani jméno, nelze určit"] };
    if (ports.has(22)) return { kind: "server", confidence: "low", reasons: ["jen SSH, nejspíš server"] };
    return { kind: "unknown", confidence: "low", reasons: ["služby nic jednoznačného neříkají"] };
  }
  const ranked = [...votes.entries()].sort((a, b) => b[1].score - a[1].score);
  const [kind, best] = ranked[0];
  // jediny slaby nazna nestaci k tvrzeni o typu: radsi poctive "neznamé"
  if (best.score < 1.1 && ranked.length === 1) return { kind: "unknown", confidence: "low", reasons: [`jediný náznak je slabý (${best.why[0]})`] };
  const second = ranked[1]?.[1].score ?? 0;
  let finalKind: DeviceKind = kind;
  // web + databaze na jednom hostu = obecny server, ne cisty web
  if (kind === "web" && ranked.some(([k]) => k === "database" || k === "mail" || k === "files")) finalKind = ranked.find(([k]) => k !== "web")![0];
  const confidence: DeviceClass["confidence"] = best.score >= 3 && best.score - second >= 1.5 ? "high" : best.score >= 2 ? "medium" : "low";
  return { kind: finalKind, confidence, reasons: best.why };
}

// ---- ikony ----
// Kazda ikona je sada prvku SVG v 24x24 (stroke = currentColor). Zadne vyplne krome malych tecek.
const dot = (x: number, y: number, r = 1.1) => `<circle cx="${x}" cy="${y}" r="${r}" fill="currentColor" stroke="none"/>`;
const ICONS: Record<DeviceKind, string> = {
  internet: `<circle cx="12" cy="12" r="8.4"/><path d="M3.8 12h16.4M12 3.6c2.6 2.4 3.6 5.2 3.6 8.4s-1 6-3.6 8.4M12 3.6C9.4 6 8.4 8.8 8.4 12s1 6 3.6 8.4"/>`,
  router: `<rect x="3.5" y="12" width="17" height="7" rx="3.5"/>${dot(8, 15.5)}${dot(12, 15.5)}<path d="M8 12V8.5M16 12V8.5M5.5 8.2a8 8 0 0 1 13 0"/>`,
  switch: `<rect x="3.5" y="8" width="17" height="8" rx="3"/><path d="M7.5 12h.01M11 12h.01M14.5 12h.01M18 12h.01" stroke-width="2.6"/><path d="M8 5.5h8M8 18.5h8" opacity=".55"/>`,
  ap: `<path d="M4.2 9.4a11 11 0 0 1 15.6 0M7 12.4a7 7 0 0 1 10 0M9.7 15.2a3.2 3.2 0 0 1 4.6 0"/>${dot(12, 18.4, 1.4)}`,
  server: `<rect x="4" y="4.5" width="16" height="6.2" rx="3.1"/><rect x="4" y="13.3" width="16" height="6.2" rx="3.1"/>${dot(8, 7.6)}${dot(8, 16.4)}<path d="M12 7.6h5M12 16.4h5"/>`,
  database: `<ellipse cx="12" cy="6.5" rx="7" ry="2.9"/><path d="M5 6.5v11c0 1.6 3.1 2.9 7 2.9s7-1.3 7-2.9v-11M5 12c0 1.6 3.1 2.9 7 2.9s7-1.3 7-2.9"/>`,
  web: `<rect x="3.5" y="5" width="17" height="14" rx="4"/><path d="M3.5 9.5h17"/>${dot(7, 7.3, 0.9)}${dot(10, 7.3, 0.9)}<circle cx="12" cy="14.2" r="2.6"/>`,
  mail: `<rect x="3.5" y="6" width="17" height="12" rx="3.6"/><path d="M4.4 8.2 12 13.6l7.6-5.4"/>`,
  files: `<path d="M3.8 8.4a2.6 2.6 0 0 1 2.6-2.6h3.3l2 2.2h5.9a2.6 2.6 0 0 1 2.6 2.6v6.2a2.6 2.6 0 0 1-2.6 2.6H6.4a2.6 2.6 0 0 1-2.6-2.6z"/>`,
  dns: `<circle cx="12" cy="6.6" r="2.4"/><circle cx="6" cy="17.4" r="2.4"/><circle cx="18" cy="17.4" r="2.4"/><path d="M12 9v3.2M12 12.2c-3.4 0-6 1.2-6 2.8M12 12.2c3.4 0 6 1.2 6 2.8"/>`,
  workstation: `<rect x="3.5" y="4.5" width="17" height="11.5" rx="3.6"/><path d="M9 20h6M12 16v4"/>`,
  mobile: `<rect x="7.2" y="3.5" width="9.6" height="17" rx="3.4"/>${dot(12, 17.6)}`,
  printer: `<path d="M7.5 9V4.8a1.3 1.3 0 0 1 1.3-1.3h6.4a1.3 1.3 0 0 1 1.3 1.3V9"/><rect x="3.5" y="9" width="17" height="8" rx="3.4"/><rect x="7.5" y="13.5" width="9" height="7" rx="1.8"/>`,
  camera: `<rect x="3.5" y="7" width="17" height="11" rx="5"/><circle cx="12" cy="12.5" r="3.4"/>${dot(17.2, 9.8, 0.9)}`,
  iot: `<rect x="7" y="7" width="10" height="10" rx="3"/><path d="M10 7V4M14 7V4M10 20v-3M14 20v-3M7 10H4M7 14H4M20 10h-3M20 14h-3"/><circle cx="12" cy="12" r="1.5"/>`,
  plc: `<rect x="4" y="4" width="16" height="16" rx="4"/><path d="M8 9h8M8 12.5h8" opacity=".6"/>${dot(8.5, 16.4)}${dot(12, 16.4)}${dot(15.5, 16.4)}`,
  hmi: `<rect x="3.5" y="5" width="17" height="12" rx="3.6"/><path d="M6.5 12.5c1.4-3.2 2.4-3.2 3.8 0s2.4 3.2 3.8 0 2.2-2.6 3.4-1.2M9 20.5h6"/>`,
  medical: `<circle cx="12" cy="12" r="8.6"/><path d="M12 7.8v8.4M7.8 12h8.4"/>`,
  voip: `<path d="M6.5 4.4h2.6l1.5 3.9-1.8 1.2a10 10 0 0 0 5.2 5.2l1.2-1.8 3.9 1.5v2.6a1.8 1.8 0 0 1-2 1.8A14.6 14.6 0 0 1 4.7 6.4a1.8 1.8 0 0 1 1.8-2z"/>`,
  vpn: `<rect x="5.5" y="10.5" width="13" height="9.5" rx="3.4"/><path d="M8.5 10.5V8a3.5 3.5 0 0 1 7 0v2.5"/>${dot(12, 15.2, 1.3)}`,
  container: `<path d="M12 3.4 19.6 7.7v8.6L12 20.6 4.4 16.3V7.7z"/><path d="M4.6 7.8 12 12l7.4-4.2M12 12v8.4"/>`,
  unknown: `<circle cx="12" cy="12" r="8.6"/><path d="M9.6 9.6a2.6 2.6 0 1 1 3.6 2.4c-.8.4-1.2.9-1.2 1.8"/>${dot(12, 17, 1.1)}`,
};

/** Inline SVG ikony (24x24, barva z currentColor). */
export function iconSvg(kind: DeviceKind, size = 20, cls = "ico"): string {
  return `<svg class="${cls}" viewBox="0 0 24 24" width="${size}" height="${size}" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${ICONS[kind]}</svg>`;
}

/** Vnitrek ikony pro vlozeni do jine SVG (mapa): jen prvky, transformace dela volajici. */
export function iconInner(kind: DeviceKind): string {
  return ICONS[kind];
}

export function kindLabel(kind: DeviceKind): string {
  return KIND_LABEL[kind];
}

// ---- srozumitelne porty ----
const PORT_INFO: Record<number, string> = {
  21: "FTP: přenos souborů, bez šifrování",
  22: "SSH: šifrovaná vzdálená správa",
  23: "Telnet: vzdálená správa bez šifrování",
  25: "SMTP: odesílání pošty",
  53: "DNS: překlad jmen na adresy",
  67: "DHCP: přidělování adres",
  80: "HTTP: web bez šifrování",
  110: "POP3: stahování pošty",
  123: "NTP: synchronizace času",
  139: "NetBIOS: starší sdílení ve Windows",
  143: "IMAP: čtení pošty",
  161: "SNMP: správa a monitoring síťových prvků",
  389: "LDAP: adresář uživatelů",
  443: "HTTPS: šifrovaný web",
  445: "SMB: sdílení souborů a tiskáren ve Windows",
  502: "Modbus: řízení průmyslových zařízení",
  515: "LPD: tisk",
  554: "RTSP: video proud z kamery",
  631: "IPP: tisk po síti",
  993: "IMAPS: šifrované čtení pošty",
  1433: "MS SQL: databáze",
  1883: "MQTT: zprávy z IoT čidel",
  1900: "UPnP: automatické objevování zařízení",
  2049: "NFS: sdílení souborů v Linuxu",
  2375: "Docker API: správa kontejnerů (bez TLS je to riziko)",
  3306: "MySQL: databáze",
  3389: "RDP: vzdálená plocha Windows",
  5060: "SIP: IP telefonie",
  5353: "mDNS: objevování zařízení v místní síti",
  5432: "PostgreSQL: databáze",
  5683: "CoAP: lehký protokol pro IoT",
  5900: "VNC: vzdálená plocha",
  6379: "Redis: rychlá databáze v paměti",
  8080: "HTTP (alternativní port): webové rozhraní",
  8443: "HTTPS (alternativní port): webové rozhraní",
  8883: "MQTT přes TLS: zprávy z IoT čidel",
  9100: "JetDirect: přímý tisk na tiskárnu",
  27017: "MongoDB: databáze",
};

/** Co port znamena lidsky; neznamy port se nevysvetluje (zadne domysleni). */
export function portMeaning(port: number): string | null {
  return PORT_INFO[port] ?? null;
}

/** Jak jistou ma rozpoznani vahu, srozumitelne. */
export const CONFIDENCE_LABEL: Record<DeviceClass["confidence"], string> = { high: "vysoká", medium: "střední", low: "nízká" };

/** Kategorie pro prehledne zobrazeni typu (infrastruktura / koncova zarizeni ...). */
export function isInfrastructure(kind: DeviceKind): boolean {
  return kind === "router" || kind === "switch" || kind === "ap" || kind === "vpn";
}
