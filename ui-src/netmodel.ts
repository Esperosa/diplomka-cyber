// Model mapy site: z reportu spocita zarizeni (typ, riziko, agent), zony (VLAN nebo podsit),
// skutecna spojeni z topologie (LLDP, klient-AP, ARP) a rozlozeni v rovine. Bez DOM, bez vymyslenych dat.
import { assetOf, classifyHost, isInfrastructure, kindLabel, type DeviceClass, type DeviceKind } from "./devices";
import { hashString, type P } from "./pebbles";
import type { Finding, Host, NetworkAsset, Report, TopologyEdge, VerificationResult } from "./types";
import { hostFindings, hostImportance, hostRisk, hypothesesForHost, maxSeverityLevel, meanUncertainty } from "./ui";

export type Hop = {
  index: number;
  asset: string;
  method: string;
  status: VerificationResult["status"];
  outcome: string | null | undefined;
  hypothesis: string;
  onMap: boolean;
};

export type AgentState = "waiting" | "done" | "failed" | "skipped";

export type Item = {
  host: Host;
  key: string;
  ip: string;
  kind: DeviceKind;
  cls: DeviceClass;
  asset: NetworkAsset | undefined;
  findings: Finding[];
  sev: number;
  risk: number;
  uncertainty: number | null;
  imp: number;
  zone: string;
  vlan: string | null;
  ssid: string | null;
  parent: string | null;
  children: string[];
  results: VerificationResult[];
  hopNos: number[];
  agent: AgentState | null;
  /** zname jen z inventare (networkAssets), bez skenu sluzeb */
  inventoryOnly: boolean;
  haystack: string;
  r: number;
  x: number;
  y: number;
};

export type Zone = {
  key: string;
  label: string;
  sub: string;
  vlan: string | null;
  items: Item[];
  kinds: Map<DeviceKind, number>;
  sevMax: number;
  withFindings: number;
  high: number;
  findings: number;
  Rd: number;
  Rb: number;
  cx: number;
  cy: number;
};

export type MapFilter = { zones: string[]; kinds: DeviceKind[]; sev: number[]; q: string };

export type NetModel = {
  runId: string;
  items: Item[];
  byKey: Map<string, Item>;
  byIp: Map<string, Item>;
  zones: Zone[];
  zoneByKey: Map<string, Zone>;
  gateway: Item | null;
  hops: Hop[];
  outsiders: Array<{ ip: string; x: number; y: number }>;
  gate: P;
  internet: P;
  bounds: { x: number; y: number; w: number; h: number };
  /** true, kdyz report obsahuje skutecna spojeni (topologyEdges) a z nich vznikl aspon jeden rodic */
  topology: boolean;
  links: Array<{ a: string; b: string; relation: string }>;
};

export const EMPTY_FILTER: MapFilter = { zones: [], kinds: [], sev: [], q: "" };
/** Do tohoto poctu stanic se mapa otevre rovnou do zarizeni (prehled s 1 az 2 bublinami by nic neukazal). */
export const AUTO_OPEN_MAX = 24;
const GATE: P = { x: 0, y: 0 };
const INTERNET: P = { x: -210, y: 0 };

export function statusLabel(status: VerificationResult["status"]): string {
  switch (status) {
    case "executed":
      return "provedeno";
    case "reused":
      return "převzato";
    case "needs_approval":
      return "čeká na schválení";
    case "skipped_out_of_scope":
      return "mimo rozsah";
    case "skipped_budget":
      return "mimo rozpočet";
    default:
      return "selhalo";
  }
}

/** Skoky agenta: poradi overovacich kontrol, po sobe jdouci kontroly stejneho aktiva se slouci. */
export function hopsOf(report: Report, ips?: Set<string>): Hop[] {
  const onMap = ips ?? new Set(report.hosts.map((h) => h.ip));
  const hops: Hop[] = [];
  for (const result of report.verification_results ?? []) {
    const previous = hops[hops.length - 1];
    if (previous && previous.asset === result.asset && previous.status === result.status) continue;
    hops.push({
      index: hops.length + 1,
      asset: result.asset,
      method: result.method,
      status: result.status,
      outcome: result.outcome,
      hypothesis: result.hypothesis_type,
      onMap: onMap.has(result.asset),
    });
  }
  return hops;
}

function subnetOf(ip: string): { key: string; label: string } {
  const m = ip.match(/^(\d+)\.(\d+)\.(\d+)\.\d+$/);
  if (!m) return { key: "other", label: "ostatní" };
  return { key: `${m[1]}.${m[2]}.${m[3]}`, label: `${m[1]}.${m[2]}.${m[3]}.0/24` };
}

/** Sitove prvky znamé jen z inventare (bez skenu sluzeb): do mapy patri, ale jako "zarizeni z inventare". */
export function inventoryHosts(report: Report): Host[] {
  const known = new Set(report.hosts.flatMap((h) => [h.ip, h.host_key]));
  const out: Host[] = [];
  const typeRank = (t: string) => (/router|gateway|firewall/.test(t) ? 3 : /switch|access-point/.test(t) ? 2 : 1);
  const best = new Map<string, NetworkAsset>();
  for (const a of report.networkAssets ?? []) {
    if (!a.ip || known.has(a.ip) || (a.linked_host_key && known.has(a.linked_host_key))) continue;
    const prev = best.get(a.ip);
    if (!prev || typeRank(a.asset_type) > typeRank(prev.asset_type)) best.set(a.ip, a);
  }
  for (const [ip, a] of best) {
    out.push({
      host_id: `asset:${a.asset_id}`,
      host_key: `asset:${ip}`,
      ip,
      hostname: a.name,
      mac: a.mac ?? null,
      vendor: a.vendor ?? null,
      asset_id: a.asset_id,
      identity_note: `Zařízení je známé jen z inventáře sítě (zdroj ${a.source}), služby na něm zatím nikdo neskenoval.`,
      services: [],
    });
  }
  return out;
}

function pickGateway(report: Report, hosts: Host[]): string | null {
  const assets = report.networkAssets ?? [];
  for (const asset of assets) {
    if (/router|gateway|firewall|brana|brána/i.test(`${asset.asset_type} ${asset.name}`)) {
      const host = hosts.find((h) => h.host_key === asset.linked_host_key || (asset.ip && h.ip === asset.ip));
      if (host) return host.host_key;
    }
  }
  const named = hosts.find((h) => /(^|[-_.])(gw|gateway|router|brana)([-_.]|\d|$)/i.test(h.hostname ?? ""));
  if (named) return named.host_key;
  const dotOne = hosts.find((h) => /\.1$/.test(h.ip));
  return dotOne ? dotOne.host_key : null;
}

function parseDetails(details: string[] | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of details ?? []) {
    const i = raw.indexOf("=");
    if (i <= 0) continue;
    const v = raw.slice(i + 1).trim();
    if (v && v !== "?") out[raw.slice(0, i).trim().toLowerCase()] = v;
  }
  return out;
}

const INFRA_REL = /lldp|cdp|uplink|trunk|link/i;
const CLIENT_REL = /client_of|associated|wireless/i;
const SEEN_REL = /arp|mac_seen|fdb|learned|seen/i;

type Topo = {
  parent: Map<string, string>;
  vlan: Map<string, { id: string; name?: string }>;
  ssid: Map<string, string>;
  links: Array<{ a: string; b: string; relation: string }>;
};

function buildTopology(report: Report, hosts: Host[], kindOf: Map<string, DeviceKind>, gatewayKey: string | null): Topo {
  const topo: Topo = { parent: new Map(), vlan: new Map(), ssid: new Map(), links: [] };
  const edges: TopologyEdge[] = report.topologyEdges ?? [];
  if (!edges.length) return topo;
  const hostOfAsset = new Map<string, string>();
  for (const asset of report.networkAssets ?? []) {
    const host = hosts.find((h) => h.host_key === asset.linked_host_key || (asset.ip && h.ip === asset.ip));
    if (host) hostOfAsset.set(asset.asset_id, host.host_key);
  }
  const isInfra = (key: string) => isInfrastructure(kindOf.get(key) ?? "unknown");
  const ancestors = (key: string) => {
    const seen = new Set<string>();
    let cur: string | undefined = key;
    while (cur && !seen.has(cur)) {
      seen.add(cur);
      cur = topo.parent.get(cur);
    }
    return seen;
  };
  const setParent = (child: string, parent: string) => {
    if (child === parent || topo.parent.has(child) || ancestors(parent).has(child)) return;
    topo.parent.set(child, parent);
  };

  const infraAdj = new Map<string, Set<string>>();
  const clientEdges: Array<[string, string]> = [];
  const seenEdges: Array<[string, string]> = [];
  for (const edge of edges) {
    const a = hostOfAsset.get(edge.source_asset_id);
    const b = hostOfAsset.get(edge.target_asset_id);
    const d = parseDetails(edge.details);
    const endpoint = a && b ? (isInfra(a) && !isInfra(b) ? b : !isInfra(a) && isInfra(b) ? a : null) : (a ?? b ?? null);
    if (endpoint && d.vlan) topo.vlan.set(endpoint, { id: d.vlan, name: d.vlan_name });
    if (endpoint && d.ssid) topo.ssid.set(endpoint, d.ssid);
    if (!a || !b) continue;
    topo.links.push({ a, b, relation: edge.relation });
    if (CLIENT_REL.test(edge.relation)) clientEdges.push([a, b]);
    else if (INFRA_REL.test(edge.relation)) {
      if (!infraAdj.has(a)) infraAdj.set(a, new Set());
      if (!infraAdj.has(b)) infraAdj.set(b, new Set());
      infraAdj.get(a)!.add(b);
      infraAdj.get(b)!.add(a);
    } else if (SEEN_REL.test(edge.relation)) seenEdges.push([a, b]);
  }
  for (const [client, ap] of clientEdges) setParent(client, ap);
  // paterni stromu infrastruktury: BFS od brany (nebo od uzlu s nejvic sousedy)
  let root = gatewayKey && infraAdj.has(gatewayKey) ? gatewayKey : null;
  if (!root && infraAdj.size) root = [...infraAdj.entries()].sort((x, y) => y[1].size - x[1].size)[0][0];
  if (root) {
    const queue = [root];
    const visited = new Set([root]);
    while (queue.length) {
      const cur = queue.shift()!;
      for (const next of infraAdj.get(cur) ?? []) {
        if (visited.has(next)) continue;
        visited.add(next);
        setParent(next, cur);
        queue.push(next);
      }
    }
  }
  for (const [sw, endpoint] of seenEdges) setParent(endpoint, sw);
  return topo;
}

/** Nejmensi vzdalenost stredu zarizeni v zone v nasobcich nejvetsiho polomeru. */
export const MIN_CENTER_FACTOR = 2.6;

function pack(radii: number[], gap: number): P[] {
  const pos: P[] = [];
  for (let i = 0; i < radii.length; i += 1) {
    if (i === 0) {
      pos.push({ x: 0, y: 0 });
      continue;
    }
    const ri = radii[i];
    const pitch = Math.max(8, Math.min(radii[0], ri) * 0.9);
    let placed: P | null = null;
    for (let k = 1; k < 6000 && !placed; k += 1) {
      const a = k * 0.42;
      const d = (a / (Math.PI * 2)) * pitch + radii[0] * 0.2;
      const x = Math.cos(a) * d;
      const y = Math.sin(a) * d;
      let ok = true;
      for (let j = 0; j < i; j += 1) {
        const need = radii[j] + ri + gap;
        const dx = pos[j].x - x;
        const dy = pos[j].y - y;
        if (dx * dx + dy * dy < need * need) {
          ok = false;
          break;
        }
      }
      if (ok) placed = { x, y };
    }
    pos.push(placed ?? { x: radii[0] + ri + gap, y: 0 });
  }
  return pos;
}

type Cluster = { r: number; rel: Map<string, P> };

function layoutCluster(item: Item, kids: Map<string, Item[]>, gap: number, depth = 0): Cluster {
  const children = depth < 6 ? kids.get(item.key) ?? [] : [];
  if (!children.length) return { r: item.r, rel: new Map([[item.key, { x: 0, y: 0 }]]) };
  const subs = children.map((child) => layoutCluster(child, kids, gap, depth + 1)).sort((a, b) => b.r - a.r);
  const radii = [item.r + 4, ...subs.map((s) => s.r)];
  const pos = pack(radii, gap);
  const rel = new Map<string, P>([[item.key, { x: 0, y: 0 }]]);
  let r = item.r;
  subs.forEach((sub, i) => {
    const o = pos[i + 1];
    for (const [key, p] of sub.rel) rel.set(key, { x: p.x + o.x, y: p.y + o.y });
    r = Math.max(r, Math.hypot(o.x, o.y) + sub.r);
  });
  return { r, rel };
}

export function itemMatches(item: Item, filter: MapFilter, ignoreZones = false): boolean {
  if (!ignoreZones && filter.zones.length && !filter.zones.includes(item.zone)) return false;
  if (filter.kinds.length && !filter.kinds.includes(item.kind)) return false;
  if (filter.sev.length && !filter.sev.includes(item.sev)) return false;
  const q = filter.q.trim().toLowerCase();
  if (q) for (const token of q.split(/\s+/)) if (!item.haystack.includes(token)) return false;
  return true;
}

export function filterActive(filter: MapFilter): boolean {
  return Boolean(filter.zones.length || filter.kinds.length || filter.sev.length || filter.q.trim());
}

/** Filtr bez zon (typ, zavaznost, hledani) zpusobi zobrazeni zarizeni ve vsech zonach. */
export function attributeFilterActive(filter: MapFilter): boolean {
  return Boolean(filter.kinds.length || filter.sev.length || filter.q.trim());
}

export function buildNetModel(report: Report): NetModel {
  const synthetic = new Set(inventoryHosts(report));
  const hosts = [...report.hosts, ...synthetic].sort((a, b) => a.host_key.localeCompare(b.host_key));
  const gatewayKey = pickGateway(report, hosts);
  const classes = new Map(hosts.map((h) => [h.host_key, classifyHost(report, h)]));
  const kindOf = new Map([...classes].map(([k, c]) => [k, c.kind]));
  const topo = buildTopology(report, hosts, kindOf, gatewayKey);
  const hops = hopsOf(report, new Set(hosts.map((h) => h.ip)));
  const hopNos = new Map<string, number[]>();
  for (const hop of hops) hopNos.set(hop.asset, [...(hopNos.get(hop.asset) ?? []), hop.index]);
  const maxImp = Math.max(1, ...hosts.map((h) => hostImportance(report, h)));

  const items: Item[] = hosts.map((host) => {
    const cls = classes.get(host.host_key)!;
    const findings = hostFindings(report, host);
    const asset = assetOf(report, host);
    const results = (report.verification_results ?? []).filter((r) => r.asset === host.ip);
    let agent: AgentState | null = null;
    if (results.some((r) => r.status === "needs_approval")) agent = "waiting";
    else if (results.some((r) => r.status === "executed" || r.status === "reused")) agent = "done";
    else if (results.some((r) => r.status === "failed")) agent = "failed";
    else if (results.length) agent = "skipped";
    const imp = hostImportance(report, host) / maxImp;
    const vlan = topo.vlan.get(host.host_key);
    const services = host.services.map((s) => `${s.port} ${s.inventory.service_name} ${s.inventory.product ?? ""}`).join(" ");
    const haystack = [host.ip, host.hostname, host.vendor, host.mac, asset?.name, asset?.model, asset?.vendor, kindLabel(cls.kind), services]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
    const infra = isInfrastructure(cls.kind);
    // jednotna ctyrstupnova skala velikosti
    const step = imp < 0.15 ? 0 : imp < 0.4 ? 1 : imp < 0.7 ? 2 : 3;
    const r = [9, 11.5, 14, 16.5][Math.min(3, step + (infra ? 1 : 0))];
    return {
      host,
      key: host.host_key,
      ip: host.ip,
      kind: cls.kind,
      cls,
      asset,
      findings,
      sev: maxSeverityLevel(findings),
      risk: hostRisk(report, host),
      uncertainty: meanUncertainty(hypothesesForHost(report, host)),
      imp,
      zone: "",
      vlan: vlan?.id ?? null,
      ssid: topo.ssid.get(host.host_key) ?? null,
      parent: topo.parent.get(host.host_key) ?? null,
      children: [],
      results,
      hopNos: hopNos.get(host.ip) ?? [],
      agent,
      inventoryOnly: synthetic.has(host),
      haystack,
      r,
      x: 0,
      y: 0,
    };
  });
  const byKey = new Map(items.map((i) => [i.key, i]));
  const byIp = new Map(items.map((i) => [i.ip, i]));
  for (const item of items) if (item.parent && byKey.has(item.parent)) byKey.get(item.parent)!.children.push(item.key);
  const gateway = gatewayKey ? byKey.get(gatewayKey) ?? null : null;
  if (gateway) gateway.r = 21;

  // ---- zony: VLAN z topologie, jinak podsit; hosty bez dukazu VLAN dedi VLAN sve podsite ----
  const vlanBySubnet = new Map<string, Map<string, number>>();
  for (const item of items) {
    if (!item.vlan) continue;
    const m = vlanBySubnet.get(subnetOf(item.ip).key) ?? new Map<string, number>();
    m.set(item.vlan, (m.get(item.vlan) ?? 0) + 1);
    vlanBySubnet.set(subnetOf(item.ip).key, m);
  }
  const vlanNames = new Map<string, string>();
  for (const [key, v] of topo.vlan) if (v.name) vlanNames.set(v.id, v.name);
  const groups = new Map<string, Item[]>();
  for (const item of items) {
    if (item === gateway) continue;
    const sub = subnetOf(item.ip);
    let vlan = item.vlan;
    if (!vlan) {
      const votes = vlanBySubnet.get(sub.key);
      if (votes) vlan = [...votes.entries()].sort((a, b) => b[1] - a[1])[0][0];
    }
    item.zone = vlan ? `vlan:${vlan}` : `net:${sub.key}`;
    if (vlan) item.vlan = vlan;
    const list = groups.get(item.zone) ?? [];
    list.push(item);
    groups.set(item.zone, list);
  }
  if (gateway) gateway.zone = "gw";

  // rozestupy: stredy zarizeni ve stejne zone jsou od sebe nejmene 2,6x nejvetsi polomer
  // (mezera = 2,6 Rmax - 2 rmin zaruci d >= ri + rj + mezera >= 2,6 Rmax i u nejmensich bublin)
  const zoneRadii = items.filter((i) => i !== gateway).map((i) => i.r);
  const rMaxZone = zoneRadii.length ? Math.max(...zoneRadii) : 16.5;
  const rMinZone = zoneRadii.length ? Math.min(...zoneRadii) : 9;
  const spacingGap = Math.max(15, MIN_CENTER_FACTOR * rMaxZone - 2 * rMinZone);

  const zones: Zone[] = [...groups.entries()].map(([key, members]) => {
    const vlan = key.startsWith("vlan:") ? key.slice(5) : null;
    const subs = [...new Set(members.map((m) => subnetOf(m.ip).label))];
    const sub = subs.length === 1 ? subs[0] : `${subs[0]} a ${subs.length - 1} dalších`;
    const name = vlan ? vlanNames.get(vlan) : undefined;
    const label = vlan ? `VLAN ${vlan}${name ? ` · ${name}` : ""}` : subs[0];
    const kinds = new Map<DeviceKind, number>();
    for (const m of members) kinds.set(m.kind, (kinds.get(m.kind) ?? 0) + 1);
    // rozlozeni uvnitr zony: stromy podle skutecnych spojeni, ostatni dle vyznamu
    const inZone = new Set(members.map((m) => m.key));
    const kids = new Map<string, Item[]>();
    const roots: Item[] = [];
    for (const m of members) {
      if (m.parent && inZone.has(m.parent)) kids.set(m.parent, [...(kids.get(m.parent) ?? []), m]);
      else roots.push(m);
    }
    for (const list of kids.values()) list.sort((a, b) => b.imp - a.imp || a.key.localeCompare(b.key));
    const clusters = roots
      .map((root) => ({ root, cluster: layoutCluster(root, kids, spacingGap) }))
      .sort((a, b) => b.cluster.r - a.cluster.r || b.root.imp - a.root.imp || a.root.key.localeCompare(b.root.key));
    const pos = pack(clusters.map((c) => c.cluster.r), spacingGap);
    const rel = new Map<string, P>();
    clusters.forEach((c, i) => {
      for (const [k, p] of c.cluster.rel) rel.set(k, { x: p.x + pos[i].x, y: p.y + pos[i].y });
    });
    let minX = Infinity;
    let maxX = -Infinity;
    let minY = Infinity;
    let maxY = -Infinity;
    for (const m of members) {
      const p = rel.get(m.key)!;
      minX = Math.min(minX, p.x - m.r);
      maxX = Math.max(maxX, p.x + m.r);
      minY = Math.min(minY, p.y - m.r);
      maxY = Math.max(maxY, p.y + m.r);
    }
    const ox = (minX + maxX) / 2;
    const oy = (minY + maxY) / 2;
    let Rz = 0;
    for (const m of members) {
      const p = rel.get(m.key)!;
      m.x = p.x - ox;
      m.y = p.y - oy;
      Rz = Math.max(Rz, Math.hypot(m.x, m.y) + m.r);
    }
    const Rd = Math.max(72, Rz + 30);
    const high = members.filter((m) => m.sev === 3).length;
    return {
      key,
      label,
      sub,
      vlan,
      items: members,
      kinds,
      sevMax: Math.max(0, ...members.map((m) => m.sev)),
      withFindings: members.filter((m) => m.sev > 0).length,
      high,
      findings: members.reduce((n, m) => n + m.findings.length, 0),
      Rd,
      Rb: Math.max(36, Rd * 0.6),
      cx: 0,
      cy: 0,
    };
  });
  zones.sort((a, b) => b.items.length - a.items.length || a.key.localeCompare(b.key));

  // ---- zony ve vejiri kolem brany (nejvetsi uprostred), aby spoje z brany nikde nekrizily jine zony ----
  const order: Zone[] = [];
  zones.forEach((z, i) => (i % 2 ? order.push(z) : order.unshift(z)));
  const arrange = [...order];
  // nejvetsi do stredu: order je nyni [..., z2, z0, z1, ...]
  const span = (rho: number) => {
    let total = 0;
    for (let i = 1; i < arrange.length; i += 1) total += (arrange[i - 1].Rd + arrange[i].Rd + 56) / rho;
    return total;
  };
  let rho = Math.max(240, arrange.length ? arrange[0].Rd + 160 : 240);
  const maxSpan = (200 * Math.PI) / 180;
  while (arrange.length > 1 && span(rho) > maxSpan && rho < 20000) rho *= 1.04;
  if (arrange.length === 1) rho = INTERNET.x * -1 + arrange[0].Rd + 40;
  const minRho = arrange.length ? Math.max(...arrange.map((z) => z.Rd)) + 190 : 0;
  rho = Math.max(rho, minRho);
  {
    const total = span(rho);
    let angle = -total / 2;
    arrange.forEach((z, i) => {
      if (i > 0) angle += (arrange[i - 1].Rd + z.Rd + 56) / rho;
      z.cx = Math.cos(angle) * rho;
      z.cy = Math.sin(angle) * rho;
    });
  }
  for (const zone of zones) for (const m of zone.items) {
    m.x += zone.cx;
    m.y += zone.cy;
  }
  if (gateway) {
    gateway.x = GATE.x;
    gateway.y = GATE.y;
  }

  // hosty z cesty skoku mimo mapu: vlevo od internetu
  const outsiderIps = [...new Set(hops.filter((h) => !h.onMap).map((h) => h.asset))];
  const outsiders = outsiderIps.map((ip, i) => ({ ip, x: INTERNET.x - 84, y: (i - (outsiderIps.length - 1) / 2) * 64 + (outsiderIps.length === 1 ? 74 : 0) }));

  let minX = INTERNET.x - 84 - 90;
  let maxX = 60;
  let minY = -70;
  let maxY = 70;
  for (const z of zones) {
    minX = Math.min(minX, z.cx - z.Rd - 20);
    maxX = Math.max(maxX, z.cx + z.Rd + 20);
    minY = Math.min(minY, z.cy - z.Rd - 40);
    maxY = Math.max(maxY, z.cy + z.Rd + 34);
  }
  const bounds = { x: minX - 24, y: minY - 24, w: maxX - minX + 48, h: maxY - minY + 48 };

  return {
    runId: report.run.run_id,
    items,
    byKey,
    byIp,
    zones,
    zoneByKey: new Map(zones.map((z) => [z.key, z])),
    gateway,
    hops,
    outsiders,
    gate: GATE,
    internet: INTERNET,
    bounds,
    topology: topo.parent.size > 0,
    links: topo.links,
  };
}

/** Pro seed organickeho obrysu zony. */
export function zoneSeed(model: NetModel, zone: Zone): string {
  return `${model.runId}:${zone.key}:${hashString(zone.key)}`;
}

/** Cesta spojeni od brany ke stanici ("brana > switch > AP > klient"), jen skutecna spojeni. */
export function uplinkChain(model: NetModel, item: Item): Item[] {
  const chain: Item[] = [];
  const seen = new Set<string>();
  let cur: Item | undefined = item;
  while (cur && !seen.has(cur.key)) {
    seen.add(cur.key);
    chain.unshift(cur);
    cur = cur.parent ? model.byKey.get(cur.parent) : undefined;
  }
  return chain;
}
