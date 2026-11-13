// Metaball most: JEDNA souvisla uzavrena krivka kolem dvojice kruhu. Dva kubicke Beziery (horni a dolni
// hrana mostu) navazuji na oblouky obou kruznic s G1 spojitosti: ridici body lezi na tecne kruznice v bode
// napojeni, takze se krivka a oblouk dotykaji beze sve a bez ostre hrany. Sklo (vypln, odlesk, okraj) se
// pak aplikuje na celou cestu naraz.
import type { P } from "./pebbles";

const f2 = (v: number) => v.toFixed(2);

export type BridgeGeometry = {
  d: string;
  /** Body napojeni (v souradnicich mapy) a tecny krivky v nich, pro ciselne overeni G1. */
  joints: Array<{ at: P; curveTangent: P; circleTangent: P }>;
  neck: number;
};

/**
 * @param neck   sirka mostu uprostred (v jednotkach mapy)
 * @param maxGap volny odstup okraju kruhu, nad kterym se most prerusi (null = nikdy)
 * @param openA  true = cesta nezahrnuje kruh a (jen krcek ven z nej, uzavreny kratkym obloukem po okraji a)
 */
export function metaballBridge(a: P, ra: number, b: P, rb: number, neck: number, maxGap: number | null = null, openA = false): BridgeGeometry | null {
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  const d = Math.hypot(dx, dy);
  if (d < 1e-6 || ra <= 0 || rb <= 0) return null;
  const gap = d - ra - rb;
  if (maxGap !== null && gap > maxGap) return null;
  // zeslabeni: s rostouci mezerou se most zuzuje (nejvic na polovinu pozadovane sirky)
  const span0 = Math.max(gap, 0);
  const reach = maxGap ?? Math.max(span0, 1) * 2;
  const thin = maxGap === null ? 1 : 1 - 0.5 * Math.min(1, span0 / reach);
  const half = Math.max(0.6, (neck * thin) / 2);
  const rmin = Math.min(ra, rb);
  const sumR = ra + rb;
  // uhel napojeni phi (od osy, na obou kruzich stejny) z pozadovane sirky mostu v pulce:
  // |y_mid| = (4 (ra+rb) sin(phi) - 3 (h1+h2) cos(phi)) / 8
  const minPhi = d < sumR ? Math.acos(Math.min(1, d / sumR)) + 0.25 : 0.04;
  // Dlouhe mosty: velka rukojet by horni hranu stahla pres osu a most by se prekrizil (motylek). Rukojet se proto
  // zkracuje, dokud vsechny vzorky hrany zustavaji striktne na sve strane osy.
  let h = 0;
  let phi = minPhi;
  for (const k of [1, 0.7, 0.45, 0.25, 0.1, 0]) {
    const handle = (p: number) => k * Math.min(2.4 * rmin, 0.45 * Math.max(d - sumR * Math.cos(p), 0.1));
    const mid = (p: number) => (4 * sumR * Math.sin(p) - 6 * handle(p) * Math.cos(p)) / 8;
    let lo = minPhi;
    let hi = Math.PI / 2 - 0.02;
    phi = lo;
    if (mid(lo) < half) {
      for (let i = 0; i < 40; i += 1) {
        phi = (lo + hi) / 2;
        if (mid(phi) < half) lo = phi;
        else hi = phi;
      }
      phi = (lo + hi) / 2;
    }
    h = handle(phi);
    const cc = Math.cos(phi);
    const ss = Math.sin(phi);
    const y0 = -ra * ss;
    const y3 = -rb * ss;
    const y1 = y0 + h * cc;
    const y2 = y3 + h * cc;
    let ok = true;
    for (let i = 0; i <= 32; i += 1) {
      const u = i / 32;
      const w = 1 - u;
      const y = w * w * w * y0 + 3 * w * w * u * y1 + 3 * w * u * u * y2 + u * u * u * y3;
      if (y > -0.25) {
        ok = false;
        break;
      }
    }
    if (ok) break;
  }
  const c = Math.cos(phi);
  const s = Math.sin(phi);
  // lokalni soustava: a v pocatku, b v (d, 0), "horni" hrana ma zaporne y
  const P1u = { x: ra * c, y: -ra * s };
  const P1l = { x: ra * c, y: ra * s };
  const P2u = { x: d - rb * c, y: -rb * s };
  const P2l = { x: d - rb * c, y: rb * s };
  const Q1u = { x: P1u.x + h * s, y: P1u.y + h * c };
  const Q1l = { x: P1l.x + h * s, y: P1l.y - h * c };
  const Q2u = { x: P2u.x - h * s, y: P2u.y + h * c };
  const Q2l = { x: P2l.x - h * s, y: P2l.y - h * c };
  const ang = Math.atan2(dy, dx);
  const ca = Math.cos(ang);
  const sa = Math.sin(ang);
  const g = (p: P): P => ({ x: a.x + p.x * ca - p.y * sa, y: a.y + p.x * sa + p.y * ca });
  const t = (p: P): string => {
    const q = g(p);
    return `${f2(q.x)},${f2(q.y)}`;
  };
  const dstr = `M${t(P1u)}C${t(Q1u)} ${t(Q2u)} ${t(P2u)}A${f2(rb)},${f2(rb)} 0 1 1 ${t(P2l)}C${t(Q2l)} ${t(Q1l)} ${t(P1l)}A${f2(ra)},${f2(ra)} 0 ${openA ? "0 0" : "1 1"} ${t(P1u)}Z`;
  const dir = (from: P, to: P): P => {
    const l = Math.hypot(to.x - from.x, to.y - from.y) || 1;
    return { x: (to.x - from.x) / l, y: (to.y - from.y) / l };
  };
  const rotv = (v: P): P => ({ x: v.x * ca - v.y * sa, y: v.x * sa + v.y * ca });
  const joint = (p: P, q: P, center: P) => ({
    at: g(p),
    curveTangent: rotv(dir(p, q)),
    circleTangent: rotv({ x: -(p.y - center.y) / (Math.hypot(p.x - center.x, p.y - center.y) || 1), y: (p.x - center.x) / (Math.hypot(p.x - center.x, p.y - center.y) || 1) }),
  });
  const A0 = { x: 0, y: 0 };
  const B0 = { x: d, y: 0 };
  return { d: dstr, neck: half * 2, joints: [joint(P1u, Q1u, A0), joint(P1l, Q1l, A0), joint(P2u, Q2u, B0), joint(P2l, Q2l, B0)] };
}

/** Nejvetsi uhel (stupne) mezi tecnou krivky a tecnou kruznice ve vsech bodech napojeni. */
export function maxJointAngleDeg(g: BridgeGeometry): number {
  let worst = 0;
  for (const j of g.joints) {
    const dot = Math.abs(j.curveTangent.x * j.circleTangent.x + j.curveTangent.y * j.circleTangent.y);
    worst = Math.max(worst, (Math.acos(Math.min(1, dot)) * 180) / Math.PI);
  }
  return worst;
}
