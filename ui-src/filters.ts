// Sdilene SVG filtry (jeden skryty <svg> v kostre). Pouziva je mapa, dok i bodove cisla.
//
//  #goo        - puvodni goo pro mapu (zachovano beze zmeny, netmap.ts na nem stoji)
//  #dock-glass-light / #dock-glass-dark - "tekute sklo" pro retez bublin doku: goo tvar,
//                pak zrcadlovy odlesk (feSpecularLighting), vnitrni svetlo na hrane,
//                tenky okraj a jemny stin. Dve varianty, protoze sklo na svetlem a na tmavem
//                pozadi se musi chovat jinak (vybira se promennou --dock-filter).

const GOO_MATRIX = "1 0 0 0 0  0 1 0 0 0  0 0 1 0 0  0 0 0 20 -8";

function glass(id: string, o: { tint: string; tintA: number; rim: string; rimA: number; glow: string; glowA: number; spec: string; specK: number; shadow: string; shadowA: number; inner: string; innerA: number }) {
  return `<filter id="${id}" x="-40%" y="-2%" width="180%" height="104%" color-interpolation-filters="sRGB">
    <feGaussianBlur in="SourceAlpha" stdDeviation="5.5" result="blur"/>
    <feColorMatrix in="blur" type="matrix" values="0 0 0 0 0  0 0 0 0 0  0 0 0 0 0  0 0 0 24 -10" result="shape"/>
    <feGaussianBlur in="shape" stdDeviation="1.6" result="soft"/>
    <feFlood flood-color="${o.tint}" flood-opacity="${o.tintA}"/>
    <feComposite in2="shape" operator="in" result="body"/>
    <feGaussianBlur in="shape" stdDeviation="7" result="wide"/>
    <feComposite in="shape" in2="wide" operator="arithmetic" k1="0" k2="1.35" k3="-1.1" k4="0" result="edge"/>
    <feFlood flood-color="${o.glow}" flood-opacity="${o.glowA}"/>
    <feComposite in2="edge" operator="in" result="glow"/>
    <feSpecularLighting in="soft" surfaceScale="6" specularConstant="${o.specK}" specularExponent="26" lighting-color="${o.spec}" result="specular">
      <feDistantLight azimuth="-70" elevation="52"/>
    </feSpecularLighting>
    <feComposite in="specular" in2="shape" operator="in" result="shine"/>
    <feOffset in="shape" dx="0" dy="-4" result="up"/>
    <feGaussianBlur in="up" stdDeviation="1.5" result="upSoft"/>
    <feComposite in="shape" in2="upSoft" operator="out" result="lowBand"/>
    <feFlood flood-color="${o.inner}" flood-opacity="${o.innerA}"/>
    <feComposite in2="lowBand" operator="in" result="lowShade"/>
    <feMorphology in="shape" operator="erode" radius="1" result="inner"/>
    <feComposite in="shape" in2="inner" operator="out" result="rimMask"/>
    <feFlood flood-color="${o.rim}" flood-opacity="${o.rimA}"/>
    <feComposite in2="rimMask" operator="in" result="rim"/>
    <feGaussianBlur in="shape" stdDeviation="3" result="shBlur"/>
    <feOffset in="shBlur" dx="0" dy="3" result="shOff"/>
    <feFlood flood-color="${o.shadow}" flood-opacity="${o.shadowA}"/>
    <feComposite in2="shOff" operator="in" result="shadow"/>
    <feMerge>
      <feMergeNode in="shadow"/>
      <feMergeNode in="body"/>
      <feMergeNode in="lowShade"/>
      <feMergeNode in="glow"/>
      <feMergeNode in="shine"/>
      <feMergeNode in="rim"/>
    </feMerge>
  </filter>`;
}

export const FILTER_DEFS = `<svg class="goo-defs" aria-hidden="true" focusable="false"><defs>
  <filter id="goo" x="-20%" y="-20%" width="140%" height="140%" color-interpolation-filters="sRGB"><feGaussianBlur in="SourceGraphic" stdDeviation="5" result="blur"/><feColorMatrix in="blur" mode="matrix" values="${GOO_MATRIX}" result="goo"/><feBlend in="SourceGraphic" in2="goo"/></filter>
  ${glass("dock-glass-light", { tint: "#ffffff", tintA: 0.46, rim: "#3a362c", rimA: 0.3, glow: "#ffffff", glowA: 0.9, spec: "#ffffff", specK: 1.1, shadow: "#2a261c", shadowA: 0.2, inner: "#6b6554", innerA: 0.32 })}
  ${glass("dock-glass-dark", { tint: "#e9e6dc", tintA: 0.05, rim: "#f4f1e6", rimA: 0.38, glow: "#f4f1e6", glowA: 0.16, spec: "#ffffff", specK: 0.5, shadow: "#000000", shadowA: 0.55, inner: "#000000", innerA: 0.45 })}
</defs></svg>`;
