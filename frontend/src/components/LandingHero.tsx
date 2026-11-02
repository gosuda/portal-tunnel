import { useEffect, useId, useRef, useState } from "react";
import { ArrowRight, BookOpen, Zap } from "lucide-react";
import { TunnelCommandModal } from "@/components/TunnelCommandModal";

// 360x180 equirectangular landmask (1° cells, rows north to south, columns
// west to east), rasterized from Natural Earth 1:50m land polygons (public
// domain, naturalearthdata.com) with 4x4 supersampling; a cell is land at
// >= 25% coverage.
const WORLD_LANDMASK_B64 =
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADf/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD///8PX////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE////3////////AAAAAAAAAAAECAAAAhAAAAAAAAAAAAAAAAAAAAAAAAAAAA////9////////4AAAAA74AAH4+2AAQAPgAAAAAAAAAAAAAAAAAAAAAAAAAGA////A////////AAAAB//4AAAAAAAAAAf9gAAAAAAAAAAAAAAAAAAAAAAAcHzv//5////////8AAAAA/+AAAAAAAAAAAAf4AAAAAAAAAAAAAAAAAAAAAAd8IBxP/A////////+AAAAAPHAAAAAAAAAAAAA4AAAAAAAAAAAAAAAAAAAAAH/jG9///AP////////AAAAACAAAAAAAf4AAAAP/+AAAAAAAAAAAAAAAAAAAAAX/1/3/8AAAf//////AAAAAAAAAAAAP+AAAH////AAAB/vAAAAAAAAAAAAAAfQ8AA7/8AAAH/////8AAAAAAAAAAAAfAAAAP///+AAAAoDAAAAAAAAAAAAAAf+A4e+f/gAAD/////4AAAAAAAAAAAB8ACAP/////+HwAGAAAAAAAAAAAAAAA///5/8//4AAD/////wAAAAAAAAAAADwAHl////////4Af2AAAAAwAABAAAAAff/8P4///gAD/////wAAAAAAAAAAAHwAff////////8///gAAABAAA//8AACAP//B8f//8AB/////wAAAAAAD/gAAA7Afv/////////////8AAAAAD///+P//n//n+D5/+AB/////gAAAAAB///AAwA+f////////////////v+4Af/////////6Hfzwf+AAf///8AAAAAAP///4MP///v/////////////////+AH/////////////45/wA///4AAAAAAAP///+M////v//////////////////8M/////////////wD/8A///wAQYAAAAf///////////////////////////f4//////////////A/+YAf/6AA/8AAAA///+D///////////////////////Bgf/////////////w//gAP/wAA/8AAAD/4//f//////////////////////+AEB////////////HIA/wAP/gAAHgAAAP/z/////////////////////////+AAP///////////8Ay+fAAH/AAAAAAAB//H/////////////////////////+AAP///////////wAA/gAAB/AAAAAAAB/+H//////////////////////3//AAAX//3////////wAA/4AAAuAAAAAAAB//H//////////////////////A/4AAAA/7AH///////gAA/4wAAAAAAAAAAB//g/////////////////////+DgAAAAAr8AA///////4AB//4AAAAAAAABYB5+D///////////////////8AAPgAAAAAH4AAP//////8AAf/8AAAAAAAAB8AE+m///////////////////wAA/gAAAAAMAAAH///////wCf/+AAAAAAAAA4AO+H///////////////////AAB/gAAAABwAAAD////////g///gAAAAAAAB+AP4H//////////////////+AAB/AAAAAGAAAABf///////z///4AAAAAAAPfAP3////////////////////QAB/AAAABQAAAABP///////x///8AAAAAAAPPB//////////////////////6AA8AAAAAAAAAAAH///////5///8AAAAAAAPfz//////////////////////+AA4AAAAAAAAAAAD///////////8AAAAAAAIfn///////////////////////AAwAAAAAAAAAAAD///////////sAAAAAAAAff//////////////////////7ABAAAAAAAAAAAAB/////////+sPAAAAAAAAD///////////////////////7AAAAAAAAAAAAAAAf/////////wfgAAAAAAAf///////////////////////yAAAAAAAAAAAAAAAf/////////gfgAAAAAAAP///////////////////////iAAAAAAAAAAAAAAAP//////////AAAAAAAAAD//////v/x//////////////GAAAAAAAAAAAAAAAP/////////+AAAAAAAAAD/////H//H/////////////+EAAAAAAAAAAAAAAAf////////+4AAAAAAAAAD//n/+Gf+P/////////////8HAAAAAAAAAAAAAAAf////////wgAAAAAAAAH//jz/+AH/H/////////////4HgAAAAAAAAAAAAAAf////////gAAAAAAAAAH/4Nw/8AB/D////////////+AfAAAAAAAAAAAAAAAf////////wAAAAAAAAAH/4A8f/fh/i////////////8AIAAAAAAAAAAAAAAAf///////+AAAAAAAAAAH/gMPfP///z///////////v4AMAAAAAAAAAAAAAAAP///////8AAAAAAAAAAP/IMCOP///h//////////+dwAMAAAAAAAAAAAAAAAP///////4AAAAAAAAAAH/AAGHP///h//////////8B4AcAAAAAAAAAAAAAAAH///////wAAAAAAAAAAH+AE4GH///x///////////44A4AAAAAAAAAAAAAAAD///////wAAAAAAAAAAB4/+ACD///////////////g8D4AAAAAAAAAAAAAAAB///////wAAAAAAAAAAA7/+AAwF//////////////A8/4AAAAAAAAAAAAAAAB///////gAAAAAAAAAAB//+AAAJ//////////////Ax/AAAAAAAAAAAAAAAAAP/////+AAAAAAAAAAAH//+AAAB//////////////gD0AAAAAAAAAAAAAAAAAP/////8AAAAAAAAAAAP///4OAB//////////////gDAAAAAAAAAAAAAAAAAAH/////4AAAAAAAAAAAP///+P8z//////////////wCAAAAAAAAAAAAAAAAAADf////4AAAAAAAAAAAP/////////////////////wAAAAAAAAAAAAAAAAAAADf///g4AAAAAAAAAAAf/////////P///////////wAAAAAAAAAAAAAAAAAAABv//AAYAAAAAAAAAAA//////////n///////////wAAAAAAAAAAAAAAAAAAAB3/+AAcAAAAAAAAAAD///////9//j///////////gAAAAAAAAAAAAAAAAAAAA7/+AAMAAAAAAAAAAD///////8//w3//////////AAAAAAAAAAAAAAAAAAAAAZ/+AAMAAAAAAAAAAH///////+f/8b//////////AAAAAAAAAAAAAAAAAAAAAM/+AABAAAAAAAAAAP///////+f/84Af///////+wAAAAAAAAAAAAAAAAAAAAGf8AAAAAAAAAAAAAP////////P//+AP///////4wAAAAAAAAAAAAAAAAAAAAAP8AB+AAAAAAAAAAf////////n///AH///////wgAAAAAAAAAAAAAAAAAAAAAP+A4DwAAAAAAAAAf////////n//+AH//+P//8AAAAAAAAAAAAAAAAAAAAAAAP+B4A8AAAAAAAAAf////////n//+AA//4P/+QAAAAAAAAAAAAAAAgAAAAAAAH/B4ABwAAAAAAAAf////////j//8AA//gH/84AAAAAAAAAAAAAAAAAAAAAAAD//wAj9AAAAAAAAf////////x//4AA//AD/8wAwAAAAAAAAAAAAAAAAAAAAAA//wAgAAAAAAAAAf////////4//wAAf+AD/+AAwAAAAAAAAAAAAAAAAAAAAAAP/wAAAAAAAAAAAf////////4/+AAAf8AD//AAwAAAAAAAAAAAAAAAAAAAAAABP/AAAAAAAAAAAf////////8/8AAAf4AAf/gAwAAAAAAAAAAAAAAAAAAAAAAAH/gAAAAAAAAAAf////////+fwAAAPwAAP/gAwAAAAAAAAAAAAAAAAAAAAAAAA/gAAAAAAAAAAf/////////eAAAAPwAAP/wA8AAAAAAAAAAAAAAAAAAAAAAAAPgAgAAAAAAAAf/////////4BAAAHwAAN/gAWAAAAAAAAAAAAAAAAAAAAAAAAHADYAAAAAAAAP/////////g4AAAHwAAMfgALAAAAAAAAAAAAAAAAAAAAAAAADgP/eAAAAAAAH//////////4AAADwAAIfABOAAAAAAAAAAAAAAAAAAAAAAAABzP/+AAAAAAAD//////////4AAADoAAMEACPAAAAAAAAAAAAAAAAAAAAAAAAA9///AAAAAAAB//////////wAAABYAAMAAAHAAAAAAAAAAAAAAAAAAAAAAAAAN///wAAAAAAB//////////wAAAAcAAGAAAPgAAAAAAAAAAAAAAAAAAAAAAAAA///4AAAAAAAf/////////gAAAAMAAHAAMDAAAAAAAAAAAAAAAAAAAAAAAAAA////gAAAAAAP/B///////gAAAAAABjgAeAAAAAAAAAAAAAAAAAAAAAAAAAAA////4AAAAAAGAB///////AAAAAAABzwA8AAAAAAAAAAAAAAAAAAAAAAAAAAA////4AAAAAAAAAH/////+AAAAAAAA9wB8AAAAAAAAAAAAAAAAAAAAAAAAAAB////4AAAAAAAAAH/////8AAAAAAAAfwH8AAAAAAAAAAAAAAAAAAAAAAAAAAB////8AAAAAAAAAH/////4AAAAAAAAfwf+CYAAAAAAAAAAAAAAAAAAAAAAAAD////8AAAAAAAAAH/////gAAAAAAAAHwf8+QAAAAAAAAAAAAAAAAAAAAAACAH/////gAAAAAAAAH/////gAAAAAAAADwf9ITwAAAAAAAAAAAAAAAAAAAAAAAH/////4AAAAAAAAH/////AAAAAAAAAL8f55RxAAAAAAAAAAAAAAAAAAAAAAAH//////QAAAAAAAH////+AAAAAAAAAB/P5wI74AAAAAAAAAAAAAAAAAAAAAAH//////4AAAAAAAD////8AAAAAAAAAA8D54u//AAAAAAAAAAAAAAAAAAAAAAP//////+AAAAAAAB////8AAAAAAAAAAcAB4AH/wYAAAAAAAAAAAAAAAAAAAAH///////gAAAAAAA////4AAAAAAAAAAMABIAA/7yAAAAAAAAAAAAAAAAAAAAH///////gAAAAAAA////4AAAAAAAAAAHsAAAI/8BAAAAAAAAAAAAAAAAAAAAD///////gAAAAAAAf///8AAAAAAAAAAD/AABA/4AAAAAAAAAAAAAAAAAAAAAB///////gAAAAAAAf///8AAAAAAAAAAAH+xgBvMACAAAAAAAAAAAAAAAAAAAB///////gAAAAAAAf///8AAAAAAAAAAAABHAAGHgCAAAAAAAAAAAAAAAAAAAA///////AAAAAAAAf///+AAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAA//////+AAAAAAAAf///+AAAAAAAAAAAAAACgCAAAAAAAAAAAAAAAAAAAAAAAf/////8AAAAAAAAf///+AQAAAAAAAAAAAAD+GAAAAAAAAAAAAAAAAAAAAAAAf/////4AAAAAAAA////+AwAAAAAAAAAAAAD+HAAAAAAAAAAAAAAAAAAAAAAAP/////4AAAAAAAA////+BwAAAAAAAAAAAB38HgAAAAAAAAAAAAAAAAAAAAAAH/////4AAAAAAAA////+D4AAAAAAAAAAAD/+HwAACAAAAAAAAAAAAAAAAAAAD/////4AAAAAAAB////8PwAAAAAAAAAAAH//HwAAAABAAAAAAAAAAAAAAAAAA/////4AAAAAAAB////wPwAAAAAAAAAAAP///wAAAAGAAAAAAAAAAAAAAAAAAf////4AAAAAAAA////gPgAAAAAAAAAAAf///wAAAAAAAAAAAAAAAAAAAAAAAf////wAAAAAAAA///+APgAAAAAAAAAAA////8AAAAAAAAAAAAAAAAAAAAAAAf////wAAAAAAAAf//+APgAAAAAAAAAAH////+AAIAAAAAAAAAAAAAAAAAAAAf////gAAAAAAAAf//+AfAAAAAAAAAAAf////+AAEAAAAAAAAAAAAAAAAAAAAf////AAAAAAAAAP///AfAAAAAAAAAAB//////gAAAAAAAAAAAAAAAAAAAAAAf///4AAAAAAAAAP///AfAAAAAAAAAAB//////gAAAAAAAAAAAAAAAAAAAAAAf///gAAAAAAAAAP//+AeAAAAAAAAAAB//////wAAAAAAAAAAAAAAAAAAAAAAf///AAAAAAAAAAP//4AMAAAAAAAAAAB//////4AAAAAAAAAAAAAAAAAAAAAAf///AAAAAAAAAAH//4AAAAAAAAAAAAB//////4AAAAAAAAAAAAAAAAAAAAAAf///AAAAAAAAAAH//4AAAAAAAAAAAAA//////4AAAAAAAAAAAAAAAAAAAAAA///+AAAAAAAAAAD//4AAAAAAAAAAAAA//////8AAAAAAAAAAAAAAAAAAAAAA///8AAAAAAAAAAB//gAAAAAAAAAAAAA//////8AAAAAAAAAAAAAAAAAAAAAA///8AAAAAAAAAAB//gAAAAAAAAAAAAAf/////4AAAAAAAAAAAAAAAAAAAAAA///wAAAAAAAAAAA//AAAAAAAAAAAAAAf/////4AAAAAAAAAAAAAAAAAAAAAA///wAAAAAAAAAAA/+AAAAAAAAAAAAAAf/gf//wAAAAAAAAAAAAAAAAAAAAAA///gAAAAAAAAAAA/4AAAAAAAAAAAAAAf8AP//wAAAAAAAAAAAAAAAAAAAAAA///AAAAAAAAAAAAcAAAAAAAAAAAAAAAeAAF//gAAAAAAAAAAAAAAAAAAAAAB//4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB//gAABgAAAAAAAAAAAAAAAAAB//4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAf/AAAAgAAAAAAAAAAAAAAAAAD//4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP/AAAAwAAAAAAAAAAAAAAAAAD//wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHYAAAA8AAAAAAAAAAAAAAAAAD/8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4AAAAAAAAAAAAAAAAAD/8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACYAAAAAAAAAAAAAAAAAD/gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+AAAHQAAAAAAAAAAAAAAAAAH/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcAAAHAAAAAAAAAAAAAAAAAAD/gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAeAAAAAAAAAAAAAAAAAAH/gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB4AAAAAAAAAAAAAAAAAAH+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD4AAAAAAAAAAAAAAAAAAP+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAAAAAAAAAAH/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP8AAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH4BwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB+AAAAAAAAAAAAAAAAAAP4AAAAD///vgPn/8AAAAAAAAAAAAAAAAAAAAAAAAHgAAAAAAAAAAAAAAAAAH///wAH//////////wAAAAAAAAAAAAAAAAAAAAAAADwAAAAAAAAAAAAAAAED////8A////////////+AAAAAAAAAAAAAAAAAAAAAB/8AAAAAAAAAAAAAAAP3////4P/////////////8AAAAAAAAAAAAAAAAAAAAM/8AAAAAAAADEH//nL//////5//////////////++AAAAAAAAAAAAAAAAAAAP/+AAAAAAAA/////////////x////////////////4AAAAAAAAAAAAAB/CgAB7/AAAAAAAD/////////////v////////////////wAAAAAAAAABmgAB///////AAAAAAAf//////////////////////////////AAAAAAAAAPn//cA//////+AAAAAAA//////////////////////////////4AAAAAAAB/////////////4AAAAAB///////////////////////////////gAAAAAAAf////////////8AAAAAB////////////////////////////////gAAAAAH/////////////+AAAAwAf////////////////////////////////zAAAABB/////////////AOAAD8A/////////////////////////////////+AAAADwD////////////w7BAH+AP///////////////////////////////+AAAAAAAA////////////4wXA/8A////////////////////////////////8AAAAADA///////////////4AAB//////////////////////////////////AAAAAAAf//////////////8H////////////////////////////////////+AAAP/////////////////////////////////////////////////////////g////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////";

interface SpherePoint {
  lat: number;
  lon: number;
  cosLat: number;
  sinLat: number;
  coastal: boolean;
}

const GLOBE_LAND_POINTS: ReadonlyArray<SpherePoint> = (() => {
  const binary =
    typeof atob === "function"
      ? atob(WORLD_LANDMASK_B64)
      : "";
  if (!binary) {
    return [];
  }

  const cols = 360;
  const rows = 180;
  const isLandCell = (r: number, c: number): boolean => {
    if (r < 0 || r >= rows) return false;
    const wrappedCol = ((c % cols) + cols) % cols;
    const bitIndex = r * cols + wrappedCol;
    const byteIndex = bitIndex >> 3;
    const bitOffset = 7 - (bitIndex & 7);
    return ((binary.charCodeAt(byteIndex) >> bitOffset) & 1) === 1;
  };

  const sampleLand = (latDeg: number, lonDeg: number): { land: boolean; coastal: boolean } => {
    const r = Math.floor(90 - latDeg);
    const c = Math.floor(lonDeg + 180);
    const land = isLandCell(r, c);
    if (!land) return { land: false, coastal: false };
    const coastal =
      !isLandCell(r - 1, c) ||
      !isLandCell(r + 1, c) ||
      !isLandCell(r, c - 1) ||
      !isLandCell(r, c + 1);
    return { land: true, coastal };
  };

  const points: SpherePoint[] = [];
  // Uniform spherical lattice: latitude rings every 2°, longitude steps scaled by cos(lat)
  for (let latDeg = -84; latDeg <= 84; latDeg += 2) {
    const lat = (latDeg * Math.PI) / 180;
    const cosLat = Math.cos(lat);
    const sinLat = Math.sin(lat);
    const ringSteps = Math.max(12, Math.round(180 * cosLat));
    for (let i = 0; i < ringSteps; i += 1) {
      const lonDeg = -180 + (i / ringSteps) * 360;
      const { land, coastal } = sampleLand(latDeg, lonDeg);
      if (land) {
        points.push({
          lat,
          lon: (lonDeg * Math.PI) / 180,
          cosLat,
          sinLat,
          coastal,
        });
      }
    }
  }
  return points;
})();

// Stars sit in the full-width backdrop; coordinates are in the 1672x360 band.
const STARS: ReadonlyArray<{ cx: number; cy: number; r: number; o: number }> = [
  { cx: 68, cy: 42, r: 0.9, o: 0.45 },
  { cx: 142, cy: 76, r: 0.7, o: 0.35 },
  { cx: 295, cy: 38, r: 0.8, o: 0.4 },
  { cx: 468, cy: 62, r: 0.9, o: 0.45 },
  { cx: 582, cy: 28, r: 0.7, o: 0.35 },
  { cx: 695, cy: 84, r: 1.0, o: 0.5 },
  { cx: 786, cy: 46, r: 0.8, o: 0.4 },
  { cx: 862, cy: 112, r: 0.9, o: 0.45 },
  { cx: 914, cy: 152, r: 1.1, o: 0.65 },
  { cx: 954, cy: 68, r: 0.8, o: 0.5 },
  { cx: 1012, cy: 124, r: 1.2, o: 0.7 },
  { cx: 1048, cy: 82, r: 0.9, o: 0.55 },
  { cx: 1082, cy: 44, r: 1.0, o: 0.6 },
  { cx: 1384, cy: 52, r: 1.1, o: 0.65 },
  { cx: 1446, cy: 78, r: 0.8, o: 0.45 },
  { cx: 1518, cy: 192, r: 1.0, o: 0.55 },
  { cx: 1564, cy: 128, r: 0.8, o: 0.4 },
  { cx: 1612, cy: 224, r: 0.9, o: 0.5 },
  { cx: 966, cy: 298, r: 0.8, o: 0.45 },
  { cx: 1054, cy: 318, r: 1.0, o: 0.55 },
];

// The globe stage is a 740x360 box whose SVG layers use the viewBox
// "860 0 740 360", so beam and ring coordinates are in band units.
const STAGE_VIEWBOX = "860 0 740 360";

const OUTGOING_BEAMS: ReadonlyArray<{
  d: string;
  nx: number;
  ny: number;
  tone: "accent" | "accent-2";
  delay: string;
}> = [
  { d: "M 1166,180 Q 1206,120 1264,95", nx: 1264, ny: 95, tone: "accent", delay: "0s" },
  { d: "M 1170,185 Q 1264,112 1388,128", nx: 1388, ny: 128, tone: "accent-2", delay: "0.4s" },
  { d: "M 1172,191 Q 1252,148 1330,174", nx: 1330, ny: 174, tone: "accent", delay: "0.8s" },
  { d: "M 1172,198 Q 1295,192 1418,278", nx: 1418, ny: 278, tone: "accent-2", delay: "0.2s" },
  { d: "M 1170,204 Q 1258,216 1338,286", nx: 1338, ny: 286, tone: "accent", delay: "0.6s" },
  { d: "M 1166,210 Q 1206,224 1246,252", nx: 1246, ny: 252, tone: "accent", delay: "1.0s" },
];

// rgb(var(--stage-<token>) / alpha), for SVG styles and Tailwind arbitrary values.
const stage = (token: string, alpha = 1) => `rgb(var(--stage-${token}) / ${alpha})`;

interface StagePalette {
  accent: string;
  accent2: string;
  accent3: string;
  highlight: string;
  ocean: [string, string, string, string];
  glow: number;
}

function readStagePalette(element: Element): StagePalette {
  const style = getComputedStyle(element);
  const read = (token: string) => style.getPropertyValue(`--stage-${token}`).trim();
  return {
    accent: read("accent"),
    accent2: read("accent-2"),
    accent3: read("accent-3"),
    highlight: read("highlight"),
    ocean: [read("ocean-1"), read("ocean-2"), read("ocean-3"), read("ocean-4")],
    glow: Number(read("glow")) || 1,
  };
}

const rgba = (rgb: string, alpha: number) => `rgb(${rgb} / ${alpha})`;

function prefersReducedMotion() {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function RotatingGlobe3DCanvas({ className }: { className?: string }) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const width = 420;
    const height = 360;
    canvas.width = width * dpr;
    canvas.height = height * dpr;

    const cx = 196;
    const cy = 195;
    const R = 154;

    // Axial tilt: pitch -16°, roll +9°.
    const pitch = (-16 * Math.PI) / 180;
    const roll = (9 * Math.PI) / 180;
    const cosPitch = Math.cos(pitch);
    const sinPitch = Math.sin(pitch);
    const cosRoll = Math.cos(roll);
    const sinRoll = Math.sin(roll);

    let palette = readStagePalette(canvas);

    const project3D = (lat: number, lon: number) => {
      const cosLat = Math.cos(lat);
      const x0 = cosLat * Math.sin(lon);
      const y0 = -Math.sin(lat);
      const z0 = cosLat * Math.cos(lon);
      const y1 = y0 * cosPitch - z0 * sinPitch;
      const z1 = y0 * sinPitch + z0 * cosPitch;
      const x2 = x0 * cosRoll - y1 * sinRoll;
      const y2 = x0 * sinRoll + y1 * cosRoll;
      // Mild perspective so the front hemisphere bulges toward the viewer.
      const perspective = 1 + z1 * 0.12;
      return { x: cx + x2 * R * perspective, y: cy + y2 * R * perspective, nx: x2, ny: y2, nz: z1 };
    };

    const drawOrbitHalf = (
      front: boolean,
      tiltX: number,
      tiltZ: number,
      orbitRadius: number,
      timeSec: number,
      color: string
    ) => {
      const steps = 96;
      const cX = Math.cos(tiltX);
      const sX = Math.sin(tiltX);
      const cZ = Math.cos(tiltZ);
      const sZ = Math.sin(tiltZ);
      const toScreen = (theta: number) => {
        const ox = Math.cos(theta) * orbitRadius;
        const oz = Math.sin(theta) * orbitRadius;
        const oy1 = -oz * sX;
        return {
          x: cx + ox * cZ - oy1 * sZ,
          y: cy + ox * sZ + oy1 * cZ,
          isFront: oz * cX >= 0,
        };
      };

      ctx.save();
      ctx.beginPath();
      let started = false;
      for (let i = 0; i <= steps; i += 1) {
        const p = toScreen((i / steps) * Math.PI * 2);
        if (p.isFront === front) {
          if (started) ctx.lineTo(p.x, p.y);
          else ctx.moveTo(p.x, p.y);
          started = true;
        } else {
          started = false;
        }
      }
      ctx.strokeStyle = rgba(color, front ? 0.42 : 0.14);
      ctx.lineWidth = front ? 1.25 : 0.8;
      ctx.stroke();

      // A satellite pulse travels along the ring.
      const sat = toScreen(timeSec * 0.85 + (tiltZ > 0 ? 1.2 : 3.9));
      if (sat.isFront === front) {
        const grad = ctx.createRadialGradient(sat.x, sat.y, 0, sat.x, sat.y, 8);
        grad.addColorStop(0, rgba(palette.highlight, front ? 0.95 : 0.25));
        grad.addColorStop(0.35, rgba(palette.accent, front ? 0.95 : 0.25));
        grad.addColorStop(1, rgba(palette.accent, 0));
        ctx.fillStyle = grad;
        ctx.beginPath();
        ctx.arc(sat.x, sat.y, 8, 0, Math.PI * 2);
        ctx.fill();
      }
      ctx.restore();
    };

    const drawGraticule = (rotationLon: number) => {
      ctx.lineWidth = 0.75;
      ctx.strokeStyle = rgba(palette.accent, 0.13);
      const strokeVisible = (points: Array<{ x: number; y: number; nz: number }>) => {
        ctx.beginPath();
        let drawing = false;
        for (const p of points) {
          if (p.nz >= 0) {
            if (drawing) ctx.lineTo(p.x, p.y);
            else ctx.moveTo(p.x, p.y);
            drawing = true;
          } else {
            drawing = false;
          }
        }
        ctx.stroke();
      };
      for (let m = 0; m < 12; m += 1) {
        const lon = rotationLon + (m * Math.PI) / 6;
        const points = [];
        for (let lat = -80; lat <= 80; lat += 8) points.push(project3D((lat * Math.PI) / 180, lon));
        strokeVisible(points);
      }
      for (let lat = -60; lat <= 60; lat += 30) {
        const points = [];
        for (let lon = 0; lon <= 360; lon += 8) {
          points.push(project3D((lat * Math.PI) / 180, rotationLon + (lon * Math.PI) / 180));
        }
        strokeVisible(points);
      }
    };

    let lastTime = 0;
    const renderFrame = (timeMs: number) => {
      lastTime = timeMs;
      const timeSec = timeMs * 0.001;
      const rotationLon = 0.32 + timeSec * 0.24;
      const { accent, accent2, accent3, highlight, ocean, glow } = palette;

      ctx.save();
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, width, height);

      // Orbital rings behind the sphere.
      drawOrbitHalf(false, 1.18, -0.28, R * 1.16, timeSec, accent2);
      drawOrbitHalf(false, 1.26, 0.36, R * 1.09, -timeSec * 0.8, accent3);

      // Atmospheric corona.
      const corona = ctx.createRadialGradient(cx - 12, cy - 8, R * 0.72, cx, cy, R * 1.24);
      corona.addColorStop(0, rgba(accent, 0.22 * glow));
      corona.addColorStop(0.55, rgba(accent2, 0.24 * glow));
      corona.addColorStop(0.8, rgba(accent3, 0.14 * glow));
      corona.addColorStop(1, rgba(accent3, 0));
      ctx.fillStyle = corona;
      ctx.beginPath();
      ctx.arc(cx, cy, R * 1.24, 0, Math.PI * 2);
      ctx.fill();

      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, Math.PI * 2);
      ctx.clip();

      // Ocean, lit from the upper left where the portal sits.
      const sphere = ctx.createRadialGradient(
        cx - R * 0.38, cy - R * 0.24, R * 0.06,
        cx + R * 0.1, cy + R * 0.12, R * 1.08
      );
      sphere.addColorStop(0, rgba(ocean[0], 1));
      sphere.addColorStop(0.34, rgba(ocean[1], 1));
      sphere.addColorStop(0.68, rgba(ocean[2], 1));
      sphere.addColorStop(1, rgba(ocean[3], 1));
      ctx.fillStyle = sphere;
      ctx.fillRect(cx - R, cy - R, R * 2, R * 2);

      // Reflection on the eastern limb.
      const limb = ctx.createRadialGradient(
        cx + R * 0.55, cy - R * 0.15, R * 0.05,
        cx + R * 0.45, cy - R * 0.05, R * 0.9
      );
      limb.addColorStop(0, rgba(accent3, 0.34 * glow));
      limb.addColorStop(0.6, rgba(accent3, 0.14 * glow));
      limb.addColorStop(1, rgba(accent3, 0));
      ctx.fillStyle = limb;
      ctx.fillRect(cx - R, cy - R, R * 2, R * 2);

      // Back hemisphere land, faintly visible through the sphere.
      ctx.fillStyle = rgba(accent3, 0.17);
      ctx.beginPath();
      for (const pt of GLOBE_LAND_POINTS) {
        const lon = pt.lon + rotationLon;
        const x0 = pt.cosLat * Math.sin(lon);
        const y0 = -pt.sinLat;
        const z0 = pt.cosLat * Math.cos(lon);
        const y1 = y0 * cosPitch - z0 * sinPitch;
        const z1 = y0 * sinPitch + z0 * cosPitch;
        if (z1 < -0.05) {
          const x2 = x0 * cosRoll - y1 * sinRoll;
          const y2 = x0 * sinRoll + y1 * cosRoll;
          const perspective = 1 + z1 * 0.12;
          const sx = cx + x2 * R * perspective;
          const sy = cy + y2 * R * perspective;
          ctx.moveTo(sx + 0.85, sy);
          ctx.arc(sx, sy, 0.85, 0, Math.PI * 2);
        }
      }
      ctx.fill();

      drawGraticule(rotationLon);

      // Front hemisphere land, tinted by distance to the portal light.
      for (const pt of GLOBE_LAND_POINTS) {
        const lon = pt.lon + rotationLon;
        const x0 = pt.cosLat * Math.sin(lon);
        const y0 = -pt.sinLat;
        const z0 = pt.cosLat * Math.cos(lon);
        const y1 = y0 * cosPitch - z0 * sinPitch;
        const z1 = y0 * sinPitch + z0 * cosPitch;
        if (z1 < 0) continue;
        const x2 = x0 * cosRoll - y1 * sinRoll;
        const y2 = x0 * sinRoll + y1 * cosRoll;
        const perspective = 1 + z1 * 0.12;
        const sx = cx + x2 * R * perspective;
        const sy = cy + y2 * R * perspective;
        const portalLight = Math.max(0, -x2 * 0.55 - y2 * 0.1 + z1 * 0.82);
        const radius = (pt.coastal ? 1.15 : 0.95) + z1 * 0.55 + portalLight * 0.25;
        const alpha = Math.min(1, 0.35 + z1 * 0.55 + (pt.coastal ? 0.18 : 0));
        const tone = portalLight > 0.58 ? accent : x2 < 0.18 ? accent2 : accent3;
        ctx.fillStyle = rgba(tone, alpha);
        ctx.beginPath();
        ctx.arc(sx, sy, radius, 0, Math.PI * 2);
        ctx.fill();
      }

      // Fresnel rim and specular highlight.
      const fresnel = ctx.createRadialGradient(cx, cy, R * 0.7, cx, cy, R);
      fresnel.addColorStop(0, rgba(accent2, 0));
      fresnel.addColorStop(0.76, rgba(accent2, 0.08 * glow));
      fresnel.addColorStop(0.93, rgba(accent, 0.32 * glow));
      fresnel.addColorStop(1, rgba(accent3, 0.68 * glow));
      ctx.fillStyle = fresnel;
      ctx.fillRect(cx - R, cy - R, R * 2, R * 2);

      const spec = ctx.createRadialGradient(cx - R * 0.45, cy - R * 0.45, 0, cx - R * 0.45, cy - R * 0.45, R * 0.65);
      spec.addColorStop(0, rgba(highlight, 0.22));
      spec.addColorStop(0.45, rgba(accent, 0.08));
      spec.addColorStop(1, rgba(accent, 0));
      ctx.fillStyle = spec;
      ctx.fillRect(cx - R, cy - R, R * 2, R * 2);
      ctx.restore();

      // Crisp outer rim arc.
      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, R, -Math.PI * 0.88, -Math.PI * 0.08);
      const rim = ctx.createLinearGradient(cx - R, cy - R * 0.6, cx + R, cy - R * 0.4);
      rim.addColorStop(0, rgba(accent, 1));
      rim.addColorStop(0.5, rgba(accent2, 1));
      rim.addColorStop(1, rgba(accent3, 1));
      ctx.strokeStyle = rim;
      ctx.lineWidth = 2.4;
      ctx.shadowColor = rgba(accent, glow);
      ctx.shadowBlur = 12;
      ctx.stroke();
      ctx.restore();

      // Orbital rings in front of the sphere.
      drawOrbitHalf(true, 1.18, -0.28, R * 1.16, timeSec, accent);
      drawOrbitHalf(true, 1.26, 0.36, R * 1.09, -timeSec * 0.8, accent3);

      ctx.restore();
    };

    renderFrame(0);

    // Repaint with the new palette when the theme class changes.
    const themeObserver = new MutationObserver(() => {
      palette = readStagePalette(canvas);
      renderFrame(lastTime);
    });
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });

    if (prefersReducedMotion()) {
      return () => themeObserver.disconnect();
    }

    // Only animate while visible: the desktop and mobile stages each mount a
    // canvas, and the one hidden by the breakpoint never intersects.
    let rafId = 0;
    const start = performance.now() - lastTime;
    const tick = (now: number) => {
      renderFrame(now - start);
      rafId = window.requestAnimationFrame(tick);
    };
    const visibilityObserver = new IntersectionObserver(([entry]) => {
      window.cancelAnimationFrame(rafId);
      if (entry.isIntersecting) {
        rafId = window.requestAnimationFrame(tick);
      }
    });
    visibilityObserver.observe(canvas);

    return () => {
      themeObserver.disconnect();
      visibilityObserver.disconnect();
      window.cancelAnimationFrame(rafId);
    };
  }, []);

  return <canvas ref={canvasRef} aria-hidden="true" className={className} />;
}

// Full-width glows and stars behind the hero text (desktop only).
function HeroBackdropSVG() {
  const uid = useId().replace(/:/g, "");
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 1672 360"
      aria-hidden="true"
      className="h-[360px] w-[1672px] shrink-0"
    >
      <defs>
        <radialGradient id={`${uid}-cta-glow`} cx="265" cy="292" r="220" gradientUnits="userSpaceOnUse">
          <stop offset="0%" style={{ stopColor: stage("accent", 0.28) }} />
          <stop offset="55%" style={{ stopColor: stage("accent-2", 0.09) }} />
          <stop offset="100%" style={{ stopColor: stage("accent-2", 0) }} />
        </radialGradient>
      </defs>
      <circle cx="265" cy="292" r="220" fill={`url(#${uid}-cta-glow)`} style={{ opacity: "var(--stage-glow)" }} />
      <g style={{ fill: stage("star") }}>
        {STARS.map((star, idx) => (
          <circle key={idx} cx={star.cx} cy={star.cy} r={star.r} opacity={star.o} />
        ))}
      </g>
    </svg>
  );
}

// The globe stage: glows behind the globe, the canvas, then beams and the
// portal ring in front. Fills its parent, which keeps a 740:360 aspect ratio.
function GlobeStage() {
  const uid = useId().replace(/:/g, "");
  const [animate] = useState(() => !prefersReducedMotion());

  return (
    <>
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox={STAGE_VIEWBOX}
        aria-hidden="true"
        className="absolute inset-0 h-full w-full overflow-visible"
      >
        <defs>
          <radialGradient id={`${uid}-portal-halo`} cx="1155" cy="196" r="230" gradientUnits="userSpaceOnUse">
            <stop offset="0%" style={{ stopColor: stage("accent", 0.46) }} />
            <stop offset="38%" style={{ stopColor: stage("accent-2", 0.24) }} />
            <stop offset="72%" style={{ stopColor: stage("accent-2", 0.08) }} />
            <stop offset="100%" style={{ stopColor: stage("accent-2", 0) }} />
          </radialGradient>
          <radialGradient id={`${uid}-globe-nebula`} cx="1256" cy="188" r="250" gradientUnits="userSpaceOnUse">
            <stop offset="0%" style={{ stopColor: stage("accent-3", 0.38) }} />
            <stop offset="45%" style={{ stopColor: stage("accent-2", 0.2) }} />
            <stop offset="78%" style={{ stopColor: stage("accent-2", 0.08) }} />
            <stop offset="100%" style={{ stopColor: stage("accent-2", 0) }} />
          </radialGradient>
          <radialGradient id={`${uid}-corner-flare`} cx="1578" cy="352" r="130" gradientUnits="userSpaceOnUse">
            <stop offset="0%" style={{ stopColor: stage("accent", 0.52) }} />
            <stop offset="42%" style={{ stopColor: stage("accent", 0.2) }} />
            <stop offset="100%" style={{ stopColor: stage("accent", 0) }} />
          </radialGradient>
        </defs>
        <g style={{ opacity: "var(--stage-glow)" }}>
          <circle cx="1256" cy="188" r="250" fill={`url(#${uid}-globe-nebula)`} />
          <circle cx="1155" cy="196" r="230" fill={`url(#${uid}-portal-halo)`} />
          <circle cx="1578" cy="352" r="130" fill={`url(#${uid}-corner-flare)`} />
        </g>
        <g style={{ stroke: stage("accent", 0.28) }} strokeWidth="1">
          <line x1="1510" y1="360" x2="1625" y2="318" />
          <line x1="1548" y1="360" x2="1604" y2="305" />
        </g>
      </svg>

      <RotatingGlobe3DCanvas className="absolute top-0 left-[24.324%] h-full w-[56.757%]" />

      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox={STAGE_VIEWBOX}
        aria-hidden="true"
        className="absolute inset-0 h-full w-full overflow-visible"
      >
        <defs>
          <linearGradient id={`${uid}-left-trail`} x1="680" y1="305" x2="1152" y2="202" gradientUnits="userSpaceOnUse">
            <stop offset="0%" style={{ stopColor: stage("accent-2", 0) }} />
            <stop offset="45%" style={{ stopColor: stage("accent-2", 0.38) }} />
            <stop offset="85%" style={{ stopColor: stage("accent", 0.85) }} />
            <stop offset="100%" style={{ stopColor: stage("highlight", 0.98) }} />
          </linearGradient>
          <linearGradient id={`${uid}-beam`} x1="1155" y1="196" x2="1420" y2="210" gradientUnits="userSpaceOnUse">
            <stop offset="0%" style={{ stopColor: stage("highlight", 0.95) }} />
            <stop offset="30%" style={{ stopColor: stage("accent", 0.9) }} />
            <stop offset="75%" style={{ stopColor: stage("accent-2", 0.75) }} />
            <stop offset="100%" style={{ stopColor: stage("accent-3", 0.85) }} />
          </linearGradient>
          <linearGradient id={`${uid}-ring`} x1="1134" y1="130" x2="1177" y2="262" gradientUnits="userSpaceOnUse">
            <stop offset="0%" style={{ stopColor: stage("accent") }} />
            <stop offset="32%" style={{ stopColor: stage("highlight") }} />
            <stop offset="68%" style={{ stopColor: stage("accent-2") }} />
            <stop offset="100%" style={{ stopColor: stage("accent-3") }} />
          </linearGradient>
          {/* Inner glow of the opening; scaled to the void ellipse. */}
          <radialGradient
            id={`${uid}-void-glow`}
            cx="1155"
            cy="196"
            r="1"
            gradientUnits="userSpaceOnUse"
            gradientTransform="translate(1155 196) scale(17.5 59.5) translate(-1155 -196)"
          >
            <stop offset="0%" style={{ stopColor: stage("accent-2", 0.32) }} />
            <stop offset="60%" style={{ stopColor: stage("accent-2", 0) }} />
            <stop offset="88%" style={{ stopColor: stage("accent", 0.12) }} />
            <stop offset="100%" style={{ stopColor: stage("accent", 0.55) }} />
          </radialGradient>
          <filter id={`${uid}-glow-strong`} x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="8" result="blur1" />
            <feGaussianBlur stdDeviation="3" result="blur2" />
            <feMerge>
              <feMergeNode in="blur1" />
              <feMergeNode in="blur2" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <filter id={`${uid}-glow-soft`} x="-30%" y="-30%" width="160%" height="160%">
            <feGaussianBlur stdDeviation="4" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* Incoming light trails from the left */}
        <path
          d="M 650,304 Q 930,300 1148,206"
          fill="none"
          stroke={`url(#${uid}-left-trail)`}
          strokeWidth="2.4"
          filter={`url(#${uid}-glow-soft)`}
        />
        <path
          d="M 900,152 Q 1045,156 1146,192"
          fill="none"
          stroke={`url(#${uid}-left-trail)`}
          strokeWidth="1.3"
          opacity="0.55"
        />
        <path
          d="M 1075,220 C 1104,220 1124,212 1146,200"
          fill="none"
          style={{ stroke: stage("accent") }}
          strokeWidth="2.6"
          filter={`url(#${uid}-glow-soft)`}
        />

        {/* Outgoing relay beams with travelling packets and pulsing nodes */}
        <g filter={`url(#${uid}-glow-soft)`}>
          {OUTGOING_BEAMS.map((beam, idx) => (
            <g key={idx}>
              <path
                d={beam.d}
                fill="none"
                stroke={`url(#${uid}-beam)`}
                strokeWidth="2.1"
                strokeLinecap="round"
              />
              {animate && (
                <circle r="2.3" style={{ fill: stage("highlight") }}>
                  <animateMotion dur="2.6s" begin={beam.delay} repeatCount="indefinite" path={beam.d} />
                </circle>
              )}
              <circle cx={beam.nx} cy={beam.ny} r="6.5" style={{ fill: stage(beam.tone, 0.45) }}>
                {animate && (
                  <animate
                    attributeName="r"
                    values="5;8;5"
                    dur="2.4s"
                    begin={beam.delay}
                    repeatCount="indefinite"
                  />
                )}
              </circle>
              <circle
                cx={beam.nx}
                cy={beam.ny}
                r="2.8"
                style={{ fill: stage("highlight"), stroke: stage(beam.tone) }}
                strokeWidth="1"
              />
            </g>
          ))}
        </g>

        {/* Portal ring, tilted 5° */}
        <g transform="rotate(5 1155 196)">
          <g style={{ opacity: "var(--stage-glow)" }}>
            <ellipse
              cx="1155"
              cy="196"
              rx="22.5"
              ry="64.5"
              fill="none"
              style={{ stroke: stage("accent") }}
              strokeWidth="10"
              opacity="0.72"
              filter={`url(#${uid}-glow-strong)`}
            >
              {animate && (
                <animate attributeName="opacity" values="0.6;0.9;0.6" dur="3.2s" repeatCount="indefinite" />
              )}
            </ellipse>
          </g>
          <ellipse cx="1155" cy="196" rx="17.5" ry="59.5" style={{ fill: stage("void", 0.96) }} />
          <ellipse cx="1155" cy="196" rx="17.5" ry="59.5" fill={`url(#${uid}-void-glow)`} />
          <ellipse
            cx="1155"
            cy="196"
            rx="20.5"
            ry="63.5"
            fill="none"
            stroke={`url(#${uid}-ring)`}
            strokeWidth="5.6"
            filter={`url(#${uid}-glow-soft)`}
          />
          <ellipse
            cx="1155"
            cy="196"
            rx="20.5"
            ry="63.5"
            fill="none"
            style={{ stroke: stage("highlight", 0.94) }}
            strokeWidth="1.8"
          />
          {animate && (
            // Light streak circling the rim (ellipse perimeter ≈ 296)
            <ellipse
              cx="1155"
              cy="196"
              rx="20.5"
              ry="63.5"
              fill="none"
              style={{ stroke: stage("highlight") }}
              strokeWidth="3.2"
              strokeLinecap="round"
              strokeDasharray="34 262"
              filter={`url(#${uid}-glow-soft)`}
            >
              <animate attributeName="stroke-dashoffset" values="0;-296" dur="2.8s" repeatCount="indefinite" />
            </ellipse>
          )}
        </g>
      </svg>
    </>
  );
}

function CalloutLaptopIcon() {
  return (
    <svg
      viewBox="0 0 28 28"
      className="h-[26px] w-[26px] shrink-0 text-[rgb(var(--stage-accent-2))]"
      aria-hidden="true"
    >
      <rect x="4" y="5" width="20" height="13.5" rx="2.2" fill="currentColor" fillOpacity="0.2" stroke="currentColor" strokeWidth="1.6" />
      <rect x="6.2" y="7.2" width="15.6" height="9" rx="1" fill="currentColor" fillOpacity="0.3" />
      <path d="M2,20.2 L26,20.2 L24.2,23 L3.8,23 Z" fill="currentColor" stroke="currentColor" strokeWidth="1.2" strokeLinejoin="round" />
    </svg>
  );
}

function CalloutRelaysIcon() {
  return (
    <svg
      viewBox="0 0 28 28"
      className="h-[25px] w-[25px] shrink-0 text-[rgb(var(--stage-accent-3))]"
      aria-hidden="true"
    >
      {[5, 11.5, 18].map((y) => (
        <g key={y}>
          <rect x="4" y={y} width="20" height="5" rx="1.5" fill="currentColor" fillOpacity="0.2" stroke="currentColor" strokeWidth="1.4" />
          <circle cx="7.5" cy={y + 2.5} r="1" style={{ fill: stage("accent") }} />
          <circle cx="10.8" cy={y + 2.5} r="1" fill="currentColor" />
          <line x1="15" y1={y + 2.5} x2="21" y2={y + 2.5} stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />
        </g>
      ))}
    </svg>
  );
}

function CalloutPublicAccessIcon() {
  return (
    <svg
      viewBox="0 0 28 28"
      className="h-[25px] w-[25px] shrink-0 text-[rgb(var(--stage-accent-3))]"
      aria-hidden="true"
    >
      <g fill="currentColor" fillOpacity="0.35" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round">
        <circle cx="9" cy="11.5" r="3" />
        <path d="M3.5,21 C3.5,17.8 6,15.8 9,15.8 C12,15.8 14.5,17.8 14.5,21" />
        <circle cx="19.5" cy="11.5" r="2.8" />
        <path d="M14.5,21 C14.5,18 16.8,16 19.5,16 C22.2,16 24.5,18 24.5,21" />
      </g>
      <g fill="currentColor" fillOpacity="0.7" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round">
        <circle cx="14.2" cy="9.5" r="3.4" />
        <path d="M8,22 C8,18.2 10.8,15.8 14.2,15.8 C17.6,15.8 20.4,18.2 20.4,22" />
      </g>
    </svg>
  );
}

const CALLOUT_CLASS =
  "absolute flex items-center whitespace-nowrap border bg-card/85 font-bold text-foreground backdrop-blur-md";
const CALLOUT_CYAN = "border-[rgb(var(--stage-accent-2)/0.4)] shadow-[0_0_24px_rgb(var(--stage-accent-2)/0.18)]";
const CALLOUT_INDIGO = "border-[rgb(var(--stage-accent-3)/0.4)] shadow-[0_0_22px_rgb(var(--stage-accent-3)/0.2)]";

function YourMachineLabel() {
  return (
    <span>
      Your machine <span className="font-medium text-muted-foreground">(localhost)</span>
    </span>
  );
}

// Desktop (xl+): backdrop across the band, and the globe stage pinned to the
// right edge of the content column. The stage steps down in scale on narrower
// screens so it never runs into the heading.
export function HeroBackdropGraphic() {
  const callout = `${CALLOUT_CLASS} h-[44px] gap-[9px] rounded-[11px] px-[12px] text-[12.5px]`;
  return (
    <div aria-hidden="true" className="pointer-events-none absolute inset-0 hidden overflow-hidden xl:block">
      <div className="absolute inset-0 flex justify-center">
        <HeroBackdropSVG />
      </div>
      <div className="relative mx-auto h-full w-full max-w-[1437px] px-[32px]">
        <div className="absolute top-0 right-[8px] h-[360px] w-[740px] origin-right scale-75 min-[1440px]:scale-95 min-[1600px]:right-[-36px] min-[1600px]:scale-100">
          <GlobeStage />
          <div className={`${callout} ${CALLOUT_CYAN} top-[198px] left-[8px]`}>
            <CalloutLaptopIcon />
            <YourMachineLabel />
          </div>
          <div className={`${callout} ${CALLOUT_INDIGO} top-[108px] left-[535px]`}>
            <CalloutRelaysIcon />
            Public relays
          </div>
          <div className={`${callout} ${CALLOUT_INDIGO} top-[266px] left-[572px]`}>
            <CalloutPublicAccessIcon />
            Public access
          </div>
        </div>
      </div>
    </div>
  );
}

export function LandingHero() {
  // On phones the labels drop their icons so they stay clear of the globe.
  const callout = `${CALLOUT_CLASS} gap-2 rounded-md px-2 py-1 text-[9.5px] [&>svg]:hidden sm:rounded-lg sm:px-3 sm:py-2 sm:text-xs sm:[&>svg]:block`;
  return (
    <section aria-labelledby="landing-title" className="relative">
      <a
        href="#live-servers"
        className="sr-only focus:not-sr-only focus:absolute focus:left-6 focus:top-6 focus:z-20 focus:rounded-md focus:bg-background focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:text-foreground"
      >
        Skip to live servers
      </a>

      <div className="relative z-10 flex flex-col xl:block">
        <div className="w-full min-w-0 max-w-[785px]">
          <h1
            id="landing-title"
            className="font-display text-[30px] font-extrabold leading-[1.08] tracking-[-0.025em] text-foreground sm:text-[44px] lg:text-[55px] lg:whitespace-nowrap"
          >
            <span>Tunnels for </span>
            <span className="bg-linear-to-r from-[rgb(var(--stage-accent))] to-[rgb(var(--stage-accent-2))] bg-clip-text text-transparent">
              local services
            </span>
          </h1>

          <p className="mt-[9px] max-w-[575px] text-[14px] leading-[22px] font-normal text-muted-foreground sm:text-[15.5px] sm:leading-[24px]">
            Connect a local service to a public URL through a relay.
          </p>

          <div
            id="quick-start"
            className="mt-[19px] flex flex-col gap-[14px] sm:flex-row sm:items-center"
          >
            <TunnelCommandModal
              trigger={
                <button
                  type="button"
                  className="inline-flex h-[48px] w-full cursor-pointer items-center justify-center gap-[10px] rounded-[10px] bg-linear-to-r from-[rgb(var(--stage-accent))] to-[rgb(var(--stage-accent-2))] px-6 text-[14px] font-bold text-[rgb(var(--stage-on-accent))] shadow-[0_0_26px_rgb(var(--stage-accent)/0.4)] transition-all hover:brightness-105 sm:w-[231px]"
                >
                  <Zap className="h-[16px] w-[16px] fill-current stroke-[2.2]" />
                  <span>Launch a tunnel</span>
                </button>
              }
            />

            <a
              href="https://gosuda.github.io/portal-tunnel"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex h-[48px] w-full items-center justify-center gap-[11px] rounded-[10px] border border-border bg-card/80 px-6 text-[14px] font-semibold text-foreground backdrop-blur-sm transition-colors hover:border-primary/50 sm:w-[260px]"
            >
              <BookOpen className="h-[16px] w-[16px] text-muted-foreground" />
              <span>View documentation</span>
              <ArrowRight className="ml-0.5 h-[15px] w-[15px] text-muted-foreground" />
            </a>
          </div>
        </div>

        {/* Below xl the globe stage sits under the heading. */}
        <div className="mt-6 flex justify-center xl:hidden">
          <div className="relative aspect-[740/360] w-full max-w-[640px] overflow-hidden rounded-xl border border-border bg-linear-to-b from-[rgb(var(--stage-bg))] to-[rgb(var(--stage-bg-edge))]">
            <GlobeStage />
            <div className={`${callout} ${CALLOUT_CYAN} bottom-[6%] left-[2%]`}>
              <CalloutLaptopIcon />
              <YourMachineLabel />
            </div>
            <div className={`${callout} ${CALLOUT_INDIGO} top-[5%] right-[2%] sm:top-[18%]`}>
              <CalloutRelaysIcon />
              Public relays
            </div>
            <div className={`${callout} ${CALLOUT_INDIGO} right-[2%] bottom-[6%]`}>
              <CalloutPublicAccessIcon />
              Public access
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
