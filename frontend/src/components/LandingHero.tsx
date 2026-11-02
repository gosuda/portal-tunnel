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

const OUTGOING_BEAMS: ReadonlyArray<{
  d: string;
  nx: number;
  ny: number;
  color: string;
  delay: string;
}> = [
  { d: "M 1166,180 Q 1206,120 1264,95", nx: 1264, ny: 95, color: "#67f9f0", delay: "0s" },
  { d: "M 1170,185 Q 1264,112 1388,128", nx: 1388, ny: 128, color: "#7dd3fc", delay: "0.4s" },
  { d: "M 1172,191 Q 1252,148 1330,174", nx: 1330, ny: 174, color: "#5eead4", delay: "0.8s" },
  { d: "M 1172,198 Q 1295,192 1418,278", nx: 1418, ny: 278, color: "#67e8f9", delay: "0.2s" },
  { d: "M 1170,204 Q 1258,216 1338,286", nx: 1338, ny: 286, color: "#5eead4", delay: "0.6s" },
  { d: "M 1166,210 Q 1206,224 1246,252", nx: 1246, ny: 252, color: "#67f9f0", delay: "1.0s" },
];

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

    // 3D Axial tilt: pitch (-16°) and roll (+9°)
    const pitch = (-16 * Math.PI) / 180;
    const roll = (9 * Math.PI) / 180;
    const cosPitch = Math.cos(pitch);
    const sinPitch = Math.sin(pitch);
    const cosRoll = Math.cos(roll);
    const sinRoll = Math.sin(roll);

    const project3D = (lat: number, lon: number, radius: number = R) => {
      const cosLat = Math.cos(lat);
      const sinLat = Math.sin(lat);
      const x0 = cosLat * Math.sin(lon);
      const y0 = -sinLat;
      const z0 = cosLat * Math.cos(lon);

      // Rotate around X (pitch)
      const y1 = y0 * cosPitch - z0 * sinPitch;
      const z1 = y0 * sinPitch + z0 * cosPitch;
      // Rotate around Z (roll)
      const x2 = x0 * cosRoll - y1 * sinRoll;
      const y2 = x0 * sinRoll + y1 * cosRoll;

      // Subtle perspective factor so front hemisphere pops out in 3D
      const perspective = 1 + z1 * 0.12;
      return {
        x: cx + x2 * radius * perspective,
        y: cy + y2 * radius * perspective,
        nx: x2,
        ny: y2,
        nz: z1,
      };
    };

    const drawOrbitHalf = (
      frontHemisphere: boolean,
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

      ctx.save();
      ctx.beginPath();
      let started = false;
      for (let i = 0; i <= steps; i += 1) {
        const theta = (i / steps) * Math.PI * 2;
        const ox = Math.cos(theta) * orbitRadius;
        const oz = Math.sin(theta) * orbitRadius;
        const oy1 = -oz * sX;
        const oz1 = oz * cX;
        const ox2 = ox * cZ - oy1 * sZ;
        const oy2 = ox * sZ + oy1 * cZ;

        const isFront = oz1 >= 0;
        if (isFront === frontHemisphere) {
          const px = cx + ox2;
          const py = cy + oy2;
          if (!started) {
            ctx.moveTo(px, py);
            started = true;
          } else {
            ctx.lineTo(px, py);
          }
        } else {
          started = false;
        }
      }
      ctx.strokeStyle = color;
      ctx.lineWidth = frontHemisphere ? 1.25 : 0.8;
      ctx.globalAlpha = frontHemisphere ? 0.42 : 0.14;
      ctx.stroke();

      // Orbiting satellite pulse along this ring
      const satAngle = timeSec * 0.85 + (tiltZ > 0 ? 1.2 : 3.9);
      const sx = Math.cos(satAngle) * orbitRadius;
      const sz = Math.sin(satAngle) * orbitRadius;
      const sy1 = -sz * sX;
      const sz1 = sz * cX;
      if ((sz1 >= 0) === frontHemisphere) {
        const sx2 = sx * cZ - sy1 * sZ;
        const sy2 = sx * sZ + sy1 * cZ;
        const px = cx + sx2;
        const py = cy + sy2;
        const grad = ctx.createRadialGradient(px, py, 0, px, py, 8);
        grad.addColorStop(0, "#ffffff");
        grad.addColorStop(0.35, "#5efce8");
        grad.addColorStop(1, "rgba(94, 252, 232, 0)");
        ctx.globalAlpha = frontHemisphere ? 0.95 : 0.25;
        ctx.fillStyle = grad;
        ctx.beginPath();
        ctx.arc(px, py, 8, 0, Math.PI * 2);
        ctx.fill();
      }
      ctx.restore();
    };

    const renderFrame = (timeMs: number) => {
      const timeSec = timeMs * 0.001;
      // Start at lon = +18° so Americas (left), Europe/Africa (center-right), and Asia (right) align at t=0
      const rotationLon = 0.32 + timeSec * 0.24;

      ctx.save();
      ctx.scale(dpr, dpr);
      ctx.clearRect(0, 0, width, height);

      // 1. Back half of 3D orbital rings (occluded behind the sphere)
      drawOrbitHalf(false, 1.18, -0.28, R * 1.16, timeSec, "#38bdf8");
      drawOrbitHalf(false, 1.26, 0.36, R * 1.09, -timeSec * 0.8, "#818cf8");

      // 2. Outer Atmospheric 3D Corona Halo
      const corona = ctx.createRadialGradient(cx - 12, cy - 8, R * 0.72, cx, cy, R * 1.24);
      corona.addColorStop(0, "rgba(56, 249, 240, 0.22)");
      corona.addColorStop(0.55, "rgba(59, 130, 246, 0.24)");
      corona.addColorStop(0.8, "rgba(129, 140, 248, 0.14)");
      corona.addColorStop(1, "rgba(2, 12, 27, 0)");
      ctx.fillStyle = corona;
      ctx.beginPath();
      ctx.arc(cx, cy, R * 1.24, 0, Math.PI * 2);
      ctx.fill();

      // 3. 3D Sphere Volumetric Body
      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, Math.PI * 2);
      ctx.clip();

      // Deep ocean sphere gradient with top-left light source from the Portal Ring
      const sphereGrad = ctx.createRadialGradient(
        cx - R * 0.38,
        cy - R * 0.24,
        R * 0.06,
        cx + R * 0.1,
        cy + R * 0.12,
        R * 1.08
      );
      sphereGrad.addColorStop(0, "#10457d");
      sphereGrad.addColorStop(0.34, "#0d2a5e");
      sphereGrad.addColorStop(0.68, "#09153c");
      sphereGrad.addColorStop(1, "#020718");
      ctx.fillStyle = sphereGrad;
      ctx.fillRect(cx - R, cy - R, R * 2, R * 2);

      // Eastern limb violet nebula reflection
      const violetLimb = ctx.createRadialGradient(
        cx + R * 0.55,
        cy - R * 0.15,
        R * 0.05,
        cx + R * 0.45,
        cy - R * 0.05,
        R * 0.9
      );
      violetLimb.addColorStop(0, "rgba(139, 92, 246, 0.34)");
      violetLimb.addColorStop(0.6, "rgba(79, 70, 229, 0.14)");
      violetLimb.addColorStop(1, "rgba(15, 23, 42, 0)");
      ctx.fillStyle = violetLimb;
      ctx.fillRect(cx - R, cy - R, R * 2, R * 2);

      // 4. Back-Hemisphere Translucent Continents (nz < 0) for true 3D glass depth
      ctx.fillStyle = "rgba(99, 102, 241, 0.17)";
      ctx.beginPath();
      for (let i = 0; i < GLOBE_LAND_POINTS.length; i += 1) {
        const pt = GLOBE_LAND_POINTS[i];
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

      // 5. 3D Rotating Spherical Graticule (Meridians & Parallels)
      ctx.lineWidth = 0.75;
      ctx.strokeStyle = "rgba(94, 252, 232, 0.13)";
      for (let m = 0; m < 12; m += 1) {
        const merLon = rotationLon + (m * Math.PI) / 6;
        ctx.beginPath();
        let drawing = false;
        for (let latStep = -80; latStep <= 80; latStep += 8) {
          const p = project3D((latStep * Math.PI) / 180, merLon);
          if (p.nz >= 0) {
            if (!drawing) {
              ctx.moveTo(p.x, p.y);
              drawing = true;
            } else {
              ctx.lineTo(p.x, p.y);
            }
          } else {
            drawing = false;
          }
        }
        ctx.stroke();
      }

      for (let latDeg = -60; latDeg <= 60; latDeg += 30) {
        const latRad = (latDeg * Math.PI) / 180;
        ctx.beginPath();
        let drawing = false;
        for (let lonStep = 0; lonStep <= 360; lonStep += 8) {
          const p = project3D(latRad, rotationLon + (lonStep * Math.PI) / 180);
          if (p.nz >= 0) {
            if (!drawing) {
              ctx.moveTo(p.x, p.y);
              drawing = true;
            } else {
              ctx.lineTo(p.x, p.y);
            }
          } else {
            drawing = false;
          }
        }
        ctx.stroke();
      }

      // 6. Front-Hemisphere 3D Continent Dot Matrix (nz >= 0) with 3D Portal Lighting
      for (let i = 0; i < GLOBE_LAND_POINTS.length; i += 1) {
        const pt = GLOBE_LAND_POINTS[i];
        const lon = pt.lon + rotationLon;
        const x0 = pt.cosLat * Math.sin(lon);
        const y0 = -pt.sinLat;
        const z0 = pt.cosLat * Math.cos(lon);
        const y1 = y0 * cosPitch - z0 * sinPitch;
        const z1 = y0 * sinPitch + z0 * cosPitch;

        if (z1 >= 0) {
          const x2 = x0 * cosRoll - y1 * sinRoll;
          const y2 = x0 * sinRoll + y1 * cosRoll;
          const perspective = 1 + z1 * 0.12;
          const sx = cx + x2 * R * perspective;
          const sy = cy + y2 * R * perspective;

          // Distance to Portal Ring light source at (-0.52, 0.0, 0.85)
          const portalLight = Math.max(0, -x2 * 0.55 - y2 * 0.1 + z1 * 0.82);
          const dotRadius = (pt.coastal ? 1.15 : 0.95) + z1 * 0.55 + portalLight * 0.25;
          const alpha = Math.min(1, 0.35 + z1 * 0.55 + (pt.coastal ? 0.18 : 0));

          if (portalLight > 0.58) {
            ctx.fillStyle = `rgba(110, 252, 242, ${alpha.toFixed(2)})`;
          } else if (x2 < 0.18) {
            ctx.fillStyle = `rgba(96, 185, 252, ${alpha.toFixed(2)})`;
          } else {
            ctx.fillStyle = `rgba(154, 146, 252, ${alpha.toFixed(2)})`;
          }

          ctx.beginPath();
          ctx.arc(sx, sy, dotRadius, 0, Math.PI * 2);
          ctx.fill();
        }
      }

      // 7. 3D Inner Fresnel Rim & Specular Glint
      const fresnel = ctx.createRadialGradient(cx, cy, R * 0.7, cx, cy, R);
      fresnel.addColorStop(0, "rgba(56, 189, 248, 0)");
      fresnel.addColorStop(0.76, "rgba(56, 189, 248, 0.08)");
      fresnel.addColorStop(0.93, "rgba(94, 252, 232, 0.32)");
      fresnel.addColorStop(1, "rgba(165, 180, 252, 0.68)");
      ctx.fillStyle = fresnel;
      ctx.fillRect(cx - R, cy - R, R * 2, R * 2);

      // Specular highlight near top-left
      const spec = ctx.createRadialGradient(
        cx - R * 0.45,
        cy - R * 0.45,
        0,
        cx - R * 0.45,
        cy - R * 0.45,
        R * 0.65
      );
      spec.addColorStop(0, "rgba(255, 255, 255, 0.22)");
      spec.addColorStop(0.45, "rgba(94, 252, 232, 0.08)");
      spec.addColorStop(1, "rgba(94, 252, 232, 0)");
      ctx.fillStyle = spec;
      ctx.fillRect(cx - R, cy - R, R * 2, R * 2);

      ctx.restore();

      // 8. Crisp 3D Outer Rim Highlight Arc
      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, R, -Math.PI * 0.88, -Math.PI * 0.08);
      const rimGrad = ctx.createLinearGradient(cx - R, cy - R * 0.6, cx + R, cy - R * 0.4);
      rimGrad.addColorStop(0, "#5efce8");
      rimGrad.addColorStop(0.5, "#38bdf8");
      rimGrad.addColorStop(1, "#a78bfa");
      ctx.strokeStyle = rimGrad;
      ctx.lineWidth = 2.4;
      ctx.shadowColor = "#38f9f0";
      ctx.shadowBlur = 12;
      ctx.stroke();
      ctx.restore();

      // 9. Front half of 3D orbital rings (crossing in front of the sphere)
      drawOrbitHalf(true, 1.18, -0.28, R * 1.16, timeSec, "#5efce8");
      drawOrbitHalf(true, 1.26, 0.36, R * 1.09, -timeSec * 0.8, "#a5b4fc");

      ctx.restore();
    };

    // Draw initial frame synchronously so first paint & screenshots have full 3D globe
    renderFrame(0);

    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduceMotion) {
      return;
    }

    // Only animate while visible: the desktop and mobile stages each mount a
    // canvas, and the one hidden by the breakpoint never intersects.
    let rafId = 0;
    const start = performance.now();
    const tick = (now: number) => {
      renderFrame(now - start);
      rafId = window.requestAnimationFrame(tick);
    };
    const observer = new IntersectionObserver(([entry]) => {
      window.cancelAnimationFrame(rafId);
      if (entry.isIntersecting) {
        rafId = window.requestAnimationFrame(tick);
      }
    });
    observer.observe(canvas);

    return () => {
      observer.disconnect();
      window.cancelAnimationFrame(rafId);
    };
  }, []);

  return <canvas ref={canvasRef} aria-hidden="true" className={className} />;
}

// The globe canvas sits between the two layers: the background holds the
// glows and stars, the foreground holds the beams and the portal ring.
function HeroSceneSVG({
  viewBox,
  className,
  layer,
}: {
  viewBox: string;
  className: string;
  layer: "background" | "foreground";
}) {
  const uid = useId().replace(/:/g, "");
  const [animate] = useState(
    () => !window.matchMedia("(prefers-reduced-motion: reduce)").matches
  );

  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox={viewBox}
      preserveAspectRatio="xMidYMid slice"
      aria-hidden="true"
      className={className}
    >
      <defs>
        <radialGradient id={`${uid}-cta-glow`} cx="265" cy="292" r="220" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#2dd4bf" stopOpacity="0.28" />
          <stop offset="55%" stopColor="#0ea5e9" stopOpacity="0.09" />
          <stop offset="100%" stopColor="#020c1b" stopOpacity="0" />
        </radialGradient>

        <radialGradient id={`${uid}-portal-halo`} cx="1155" cy="196" r="230" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#38f9f0" stopOpacity="0.46" />
          <stop offset="38%" stopColor="#0ea5e9" stopOpacity="0.24" />
          <stop offset="72%" stopColor="#3b82f6" stopOpacity="0.08" />
          <stop offset="100%" stopColor="#020c1b" stopOpacity="0" />
        </radialGradient>

        <radialGradient id={`${uid}-globe-nebula`} cx="1256" cy="188" r="250" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#4f46e5" stopOpacity="0.38" />
          <stop offset="45%" stopColor="#2563eb" stopOpacity="0.24" />
          <stop offset="78%" stopColor="#0ea5e9" stopOpacity="0.09" />
          <stop offset="100%" stopColor="#020c1b" stopOpacity="0" />
        </radialGradient>

        <radialGradient id={`${uid}-corner-flare`} cx="1578" cy="352" r="130" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#5efce8" stopOpacity="0.52" />
          <stop offset="42%" stopColor="#22d3ee" stopOpacity="0.2" />
          <stop offset="100%" stopColor="#020c1b" stopOpacity="0" />
        </radialGradient>

        <radialGradient id={`${uid}-portal-void`} cx="1155" cy="196" r="1" gradientUnits="userSpaceOnUse" gradientTransform="translate(1155 196) scale(17.5 59.5) translate(-1155 -196)">
          <stop offset="0%" stopColor="#0e4a6e" stopOpacity="0.95" />
          <stop offset="55%" stopColor="#041427" stopOpacity="0.96" />
          <stop offset="85%" stopColor="#06233d" stopOpacity="0.95" />
          <stop offset="100%" stopColor="#2dd4bf" stopOpacity="0.55" />
        </radialGradient>

        <linearGradient id={`${uid}-ring-stroke`} x1="1134" y1="130" x2="1177" y2="262" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#5efce8" />
          <stop offset="32%" stopColor="#ffffff" />
          <stop offset="68%" stopColor="#60a5fa" />
          <stop offset="100%" stopColor="#a5b4fc" />
        </linearGradient>

        <linearGradient id={`${uid}-beam-grad`} x1="1155" y1="196" x2="1420" y2="210" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#ffffff" stopOpacity="0.95" />
          <stop offset="30%" stopColor="#5efce8" stopOpacity="0.9" />
          <stop offset="75%" stopColor="#38bdf8" stopOpacity="0.75" />
          <stop offset="100%" stopColor="#818cf8" stopOpacity="0.85" />
        </linearGradient>

        <linearGradient id={`${uid}-left-trail`} x1="680" y1="305" x2="1152" y2="202" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#0ea5e9" stopOpacity="0" />
          <stop offset="45%" stopColor="#22d3ee" stopOpacity="0.38" />
          <stop offset="85%" stopColor="#5efce8" stopOpacity="0.85" />
          <stop offset="100%" stopColor="#ffffff" stopOpacity="0.98" />
        </linearGradient>

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

      {layer === "background" ? (
        <>
          <rect width="1672" height="360" fill="#020c1b" />
          <circle cx="265" cy="292" r="220" fill={`url(#${uid}-cta-glow)`} />
          <circle cx="1256" cy="188" r="250" fill={`url(#${uid}-globe-nebula)`} />
          <circle cx="1155" cy="196" r="230" fill={`url(#${uid}-portal-halo)`} />
          <circle cx="1578" cy="352" r="130" fill={`url(#${uid}-corner-flare)`} />

          {/* Bottom-Right Lens Flare Rays */}
          <g stroke="#5efce8" strokeOpacity="0.28" strokeWidth="1">
            <line x1="1510" y1="360" x2="1625" y2="318" />
            <line x1="1548" y1="360" x2="1604" y2="305" />
          </g>

          {/* Starfield */}
          <g fill="#e0f2fe">
            {STARS.map((star, idx) => (
              <circle
                key={idx}
                cx={star.cx}
                cy={star.cy}
                r={star.r}
                opacity={star.o}
              />
            ))}
          </g>
        </>
      ) : (
        <>
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
            stroke="#5efce8"
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
                  stroke={`url(#${uid}-beam-grad)`}
                  strokeWidth="2.1"
                  strokeLinecap="round"
                />
                {animate && (
                  <circle r="2.3" fill="#ffffff">
                    <animateMotion
                      dur="2.6s"
                      begin={beam.delay}
                      repeatCount="indefinite"
                      path={beam.d}
                    />
                  </circle>
                )}
                <circle cx={beam.nx} cy={beam.ny} r="6.5" fill={beam.color} opacity="0.38">
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
                <circle cx={beam.nx} cy={beam.ny} r="2.8" fill="#ffffff" />
              </g>
            ))}
          </g>

          {/* Portal ring, tilted 5° */}
          <g transform="rotate(5 1155 196)">
            <ellipse
              cx="1155"
              cy="196"
              rx="22.5"
              ry="64.5"
              fill="none"
              stroke="#22d3ee"
              strokeWidth="10"
              opacity="0.72"
              filter={`url(#${uid}-glow-strong)`}
            >
              {animate && (
                <animate
                  attributeName="opacity"
                  values="0.6;0.9;0.6"
                  dur="3.2s"
                  repeatCount="indefinite"
                />
              )}
            </ellipse>
            {/* Void with a faint inner glow so the opening reads as depth */}
            <ellipse
              cx="1155"
              cy="196"
              rx="17.5"
              ry="59.5"
              fill={`url(#${uid}-portal-void)`}
            />
            <ellipse
              cx="1155"
              cy="196"
              rx="20.5"
              ry="63.5"
              fill="none"
              stroke={`url(#${uid}-ring-stroke)`}
              strokeWidth="5.6"
              filter={`url(#${uid}-glow-soft)`}
            />
            <ellipse
              cx="1155"
              cy="196"
              rx="20.5"
              ry="63.5"
              fill="none"
              stroke="#ffffff"
              strokeWidth="1.8"
              opacity="0.94"
            />
            {animate && (
              // Light streak circling the rim (ellipse perimeter ≈ 296)
              <ellipse
                cx="1155"
                cy="196"
                rx="20.5"
                ry="63.5"
                fill="none"
                stroke="#ffffff"
                strokeWidth="3.2"
                strokeLinecap="round"
                strokeDasharray="34 262"
                filter={`url(#${uid}-glow-soft)`}
              >
                <animate
                  attributeName="stroke-dashoffset"
                  values="0;-296"
                  dur="2.8s"
                  repeatCount="indefinite"
                />
              </ellipse>
            )}
          </g>
        </>
      )}
    </svg>
  );
}

function CalloutLaptopIcon() {
  return (
    <svg viewBox="0 0 28 28" className="h-[26px] w-[26px] shrink-0" aria-hidden="true">
      <rect
        x="4"
        y="5"
        width="20"
        height="13.5"
        rx="2.2"
        fill="#1e3a8a"
        stroke="#93c5fd"
        strokeWidth="1.6"
      />
      <rect x="6.2" y="7.2" width="15.6" height="9" rx="1" fill="#3b82f6" fillOpacity="0.35" />
      <path
        d="M2,20.2 L26,20.2 L24.2,23 L3.8,23 Z"
        fill="#60a5fa"
        stroke="#bae6fd"
        strokeWidth="1.2"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function CalloutRelaysIcon() {
  return (
    <svg viewBox="0 0 28 28" className="h-[25px] w-[25px] shrink-0" aria-hidden="true">
      {[5, 11.5, 18].map((y, idx) => (
        <g key={idx}>
          <rect
            x="4"
            y={y}
            width="20"
            height="5"
            rx="1.5"
            fill="#312e81"
            stroke="#a5b4fc"
            strokeWidth="1.4"
          />
          <circle cx="7.5" cy={y + 2.5} r="1" fill="#67e8f9" />
          <circle cx="10.8" cy={y + 2.5} r="1" fill="#a5b4fc" />
          <line
            x1="15"
            y1={y + 2.5}
            x2="21"
            y2={y + 2.5}
            stroke="#c7d2fe"
            strokeWidth="1.3"
            strokeLinecap="round"
          />
        </g>
      ))}
    </svg>
  );
}

function CalloutPublicAccessIcon() {
  return (
    <svg viewBox="0 0 28 28" className="h-[25px] w-[25px] shrink-0" aria-hidden="true">
      <circle cx="9" cy="11.5" r="3" fill="#6366f1" stroke="#a5b4fc" strokeWidth="1.2" />
      <path
        d="M3.5,21 C3.5,17.8 6,15.8 9,15.8 C12,15.8 14.5,17.8 14.5,21"
        fill="#4f46e5"
        stroke="#a5b4fc"
        strokeWidth="1.2"
        strokeLinecap="round"
      />
      <circle cx="19.5" cy="11.5" r="2.8" fill="#6366f1" stroke="#a5b4fc" strokeWidth="1.2" />
      <path
        d="M14.5,21 C14.5,18 16.8,16 19.5,16 C22.2,16 24.5,18 24.5,21"
        fill="#4f46e5"
        stroke="#a5b4fc"
        strokeWidth="1.2"
        strokeLinecap="round"
      />
      <circle cx="14.2" cy="9.5" r="3.4" fill="#818cf8" stroke="#e0e7ff" strokeWidth="1.3" />
      <path
        d="M8,22 C8,18.2 10.8,15.8 14.2,15.8 C17.6,15.8 20.4,18.2 20.4,22"
        fill="#6366f1"
        stroke="#e0e7ff"
        strokeWidth="1.3"
        strokeLinecap="round"
      />
    </svg>
  );
}

export function HeroBackdropGraphic() {
  return (
    <div
      aria-hidden="true"
      className="pointer-events-none absolute inset-0 hidden justify-center overflow-hidden lg:flex"
    >
      <div className="relative h-[360px] w-[1672px] shrink-0">
        {/* Base Cosmic Glows & Starfield */}
        <HeroSceneSVG viewBox="0 0 1672 360" className="h-full w-full" layer="background" />

        {/* Real 3D Rotating Globe Canvas (centered at x=1236, y=195) */}
        <RotatingGlobe3DCanvas className="absolute top-0 left-[1040px] h-[360px] w-[420px]" />

        {/* Foreground Portal Ring & Animated Beams */}
        <HeroSceneSVG
          viewBox="0 0 1672 360"
          className="absolute inset-0 h-full w-full"
          layer="foreground"
        />

        <div className="absolute top-[198px] left-[868px] flex h-[44px] items-center gap-[9px] whitespace-nowrap rounded-[11px] border border-[#38bdf8]/40 bg-[#07162c]/85 px-[12px] text-[12.5px] font-bold text-white shadow-[0_0_24px_rgba(34,211,238,0.18)] backdrop-blur-md">
          <CalloutLaptopIcon />
          <span>
            Your machine <span className="font-medium text-[#94a3b8]">(localhost)</span>
          </span>
        </div>

        <div className="absolute top-[108px] left-[1395px] flex h-[44px] items-center gap-[9px] whitespace-nowrap rounded-[11px] border border-[#818cf8]/40 bg-[#0b152e]/85 px-[12px] text-[12.5px] font-bold text-white shadow-[0_0_22px_rgba(99,102,241,0.2)] backdrop-blur-md">
          <CalloutRelaysIcon />
          Public relays
        </div>

        <div className="absolute top-[266px] left-[1432px] flex h-[44px] items-center gap-[9px] whitespace-nowrap rounded-[11px] border border-[#818cf8]/40 bg-[#0b152e]/85 px-[12px] text-[12.5px] font-bold text-white shadow-[0_0_22px_rgba(99,102,241,0.2)] backdrop-blur-md">
          <CalloutPublicAccessIcon />
          Public access
        </div>
      </div>
    </div>
  );
}

export function LandingHero() {
  return (
    <section
      aria-labelledby="landing-title"
      className="relative"
    >
      <a
        href="#live-servers"
        className="sr-only focus:not-sr-only focus:absolute focus:left-6 focus:top-6 focus:z-20 focus:rounded-md focus:bg-background focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:text-foreground"
      >
        Skip to live servers
      </a>

      <div className="relative z-10 flex flex-col lg:block">
        <div className="w-full min-w-0 max-w-[785px]">
          <h1
            id="landing-title"
            className="font-display text-[30px] font-extrabold leading-[1.08] tracking-[-0.025em] text-white sm:text-[44px] lg:text-[55px] lg:whitespace-nowrap"
          >
            <span>Tunnels for </span>
            <span className="bg-linear-to-r from-[#5bf7ea] via-[#3dddf4] to-[#26bae8] bg-clip-text text-transparent">
              local services
            </span>
          </h1>

          <p className="mt-[9px] max-w-[575px] text-[14px] leading-[22px] font-normal text-[#b4c4d8] sm:text-[15.5px] sm:leading-[24px]">
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
                  className="inline-flex h-[48px] w-full cursor-pointer items-center justify-center gap-[10px] rounded-[10px] bg-linear-to-r from-[#58f9e4] to-[#41d8f5] px-6 text-[14px] font-bold text-[#031322] shadow-[0_0_26px_rgba(72,240,232,0.45)] transition-all hover:brightness-105 sm:w-[231px]"
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
              className="inline-flex h-[48px] w-full items-center justify-center gap-[11px] rounded-[10px] border border-[#243b56] bg-[#081629]/80 px-6 text-[14px] font-semibold text-[#e2e8f0] backdrop-blur-sm transition-colors hover:border-[#38bdf8]/50 hover:text-white sm:w-[260px]"
            >
              <BookOpen className="h-[16px] w-[16px] text-[#94a3b8]" />
              <span>View documentation</span>
              <ArrowRight className="ml-0.5 h-[15px] w-[15px] text-[#94a3b8]" />
            </a>
          </div>
        </div>

        {/* Responsive 3D Rotating Globe + Vector Stage for Tablet & Mobile (< lg) */}
        <div className="mt-6 flex justify-center lg:hidden">
          <div className="relative aspect-[710/320] w-full max-w-[620px] overflow-hidden rounded-xl border border-white/10 bg-[#020c1b]">
            <HeroSceneSVG viewBox="890 30 710 320" className="h-full w-full" layer="background" />
            <RotatingGlobe3DCanvas className="absolute top-[-8%] left-[21%] h-[112%] w-[59%]" />
            <HeroSceneSVG
              viewBox="890 30 710 320"
              className="absolute inset-0 h-full w-full"
              layer="foreground"
            />

            <div className="absolute bottom-[6%] left-[3%] flex items-center gap-2 whitespace-nowrap rounded-lg border border-[#38bdf8]/40 bg-[#07162c]/85 px-2.5 py-1.5 text-[10px] font-bold text-white shadow-[0_0_18px_rgba(34,211,238,0.18)] backdrop-blur-md sm:px-3 sm:py-2 sm:text-xs">
              <CalloutLaptopIcon />
              <span>
                Your machine <span className="font-medium text-[#94a3b8]">(localhost)</span>
              </span>
            </div>

            <div className="absolute top-[22%] right-[3%] flex items-center gap-2 whitespace-nowrap rounded-lg border border-[#818cf8]/40 bg-[#0b152e]/85 px-2.5 py-1.5 text-[10px] font-bold text-white shadow-[0_0_18px_rgba(99,102,241,0.2)] backdrop-blur-md sm:px-3 sm:py-2 sm:text-xs">
              <CalloutRelaysIcon />
              Public relays
            </div>

            <div className="absolute right-[2%] bottom-[6%] flex items-center gap-2 whitespace-nowrap rounded-lg border border-[#818cf8]/40 bg-[#0b152e]/85 px-2.5 py-1.5 text-[10px] font-bold text-white shadow-[0_0_18px_rgba(99,102,241,0.2)] backdrop-blur-md sm:px-3 sm:py-2 sm:text-xs">
              <CalloutPublicAccessIcon />
              Public access
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
