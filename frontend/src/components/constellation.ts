export interface ConstellationData {
  nebulaHue: number;
  nebulaCx: number;
  nebulaCy: number;
  bgStars: { cx: number; cy: number; r: number; opacity: number }[];
  stars: { x: number; y: number; r: number; opacity: number; isPrimary: boolean }[];
  lines: { x1: number; y1: number; x2: number; y2: number; opacity: number }[];
}

type StarPoint = { x: number; y: number; r: number; opacity: number };

type BackgroundStar = { cx: number; cy: number; r: number; opacity: number };

type PlottedStar = StarPoint & { isPrimary: boolean };

function createSeededRandom(seed: string): () => number {
  const normalizedSeed = seed.toLowerCase().trim();
  const randseed = new Int32Array(4);
  for (let i = 0; i < normalizedSeed.length; i += 1) {
    randseed[i % 4] = ((randseed[i % 4] << 5) - randseed[i % 4]) + normalizedSeed.charCodeAt(i);
  }
  return () => {
    const t = randseed[0] ^ (randseed[0] << 11);
    randseed[0] = randseed[1];
    randseed[1] = randseed[2];
    randseed[2] = randseed[3];
    randseed[3] = (randseed[3] ^ (randseed[3] >> 19)) ^ t ^ (t >> 8);
    return (randseed[3] >>> 0) / ((1 << 31) >>> 0);
  };
}

function scatterBackgroundStars(rand: () => number): BackgroundStar[] {
  const bgCount = 20 + Math.floor(rand() * 9);
  const bgStars: BackgroundStar[] = [];
  for (let i = 0; i < bgCount; i += 1) {
    bgStars.push({
      cx: Math.round(rand() * 320 * 10) / 10,
      cy: Math.round(rand() * 180 * 10) / 10,
      r: Math.round((0.5 + rand() * 0.7) * 10) / 10,
      opacity: Math.round((0.15 + rand() * 0.35) * 100) / 100,
    });
  }
  return bgStars;
}

function scatterCandidateStars(rand: () => number): StarPoint[] {
  const starCount = 6 + Math.floor(rand() * 3);
  const candidateStars: StarPoint[] = [];
  const minDistance = 42;
  const minDistanceSq = minDistance * minDistance;
  for (let attempt = 0; attempt < 120 && candidateStars.length < starCount; attempt += 1) {
    const x = Math.round((45 + rand() * 230) * 10) / 10;
    const y = Math.round((30 + rand() * 120) * 10) / 10;
    let tooClose = false;
    for (const existing of candidateStars) {
      const dx = existing.x - x;
      const dy = existing.y - y;
      if (dx * dx + dy * dy < minDistanceSq) {
        tooClose = true;
        break;
      }
    }
    if (tooClose) {
      continue;
    }
    candidateStars.push({
      x,
      y,
      r: Math.round((1.6 + rand() * 1.5) * 10) / 10,
      opacity: Math.round((0.85 + rand() * 0.15) * 100) / 100,
    });
  }
  return candidateStars;
}

function markPrimaryStars(candidateStars: StarPoint[]): PlottedStar[] {
  const sortedIndices = candidateStars
    .map((s, idx) => ({ r: s.r, idx }))
    .sort((a, b) => b.r - a.r);
  const primarySet = new Set(sortedIndices.slice(0, 2).map((item) => item.idx));
  return candidateStars.map((s, idx) => ({
    ...s,
    isPrimary: primarySet.has(idx),
  }));
}

function nearestOutsideStar(
  stars: PlottedStar[],
  inTree: Set<number>
): { u: number; v: number } | null {
  let bestDist = Infinity;
  let bestU = -1;
  let bestV = -1;
  for (const u of inTree) {
    for (let v = 0; v < stars.length; v += 1) {
      if (inTree.has(v)) {
        continue;
      }
      const dx = stars[u].x - stars[v].x;
      const dy = stars[u].y - stars[v].y;
      const distSq = dx * dx + dy * dy;
      if (distSq < bestDist) {
        bestDist = distSq;
        bestU = u;
        bestV = v;
      }
    }
  }
  if (bestU === -1 || bestV === -1) {
    return null;
  }
  return { u: bestU, v: bestV };
}

function spanConstellationTree(stars: PlottedStar[]): [number, number][] {
  const n = stars.length;
  const inTree = new Set<number>([0]);
  const edges: [number, number][] = [];
  while (inTree.size < n) {
    const next = nearestOutsideStar(stars, inTree);
    if (next === null) {
      break;
    }
    inTree.add(next.v);
    edges.push([next.u, next.v]);
  }
  return edges;
}

function closingConstellationEdge(
  stars: PlottedStar[],
  edges: [number, number][],
  rand: () => number
): [number, number] | null {
  if (stars.length < 4) {
    return null;
  }
  let extraDist = Infinity;
  let extraU = -1;
  let extraV = -1;
  for (let u = 0; u < stars.length; u += 1) {
    for (let v = u + 1; v < stars.length; v += 1) {
      const alreadyConnected = edges.some(
        ([a, b]) => (a === u && b === v) || (a === v && b === u)
      );
      if (alreadyConnected) {
        continue;
      }
      const dx = stars[u].x - stars[v].x;
      const dy = stars[u].y - stars[v].y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < 85 && dist < extraDist) {
        extraDist = dist;
        extraU = u;
        extraV = v;
      }
    }
  }
  if (extraU === -1 || extraV === -1 || rand() > 0.3) {
    return null;
  }
  return [extraU, extraV];
}

function toConstellationLines(
  stars: PlottedStar[],
  edges: [number, number][],
  rand: () => number
): ConstellationData["lines"] {
  return edges.map(([u, v]) => ({
    x1: stars[u].x,
    y1: stars[u].y,
    x2: stars[v].x,
    y2: stars[v].y,
    opacity: Math.round((0.26 + rand() * 0.16) * 100) / 100,
  }));
}

export function createConstellationData(seed: string): ConstellationData {
  const rand = createSeededRandom(seed);
  const nebulaHue = Math.floor(205 + rand() * 35);
  const nebulaCx = Math.floor(90 + rand() * 140);
  const nebulaCy = Math.floor(45 + rand() * 90);
  const bgStars = scatterBackgroundStars(rand);
  const stars = markPrimaryStars(scatterCandidateStars(rand));
  const edges = spanConstellationTree(stars);
  const closing = closingConstellationEdge(stars, edges, rand);
  if (closing !== null) {
    edges.push(closing);
  }
  const lines = toConstellationLines(stars, edges, rand);
  return {
    nebulaHue,
    nebulaCx,
    nebulaCy,
    bgStars,
    stars,
    lines,
  };
}
