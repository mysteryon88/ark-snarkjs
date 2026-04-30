import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { groth16 } from "snarkjs";
import type { Groth16Proof, PublicSignals } from "snarkjs";
import { beforeAll, describe, expect, it } from "vitest";

process.env.FFJAVASCRIPT_MAX_WORKERS = "0";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");
const targetOutputRoot = resolve(repoRoot, "target", "test-output");

type SnarkProof = {
  publicSignals: PublicSignals;
} & Groth16Proof;

type ArtifactPair = {
  label: string;
  proofPath: string;
  verificationKeyPath: string;
};

beforeAll(() => {
  // snarkjs falls back to single-threaded verification when Worker is unavailable.
  // @ts-expect-error Reassigning Worker on the global object is intentional here.
  globalThis.Worker = undefined;
});

function loadJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

function collectArtifactPairs(root: string): ArtifactPair[] {
  if (!existsSync(root)) {
    return [];
  }

  const pairs: ArtifactPair[] = [];
  const stack = [root];

  while (stack.length > 0) {
    const current = stack.pop()!;

    for (const entry of readdirSync(current, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        stack.push(resolve(current, entry.name));
      }
    }

    const proofPath = resolve(current, "proof.json");
    const verificationKeyPath = resolve(current, "verification_key.json");

    if (existsSync(proofPath) && existsSync(verificationKeyPath)) {
      pairs.push({
        label: relative(targetOutputRoot, current).replaceAll("\\", "/"),
        proofPath,
        verificationKeyPath,
      });
    }
  }

  return pairs.sort((left, right) => left.label.localeCompare(right.label));
}

function makeWrongPublicSignals(publicSignals: PublicSignals): PublicSignals {
  if (publicSignals.length === 0) {
    return ["1"];
  }

  const wrongSignals = [...publicSignals];
  wrongSignals[0] = wrongSignals[0] === "0" ? "1" : "0";
  return wrongSignals;
}

const artifactPairs = collectArtifactPairs(targetOutputRoot);

describe("snarkjs verification for target/test-output exports", () => {
  it("finds at least one proof and verification key pair", () => {
    expect(artifactPairs.length).toBeGreaterThan(0);
  });

  for (const artifact of artifactPairs) {
    describe(artifact.label, () => {
      it("verifies exported proof with snarkjs", async () => {
        const verificationKey = loadJson<Record<string, unknown>>(
          artifact.verificationKeyPath,
        );
        const proof = loadJson<SnarkProof>(artifact.proofPath);

        expect(Array.isArray(proof.publicSignals)).toBe(true);

        const verified = await groth16.verify(
          verificationKey,
          proof.publicSignals,
          proof,
        );

        expect(verified).toBe(true);
      });

      it("rejects wrong public signals", async () => {
        const verificationKey = loadJson<Record<string, unknown>>(
          artifact.verificationKeyPath,
        );
        const proof = loadJson<SnarkProof>(artifact.proofPath);
        const wrongPublicSignals = makeWrongPublicSignals(proof.publicSignals);

        const verified = await groth16.verify(
          verificationKey,
          wrongPublicSignals,
          proof,
        );

        expect(verified).toBe(false);
      });
    });
  }
});
