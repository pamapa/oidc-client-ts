import { DPoPService } from "./DPoPService";
import { jwtVerify, decodeProtectedHeader, importJWK, type JWK } from "jose";
import { del, set } from "idb-keyval";

describe("DPoPService", () => {
    let subject: DPoPService;

    beforeEach(async () => {
        subject = new DPoPService();
        await del("oidc.dpop");
    });

    describe("generateDPoPProof", () => {
        it("should generate a valid proof without an access token", async () => {
            const proof = await subject.generateDPoPProof("http://example.com");
            const protectedHeader = decodeProtectedHeader(proof);
            const publicKey = await importJWK(<JWK>protectedHeader.jwk);
            const verifiedResult = await jwtVerify(proof, publicKey);

            expect(verifiedResult.payload).toHaveProperty("htu");
            expect(verifiedResult.payload).toHaveProperty("htm");
        });

        it("should generate a valid proof with an access token", async () => {
            await subject.generateDPoPProof("http://example.com");
            const proof = await subject.generateDPoPProof("http://example.com", "some_access_token");

            const protectedHeader = decodeProtectedHeader(proof);
            const publicKey = await importJWK(<JWK>protectedHeader.jwk);
            const verifiedResult = await jwtVerify(proof, publicKey);

            expect(verifiedResult.payload).toHaveProperty("htu");
            expect(verifiedResult.payload).toHaveProperty("htm");
            expect(verifiedResult.payload).toHaveProperty("ath");
            expect(verifiedResult.payload["htu"]).toEqual("http://example.com");
        });

        it("should generate a valid proof with a nonce", async () => {
            const proof = await subject.generateDPoPProof("http://example.com", undefined, undefined, "some-nonce");
            const protectedHeader = decodeProtectedHeader(proof);
            const publicKey = await importJWK(<JWK>protectedHeader.jwk);
            const verifiedResult = await jwtVerify(proof, publicKey);

            expect(verifiedResult.payload).toHaveProperty("htu");
            expect(verifiedResult.payload).toHaveProperty("htm");
            expect(verifiedResult.payload).toHaveProperty("nonce");
            expect(verifiedResult.payload["nonce"]).toEqual("some-nonce");
            expect(verifiedResult.payload["htu"]).toEqual("http://example.com");
        });

        it("should throw an exception if the stored proof keys are not a CryptoKeyPair object", async () => {
            await subject.generateDPoPProof("http://example.com");
            await set("oidc.dpop", "some string");
            await expect(subject.generateDPoPProof("http://example.com", "some_access_token"))
                .rejects.toThrowError("Could not retrieve dpop keys from storage: Key must be one of type KeyObject, CryptoKey, or Uint8Array. Received undefined");
        });

        it("should throw an exception if an access token is provided but no keys are found in the store", async () => {
            await expect(subject.generateDPoPProof("http://example.com", "some_access_token"))
                .rejects.toThrowError("Could not retrieve dpop keys from storage: Cannot read properties of undefined (reading 'publicKey')");
        });
    });
});
