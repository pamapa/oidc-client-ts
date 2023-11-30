import { WebStorageStateStore } from "./WebStorageStateStore";
import * as jose from "jose";
import { SignJWT, base64url } from "jose";

export class DPoPService {

    public readonly keyStore: WebStorageStateStore;

    public constructor() {
        this.keyStore = new WebStorageStateStore({ prefix: ".dpop", store: window.sessionStorage });
    }
    public async generateDPoPProofForAccessTokenRequest() : Promise<string> {
        const keyPair = await this.generateKeys();
        await this.keyStore.set("dpopKeys", JSON.stringify(keyPair));

        const publicJwk = await jose.exportJWK(keyPair.publicKey);

        const dpopProofJwt = await new SignJWT({
            "jti": window.crypto.randomUUID(),
            "htm": "POST",
            "htu": "https://localhost:5001/connect/token",
        })
            .setProtectedHeader({
                "alg": "ES256",
                "typ": "dpop+jwt",
                "jwk": publicJwk,
            }).setIssuedAt().sign(keyPair.privateKey);

        console.log("DPoP proof token for requesting access token: ", dpopProofJwt);
        return dpopProofJwt;
    }

    public async generateDPoPProof(accessToken : string) : Promise<string> {
        const keyPairString = await this.keyStore.get("dpopKeys");

        const keyPair = JSON.parse(keyPairString as string) as CryptoKeyPair;

        const publicJwk = await jose.exportJWK(keyPair.publicKey);

        const digestHex = await this.digestMessage(accessToken);
        console.log("Hash: ", digestHex);
        const hash = base64url.encode(digestHex);
        console.log("Base64 encoded hash: ", hash);

        const dpopProofJwt = await new SignJWT({
            "jti": window.crypto.randomUUID(),
            "htm": "GET",
            "htu": "https://localhost:5005/identity",
            "ath": hash,
        }).setProtectedHeader({
            "alg": "ES256",
            "typ": "dpop+jwt",
            "jwk": publicJwk,
        }).setIssuedAt().sign(keyPair.privateKey);

        console.log("DPoP proof token for requesting access token: ", dpopProofJwt);
        return dpopProofJwt;
    }

    protected async digestMessage(message: string) : Promise<Uint8Array> {
        const msgUint8 = new TextEncoder().encode(message);
        console.log("access token as Unit8Array", msgUint8);
        const hashBuffer = await crypto.subtle.digest("SHA-256", msgUint8);
        return new Uint8Array(hashBuffer);
    }

    protected async generateKeys() : Promise<CryptoKeyPair> {
        return await window.crypto.subtle.generateKey(
            {
                name: "ECDSA",
                namedCurve: "P-256",
            },
            true,
            ["sign", "verify"],
        );
    }
}
