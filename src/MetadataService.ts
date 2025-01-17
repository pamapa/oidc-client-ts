// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import { Logger } from "./utils";
import { JsonService } from "./JsonService";
import type { OidcClientSettingsStore, SigningKey } from "./OidcClientSettings";
import type { OidcMetadata } from "./OidcMetadata";

/**
 * @public
 * @see https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
 */
export class MetadataService {
    private readonly _logger = new Logger("MetadataService");
    private readonly _jsonService;

    // cache
    private _metadataUrl: string;
    private _signingKeys: SigningKey[] | null = null;
    private _metadata: Partial<OidcMetadata> | null = null;
    private _fetchRequestCredentials: RequestCredentials | undefined;

    public constructor(private readonly _settings: OidcClientSettingsStore) {
        this._metadataUrl = this._settings.metadataUrl;
        this._jsonService = new JsonService(
            ["application/jwk-set+json"],
            null,
            this._settings.extraHeaders,
        );
        if (this._settings.signingKeys) {
            this._logger.debug("using signingKeys from settings");
            this._signingKeys = this._settings.signingKeys;
        }

        if (this._settings.metadata) {
            this._logger.debug("using metadata from settings");
            this._metadata = this._settings.metadata;
        }

        if (this._settings.fetchRequestCredentials) {
            this._logger.debug("using fetchRequestCredentials from settings");
            this._fetchRequestCredentials = this._settings.fetchRequestCredentials;
        }
    }

    public resetSigningKeys(): void {
        this._signingKeys = null;
    }

    public async getMetadata(): Promise<Partial<OidcMetadata>> {
        const logger = this._logger.create("getMetadata");
        if (this._metadata) {
            logger.debug("using cached values");
            return this._metadata;
        }

        if (!this._metadataUrl) {
            logger.throw(new Error("No authority or metadataUrl configured on settings"));
            // eslint-disable-next-line @typescript-eslint/only-throw-error
            throw null; // https://github.com/microsoft/TypeScript/issues/46972
        }

        logger.debug("getting metadata from", this._metadataUrl);
        const metadata = await this._jsonService.getJson(this._metadataUrl, { credentials: this._fetchRequestCredentials, timeoutInSeconds: this._settings.requestTimeoutInSeconds });

        logger.debug("merging remote JSON with seed metadata");
        this._metadata = Object.assign({}, metadata, this._settings.metadataSeed);
        return this._metadata;
    }

    public getIssuer(): Promise<string> {
        return this._getMetadataProperty("issuer") as Promise<string>;
    }

    public getAuthorizationEndpoint(): Promise<string> {
        return this._getMetadataProperty("authorization_endpoint") as Promise<string>;
    }

    public getUserInfoEndpoint(): Promise<string> {
        return this._getMetadataProperty("userinfo_endpoint") as Promise<string>;
    }

    public getTokenEndpoint(optional: false): Promise<string>;
    public getTokenEndpoint(optional?: true): Promise<string | undefined>;
    public getTokenEndpoint(optional = true): Promise<string | undefined> {
        return this._getMetadataProperty("token_endpoint", optional) as Promise<string | undefined>;
    }

    public getCheckSessionIframe(): Promise<string | undefined> {
        return this._getMetadataProperty("check_session_iframe", true) as Promise<string | undefined>;
    }

    public getEndSessionEndpoint(): Promise<string | undefined> {
        return this._getMetadataProperty("end_session_endpoint", true) as Promise<string | undefined>;
    }

    public getRevocationEndpoint(optional: false): Promise<string>;
    public getRevocationEndpoint(optional?: true): Promise<string | undefined>;
    public getRevocationEndpoint(optional = true): Promise<string | undefined> {
        return this._getMetadataProperty("revocation_endpoint", optional) as Promise<string | undefined>;
    }

    public getKeysEndpoint(optional: false): Promise<string>;
    public getKeysEndpoint(optional?: true): Promise<string | undefined>;
    public getKeysEndpoint(optional = true): Promise<string | undefined> {
        return this._getMetadataProperty("jwks_uri", optional) as Promise<string | undefined>;
    }

    protected async _getMetadataProperty(name: keyof OidcMetadata, optional=false): Promise<string | boolean | string[] | undefined> {
        const logger = this._logger.create(`_getMetadataProperty('${name}')`);

        const metadata = await this.getMetadata();
        logger.debug("resolved");

        if (metadata[name] === undefined) {
            if (optional === true) {
                logger.warn("Metadata does not contain optional property");
                return undefined;
            }

            logger.throw(new Error("Metadata does not contain property " + name));
        }

        return metadata[name];
    }

    public async getSigningKeys(): Promise<SigningKey[] | null> {
        const logger = this._logger.create("getSigningKeys");
        if (this._signingKeys) {
            logger.debug("returning signingKeys from cache");
            return this._signingKeys;
        }

        const jwks_uri = await this.getKeysEndpoint(false);
        logger.debug("got jwks_uri", jwks_uri);

        const keySet = await this._jsonService.getJson(jwks_uri, { timeoutInSeconds: this._settings.requestTimeoutInSeconds });
        logger.debug("got key set", keySet);

        if (!Array.isArray(keySet.keys)) {
            logger.throw(new Error("Missing keys on keyset"));
            // eslint-disable-next-line @typescript-eslint/only-throw-error
            throw null; // https://github.com/microsoft/TypeScript/issues/46972
        }

        this._signingKeys = keySet.keys;
        return this._signingKeys;
    }
}
