// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import { MetadataService } from "./MetadataService";
import { type OidcClientSettings, OidcClientSettingsStore } from "./OidcClientSettings";

describe("MetadataService", () => {
    let settings: OidcClientSettings;
    let subject: MetadataService;

    beforeEach(() => {
        settings = {
            authority: "authority",
            client_id: "client",
            redirect_uri: "redirect",
        };
        subject = new MetadataService(new OidcClientSettingsStore(settings));
    });

    describe("resetSigningKeys", () => {
        it("should reset signing keys", () => {
            // arrange
            subject["_signingKeys"] = [{ a: "b" }];

            // act
            subject.resetSigningKeys();

            // assert
            expect(subject["_signingKeys"]).toBeNull();
        });
    });

    describe("getMetadata", () => {
        it("should use metadata on settings", async () => {
            // arrange
            settings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                metadata: { issuer: "test" },
            };
            subject = new MetadataService(new OidcClientSettingsStore(settings));

            // act
            const result = await subject.getMetadata();

            // assert
            expect(result).toEqual({ issuer: "test" });
        });

        it("should calculate metadataUrl from authority", async () => {
            // arrange
            const jsonService = subject["_jsonService"]; // access private member
            const getJsonMock = jest.spyOn(jsonService, "getJson")
                .mockResolvedValue({ foo: "bar" });

            // act
            await subject.getMetadata();

            // assert
            expect(getJsonMock).toHaveBeenCalledWith("authority/.well-known/openid-configuration", { credentials: "same-origin", timeoutInSeconds: undefined } );
        });

        it("should fail when no authority or metadataUrl configured", async () => {
            // arrange
            settings = {
                authority: "",
                client_id: "client",
                redirect_uri: "redirect",
            };
            subject = new MetadataService(new OidcClientSettingsStore(settings));

            // act
            await expect(subject.getMetadata())
                // assert
                .rejects.toThrow(/No authority or metadataUrl/);
        });

        it("should use metadataUrl to make json call", async () => {
            // arrange
            settings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                metadataUrl: "http://sts/metadata",
            };
            subject = new MetadataService(new OidcClientSettingsStore(settings));
            const jsonService = subject["_jsonService"]; // access private member
            const getJsonMock = jest.spyOn(jsonService, "getJson")
                .mockResolvedValue({ foo: "bar" });

            // act
            await subject.getMetadata();

            // assert
            expect(getJsonMock).toHaveBeenCalledWith("http://sts/metadata", { credentials: "same-origin", timeoutInSeconds: undefined });
        });

        it("should return metadata from json call", async () => {
            // arrange
            settings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                metadataUrl: "http://sts/metadata",
            };
            subject = new MetadataService(new OidcClientSettingsStore(settings));
            const jsonService = subject["_jsonService"]; // access private member
            const json = { "test": "data" };
            jest.spyOn(jsonService, "getJson").mockImplementation(() => Promise.resolve(json));

            // act
            const result = await subject.getMetadata();

            // assert
            expect(result).toEqual(json);
        });

        it("should cache metadata from json call", async () => {
            // arrange
            settings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                metadataUrl: "http://sts/metadata",
            };
            subject = new MetadataService(new OidcClientSettingsStore(settings));
            const jsonService = subject["_jsonService"]; // access private member
            const json = { test: "value" };
            jest.spyOn(jsonService, "getJson").mockImplementation(() => Promise.resolve(json));

            // act
            await subject.getMetadata();

            // assert
            const _metadata = subject["_metadata"]; // access private member
            expect(_metadata).toEqual(json);
        });

        it("should merge metadata from seed", async () => {
            // arrange
            settings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                metadataUrl: "http://sts/metadata",
                metadataSeed: { issuer: "one" },
            };
            subject = new MetadataService(new OidcClientSettingsStore(settings));
            const jsonService = subject["_jsonService"]; // access private member
            jest.spyOn(jsonService, "getJson").mockImplementation(() => Promise.resolve({ issuer: "two", jwks_uri: "two" }));

            // act
            const result = await subject.getMetadata();

            // assert
            expect(result).toEqual({ issuer: "one", jwks_uri: "two" });
            const _metadata = subject["_metadata"]; // access private member
            expect(_metadata).toEqual({ issuer: "one", jwks_uri: "two" });
        });

        it("should fail if json call fails", async () => {
            // arrange
            settings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                metadataUrl: "http://sts/metadata",
            };
            subject = new MetadataService(new OidcClientSettingsStore(settings));
            const error = new Error("test");
            const jsonService = subject["_jsonService"]; // access private member
            jest.spyOn(jsonService, "getJson").mockRejectedValue(error);

            // act
            await expect(subject.getMetadata())
                // assert
                .rejects.toThrow(error);
        });

        it("should use getRequestCredentials to make json call when set", async () => {
            // arrange
            settings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                metadataUrl: "http://sts/metadata",
                fetchRequestCredentials: "include",
            };
            subject = new MetadataService(new OidcClientSettingsStore(settings));
            const jsonService = subject["_jsonService"]; // access private member
            const getJsonMock = jest.spyOn(jsonService, "getJson")
                .mockResolvedValue({ foo: "bar" });

            // act
            await subject.getMetadata();

            // assert
            expect(getJsonMock).toHaveBeenCalledWith("http://sts/metadata", { credentials: "include", timeoutInSeconds: undefined });
        });
    });

    describe("getIssuer", () => {
        it("should use metadata on settings", async () => {
            // arrange
            settings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                metadata: {
                    issuer: "test",
                },
            };
            subject = new MetadataService(new OidcClientSettingsStore(settings));

            // act
            const result = await subject.getIssuer();

            // assert
            expect(result).toEqual("test");
        });

        it("should fail if no data on metadata", async () => {
            // arrange
            settings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                metadata: {
                },
            };
            subject = new MetadataService(new OidcClientSettingsStore(settings));

            // act
            await expect(subject.getIssuer())
                // assert
                .rejects.toThrow(/issuer/);
        });

        it("should fail if json call to load metadata fails", async () => {
            // arrange
            settings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                metadataUrl: "http://sts/metadata",
            };
            subject = new MetadataService(new OidcClientSettingsStore(settings));
            const error = new Error("test");
            const jsonService = subject["_jsonService"]; // access private member
            jest.spyOn(jsonService, "getJson").mockRejectedValue(error);

            // act
            await expect(subject.getIssuer())
                // assert
                .rejects.toThrow(error);
        });

        it("should return value from", async () => {
            // arrange
            settings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                metadata: {
                    issuer: "http://sts",
                },
            };
            subject = new MetadataService(new OidcClientSettingsStore(settings));

            // act
            const result = await subject.getIssuer();

            // assert
            expect(result).toEqual("http://sts");
        });
    });

    describe("getAuthorizationEndpoint", () => {
        it("should return value from metadata", async () => {
            // arrange
            settings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                metadata: {
                    authorization_endpoint: "http://sts/authorize",
                },
            };
            subject = new MetadataService(new OidcClientSettingsStore(settings));

            // act
            const result = await subject.getAuthorizationEndpoint();

            // assert
            expect(result).toEqual("http://sts/authorize");
        });
    });

    describe("getUserInfoEndpoint", () => {
        it("should return value from", async () => {
            // arrange
            settings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                metadata: {
                    userinfo_endpoint: "http://sts/userinfo",
                },
            };
            subject = new MetadataService(new OidcClientSettingsStore(settings));

            // act
            const result = await subject.getUserInfoEndpoint();

            // assert
            expect(result).toEqual("http://sts/userinfo");
        });
    });

    describe("getTokenEndpoint", () => {
        it("should return value from", async () => {
            // arrange
            settings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                metadata: {
                    token_endpoint: "http://sts/tokeninfo",
                },
            };
            subject = new MetadataService(new OidcClientSettingsStore(settings));

            // act
            const result = await subject.getTokenEndpoint();

            // assert
            expect(result).toEqual("http://sts/tokeninfo");
        });
    });

    describe("getCheckSessionIframe", () => {
        it("should return value from", async () => {
            // arrange
            settings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                metadata: {
                    check_session_iframe: "http://sts/check_session",
                },
            };
            subject = new MetadataService(new OidcClientSettingsStore(settings));

            // act
            const result = await subject.getCheckSessionIframe();

            // assert
            expect(result).toEqual("http://sts/check_session");
        });

        it("should support optional value", async () => {
            // arrange
            settings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                metadata: {
                },
            };
            subject = new MetadataService(new OidcClientSettingsStore(settings));

            // act
            const result = await subject.getCheckSessionIframe();

            // assert
            expect(result).toBeUndefined();
        });
    });

    describe("getEndSessionEndpoint", () => {
        it("should return value from", async () => {
            // arrange
            settings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                metadata: {
                    end_session_endpoint: "http://sts/signout",
                },
            };
            subject = new MetadataService(new OidcClientSettingsStore(settings));

            // act
            const result = await subject.getEndSessionEndpoint();

            // assert
            expect(result).toEqual("http://sts/signout");
        });

        it("should support optional value", async () => {
            // arrange
            settings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                metadata: {
                },
            };
            subject = new MetadataService(new OidcClientSettingsStore(settings));

            // act
            const result = await subject.getEndSessionEndpoint();

            // assert
            expect(result).toBeUndefined();
        });
    });

    describe("getRevocationEndpoint", () => {
        it("should return value from", async () => {
            // arrange
            settings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                metadata: {
                    revocation_endpoint: "http://sts/revocation",
                },
            };
            subject = new MetadataService(new OidcClientSettingsStore(settings));

            // act
            const result = await subject.getRevocationEndpoint();

            // assert
            expect(result).toEqual("http://sts/revocation");
        });

        it("should support optional value", async () => {
            // arrange
            settings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                metadata: {
                },
            };
            subject = new MetadataService(new OidcClientSettingsStore(settings));

            // act
            const result = await subject.getRevocationEndpoint();

            // assert
            expect(result).toBeUndefined();
        });
    });

    describe("getSigningKeys", () => {
        it("should use signingKeys on settings", async () => {
            // arrange
            settings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                signingKeys: [{ kid: "test" }],
            };
            subject = new MetadataService(new OidcClientSettingsStore(settings));

            // act
            const result = await subject.getSigningKeys();

            // assert
            expect(result).toEqual([{ kid: "test" }]);
        });

        it("should fail if metadata does not have jwks_uri", async () => {
            // arrange
            settings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                metadata: { issuer: "test" },
            };
            subject = new MetadataService(new OidcClientSettingsStore(settings));

            // act
            await expect(subject.getSigningKeys())
                // assert
                .rejects.toThrow(/jwks_uri/);
        });

        it("should fail if keys missing on keyset from jwks_uri", async () => {
            // arrange
            settings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                metadata: {
                    jwks_uri: "http://sts/metadata/keys",
                },
            };
            subject = new MetadataService(new OidcClientSettingsStore(settings));
            const jsonService = subject["_jsonService"]; // access private member
            jest.spyOn(jsonService, "getJson").mockImplementation(() => Promise.resolve({}));

            // act
            await expect(subject.getSigningKeys())
                // assert
                .rejects.toThrow(/keyset/);
        });

        it("should make json call to jwks_uri", async () => {
            // arrange
            settings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                metadata: {
                    jwks_uri: "http://sts/metadata/keys",
                },
            };
            subject = new MetadataService(new OidcClientSettingsStore(settings));
            const jsonService = subject["_jsonService"]; // access private member
            const json = {
                keys: [{
                    use:"sig",
                    kid:"test",
                }],
            };
            const getJsonMock = jest.spyOn(jsonService, "getJson")
                .mockImplementation(() => Promise.resolve(json));

            // act
            await subject.getSigningKeys();

            // assert
            expect(getJsonMock).toHaveBeenCalledWith("http://sts/metadata/keys", { "timeoutInSeconds": undefined });
        });

        it("should return keys from jwks_uri", async () => {
            // arrange
            settings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                metadata: {
                    jwks_uri: "http://sts/metadata/keys",
                },
            };
            subject = new MetadataService(new OidcClientSettingsStore(settings));
            const jsonService = subject["_jsonService"]; // access private member
            const expectedKeys = [{
                use:"sig",
                kid:"test",
            }];
            const json = {
                keys: expectedKeys,
            };
            jest.spyOn(jsonService, "getJson").mockImplementation(() => Promise.resolve(json));

            // act
            const result = await subject.getSigningKeys();

            // assert
            expect(result).toEqual(expectedKeys);
        });

        it("should cache keys from json call", async () => {
            // arrange
            settings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                metadata: {
                    jwks_uri: "http://sts/metadata/keys",
                },
            };
            subject = new MetadataService(new OidcClientSettingsStore(settings));
            const jsonService = subject["_jsonService"]; // access private member
            const expectedKeys = [{
                use:"sig",
                kid:"test",
            }];
            const json = {
                keys: expectedKeys,
            };
            jest.spyOn(jsonService, "getJson").mockImplementation(() => Promise.resolve(json));

            // act
            await subject.getSigningKeys();

            // assert
            const _signingKeys = subject["_signingKeys"]; // access private member
            expect(_signingKeys).toEqual(expectedKeys);
        });
    });
});
