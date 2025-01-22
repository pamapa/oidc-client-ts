// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import { CryptoUtils, JwtUtils, URL_STATE_DELIMITER } from "./utils";
import type { ErrorResponse } from "./errors";
import type { JwtClaims } from "./Claims";
import { OidcClient } from "./OidcClient";
import { type ExtraHeader, type OidcClientSettings, OidcClientSettingsStore } from "./OidcClientSettings";
import { SigninState } from "./SigninState";
import { State } from "./State";
import { SigninRequest } from "./SigninRequest";
import { SignoutRequest } from "./SignoutRequest";
import { SignoutResponse } from "./SignoutResponse";
import { RefreshState } from "./RefreshState";
import { SigninResponse } from "./SigninResponse";
import type { UserProfile } from "./User";
import { IndexedDbDPoPStore } from "./IndexedDbDPoPStore";
import { ErrorDPoPNonce } from "./errors/ErrorDPoPNonce";
import { DPoPState } from "./DPoPStore";

describe("OidcClient", () => {
    let subject: OidcClient;

    beforeEach(() => {
        subject = new OidcClient({
            authority: "authority",
            client_id: "client",
            redirect_uri: "redirect",
            post_logout_redirect_uri: "http://app",
        });
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    describe("constructor", () => {
        it("should expose settings", () => {
            // assert
            expect(subject.settings).not.toBeNull();
            expect(subject.settings.client_id).toEqual("client");
        });
    });

    describe("settings", () => {

        it("should be OidcClientSettings", () => {
            // assert
            expect(subject.settings).toBeInstanceOf(OidcClientSettingsStore);
        });
    });

    describe("createSigninRequest", () => {

        it("should return SigninRequest", async () => {
            // arrange
            const args = {
                redirect_uri: "redirect",
                response_type: "code",
                scope: "scope",
            };
            jest.spyOn(subject.metadataService, "getAuthorizationEndpoint").mockImplementation(() => Promise.resolve("http://sts/authorize"));

            // act
            const request = await subject.createSigninRequest(args);

            // assert
            expect(request).toBeInstanceOf(SigninRequest);
        });

        it("should pass params to SigninRequest", async () => {
            // arrange
            jest.spyOn(subject.metadataService, "getAuthorizationEndpoint").mockImplementation(() => Promise.resolve("http://sts/authorize"));

            // act
            const request = await subject.createSigninRequest({
                state: "foo",
                response_type: "code",
                response_mode: "fragment",
                scope: "baz",
                redirect_uri: "quux",
                prompt: "p",
                display: "d",
                max_age: 42,
                ui_locales: "u",
                id_token_hint: "ith",
                login_hint: "lh",
                acr_values: "av",
                resource: "res",
                request: "req",
                request_uri: "req_uri",
                nonce: "rnd",
                url_state: "url_state",
            });

            // assert
            expect(request.state.data).toEqual("foo");
            const url = request.url;
            expect(url).toContain("http://sts/authorize");
            expect(url).toContain("response_type=code");
            expect(url).toContain("scope=baz");
            expect(url).toContain("redirect_uri=quux");
            expect(url).toContain("prompt=p");
            expect(url).toContain("display=d");
            expect(url).toContain("max_age=42");
            expect(url).toContain("ui_locales=u");
            expect(url).toContain("id_token_hint=ith");
            expect(url).toContain("login_hint=lh");
            expect(url).toContain("acr_values=av");
            expect(url).toContain("resource=res");
            expect(url).toContain("request=req");
            expect(url).toContain("request_uri=req_uri");
            expect(url).toContain("response_mode=fragment");
            expect(url).toContain("nonce=rnd");
            expect(url.match(/state=.*%3Burl_state/)).toBeTruthy();
        });

        it("should pass state in place of data to SigninRequest", async () => {
            // arrange
            jest.spyOn(subject.metadataService, "getAuthorizationEndpoint").mockImplementation(() => Promise.resolve("http://sts/authorize"));

            // act
            const request = await subject.createSigninRequest({
                state: "foo",
                response_type: "code",
                scope: "baz",
                redirect_uri: "quux",
                prompt: "p",
                display: "d",
                max_age: 42,
                ui_locales: "u",
                id_token_hint: "ith",
                login_hint: "lh",
                acr_values: "av",
                resource: "res",
                url_state: "url_state",
            });

            // assert
            expect(request.state.data).toEqual("foo");
            const url = request.url;
            expect(url).toContain("http://sts/authorize");
            expect(url).toContain("response_type=code");
            expect(url).toContain("scope=baz");
            expect(url).toContain("redirect_uri=quux");
            expect(url).toContain("prompt=p");
            expect(url).toContain("display=d");
            expect(url).toContain("max_age=42");
            expect(url).toContain("ui_locales=u");
            expect(url).toContain("id_token_hint=ith");
            expect(url).toContain("login_hint=lh");
            expect(url).toContain("acr_values=av");
            expect(url).toContain("resource=res");
            expect(url.match(/state=.*%3Burl_state/)).toBeTruthy();
        });

        it("should exclude scope from SigninRequest if omitScopeWhenRequesting is true", async () => {
            // arrange
            jest.spyOn(subject.metadataService, "getAuthorizationEndpoint").mockImplementation(() => Promise.resolve("http://sts/authorize"));

            // act
            const request = await subject.createSigninRequest({
                state: "foo",
                response_type: "code",
                scope: "baz",
                redirect_uri: "quux",
                prompt: "p",
                display: "d",
                max_age: 42,
                ui_locales: "u",
                id_token_hint: "ith",
                login_hint: "lh",
                acr_values: "av",
                resource: "res",
                url_state: "url_state",
                omitScopeWhenRequesting: true,
            });

            // assert
            expect(request.state.data).toEqual("foo");
            const url = request.url;
            expect(url).not.toContain("scope");
        });

        it("should fail if implicit flow requested", async () => {
            // arrange
            const args = {
                redirect_uri: "redirect",
                scope: "scope",
                response_type: "id_token",
            };

            // act
            try {
                await subject.createSigninRequest(args);
                fail("should not come here");
            }
            catch (err) {
                expect(err).toBeInstanceOf(Error);
                expect((err as Error).message).toContain("Only the Authorization Code flow");
            }
        });

        it("should fail if metadata fails", async () => {
            // arrange
            const args = {
                redirect_uri: "redirect",
                response_type: "code",
                scope: "scope",
            };
            jest.spyOn(subject.metadataService, "getAuthorizationEndpoint").mockRejectedValue(new Error("test"));

            // act
            try {
                await subject.createSigninRequest(args);
                fail("should not come here");
            }
            catch (err) {
                expect(err).toBeInstanceOf(Error);
                expect((err as Error).message).toContain("test");
            }
        });

        it("should fail if setting state into store fails", async () => {
            // arrange
            const args = {
                redirect_uri: "redirect",
                response_type: "code",
                scope: "scope",
            };
            jest.spyOn(subject.metadataService, "getAuthorizationEndpoint").mockImplementation(() => Promise.resolve("http://sts/authorize"));
            jest.spyOn(subject.settings.stateStore, "set").mockRejectedValue(new Error("foo"));

            // act
            try {
                await subject.createSigninRequest(args);
                fail("should not come here");
            }
            catch (err) {
                expect(err).toBeInstanceOf(Error);
                expect((err as Error).message).toContain("foo");
            }
        });

        it("should store state", async () => {
            // arrange
            const args = {
                redirect_uri: "redirect",
                response_type: "code",
                scope: "scope",
            };
            jest.spyOn(subject.metadataService, "getAuthorizationEndpoint").mockImplementation(() => Promise.resolve("http://sts/authorize"));
            const setMock = jest.spyOn(subject.settings.stateStore, "set").mockImplementation(() => Promise.resolve());

            // act
            await subject.createSigninRequest(args);

            // assert
            expect(setMock).toHaveBeenCalled();
        });
    });

    describe("readSigninResponseState", () => {

        it("should fail if no state on response", async () => {
            // arrange
            jest.spyOn(subject.settings.stateStore, "get").mockImplementation(() => Promise.resolve("state"));

            // act
            try {
                await subject.readSigninResponseState("http://app/cb");
                fail("should not come here");
            }
            catch (err) {
                expect(err).toBeInstanceOf(Error);
                expect((err as Error).message).toContain("state");
            }
        });

        it("should fail if storage fails", async () => {
            // arrange
            jest.spyOn(subject.settings.stateStore, "get").mockRejectedValue(new Error("fail"));

            // act
            try {
                await subject.readSigninResponseState("http://app/cb?state=state");
                fail("should not come here");
            }
            catch (err) {
                expect(err).toBeInstanceOf(Error);
                expect((err as Error).message).toContain("fail");
            }
        });

        it("should deserialize stored state and return state and response", async () => {
            // arrange
            const item = await SigninState.create({
                id: "1",
                authority: "authority",
                client_id: "client",
                redirect_uri: "http://app/cb",
                scope: "scope",
                request_type: "type",
            });
            jest.spyOn(subject.settings.stateStore, "get").mockImplementation(() => Promise.resolve(item.toStorageString()));

            // act
            const { state, response } = await subject.readSigninResponseState("http://app/cb?state=1");

            // assert
            expect(state.id).toEqual("1");
            expect(state.authority).toEqual("authority");
            expect(state.client_id).toEqual("client");
            expect(state.request_type).toEqual("type");
            expect(response.state).toEqual("1");
        });
    });

    describe("processSigninResponse", () => {
        it("should fail if no state on response", async () => {
            // arrange
            jest.spyOn(subject.settings.stateStore, "get").mockImplementation(() => Promise.resolve("state"));

            // act
            try {
                await subject.processSigninResponse("http://app/cb");
                fail("should not come here");
            }
            catch (err) {
                expect(err).toBeInstanceOf(Error);
                expect((err as Error).message).toContain("state");
            }
        });

        it("should fail if storage fails", async () => {
            // arrange
            jest.spyOn(subject.settings.stateStore, "remove").mockRejectedValue(new Error("fail"));

            // act
            try {
                await subject.processSigninResponse("http://app/cb?state=state");
                fail("should not come here");
            }
            catch (err) {
                expect(err).toBeInstanceOf(Error);
                expect((err as Error).message).toContain("fail");
            }
        });

        it("should deserialize stored state and call validator", async () => {
            // arrange
            const item = await SigninState.create({
                id: "1",
                authority: "authority",
                client_id: "client",
                redirect_uri: "http://app/cb",
                scope: "scope",
                request_type: "type",
            });
            jest.spyOn(subject.settings.stateStore, "remove")
                .mockImplementation(async () => item.toStorageString());
            const validateSigninResponseMock = jest.spyOn(subject["_validator"], "validateSigninResponse")
                .mockResolvedValue();

            // act
            const response = await subject.processSigninResponse("http://app/cb?state=1");

            // assert
            expect(validateSigninResponseMock).toHaveBeenCalledWith(response, item, undefined);
        });

        it("should pass on extraHeaders if supplied", async () => {
            // arrange
            const item = await SigninState.create({
                id: "1",
                authority: "authority",
                client_id: "client",
                redirect_uri: "http://app/cb",
                scope: "scope",
                request_type: "type",
            });

            const extraHeaders: Record<string, ExtraHeader> = { "foo": "bar" };

            jest.spyOn(subject.settings.stateStore, "remove")
                .mockImplementation(async () => item.toStorageString());
            const validateSigninResponseMock = jest.spyOn(subject["_validator"], "validateSigninResponse")
                .mockResolvedValue();

            // act
            const response = await subject.processSigninResponse("http://app/cb?state=1", extraHeaders);

            // assert
            expect(validateSigninResponseMock).toHaveBeenCalledWith(response, item, extraHeaders);
        });

        it("should pass DPoP extraHeader if enabled", async () => {
            subject = new OidcClient({
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                post_logout_redirect_uri: "http://app",
                dpop: {
                    bind_authorization_code: false,
                    store: new IndexedDbDPoPStore(),
                },
            });

            // arrange
            const item = await SigninState.create({
                id: "1",
                authority: "authority",
                client_id: "client",
                redirect_uri: "http://app/cb",
                scope: "scope",
                request_type: "type",
            });
            jest.spyOn(subject.settings.stateStore, "remove")
                .mockImplementation(async () => item.toStorageString());
            const validateSigninResponseMock = jest.spyOn(subject["_validator"], "validateSigninResponse")
                .mockResolvedValue();
            const metadataServiceMock = jest.spyOn(subject["metadataService"], "getTokenEndpoint").mockResolvedValue("http://sts/token");

            // act
            const response = await subject.processSigninResponse("http://app/cb?state=1");

            // assert
            expect(metadataServiceMock).toHaveBeenCalled();
            expect(validateSigninResponseMock).toHaveBeenCalledWith(response, item, { "DPoP": expect.any(String) });
        });

        it("should retry code request if original fails with ErrorDPoPNonce exception", async () => {
            subject = new OidcClient({
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                post_logout_redirect_uri: "http://app",
                dpop: {
                    bind_authorization_code: false,
                    store: new IndexedDbDPoPStore(),
                },
            });

            // arrange
            const item = await SigninState.create({
                id: "1",
                authority: "authority",
                client_id: "client",
                redirect_uri: "http://app/cb",
                scope: "scope",
                request_type: "type",
            });
            jest.spyOn(subject.settings.stateStore, "remove")
                .mockImplementation(async () => item.toStorageString());
            const validateSigninResponseMock = jest.spyOn(subject["_validator"], "validateSigninResponse")
                .mockRejectedValueOnce(new ErrorDPoPNonce("some-nonce"));
            const getDpopProofMock = jest.spyOn(subject, "getDpopProof");
            const metadataServiceMock = jest.spyOn(subject["metadataService"], "getTokenEndpoint").mockResolvedValue("http://sts/token");
            // act
            await subject.processSigninResponse("http://app/cb?state=1");

            // assert
            expect(metadataServiceMock).toHaveBeenCalled();
            expect(validateSigninResponseMock).toHaveBeenCalledTimes(2);
            expect(getDpopProofMock).toHaveBeenCalledTimes(2);
            expect(getDpopProofMock).toHaveBeenNthCalledWith(2, { "_dbName": "oidc", "_storeName": "dpop" }, "some-nonce");
        });

        it("should not delete state when removeState = false", async () => {
            // arrange
            const item = await SigninState.create({
                id: "1",
                authority: "authority",
                client_id: "client",
                redirect_uri: "http://app/cb",
                scope: "scope",
                request_type: "type",
            });
            const getStateMock = jest.spyOn(subject.settings.stateStore, "get")
                .mockImplementation(async () => item.toStorageString());
            const removeStateMock = jest.spyOn(subject.settings.stateStore, "remove")
                .mockImplementation(async () => item.toStorageString());
            jest.spyOn(subject["_validator"], "validateSigninResponse").mockResolvedValue();

            // act
            await subject.processSigninResponse("http://app/cb?state=1", undefined, false);

            // assert
            expect(getStateMock).toHaveBeenCalled();
            expect(removeStateMock).not.toHaveBeenCalled();
        });
    });

    describe("processResourceOwnerPasswordCredentials", () => {

        it("should fail on wrong credentials", async () => {
            // arrange
            jest.spyOn(subject["_tokenClient"], "exchangeCredentials").mockRejectedValue(new Error("Wrong credentials"));

            // act
            await expect(subject.processResourceOwnerPasswordCredentials({ username: "u", password: "p", skipUserInfo: false }))
                // assert
                .rejects.toThrow(Error);
        });

        it("should fail on invalid response", async () => {
            // arrange
            jest.spyOn(subject["_tokenClient"], "exchangeCredentials").mockResolvedValue({});
            jest.spyOn(subject["_validator"], "validateCredentialsResponse").mockRejectedValue(new Error("Wrong response"));

            // act
            await expect(subject.processResourceOwnerPasswordCredentials({ username: "u", password: "p", skipUserInfo: false }))
                // assert
                .rejects.toThrow(Error);
        });

        it("should return response on success", async () => {
            // arrange
            jest.spyOn(subject["_tokenClient"], "exchangeCredentials").mockResolvedValue({
                access_token: "access_token",
                id_token: "id_token",
                scope: "openid profile email",
            });
            jest.spyOn(subject["_validator"], "validateCredentialsResponse").mockImplementation(
                async (response: SigninResponse): Promise<void> => {
                    Object.assign(response, { profile: { sub: "subsub" } });
                },
            );

            // act
            const signinResponse: SigninResponse = await subject.processResourceOwnerPasswordCredentials({ username: "u", password: "p", skipUserInfo: false });

            // assert
            expect(signinResponse).toHaveProperty("access_token", "access_token");
            expect(signinResponse).toHaveProperty("id_token", "id_token");
            expect(signinResponse).toHaveProperty("scope", "openid profile email");
            expect(signinResponse).toHaveProperty("profile", { sub: "subsub" });
        });

    });

    describe("useRefreshToken", () => {
        it("should return a SigninResponse", async () => {
            // arrange
            const tokenResponse = {
                access_token: "new_access_token",
                scope: "replacement scope",
            };
            jest.spyOn(subject["_tokenClient"], "exchangeRefreshToken").mockResolvedValue(tokenResponse);
            const state = new RefreshState({
                refresh_token: "refresh_token",
                id_token: "id_token",
                session_state: "session_state",
                scope: "openid",
                profile: {} as UserProfile,
            });

            // act
            const response = await subject.useRefreshToken({ state });

            // assert
            expect(response).toBeInstanceOf(SigninResponse);
            expect(response).toMatchObject(tokenResponse);
        });

        it("should preserve the session_state and scope", async () => {
            // arrange
            const tokenResponse = {
                access_token: "new_access_token",
            };
            const exchangeRefreshTokenMock =
                jest.spyOn(subject["_tokenClient"], "exchangeRefreshToken")
                    .mockResolvedValue(tokenResponse);
            jest.spyOn(JwtUtils, "decode").mockReturnValue({ sub: "sub" });
            const state = new RefreshState({
                refresh_token: "refresh_token",
                id_token: "id_token",
                session_state: "session_state",
                scope: "openid",
                profile: {} as UserProfile,
            });

            // act
            const response = await subject.useRefreshToken({ state, resource: "resource" });

            // assert
            expect(exchangeRefreshTokenMock).toHaveBeenCalledWith( {
                refresh_token: "refresh_token",
                scope: "openid",
                timeoutInSeconds: undefined,
                resource: "resource",
            });
            expect(response).toBeInstanceOf(SigninResponse);
            expect(response).toMatchObject(tokenResponse);
            expect(response).toHaveProperty("session_state", state.session_state);
            expect(response).toHaveProperty("scope", state.scope);
        });

        it("should filter allowable scopes", async () => {
            // arrange
            const settings: OidcClientSettings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                post_logout_redirect_uri: "http://app",
                refreshTokenAllowedScope: "allowed_scope",
            };
            subject = new OidcClient(settings);

            const tokenResponse = {
                access_token: "new_access_token",
            };
            const exchangeRefreshTokenMock =
                jest.spyOn(subject["_tokenClient"], "exchangeRefreshToken")
                    .mockResolvedValue(tokenResponse);
            jest.spyOn(JwtUtils, "decode").mockReturnValue({ sub: "sub" });
            const state = new RefreshState({
                refresh_token: "refresh_token",
                id_token: "id_token",
                session_state: "session_state",
                scope: "unallowed_scope allowed_scope unallowed_scope_2",
                profile: {} as UserProfile,
            });

            // act
            const response = await subject.useRefreshToken({ state });

            // assert
            expect(exchangeRefreshTokenMock).toHaveBeenCalledWith( {
                refresh_token: "refresh_token",
                scope: "allowed_scope",
                timeoutInSeconds: undefined,
            });
            expect(response).toBeInstanceOf(SigninResponse);
            expect(response).toMatchObject(tokenResponse);
            expect(response).toHaveProperty("session_state", state.session_state);
            expect(response).toHaveProperty("scope", "allowed_scope");
        });

        it("should enforce a matching sub claim", async () => {
            // arrange
            const profiles: Record<string, JwtClaims> = {
                id_token: {
                    sub: "current_sub",
                },
                new_id_token: {
                    sub: "new_sub",
                },
            };
            const tokenResponse = {
                access_token: "new_access_token",
                id_token: "new_id_token",
            };
            jest.spyOn(subject["_tokenClient"], "exchangeRefreshToken").mockResolvedValue(tokenResponse);
            jest.spyOn(JwtUtils, "decode").mockImplementation((token) => profiles[token]);
            const state = new RefreshState({
                refresh_token: "refresh_token",
                id_token: "id_token",
                session_state: "session_state",
                scope: "openid",
                profile: {} as UserProfile,
            });

            // act
            await expect(subject.useRefreshToken({ state }))
                // assert
                .rejects.toThrow("sub in id_token does not match current sub");
        });

        it("should pass DPoP extraHeader to tokenClient.exchangeRefreshToken if DPoP enabled", async () => {
            // arrange
            const settings: OidcClientSettings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                post_logout_redirect_uri: "http://app",
                dpop: {
                    bind_authorization_code: false,
                    store: new IndexedDbDPoPStore(),
                },
            };

            subject = new OidcClient(settings);

            const tokenResponse = {
                access_token: "new_access_token",
            };
            const exchangeRefreshTokenMock =
                jest.spyOn(subject["_tokenClient"], "exchangeRefreshToken")
                    .mockResolvedValue(tokenResponse);
            jest.spyOn(JwtUtils, "decode").mockReturnValue({ sub: "sub" });
            const mockMetaDataService = jest.spyOn(subject["metadataService"], "getTokenEndpoint").mockResolvedValue("http://sts/token");

            const state = new RefreshState({
                refresh_token: "refresh_token",
                id_token: "id_token",
                session_state: "session_state",
                scope: "openid",
                profile: {} as UserProfile,
            });

            // act
            const response = await subject.useRefreshToken({ state, resource: "resource" });

            // assert
            expect(mockMetaDataService).toHaveBeenCalled();
            expect(exchangeRefreshTokenMock).toHaveBeenCalledWith( {
                refresh_token: "refresh_token",
                scope: "openid",
                timeoutInSeconds: undefined,
                resource: "resource",
                extraHeaders: { "DPoP": expect.any(String) },
            });
            expect(response).toBeInstanceOf(SigninResponse);
            expect(response).toMatchObject(tokenResponse);
            expect(response).toHaveProperty("session_state", state.session_state);
            expect(response).toHaveProperty("scope", state.scope);
        });

        it("should retry token exchange if tokenClient exchange throws ErrorDPoPNonce exception", async () => {
            // arrange
            const settings: OidcClientSettings = {
                authority: "authority",
                client_id: "client",
                redirect_uri: "redirect",
                post_logout_redirect_uri: "http://app",
                dpop: {
                    bind_authorization_code: false,
                    store: new IndexedDbDPoPStore(),
                },
            };

            subject = new OidcClient(settings);

            const tokenResponse = {
                access_token: "new_access_token",
            };
            const exchangeRefreshTokenMock =
                jest.spyOn(subject["_tokenClient"], "exchangeRefreshToken")
                    .mockRejectedValueOnce(new ErrorDPoPNonce("some-nonce"))
                    .mockResolvedValueOnce(tokenResponse);
            jest.spyOn(JwtUtils, "decode").mockReturnValue({ sub: "sub" });
            jest.spyOn(subject["metadataService"], "getTokenEndpoint").mockResolvedValue("http://sts/token");
            const getDpopProofSpy = jest.spyOn(subject, "getDpopProof");

            const state = new RefreshState({
                refresh_token: "refresh_token",
                id_token: "id_token",
                session_state: "session_state",
                scope: "openid",
                profile: {} as UserProfile,
            });

            // act
            await subject.useRefreshToken({ state, resource: "resource" });

            // assert

            expect(exchangeRefreshTokenMock).toHaveBeenCalledTimes(2);
            expect(getDpopProofSpy).toHaveBeenCalledTimes(2);
            expect(getDpopProofSpy).toHaveBeenNthCalledWith(2, { "_dbName": "oidc", "_storeName": "dpop" }, "some-nonce");
        });

        it("should pass extraHeaders to tokenClient.exchangeRefreshToken if supplied", async () => {
            // arrange
            const tokenResponse = {
                access_token: "new_access_token",
            };
            const exchangeRefreshTokenMock =
                jest.spyOn(subject["_tokenClient"], "exchangeRefreshToken")
                    .mockResolvedValue(tokenResponse);
            jest.spyOn(JwtUtils, "decode").mockReturnValue({ sub: "sub" });
            const state = new RefreshState({
                refresh_token: "refresh_token",
                id_token: "id_token",
                session_state: "session_state",
                scope: "openid",
                profile: {} as UserProfile,
            });
            const extraHeaders: Record<string, ExtraHeader> = { "foo": "bar" };

            // act
            const response = await subject.useRefreshToken({ state, resource: "resource", extraHeaders: extraHeaders });

            // assert
            expect(exchangeRefreshTokenMock).toHaveBeenCalledWith( {
                refresh_token: "refresh_token",
                scope: "openid",
                timeoutInSeconds: undefined,
                resource: "resource",
                extraHeaders: extraHeaders,
            });
            expect(response).toBeInstanceOf(SigninResponse);
            expect(response).toMatchObject(tokenResponse);
            expect(response).toHaveProperty("session_state", state.session_state);
            expect(response).toHaveProperty("scope", state.scope);
        });
    });

    describe("createSignoutRequest", () => {
        it("should return SignoutRequest", async () => {
            // arrange
            jest.spyOn(subject.metadataService, "getEndSessionEndpoint").mockImplementation(() => Promise.resolve("http://sts/signout"));

            // act
            const request = await subject.createSignoutRequest();

            // assert
            expect(request).toBeInstanceOf(SignoutRequest);
        });

        it("should pass state in place of data to SignoutRequest", async () => {
            // arrange
            jest.spyOn(subject.metadataService, "getEndSessionEndpoint").mockImplementation(() => Promise.resolve("http://sts/signout"));

            // act
            const request = await subject.createSignoutRequest({
                state: "foo",
                post_logout_redirect_uri: "bar",
                id_token_hint: "baz",
            });

            // assert
            expect(request.state).toBeDefined();
            expect(request.state?.data).toEqual("foo");
            const url = request.url;
            expect(url).toContain("http://sts/signout");
            expect(url).toContain("post_logout_redirect_uri=bar");
            expect(url).toContain("id_token_hint=baz");
        });

        it("should pass params to SignoutRequest", async () => {
            // arrange
            jest.spyOn(subject.metadataService, "getEndSessionEndpoint").mockImplementation(() => Promise.resolve("http://sts/signout"));

            // act
            const request = await subject.createSignoutRequest({
                state: "foo",
                post_logout_redirect_uri: "bar",
                id_token_hint: "baz",
                url_state: "qux",
            });

            // assert
            expect(request.state).toBeDefined();
            expect(request.state?.data).toEqual("foo");
            const url = request.url;
            expect(url).toContain("http://sts/signout");
            expect(url).toContain("post_logout_redirect_uri=bar");
            expect(url).toContain("id_token_hint=baz");
            expect(url).toContain(encodeURIComponent(URL_STATE_DELIMITER + "qux"));
        });

        it("should pass params to SignoutRequest w/o id_token_hint and client_id", async () => {
            // arrange
            jest.spyOn(subject.metadataService, "getEndSessionEndpoint").mockImplementation(() => Promise.resolve("http://sts/signout"));

            // act
            const request = await subject.createSignoutRequest({
                state: "foo",
                post_logout_redirect_uri: "bar",
            });

            // assert
            expect(request.state).toBeDefined();
            expect(request.state?.data).toEqual("foo");
            const url = request.url;
            expect(url).toContain("http://sts/signout");
            expect(url).toContain("post_logout_redirect_uri=bar");
            expect(url).toContain("client_id=client");
        });

        it("should pass params to SignoutRequest with client_id", async () => {
            // arrange
            jest.spyOn(subject.metadataService, "getEndSessionEndpoint").mockImplementation(() => Promise.resolve("http://sts/signout"));

            // act
            const request = await subject.createSignoutRequest({
                state: "foo",
                post_logout_redirect_uri: "bar",
                client_id: "baz",
            });

            // assert
            expect(request.state).toBeDefined();
            expect(request.state?.data).toEqual("foo");
            const url = request.url;
            expect(url).toContain("http://sts/signout");
            expect(url).toContain("post_logout_redirect_uri=bar");
            expect(url).toContain("client_id=baz");
        });

        it("should fail if metadata fails", async () => {
            // arrange
            jest.spyOn(subject.metadataService, "getEndSessionEndpoint").mockRejectedValue(new Error("test"));

            // act
            try {
                await subject.createSignoutRequest();
                fail("should not come here");
            }
            catch (err) {
                expect(err).toBeInstanceOf(Error);
                expect((err as Error).message).toContain("test");
            }
        });

        it("should fail if no signout endpoint on metadata", async () => {
            // arrange
            jest.spyOn(subject.metadataService, "getEndSessionEndpoint").mockImplementation(() => Promise.resolve(undefined));

            // act
            try {
                await subject.createSignoutRequest();
                fail("should not come here");
            }
            catch (err) {
                expect(err).toBeInstanceOf(Error);
                expect((err as Error).message).toContain("No end session endpoint");
            }
        });

        it("should store state", async () => {
            // arrange
            jest.spyOn(subject.metadataService, "getEndSessionEndpoint").mockImplementation(() => Promise.resolve("http://sts/signout"));
            const setMock = jest.spyOn(subject.settings.stateStore, "set").mockImplementation(() => Promise.resolve());

            // act
            await subject.createSignoutRequest({
                state: "foo",
            });

            // assert
            expect(setMock).toHaveBeenCalled();
        });

        it("should not generate state if no data", async () => {
            // arrange
            jest.spyOn(subject.metadataService, "getEndSessionEndpoint").mockImplementation(() => Promise.resolve("http://sts/signout"));
            const setMock = jest.spyOn(subject.settings.stateStore, "set").mockImplementation(() => Promise.resolve());

            // act
            await subject.createSignoutRequest();

            // assert
            expect(setMock).not.toHaveBeenCalled();
        });
    });

    describe("readSignoutResponseState", () => {
        it("should return a promise", async () => {
            // act
            const p = subject.readSignoutResponseState("http://app/cb?state=state");

            // assert
            expect(p).toBeInstanceOf(Promise);
            // eslint-disable-next-line no-empty
            try { await p; } catch {}
        });

        it("should return result if no state on response", async () => {
            // act
            const { response } = await subject.readSignoutResponseState("http://app/cb");

            // assert
            expect(response).toBeInstanceOf(SignoutResponse);
        });

        it("should return error", async () => {
            // act
            try {
                await subject.readSignoutResponseState("http://app/cb?error=foo");
                fail("should not come here");
            }
            catch (err) {
                expect(err).toBeInstanceOf(Error);
                expect((err as ErrorResponse).error).toEqual("foo");
            }
        });

        it("should fail if storage fails", async () => {
            // arrange
            jest.spyOn(subject.settings.stateStore, "get").mockRejectedValue(new Error("fail"));

            // act
            try {
                await subject.readSignoutResponseState("http://app/cb?state=state");
                fail("should not come here");
            }
            catch (err) {
                expect(err).toBeInstanceOf(Error);
                expect((err as Error).message).toContain("fail");
            }
        });

        it("should deserialize stored state and return state and response", async () => {
            // arrange
            const item = new State({ id: "1", request_type: "type" }).toStorageString();
            jest.spyOn(subject.settings.stateStore, "get").mockImplementation(() => Promise.resolve(item));

            // act
            const { state, response } = await subject.readSignoutResponseState("http://app/cb?state=1");

            // assert
            expect(state).toBeDefined();
            expect(state?.id).toEqual("1");
            expect(state?.request_type).toEqual("type");
            expect(response.state).toEqual("1");
        });

        it("should call validator with state even if error in response", async () => {
            // arrange
            const item = new State({
                id: "1",
                data: "bar",
                request_type: "type",
            });
            jest.spyOn(subject.settings.stateStore, "remove")
                .mockImplementation(() => Promise.resolve(item.toStorageString()));
            const validateSignoutResponse = jest.spyOn(subject["_validator"], "validateSignoutResponse")
                .mockReturnValue();

            // act
            const response = await subject.processSignoutResponse("http://app/cb?state=1&error=foo");

            // assert
            expect(validateSignoutResponse).toHaveBeenCalledWith(response, item);
        });
    });

    describe("processSignoutResponse", () => {
        it("should return a promise", async () => {
            // act
            const p = subject.processSignoutResponse("state=state");

            // assert
            expect(p).toBeInstanceOf(Promise);
            // eslint-disable-next-line no-empty
            try { await p; } catch {}
        });

        it("should return result if no state on response", async () => {
            // act
            const response = await subject.processSignoutResponse("http://app/cb");

            // assert
            expect(response).toBeInstanceOf(SignoutResponse);
        });

        it("should return error", async () => {
            // act
            try {
                await subject.processSignoutResponse("http://app/cb?error=foo");
                fail("should not come here");
            }
            catch (err) {
                expect(err).toBeInstanceOf(Error);
                expect((err as ErrorResponse).error).toEqual("foo");
            }
        });

        it("should fail if storage fails", async () => {
            // arrange
            jest.spyOn(subject.settings.stateStore, "remove").mockRejectedValue(new Error("fail"));

            // act
            try {
                await subject.processSignoutResponse("http://app/cb?state=state");
                fail("should not come here");
            }
            catch (err) {
                expect(err).toBeInstanceOf(Error);
                expect((err as Error).message).toContain("fail");
            }
        });

        it("should deserialize stored state and call validator", async () => {
            // arrange
            const item = new State({
                id: "1",
                request_type: "type",
            });
            jest.spyOn(subject.settings.stateStore, "remove")
                .mockImplementation(async () => item.toStorageString());
            const validateSignoutResponse = jest.spyOn(subject["_validator"], "validateSignoutResponse")
                .mockReturnValue();

            // act
            const response = await subject.processSignoutResponse("http://app/cb?state=1");

            // assert
            expect(validateSignoutResponse).toHaveBeenCalledWith(response, item);
        });

        it("should call validator with state even if error in response", async () => {
            // arrange
            const item = new State({
                id: "1",
                data: "bar",
                request_type: "type",
            });
            jest.spyOn(subject.settings.stateStore, "remove")
                .mockImplementation(async () => item.toStorageString());
            const validateSignoutResponse = jest.spyOn(subject["_validator"], "validateSignoutResponse")
                .mockReturnValue();

            // act
            const response = await subject.processSignoutResponse("http://app/cb?state=1&error=foo");

            // assert
            expect(validateSignoutResponse).toHaveBeenCalledWith(response, item);
        });
    });

    describe("clearStaleState", () => {

        it("should call State.clearStaleState", async () => {
            // arrange
            const clearStaleState = jest.spyOn(State, "clearStaleState");

            // act
            await subject.clearStaleState();

            // assert
            expect(clearStaleState).toHaveBeenCalled();
        });
    });

    describe("revokeToken", () => {
        it("revokes a token type", async () => {
            // arrange
            const revokeSpy = jest.spyOn(subject["_tokenClient"], "revoke").mockResolvedValue();

            // act
            await subject.revokeToken("token", "access_token");

            // assert
            expect(revokeSpy).toHaveBeenCalledWith({
                token: "token",
                token_type_hint: "access_token",
            });
        });
    });

    describe("getDpopProof", () => {
        it("stores a nonce if one is provided", async () => {
            // arrange
            const store = new IndexedDbDPoPStore();
            const keyPair = await CryptoUtils.generateDPoPKeys();
            jest.spyOn(CryptoUtils, "generateDPoPKeys").mockResolvedValue(keyPair);

            const settings: OidcClientSettings = {
                authority: "authority",
                client_id: "dpop_client",
                redirect_uri: "redirect",
                post_logout_redirect_uri: "http://app",
                dpop: {
                    bind_authorization_code: false,
                    store: store,
                },
            };

            subject = new OidcClient(settings);

            jest.spyOn(subject["metadataService"], "getTokenEndpoint").mockResolvedValue("http://sts/token");

            // act
            await subject.getDpopProof(store, "some-nonce");
            const storedDPoPState = await subject.settings.dpop?.store.get("dpop_client");
            // assert

            expect(storedDPoPState?.nonce).toEqual("some-nonce");
        });

        it("updates the stored nonce if a new one is provided", async () => {
            // arrange
            const store = new IndexedDbDPoPStore();
            const keyPair = await CryptoUtils.generateDPoPKeys();
            jest.spyOn(CryptoUtils, "generateDPoPKeys").mockResolvedValue(keyPair);
            const dpopState = new DPoPState(keyPair, "some-nonce");

            const settings: OidcClientSettings = {
                authority: "authority",
                client_id: "dpop_client",
                redirect_uri: "redirect",
                post_logout_redirect_uri: "http://app",
                dpop: {
                    bind_authorization_code: false,
                    store: store,
                },
            };

            subject = new OidcClient(settings);

            jest.spyOn(subject["metadataService"], "getTokenEndpoint").mockResolvedValue("http://sts/token");
            await subject.getDpopProof(store, "some-nonce");
            let storedDPoPState = await subject.settings.dpop?.store.get("dpop_client");
            expect(storedDPoPState?.nonce).toEqual("some-nonce");
            dpopState.nonce = "some-other-nonce";

            // act
            await subject.getDpopProof(store, "some-other-nonce");
            storedDPoPState = await subject.settings.dpop?.store.get("dpop_client");

            // assert
            expect(storedDPoPState?.nonce).toEqual("some-other-nonce");
        });
    });
});
