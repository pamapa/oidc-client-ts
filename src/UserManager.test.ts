// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import { once } from "events";
import {
    RedirectNavigator,
    type PopupWindow,
    PopupNavigator,
    IFrameNavigator,
    type NavigateResponse,
} from "./navigators";
import type { SigninResponse } from "./SigninResponse";
import type { SignoutResponse } from "./SignoutResponse";
import { UserManager, type SigninPopupArgs, type SigninRedirectArgs, type SigninSilentArgs, type SignoutSilentArgs, type SignoutPopupArgs } from "./UserManager";
import { UserManagerSettingsStore } from "./UserManagerSettings";
import { User } from "./User";
import type { UserProfile } from "./User";
import { WebStorageStateStore } from "./WebStorageStateStore";
import type { SigninState } from "./SigninState";
import type { State } from "./State";

import { mocked } from "jest-mock";
import { CryptoUtils } from "./utils";
import { IndexedDbDPoPStore } from "./IndexedDbDPoPStore";
import { DPoPState } from "./DPoPStore";

describe("UserManager", () => {
    let userStoreMock: WebStorageStateStore;

    let subject: UserManager;

    beforeEach(() => {
        localStorage.clear();

        userStoreMock = new WebStorageStateStore();

        subject = new UserManager({
            authority: "http://sts/oidc",
            client_id: "client",
            redirect_uri: "http://app/cb",
            monitorSession : false,
            userStore: userStoreMock,
            metadata: {
                authorization_endpoint: "http://sts/oidc/authorize",
                end_session_endpoint:  "http://sts/oidc/logout",
                token_endpoint: "http://sts/oidc/token",
                revocation_endpoint: "http://sts/oidc/revoke",
            },
        });
    });

    describe("constructor", () => {
        it("should accept settings", () => {
            // act
            expect(subject.settings.client_id).toEqual("client");
        });

        it.each([
            { monitorSession: true, message: "should" },
            { monitorSession: false, message: "should not" },
        ])("when monitorSession is $monitorSession $message init sessionMonitor", (args) => {
            // arrange
            const settings = { ...subject.settings, monitorSession: args.monitorSession };

            // act
            subject= new UserManager(settings);

            // assert
            const sessionMonitor = subject["_sessionMonitor"];
            if (args.monitorSession) {
                expect(sessionMonitor).toBeDefined();
            } else {
                expect(sessionMonitor).toBeNull();
            }
        });

        it("should accept redirectNavigator", () => {
            // arrange
            const customRedirectNavigator = new RedirectNavigator(subject.settings);

            // act
            subject = new UserManager(subject.settings, customRedirectNavigator);

            // assert
            expect(subject["_redirectNavigator"]).toBe(customRedirectNavigator);
        });

        it("should accept popupNavigator", () => {
            // arrange
            const customPopupNavigator = new PopupNavigator(subject.settings);

            subject = new UserManager(subject.settings, undefined, customPopupNavigator);

            // assert
            expect(subject["_popupNavigator"]).toBe(customPopupNavigator);
        });

        it("should accept iframeNavigator", () => {
            // arrange
            const customiframeNavigator = new IFrameNavigator(subject.settings);

            // act
            subject = new UserManager(subject.settings, undefined, undefined, customiframeNavigator);

            // assert
            expect(subject["_iframeNavigator"]).toBe(customiframeNavigator);
        });
    });

    describe("settings", () => {
        it("should be UserManagerSettings", () => {
            // act & assert
            expect(subject.settings).toBeInstanceOf(UserManagerSettingsStore);
        });
    });

    describe("getUser", () => {
        it("should be able to call getUser without recursion", async () => {
            // arrange
            subject.events.addUserLoaded(async () => {
                await subject.getUser();
            });

            // act
            await subject.events.load({} as User);
        });

        it("should return user if there is a user stored", async () => {
            // arrange
            const user = new User({
                access_token: "access_token",
                token_type: "token_type",
                profile: {} as UserProfile,
            });
            subject["_loadUser"] = jest.fn().mockReturnValue(user);
            const loadMock = jest.spyOn(subject["_events"], "load");

            // act
            const result = await subject.getUser();

            // assert
            expect(result).toEqual(user);
            expect(loadMock).toHaveBeenCalledWith(user, false);
        });

        it("should execute callbacks for userLoaded event if there is a user stored and the raiseEvent parameter is true", async () => {
            // arrange
            const user = new User({
                access_token: "access_token",
                token_type: "token_type",
                profile: {} as UserProfile,
            });
            subject["_loadUser"] = jest.fn().mockReturnValue(user);
            const cb = jest.fn();
            subject.events.addUserLoaded(cb);

            // act
            await subject.getUser(true);

            // assert
            expect(cb).toHaveBeenCalled();
        });

        it("should not execute callbacks for userLoaded event if there is a user stored and the raiseEvent parameter is false", async () => {
            // arrange
            const user = new User({
                access_token: "access_token",
                token_type: "token_type",
                profile: {} as UserProfile,
            });
            subject["_loadUser"] = jest.fn().mockReturnValue(user);
            const cb = jest.fn();
            subject.events.addUserLoaded(cb);

            // act
            await subject.getUser(false);

            // assert
            expect(cb).not.toHaveBeenCalled();
        });

        it("should not execute callbacks for userLoaded event if there is a user stored and the raiseEvent parameter is not defined", async () => {
            // arrange
            const user = new User({
                access_token: "access_token",
                token_type: "token_type",
                profile: {} as UserProfile,
            });
            subject["_loadUser"] = jest.fn().mockReturnValue(user);
            const cb = jest.fn();
            subject.events.addUserLoaded(cb);

            // act
            await subject.getUser();

            // assert
            expect(cb).not.toHaveBeenCalled();
        });

        it("should return null if there is no user stored", async () => {
            // arrange
            subject["_loadUser"] = jest.fn().mockReturnValue(null);
            const loadMock = jest.spyOn(subject["_events"], "load");

            // act
            const result = await subject.getUser();

            // assert
            expect(result).toBeNull();
            expect(loadMock).not.toHaveBeenCalled();
        });
    });

    describe("removeUser", () => {
        it("should remove user from store and event unload", async () => {
            // arrange
            const storeUserMock = jest.spyOn(subject, "storeUser");
            const unloadMock = jest.spyOn(subject["_events"], "unload");

            // act
            await subject.removeUser();

            // assert
            expect(storeUserMock).toHaveBeenCalledWith(null);
            expect(unloadMock).toHaveBeenCalled();
        });
    });

    describe("removeUser", () => {
        it("should remove user from store", async () => {
            // arrange
            const storeUserMock = jest.spyOn(subject, "storeUser");
            const unloadMock = jest.spyOn(subject["_events"], "unload");
            // act
            await subject.removeUser();

            // assert
            expect(storeUserMock).toBeCalledWith(null);
            expect(unloadMock).toBeCalled();
        });

        it("should remove dpop key from store if DPoP enabled", async () => {
            // arrange
            subject = new UserManager({
                authority: "http://sts/oidc",
                client_id: "client",
                redirect_uri: "http://app/cb",
                monitorSession : false,
                userStore: userStoreMock,
                metadata: {
                    authorization_endpoint: "http://sts/oidc/authorize",
                    end_session_endpoint:  "http://sts/oidc/logout",
                    token_endpoint: "http://sts/oidc/token",
                    revocation_endpoint: "http://sts/oidc/revoke",
                },
                dpop: {
                    bind_authorization_code: false,
                    store: new IndexedDbDPoPStore(),
                },
            });

            const storeUserMock = jest.spyOn(subject, "storeUser");
            const unloadMock = jest.spyOn(subject["_events"], "unload");

            const dpopStoreMock = jest.spyOn(subject.settings.dpop!.store, "remove");

            // act
            await subject.removeUser();

            // assert
            expect(storeUserMock).toHaveBeenCalledWith(null);
            expect(unloadMock).toHaveBeenCalled();
            expect(dpopStoreMock).toHaveBeenCalled();
        });
    });

    describe("revokeTokens", () => {
        it("should revoke the token types specified", async () => {
            // arrange
            const user = {
                access_token: "foo",
                refresh_token: "bar",
            };
            subject["_loadUser"] = jest.fn().mockReturnValue(user);
            const revokeSpy = jest.spyOn(subject["_client"], "revokeToken").mockResolvedValue(undefined);
            const storeUserSpy = jest.spyOn(subject, "storeUser").mockResolvedValue(undefined);

            // act
            await subject.revokeTokens(["access_token", "refresh_token"]);

            // assert
            expect(revokeSpy).toHaveBeenNthCalledWith(1, "foo", "access_token");
            expect(revokeSpy).toHaveBeenNthCalledWith(2, "bar", "refresh_token");
            expect(user).toMatchObject({
                access_token: "foo",
                refresh_token: null,
            });
            expect(storeUserSpy).toHaveBeenCalled();
        });

        it("should skip revoking absent token types", async () => {
            // arrange
            subject["_loadUser"] = jest.fn().mockReturnValue({
                access_token: "foo",
            });
            const revokeSpy = jest.spyOn(subject["_client"], "revokeToken").mockResolvedValue(undefined);
            jest.spyOn(subject, "storeUser").mockResolvedValue(undefined);

            // act
            await subject.revokeTokens(["access_token", "refresh_token"]);

            // assert
            expect(revokeSpy).toHaveBeenCalledTimes(1);
            expect(revokeSpy).not.toHaveBeenCalledWith(expect.anything(), "refresh_token");
        });

        it("should succeed with no user session", async () => {
            // act
            await expect(subject.revokeTokens())
                // assert
                .resolves.toBe(undefined);
        });
    });

    describe("signinRedirect", () => {
        it("should redirect the browser to the authorize url", async () => {
            // act
            const spy = jest.fn();
            void subject.signinRedirect().finally(spy);

            // signinRedirect is a promise that will never resolve (since we
            // want it to hold until the page has redirected), so we wait for
            // the browser unload event before checking the test assertions.
            await once(window, "unload");

            // assert
            expect(window.location.assign).toHaveBeenCalledWith(
                expect.stringContaining(subject.settings.metadata!.authorization_endpoint!),
            );
            const [location] = mocked(window.location.assign).mock.calls[0];
            const state = new URL(location).searchParams.get("state");
            const item = await userStoreMock.get(state!);
            expect(JSON.parse(item!)).toHaveProperty("request_type", "si:r");

            // We check to make sure the promise has not resolved
            expect(spy).not.toHaveBeenCalled();
        });

        it("should pass navigator params to navigator", async () => {
            // arrange
            const prepareMock = jest.spyOn(subject["_redirectNavigator"], "prepare");
            subject["_signinStart"] = jest.fn();
            const navParams: SigninRedirectArgs = {
                redirectMethod: "assign",
            };

            // act
            await subject.signinRedirect(navParams);

            // assert
            expect(prepareMock).toHaveBeenCalledWith(navParams);
        });

        it("should pass extra args to _signinStart", async () => {
            // arrange
            jest.spyOn(subject["_redirectNavigator"], "prepare");
            subject["_signinStart"] = jest.fn();
            const extraArgs: SigninRedirectArgs = {
                extraQueryParams: { q : "q" },
                extraTokenParams: { t: "t" },
                state: "state",
                nonce: "random_nonce",
                redirect_uri: "http://app/extra_callback",
                prompt: "login",
                url_state: "url_state",
            };

            // act
            await subject.signinRedirect(extraArgs);

            // assert
            expect(subject["_signinStart"]).toHaveBeenCalledWith(
                {
                    request_type: "si:r",
                    ...extraArgs,
                },
                expect.objectContaining({
                    close: expect.any(Function),
                    navigate: expect.any(Function),
                }),
            );
        });

        it("should pass dpopJkt to _signin if dpop.bind_authorization_code is true", async () => {
            // arrange
            subject = new UserManager({
                authority: "http://sts/oidc",
                client_id: "client",
                redirect_uri: "http://app/cb",
                monitorSession : false,
                userStore: userStoreMock,
                metadata: {
                    authorization_endpoint: "http://sts/oidc/authorize",
                    end_session_endpoint:  "http://sts/oidc/logout",
                    token_endpoint: "http://sts/oidc/token",
                    revocation_endpoint: "http://sts/oidc/revoke",
                },
                dpop: {
                    bind_authorization_code: true,
                    store: new IndexedDbDPoPStore(),
                },
            });
            jest.spyOn(subject["_redirectNavigator"], "prepare");
            subject["_signinStart"] = jest.fn();

            const generateDPoPJktSpy = jest.spyOn(subject, "generateDPoPJkt");

            const keyPair = await CryptoUtils.generateDPoPKeys();

            await subject.settings.dpop?.store?.set("client", new DPoPState(keyPair));

            // act
            await subject.signinRedirect();

            // assert
            expect(generateDPoPJktSpy).toHaveBeenCalled();
            expect(subject["_signinStart"]).toHaveBeenCalledWith({
                request_type: "si:r",
                dpopJkt: expect.any(String),
            }, expect.any(Object));
        });
    });

    describe("signinRedirectCallback", () => {
        it("should return a user", async () => {
            // arrange
            const spy = jest.spyOn(subject["_client"], "processSigninResponse")
                .mockResolvedValue({} as SigninResponse);

            // act
            const user = await subject.signinRedirectCallback("http://app/cb?state=test&code=code");

            // assert
            expect(user).toBeInstanceOf(User);
            spy.mockRestore();
        });
    });

    describe("signinResourceOwnerCredentials", () => {
        it("should fail on wrong credentials", async () => {
            // arrange
            jest.spyOn(subject["_client"], "processResourceOwnerPasswordCredentials").mockRejectedValue(new Error("Wrong credentials"));

            // act
            await expect(subject.signinResourceOwnerCredentials({ username: "u", password: "p" }))
                // assert
                .rejects.toThrow(Error);
        });

        it("should convert and store received response", async () => {
            // arrange
            const mockUser = {
                access_token: "access_token",
                token_type: "Bearer",
                profile: {
                    sub: "subsub",
                    iss: "ississ",
                    aud: "aud",
                    exp: 0,
                    iat: 0,
                    nickname: "Nick",
                },
                session_state: "ssss",
                expires_at: 0,
                refresh_token: "refresh_token",
                id_token: "id_token",
                scope: "openid profile email",
            };
            jest.spyOn(subject["_client"], "processResourceOwnerPasswordCredentials").mockResolvedValue(mockUser as SigninResponse);
            jest.spyOn(subject["_events"], "load").mockImplementation(() => Promise.resolve());

            // act
            const user:User = await subject.signinResourceOwnerCredentials({ username: "u", password: "p" });

            // assert
            await expect(subject.getUser()).resolves.toEqual(mockUser);
            expect(subject["_events"].load).toHaveBeenCalledWith(mockUser);
            expect(user).toEqual(mockUser);
        });
    });

    describe("signinPopup", () => {
        it("should pass navigator params to navigator", async () => {
            // arrange
            const handle = {} as PopupWindow;
            const prepareMock = jest.spyOn(subject["_popupNavigator"], "prepare")
                .mockImplementation(() => Promise.resolve(handle));
            subject["_signin"] = jest.fn();
            const navParams: SigninPopupArgs = {
                popupWindowFeatures: {
                    location: false,
                    toolbar: false,
                    height: 100,
                },
                popupWindowTarget: "popupWindowTarget",
            };

            // act
            await subject.signinPopup(navParams);

            // assert
            expect(prepareMock).toHaveBeenCalledWith(navParams);
        });

        it("should pass extra args to _signinStart", async () => {
            // arrange
            const user = new User({
                access_token: "access_token",
                token_type: "token_type",
                profile: {} as UserProfile,
            });
            const handle = {} as PopupWindow;
            jest.spyOn(subject["_popupNavigator"], "prepare")
                .mockImplementation(() => Promise.resolve(handle));
            subject["_signin"] = jest.fn().mockResolvedValue(user);
            const extraArgs: SigninPopupArgs = {
                extraQueryParams: { q: "q" },
                extraTokenParams: { t: "t" },
                state: "state",
                nonce: "random_nonce",
                redirect_uri: "http://app/extra_callback",
                prompt: "login",
            };

            // act
            await subject.signinPopup(extraArgs);

            // assert
            expect(subject["_signin"]).toHaveBeenCalledWith(
                {
                    request_type: "si:p",
                    display: "popup",
                    ...extraArgs,
                },
                handle,
            );
        });

        it("should pass dpopJkt to _signin if dpop.bind_authorization_code is true", async () => {
            // arrange
            subject = new UserManager({
                authority: "http://sts/oidc",
                client_id: "client",
                redirect_uri: "http://app/cb",
                monitorSession : false,
                userStore: userStoreMock,
                metadata: {
                    authorization_endpoint: "http://sts/oidc/authorize",
                    end_session_endpoint:  "http://sts/oidc/logout",
                    token_endpoint: "http://sts/oidc/token",
                    revocation_endpoint: "http://sts/oidc/revoke",
                },
                dpop: {
                    bind_authorization_code: true,
                    store: new IndexedDbDPoPStore(),
                },
            });

            const handle = {} as PopupWindow;
            jest.spyOn(subject["_popupNavigator"], "prepare")
                .mockImplementation(() => Promise.resolve(handle));
            const generateDPoPJktSpy = jest.spyOn(subject, "generateDPoPJkt");

            const keyPair = await CryptoUtils.generateDPoPKeys();
            await subject.settings.dpop?.store?.set("client", new DPoPState(keyPair));

            const user = new User({
                access_token: "access_token",
                token_type: "token_type",
                profile: {
                    sub: "sub",
                    nickname: "Nicholas",
                } as UserProfile,
            });

            subject["_signin"] = jest.fn().mockResolvedValue(user);

            subject["_loadUser"] = jest.fn().mockResolvedValue(user);

            // act
            await subject.signinPopup({ resource: "resource" });

            // assert
            expect(generateDPoPJktSpy).toHaveBeenCalled();
            expect(subject["_signin"]).toHaveBeenCalledWith({
                request_type: "si:p",
                redirect_uri: "http://app/cb",
                dpopJkt: expect.any(String),
                resource: "resource",
                display: "popup",
            }, expect.any(Object));
        });
    });

    describe("signinPopupCallback", () => {
        it("should call navigator callback", async () => {
            // arrange
            const callbackMock = jest.spyOn(subject["_popupNavigator"], "callback").mockResolvedValue();
            const url = "http://app/cb?state=test&code=code";
            const keepOpen = true;

            // act
            await subject.signinPopupCallback(url, keepOpen);

            // assert
            expect(callbackMock).toHaveBeenCalledWith(url, { keepOpen });
        });
    });

    describe("signinSilent", () => {
        it("should pass silentRequestTimeout from settings", async () => {
            // arrange
            const user = new User({
                id_token: "id_token",
                access_token: "access_token",
                token_type: "token_type",
                profile: {} as UserProfile,
            });

            Object.assign(subject.settings, {
                silentRequestTimeoutInSeconds: 123,
                silent_redirect_uri: "http://client/silent_callback",
            });
            subject["_signin"] = jest.fn().mockResolvedValue(user);

            // act
            await subject.signinSilent();
            const [, navInstance] = mocked(subject["_signin"]).mock.calls[0];

            // assert
            expect(navInstance).toHaveProperty("_timeoutInSeconds", 123);
        });

        it("should pass navigator params to navigator", async () => {
            // arrange
            const prepareMock = jest.spyOn(subject["_iframeNavigator"], "prepare");
            subject["_signin"] = jest.fn();
            const navParams: SigninSilentArgs = {
                silentRequestTimeoutInSeconds: 234,
            };

            // act
            await subject.signinSilent(navParams);

            // assert
            expect(prepareMock).toHaveBeenCalledWith(navParams);
        });

        it("should pass extra args to _signinStart", async () => {
            // arrange
            const user = new User({
                access_token: "access_token",
                token_type: "token_type",
                profile: {} as UserProfile,
            });
            jest.spyOn(subject["_popupNavigator"], "prepare");
            subject["_signin"] = jest.fn().mockResolvedValue(user);
            const extraArgs: SigninSilentArgs = {
                extraQueryParams: { q : "q" },
                extraTokenParams: { t: "t" },
                state: "state",
                nonce: "random_nonce",
                redirect_uri: "http://app/extra_callback",
            };

            // act
            await subject.signinSilent(extraArgs);

            // assert
            expect(subject["_signin"]).toHaveBeenCalledWith(
                {
                    request_type: "si:s",
                    prompt: "none",
                    id_token_hint: undefined,
                    ...extraArgs,
                },
                expect.objectContaining({
                    close: expect.any(Function),
                    navigate: expect.any(Function),
                }),
                undefined,
            );
        });

        it("should work when having no user present", async () => {
            // arrange
            const user = new User({
                access_token: "access_token",
                token_type: "token_type",
                profile: {} as UserProfile,
            });
            Object.assign(subject.settings, {
                silent_redirect_uri: "http://client/silent_callback",
            });
            subject["_signin"] = jest.fn().mockResolvedValue(user);

            // act
            await subject.signinSilent();
        });

        it("should use the refresh_token grant when a refresh token is present", async () => {
            // arrange
            const user = new User({
                access_token: "access_token",
                token_type: "token_type",
                refresh_token: "refresh_token",
                profile: {
                    sub: "sub",
                    nickname: "Nick",
                } as UserProfile,
            });

            const useRefreshTokenSpy = jest.spyOn(subject["_client"], "useRefreshToken").mockResolvedValue({
                access_token: "new_access_token",
                profile: {
                    sub: "sub",
                    nickname: "Nicholas",
                },
            } as unknown as SigninResponse);
            subject["_loadUser"] = jest.fn().mockResolvedValue(user);

            // act
            const refreshedUser = await subject.signinSilent();
            expect(refreshedUser).toHaveProperty("access_token", "new_access_token");
            expect(refreshedUser!.profile).toHaveProperty("nickname", "Nicholas");
            expect(useRefreshTokenSpy).toHaveBeenCalledWith(
                expect.objectContaining({
                    state: {
                        refresh_token: user.refresh_token,
                        session_state: null,
                        "profile": { "nickname": "Nick", "sub": "sub" },
                    },
                }),
            );
        });

        it("should use the resource from settings when a refresh token is present", async () => {
            // arrange
            const user = new User({
                access_token: "access_token",
                token_type: "token_type",
                refresh_token: "refresh_token",
                profile: {
                    sub: "sub",
                    nickname: "Nick",
                } as UserProfile,
            });

            const useRefreshTokenSpy = jest.spyOn(subject["_client"], "useRefreshToken").mockResolvedValue({
                access_token: "new_access_token",
                profile: {
                    sub: "sub",
                    nickname: "Nicholas",
                },
            } as unknown as SigninResponse);
            subject["_loadUser"] = jest.fn().mockResolvedValue(user);

            // act
            await subject.signinSilent({ resource: "resource" });
            expect(useRefreshTokenSpy).toHaveBeenCalledWith(
                expect.objectContaining({
                    state: {
                        refresh_token: user.refresh_token,
                        session_state: null,
                        "profile": { "nickname": "Nick", "sub": "sub" },
                    },
                    resource: "resource",
                }),
            );
        });

        it("should pass dpopJkt if dpop.bind_authorization_code is true", async () => {
            // arrange
            subject = new UserManager({
                authority: "http://sts/oidc",
                client_id: "client",
                redirect_uri: "http://app/cb",
                monitorSession : false,
                userStore: userStoreMock,
                metadata: {
                    authorization_endpoint: "http://sts/oidc/authorize",
                    end_session_endpoint:  "http://sts/oidc/logout",
                    token_endpoint: "http://sts/oidc/token",
                    revocation_endpoint: "http://sts/oidc/revoke",
                },
                dpop: {
                    bind_authorization_code: true,
                    store: new IndexedDbDPoPStore(),
                },
            });

            const keyPair = await CryptoUtils.generateDPoPKeys();
            await subject.settings.dpop?.store?.set("client", new DPoPState(keyPair));

            const user = new User({
                access_token: "access_token",
                token_type: "token_type",
                profile: {
                    sub: "sub",
                    nickname: "Nicholas",
                } as UserProfile,
            });

            subject["_signin"] = jest.fn().mockResolvedValue(user);

            subject["_loadUser"] = jest.fn().mockResolvedValue(user);

            const generateDPoPJktSpy = jest.spyOn(subject, "generateDPoPJkt");

            // act
            await subject.signinSilent({ resource: "resource" });

            // assert
            expect(generateDPoPJktSpy).toHaveBeenCalled();
            expect(subject["_signin"]).toHaveBeenCalledWith({
                request_type: "si:s",
                id_token_hint: undefined,
                redirect_uri: "http://app/cb",
                prompt: "none",
                dpopJkt: expect.any(String),
                resource: "resource",
            }, expect.any(Object), expect.any(String));
        });
    });

    describe("signinSilentCallback", () => {
        it("should call navigator callback", async () => {
            // arrange
            const callbackMock = jest.spyOn(subject["_iframeNavigator"], "callback");
            const url = "http://app/cb?state=test&code=code";

            // act
            await subject.signinSilentCallback(url);

            // assert
            expect(callbackMock).toHaveBeenCalledWith(url);
        });
    });

    describe("signinCallback", () => {
        it("should signin redirect callback for request type si:r", async () => {
            // arrange
            const user = new User({
                access_token: "access_token",
                token_type: "token_type",
                profile: {} as UserProfile,
            });
            const responseState = {
                state: { request_type: "si:r" } as SigninState,
                response: { } as SigninResponse,
            };
            jest.spyOn(subject["_client"], "readSigninResponseState")
                .mockImplementation(() => Promise.resolve(responseState));
            const signinRedirectCallbackMock = jest.spyOn(subject, "signinRedirectCallback")
                .mockImplementation(() => Promise.resolve(user));
            const url = "http://app/cb?state=test&code=code";

            // act
            const result = await subject.signinCallback(url);

            // assert
            expect(signinRedirectCallbackMock).toHaveBeenCalledWith(url);
            expect(result).toEqual(user);
        });

        it("should signin popup callback for request type si:p", async () => {
            // arrange
            const responseState = {
                state: { request_type: "si:p" } as SigninState,
                response: { } as SigninResponse,
            };
            jest.spyOn(subject["_client"], "readSigninResponseState")
                .mockImplementation(() => Promise.resolve(responseState));
            const signinPopupCallbackMock = jest.spyOn(subject, "signinPopupCallback").mockResolvedValue();
            const url = "http://app/cb?state=test&code=code";

            // act
            const result = await subject.signinCallback(url);

            // assert
            expect(signinPopupCallbackMock).toHaveBeenCalledWith(url);
            expect(result).toBe(undefined);
        });

        it("should signin silent callback for request type si:s", async () => {
            // arrange
            const responseState = {
                state: { request_type: "si:s" } as SigninState,
                response: { } as SigninResponse,
            };
            jest.spyOn(subject["_client"], "readSigninResponseState")
                .mockImplementation(() => Promise.resolve(responseState));
            const signinRedirectCallbackMock = jest.spyOn(subject, "signinSilentCallback").mockResolvedValue();
            const url = "http://app/cb?state=test&code=code";

            // act
            const result = await subject.signinCallback(url);

            // assert
            expect(signinRedirectCallbackMock).toHaveBeenCalledWith(url);
            expect(result).toBe(undefined);
        });

        it("should have valid request type", async () => {
            // arrange
            const responseState = {
                state: { request_type: "dummy" } as SigninState,
                response: { } as SigninResponse,
            };
            jest.spyOn(subject["_client"], "readSigninResponseState")
                .mockImplementation(() => Promise.resolve(responseState));

            // act
            await expect(subject.signinCallback())
                // assert
                .rejects.toThrow(Error);
        });
    });

    describe("signoutCallback", () => {
        it("should signout redirect callback for request type so:r", async () => {
            // arrange
            const responseState = {
                state: { request_type: "so:r" } as State,
                response: { } as SignoutResponse,
            };
            jest.spyOn(subject["_client"], "readSignoutResponseState")
                .mockImplementation(() => Promise.resolve(responseState));
            const signoutRedirectCallbackMock = jest.spyOn(subject, "signoutRedirectCallback")
                .mockImplementation();
            const url = "http://app/cb?state=test&code=code";

            // act
            await subject.signoutCallback(url);

            // assert
            expect(signoutRedirectCallbackMock).toHaveBeenCalledWith(url);
        });

        it("should signout popup callback for request type so:p", async () => {
            // arrange
            const responseState = {
                state: { request_type: "so:p" } as State,
                response: { } as SignoutResponse,
            };
            jest.spyOn(subject["_client"], "readSignoutResponseState")
                .mockImplementation(() => Promise.resolve(responseState));
            const signoutPopupCallbackMock = jest.spyOn(subject, "signoutPopupCallback")
                .mockImplementation();
            const url = "http://app/cb?state=test&code=code";
            const keepOpen = true;

            // act
            await subject.signoutCallback(url, keepOpen);

            // assert
            expect(signoutPopupCallbackMock).toHaveBeenCalledWith(url, keepOpen);
        });

        it("should signout silent callback for request type so:s", async () => {
            // arrange
            const responseState = {
                state: { request_type: "so:s" } as State,
                response: { } as SignoutResponse,
            };
            jest.spyOn(subject["_client"], "readSignoutResponseState")
                .mockImplementation(() => Promise.resolve(responseState));
            const signoutSilentCallbackMock = jest.spyOn(subject, "signoutSilentCallback")
                .mockImplementation();
            const url = "http://app/cb?state=test&code=code";

            // act
            await subject.signoutCallback(url);

            // assert
            expect(signoutSilentCallbackMock).toHaveBeenCalledWith(url);
        });

        it("should do nothing without state", async () => {
            // arrange
            const responseState = {
                state: undefined,
                response: { } as SignoutResponse,
            };
            jest.spyOn(subject["_client"], "readSignoutResponseState")
                .mockImplementation(() => Promise.resolve(responseState));

            // act & assert (no throw)
            await subject.signoutCallback();
        });

        it("should have valid request type", async () => {
            // arrange
            const responseState = {
                state: { request_type: "dummy" } as State,
                response: { } as SignoutResponse,
            };
            jest.spyOn(subject["_client"], "readSignoutResponseState")
                .mockImplementation(() => Promise.resolve(responseState));

            // act
            await expect(subject.signoutCallback())
                // assert
                .rejects.toThrow(Error);
        });
    });

    describe("signoutSilent", () => {
        it("should pass silentRequestTimeout from settings", async () => {
            // arrange
            Object.assign(subject.settings, {
                silentRequestTimeoutInSeconds: 123,
                silent_redirect_uri: "http://client/silent_callback",
            });
            subject["_signout"] = jest.fn();

            // act
            await subject.signoutSilent();
            const [, navInstance] = mocked(subject["_signout"]).mock.calls[0];

            // assert
            expect(navInstance).toHaveProperty("_timeoutInSeconds", 123);
        });

        it("should pass navigator params to navigator", async () => {
            // arrange
            const prepareMock = jest.spyOn(subject["_iframeNavigator"], "prepare");
            subject["_signout"] = jest.fn();
            const navParams: SignoutSilentArgs = {
                silentRequestTimeoutInSeconds: 234,
            };

            // act
            await subject.signoutSilent(navParams);

            // assert
            expect(prepareMock).toHaveBeenCalledWith(navParams);
        });

        it("should pass extra args to _signoutStart", async () => {
            // arrange
            jest.spyOn(subject["_popupNavigator"], "prepare");
            subject["_signout"] = jest.fn();
            const extraArgs: SignoutSilentArgs = {
                extraQueryParams: { q : "q" },
                state: "state",
                post_logout_redirect_uri: "http://app/extra_callback",
            };

            // act
            await subject.signoutSilent(extraArgs);

            // assert
            expect(subject["_signout"]).toHaveBeenCalledWith(
                {
                    request_type: "so:s",
                    id_token_hint: undefined,
                    ...extraArgs,
                },
                expect.objectContaining({
                    close: expect.any(Function),
                    navigate: expect.any(Function),
                }),
            );
        });

        it("should pass id_token as id_token_hint when user present and setting enabled", async () => {
            // arrange
            const user = new User({
                id_token: "id_token",
                access_token: "access_token",
                token_type: "token_type",
                profile: {} as UserProfile,
            });
            subject["_loadUser"] = jest.fn().mockResolvedValue(user);
            Object.assign(subject.settings, {
                includeIdTokenInSilentSignout: true,
            });
            subject["_signout"] = jest.fn().mockResolvedValue(user);

            // act
            await subject.signoutSilent();

            // assert
            expect(subject["_signout"]).toHaveBeenCalledWith(
                expect.objectContaining({
                    id_token_hint: "id_token",
                }),
                expect.anything(),
            );
        });

        it("should not pass id_token as id_token_hint when user present but setting disabled", async () => {
            // arrange
            const user = new User({
                id_token: "id_token",
                access_token: "access_token",
                token_type: "token_type",
                profile: {} as UserProfile,
            });
            subject["_loadUser"] = jest.fn().mockResolvedValue(user);
            Object.assign(subject.settings, {
                includeIdTokenInSilentSignout: false,
            });
            subject["_signout"] = jest.fn().mockResolvedValue(user);

            // act
            await subject.signoutSilent();

            // assert
            expect(subject["_signout"]).toHaveBeenCalledWith(
                expect.objectContaining({
                    id_token_hint: undefined,
                }),
                expect.anything(),
            );
        });
    });

    describe("signoutSilentCallback", () => {
        it("should call navigator callback", async () => {
            // arrange
            const callbackMock = jest.spyOn(subject["_iframeNavigator"], "callback");
            const url = "http://app/cb?state=test&code=code";

            // act
            await subject.signoutSilentCallback(url);

            // assert
            expect(callbackMock).toHaveBeenCalledWith(url);
        });
    });

    describe("signoutRedirect", () => {
        it("must remove the user before requesting the logout", async () => {
            // arrange
            const navigateMock = jest.fn().mockReturnValue(Promise.resolve({
                url: "http://localhost:8080",
            } as NavigateResponse));
            jest.spyOn(subject["_redirectNavigator"], "prepare").mockReturnValue(Promise.resolve({
                navigate: navigateMock,
                close: () => {},
            }));
            const user = new User({
                access_token: "access_token",
                token_type: "token_type",
                profile: {} as UserProfile,
            });
            await subject.storeUser(user);

            // act
            await subject.signoutRedirect();

            // assert
            expect(navigateMock).toHaveBeenCalledTimes(1);
            const storageString = await subject.settings.userStore.get(subject["_userStoreKey"]);
            expect(storageString).toBeNull();
        });
    });

    describe("signoutPopup", () => {
        it("should pass navigator params to navigator", async () => {
            // arrange
            const handle = { } as PopupWindow;
            const prepareMock = jest.spyOn(subject["_popupNavigator"], "prepare")
                .mockImplementation(() => Promise.resolve(handle));
            subject["_signout"] = jest.fn();
            const navParams: SignoutPopupArgs = {
                popupWindowFeatures: {
                    location: false,
                    toolbar: false,
                    height: 100,
                },
                popupWindowTarget: "popupWindowTarget",
            };

            // act
            await subject.signoutPopup(navParams);

            // assert
            expect(prepareMock).toHaveBeenCalledWith(navParams);
        });

        it("should pass extra args to _signoutStart", async () => {
            // arrange
            const handle = { } as PopupWindow;
            jest.spyOn(subject["_popupNavigator"], "prepare")
                .mockImplementation(() => Promise.resolve(handle));
            subject["_signout"] = jest.fn().mockResolvedValue({} as SignoutResponse);
            const extraArgs: SignoutPopupArgs = {
                extraQueryParams: { q : "q" },
                state: "state",
                post_logout_redirect_uri: "http://app/extra_callback",
            };

            // act
            await subject.signoutPopup(extraArgs);

            // assert
            expect(subject["_signout"]).toHaveBeenCalledWith(
                {
                    request_type: "so:p",
                    ...extraArgs,
                },
                handle,
            );
        });
    });

    describe("storeUser", () => {
        it("should add user to store", async () => {
            // arrange
            const user = new User({
                access_token: "access_token",
                token_type: "token_type",
                profile: {} as UserProfile,
            });

            // act
            await subject.storeUser(user);

            // assert
            const storageString = await subject.settings.userStore.get(subject["_userStoreKey"]);
            expect(storageString).not.toBeNull();
        });

        it("should remove user from store", async () => {
            // arrange
            const user = new User({
                access_token: "access_token",
                token_type: "token_type",
                profile: {} as UserProfile,
            });
            await subject.storeUser(user);

            // act
            await subject.storeUser(null);

            // assert
            const storageString = await subject.settings.userStore.get(subject["_userStoreKey"]);
            expect(storageString).toBeNull();
        });

        it("should remove dpop keys from the dpop store if dpop enabled", async () => {
            // arrange
            subject = new UserManager({
                authority: "http://sts/oidc",
                client_id: "client",
                redirect_uri: "http://app/cb",
                monitorSession : false,
                userStore: userStoreMock,
                metadata: {
                    authorization_endpoint: "http://sts/oidc/authorize",
                    end_session_endpoint:  "http://sts/oidc/logout",
                    token_endpoint: "http://sts/oidc/token",
                    revocation_endpoint: "http://sts/oidc/revoke",
                },
                dpop: { store: new IndexedDbDPoPStore() },
            });

            const user = new User({
                access_token: "access_token",
                token_type: "token_type",
                profile: {} as UserProfile,
            });
            await subject.storeUser(user);
            const dpopKeyPair = await CryptoUtils.generateDPoPKeys();
            await subject.settings.dpop?.store.set("client", new DPoPState(dpopKeyPair));

            // act
            await subject.storeUser(null);

            // assert
            const storageString = await subject.settings.userStore.get(subject["_userStoreKey"]);
            expect(storageString).toBeNull();
            const dpopKeys = await subject.settings.dpop?.store.get("client");
            expect(dpopKeys).toBeUndefined();
        });
    });

    describe("getDPoPProof",() => {
        it("should return a DPoP proof", async () => {
            // arrange
            subject = new UserManager({
                authority: "http://sts/oidc",
                client_id: "client",
                redirect_uri: "http://app/cb",
                monitorSession : false,
                userStore: userStoreMock,
                metadata: {
                    authorization_endpoint: "http://sts/oidc/authorize",
                    end_session_endpoint:  "http://sts/oidc/logout",
                    token_endpoint: "http://sts/oidc/token",
                    revocation_endpoint: "http://sts/oidc/revoke",
                },
                dpop: {
                    bind_authorization_code: false,
                    store: new IndexedDbDPoPStore(),
                },
            });

            const user = await subject.getUser() as User;
            const keyPair = await CryptoUtils.generateDPoPKeys();
            const mockDpopStore = jest.spyOn(subject.settings.dpop!.store, "get").mockResolvedValue(new DPoPState(keyPair));

            // act
            const dpopProof = await subject.dpopProof("http://some.url", user, "POST");

            // assert
            expect(mockDpopStore).toHaveBeenCalledWith("client");
            expect(dpopProof).toBeDefined();
            expect(typeof dpopProof).toBe("string");
        });
    });
});
