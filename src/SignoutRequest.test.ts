// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import { SignoutRequest, type SignoutRequestArgs } from "./SignoutRequest";
import { URL_STATE_DELIMITER } from "./utils";

describe("SignoutRequest", () => {

    let subject: SignoutRequest;
    let settings: SignoutRequestArgs;

    beforeEach(() => {
        settings = {
            url: "http://sts/signout",
            id_token_hint: "hint",
            post_logout_redirect_uri: "loggedout",
            state_data: { data: "test" },
        };
        subject = new SignoutRequest(settings);
    });

    describe("constructor", () => {

        it("should require a url param", () => {
            // arrange
            Object.assign(settings, { url: undefined });

            // act
            try {
                new SignoutRequest(settings);
                fail("should not come here");
            }
            catch (err) {
                expect(err).toBeInstanceOf(Error);
                expect((err as Error).message).toContain("url");
            }
        });
    });

    describe("url", () => {

        it("should include url", () => {
            // assert
            expect(subject.url.indexOf("http://sts/signout")).toEqual(0);
        });

        it("should include id_token_hint", () => {
            // assert
            expect(subject.url).toContain("id_token_hint=hint");
        });

        it("should include post_logout_redirect_uri if id_token_hint also provided", () => {
            // assert
            expect(subject.url).toContain("post_logout_redirect_uri=loggedout");
        });

        it("should include post_logout_redirect_uri if no id_token_hint provided", () => {
            // arrange
            delete settings.id_token_hint;

            // act
            subject = new SignoutRequest(settings);

            // assert
            expect(subject.url).toContain("post_logout_redirect_uri=loggedout");
        });

        it("should include state if post_logout_redirect_uri provided", () => {
            // assert
            expect(subject.state).toBeDefined();
            expect(subject.url).toContain("state=" + subject.state!.id);
        });

        it("should include state if post_logout_redirect_uri and url_state provided even if state_data is empty", () => {
            // arrange
            delete settings.state_data;
            settings.url_state = "foo";

            // act
            subject = new SignoutRequest(settings);

            // assert
            expect(subject.state).toBeDefined();
            expect(subject.url).toContain("state=" + subject.state!.id + encodeURIComponent(URL_STATE_DELIMITER + "foo"));
        });

        it("should not include state if no post_logout_redirect_uri provided", () => {
            // arrange
            delete settings.post_logout_redirect_uri;

            // act
            subject = new SignoutRequest(settings);

            // assert
            expect(subject.url).not.toContain("state=");
        });
        
        it("should include url_state", async () => {
            // arrange
            settings.url_state = "foo";

            // act
            subject = new SignoutRequest(settings);

            // assert
            expect(subject.url).toContain("state=" + subject.state!.id + encodeURIComponent(URL_STATE_DELIMITER + "foo"));
        });

        it("should not include state or url_state if no post_logout_redirect_uri provided", () => {
            // arrange
            delete settings.post_logout_redirect_uri;
            settings.url_state = "foo";

            // act
            subject = new SignoutRequest(settings);

            // assert
            expect(subject.url).not.toContain("state=");
        });

        it("should include id_token_hint, post_logout_redirect_uri, and state", () => {
            // assert
            const url = subject.url;
            expect(url.indexOf("http://sts/signout?")).toEqual(0);
            expect(url).toContain("id_token_hint=hint");
            expect(url).toContain("post_logout_redirect_uri=loggedout");
            expect(subject.state).toBeDefined();
            expect(url).toContain("state=" + subject.state!.id);
        });

        it("should include extra query params", () => {
            // arrange
            settings.extraQueryParams = {
                "TargetResource": "logouturl.com",
                "InErrorResource": "errorurl.com",
            };

            // act
            subject = new SignoutRequest(settings);

            // assert
            expect(subject.url).toContain("TargetResource=logouturl.com&InErrorResource=errorurl.com");
        });

    });
});
