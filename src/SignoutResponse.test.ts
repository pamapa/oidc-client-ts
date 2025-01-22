// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import { SignoutResponse } from "./SignoutResponse";

describe("SignoutResponse", () => {

    describe("constructor", () => {

        it("should read error", () => {
            // act
            const subject = new SignoutResponse(new URLSearchParams("error=foo"));

            // assert
            expect(subject.error).toEqual("foo");
        });

        it("should read error_description", () => {
            // act
            const subject = new SignoutResponse(new URLSearchParams("error_description=foo"));

            // assert
            expect(subject.error_description).toEqual("foo");
        });

        it("should read error_uri", () => {
            // act
            const subject = new SignoutResponse(new URLSearchParams("error_uri=foo"));

            // assert
            expect(subject.error_uri).toEqual("foo");
        });

        it("should read state", () => {
            // act
            const subject = new SignoutResponse(new URLSearchParams("state=foo"));

            // assert
            expect(subject.state).toEqual("foo");
        });
        
        it("should read url_state", () => {
            // act
            const subject = new SignoutResponse(new URLSearchParams("state=foo;bar"));

            // assert
            expect(subject.state).toEqual("foo");
            expect(subject.url_state).toEqual("bar");
        });
    });
});
