// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import { URL_STATE_DELIMITER } from "./utils";

/**
 * @public
 * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthError
 */
export class SignoutResponse {
    public readonly state: string | null;

    // error props
    /** @see {@link ErrorResponse.error} */
    public error: string | null;
    /** @see {@link ErrorResponse.error_description} */
    public error_description: string | null;
    /** @see {@link ErrorResponse.error_uri} */
    public error_uri: string | null;

    /** custom state data set during the initial signin request */
    public userState: unknown;
    public url_state?: string;

    public constructor(params: URLSearchParams) {
        this.state = params.get("state");
        if (this.state) {
            const splitState = decodeURIComponent(this.state).split(URL_STATE_DELIMITER);
            this.state = splitState[0];
            if (splitState.length > 1) {
                this.url_state = splitState.slice(1).join(URL_STATE_DELIMITER);
            }
        }

        this.error = params.get("error");
        this.error_description = params.get("error_description");
        this.error_uri = params.get("error_uri");
    }
}
