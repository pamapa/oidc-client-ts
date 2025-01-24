// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import { Logger } from "../utils";
import { ErrorTimeout } from "../errors";
import type { NavigateParams, NavigateResponse } from "./IWindow";
import { AbstractChildWindow } from "./AbstractChildWindow";
import { DefaultSilentRequestTimeoutInSeconds } from "../UserManagerSettings";

/**
 * @public
 */
export interface IFrameWindowParams {
    silentRequestTimeoutInSeconds?: number;
}

/**
 * @internal
 */
export class IFrameWindow extends AbstractChildWindow {
    protected readonly _logger = new Logger("IFrameWindow");
    private _frame: HTMLIFrameElement | null;
    private _timeoutInSeconds: number;

    public constructor({
        silentRequestTimeoutInSeconds = DefaultSilentRequestTimeoutInSeconds,
    }: IFrameWindowParams) {
        super();
        this._timeoutInSeconds = silentRequestTimeoutInSeconds;

        this._frame = IFrameWindow.createHiddenIframe();
        this._window = this._frame.contentWindow;
    }

    private static createHiddenIframe(): HTMLIFrameElement {
        const iframe = window.document.createElement("iframe");

        // shotgun approach
        iframe.style.visibility = "hidden";
        iframe.style.position = "fixed";
        iframe.style.left = "-1000px";
        iframe.style.top = "0";
        iframe.width = "0";
        iframe.height = "0";

        // allow access to local storage
        iframe.setAttribute(
            "sandbox",
            "allow-storage-access-by-user-activation allow-scripts allow-same-origin",
        );

        window.document.body.appendChild(iframe);
        return iframe;
    }

    public async navigate(params: NavigateParams): Promise<NavigateResponse> {
        this._logger.debug("navigate: Using timeout of:", this._timeoutInSeconds);
        const timer = setTimeout(() => void this._abort.raise(new ErrorTimeout("IFrame timed out without a response")), this._timeoutInSeconds * 1000);
        this._disposeHandlers.add(() => clearTimeout(timer));

        return await super.navigate(params);
    }

    public close(): void {
        if (this._frame) {
            if (this._frame.parentNode) {
                this._frame.addEventListener("load", (ev) => {
                    const frame = ev.target as HTMLIFrameElement;
                    frame.parentNode?.removeChild(frame);
                    void this._abort.raise(new Error("IFrame removed from DOM"));
                }, true);
                this._frame.contentWindow?.location.replace("about:blank");
            }
            this._frame = null;
        }
        this._window = null;
    }

    public static notifyParent(url: string, targetOrigin?: string): void {
        return super._notifyParent(window.parent, url, false, targetOrigin);
    }
}
