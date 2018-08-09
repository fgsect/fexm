/*
 * WebSockets telnet client
 * Copyright (C) 2011 Joel Martin
 * Licensed under LGPL-3 (see LICENSE.txt)
 *
 * Includes VT100.js from:
 *   http://code.google.com/p/sshconsole
 * Which was modified from:
 *   http://fzort.org/bi/o.php#vt100_js
 * The complete code was changed (and partly fixed for latest browser) to integrate it into FExM.
 *   https://github.com/fgsect/fexm
 *
 * Telnet protocol:
 *   http://www.networksorcery.com/enp/protocol/telnet.htm
 *   http://www.networksorcery.com/enp/rfc/rfc1091.txt
 *
 * ANSI escape sequeneces:
 *   http://en.wikipedia.org/wiki/ANSI_escape_code
 *   http://ascii-table.com/ansi-escape-sequences-vt-100.php
 *   http://www.termsys.demon.co.uk/vtansi.htm
 *   http://invisible-island.net/xterm/ctlseqs/ctlseqs.html
 *
 * ASCII codes:
 *   http://en.wikipedia.org/wiki/ASCII
 *   http://www.hobbyprojects.com/ascii-table/ascii-table.html
 *
 * Other web consoles:
 *   http://stackoverflow.com/questions/244750/ajax-console-window-with-ansi-vt100-support
 */


function Telnet(target, connect_callback, disconnect_callback) {

    var that = {},  // Public API interface
        vt100, ws, sQ = [];
    var termType = "VT100";

    Array.prototype.pushStr = function (str) {
        var n = str.length;
        for (var i = 0; i < n; i++) {
            this.push(str.charCodeAt(i));
        }
    };

    function do_send() {
        if (sQ.length > 0) {
            console.debug("Sending " + sQ);
            ws.send(sQ);
            sQ = [];
        }
    }

    /**
     * Returns an array containing head at [0] and the rest of the array at [1].
     * This can is used to replace .shift() in immutable objects.
     * val = arr.shift(); -> [val, arr] = head(arr);
     * @param arr the array to shift
     * @return [arr[0], arr[1:]]
     */
    function head(arr) {
        return [arr[0], arr.slice(1)];
    }

    function stopEvent(e) {
        e.stopPropagation ? e.stopPropagation() : e.cancelBubble = true;
        e.preventDefault ? e.preventDefault() : e.returnValue = false;
    };

    function do_recv() {
        //console.log(">> do_recv");
        var arr = ws.rQshiftBytes(ws.rQlen()), str = "",
            chr, cmd, code, value;
        var _ = undefined;

        console.debug("Received array '" + arr + "'");
        while (arr.length > 0) {
            [chr, arr] = head(arr);
            switch (chr) {
                case 255:   // IAC
                    cmd = chr;
                    [code, arr] = head(arr);
                    [value, arr] = head(arr);
                    switch (code) {
                        case 254: // DONT
                            console.debug("Got Cmd DONT '" + value + "', ignoring");
                            break;
                        case 253: // DO
                            console.debug("Got Cmd DO '" + value + "'");
                            if (value === 24) {
                                // Terminal type
                                console.info("Send WILL '" + value + "' (TERM-TYPE)");
                                sQ.push(255, 251, value);
                            } else {
                                // Refuse other DO requests with a WONT
                                console.debug("Send WONT '" + value + "'");
                                sQ.push(255, 252, value);
                            }
                            break;
                        case 252: // WONT
                            console.debug("Got Cmd WONT '" + value + "', ignoring");
                            break;
                        case 251: // WILL
                            console.debug("Got Cmd WILL '" + value + "'");
                            if (value === 1) {
                                // Server will echo, turn off local echo
                                vt100.noecho();
                                // Affirm echo with DO
                                console.info("Send Cmd DO '" + value + "' (echo)");
                                sQ.push(255, 253, value);
                            } else {
                                // Reject other WILL offers with a DONT
                                console.debug("Send Cmd DONT '" + value + "'");
                                sQ.push(255, 254, value);
                            }
                            break;
                        case 250: // SB (subnegotiation)
                            if (value === 24) {
                                console.info("Got IAC SB TERM-TYPE SEND(1) IAC SE");
                                // TERM-TYPE subnegotiation
                                if (arr[0] === 1 &&
                                    arr[1] === 255 &&
                                    arr[2] === 240) {
                                    [_, arr] = head(arr);
                                    [_, arr] = head(arr);
                                    [_, arr] = head(arr);
                                    console.info("Send IAC SB TERM-TYPE IS(0) '" +
                                        termType + "' IAC SE");
                                    sQ.push(255, 250, 24, 0);
                                    sQ.pushStr(termType);
                                    sQ.push(255, 240);
                                } else {
                                    console.info("Invalid subnegotiation received" + arr);
                                }
                            } else {
                                console.info("Ignoring SB " + value);
                            }
                            break;
                        default:
                            console.info("Got Cmd " + cmd + " " + value + ", ignoring");
                    }
                    continue;
                case 242:   // Data Mark (Synch)
                    cmd = chr;
                    [code, arr] = head(arr);
                    [value, arr] = head(arr);
                    console.info("Ignoring Data Mark (Synch)");
                    break;
                default:   // everything else
                    str += String.fromCharCode(chr);
            }
        }

        if (sQ) {
            do_send();
        }

        if (str) {
            vt100.write(str);
        }

        //console.log("<< do_recv");
    }


    that.connect = function (host, port, encrypt) {
        var host = host,
            port = port,
            scheme = "ws://", uri;

        console.debug(">> connect");
        if ((!host) || (!port)) {
            console.log("must set host and port");
            return;
        }

        if (ws) {
            ws.close();
        }

        if (encrypt) {
            scheme = "wss://";
        }
        uri = scheme + host + ":" + port;
        console.info("connecting to " + uri);

        //var ws = new WebSocket(uri, ['binary', 'base64']);
        ws.open(uri, ['binary', 'base64']);

        console.debug("<< connect");
    }

    that.disconnect = function () {
        console.debug(">> disconnect");
        if (ws) {
            ws.close();
        }
        vt100.curs_set(true, false);

        disconnect_callback();
        console.debug("<< disconnect");
    }


    function constructor() {
        /* Initialize Websock object */
        ws = new Websock();


        ws.on('message', do_recv);
        ws.on('open', function (e) {
            console.info(">> WebSockets.onopen");
            vt100.curs_set(true, true);
            connect_callback();
            console.info("<< WebSockets.onopen");
        });
        ws.on('close', function (e) {
            console.info(">> WebSockets.onclose");
            that.disconnect();
            console.info("<< WebSockets.onclose");
        });
        ws.on('error', function (e) {
            console.info(">> WebSockets.onerror");
            that.disconnect();
            console.info("<< WebSockets.onerror");
        });

        /* Initialize the terminal emulator/renderer */

        vt100 = new VT100(80, 24, target);

        /*
         * Override VT100 I/O routines
         */
        // Set handler for sending characters
        vt100.getch(
            function send_chr(chr, vt) {
                var i;
                console.debug(">> send_chr: " + chr);
                for (i = 0; i < chr.length; i++) {
                    sQ.push(chr.charCodeAt(i));
                }
                do_send();
                vt100.getch(send_chr);
            }
        );

        vt100.debug = function (message) {
            console.debug(message + "\n");
        }

        vt100.warn = function (message) {
            console.warn(message + "\n");
        }

        vt100.curs_set = function (vis, grab, eventist) {
            this.debug("curs_set:: vis: " + vis + ", grab: " + grab);
            if (vis !== undefined)
                this.cursor_vis_ = (vis > 0);
            if (eventist === undefined)
                eventist = window;
            if (grab === true || grab === false) {
                var $eventist = $(eventist);
                if (grab === this.grab_events_)
                    return;
                if (grab) {
                    this.grab_events_ = true;
                    VT100.the_vt_ = this;
                    $eventist.on('keydown', vt100.key_down);
                    $eventist.on('keyup', vt100.key_up);
                } else {
                    $eventist.on('keydown', vt100.key_down);
                    $eventist.on('keyup', vt100.key_up);
                    this.grab_events_ = false;
                    VT100.the_vt_ = undefined;
                }
            }
        }

        vt100.key_down = function (e) {
            var vt = VT100.the_vt_, keysym, ch, str = "";

            if (vt === undefined)
                return true;

            keysym = getKeysym(e);

            if (keysym < 128) {
                if (e.ctrlKey) {
                    if (keysym == 64) {
                        // control 0
                        ch = 0;
                    } else if ((keysym >= 97) && (keysym <= 122)) {
                        // control codes 1-26
                        ch = keysym - 96;
                    } else if ((keysym >= 91) && (keysym <= 95)) {
                        // control codes 27-31
                        ch = keysym - 64;
                    } else {
                        console.info("Debug unknown control keysym: " + keysym);
                    }
                } else {
                    ch = keysym;
                }
                str = String.fromCharCode(ch);
            } else {
                switch (keysym) {
                    case 65505: // Shift, do not send directly
                        break;
                    case 65507: // Ctrl, do not send directly
                        break;
                    case 65293: // Carriage return, line feed
                        str = '\n';
                        break;
                    case 65288: // Backspace
                        str = '\b';
                        break;
                    case 65289: // Tab
                        str = '\t';
                        break;
                    case 65307: // Escape
                        str = '\x1b';
                        break;
                    case 65361: // Left arrow
                        str = '\x1b[D';
                        break;
                    case 65362: // Up arrow
                        str = '\x1b[A';
                        break;
                    case 65363: // Right arrow
                        str = '\x1b[C';
                        break;
                    case 65364: // Down arrow
                        str = '\x1b[B';
                        break;
                    default:
                        console.info("Unrecoginized keysym " + keysym);
                }
            }

            if (str) {
                vt.key_buf_.push(str);
                setTimeout(VT100.go_getch_, 0);
            }

            stopEvent(e);
            return false;
        }

        vt100.key_up = function (e) {
            var vt = VT100.the_vt_;
            if (vt === undefined)
                return true;
            stopEvent(e);
            return false;
        }

        return that;
    }

    return constructor(); // Return the public API interface

} // End of Telnet()
