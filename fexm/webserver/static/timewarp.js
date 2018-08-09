/**
 * Inits Timwarp
 * @param $stdio obj stdio telnet view
 * @param stdio port for the stdio websocket
 * @param $cnc obj for the cnc telnet view
 * @param cnc port for the cnc websocket
 * @param options: optional params:
 *                 host: the host (default: the current hostname)
 *                 encrypt: if the connection request should use secure websockets (default: false)
 * @constructor
 */
function Timewarp($stdio, stdio, options) {  //. $cnc, cnc, options) {
    options = options ? options : {};
    var host = options.host ? options.host : window.location.hostname;
    var encrypt = !!options.encrypt;

    var stdionet = Telnet($($stdio)[0].id, ()=>console.log("stdio con"), ()=>console.log("stdio decon"));
    //var cncnet = Telnet($($cnc)[0].id, ()=>console.log("cnc con"), ()=>console.log("cnc decon"));
    stdionet.connect(host, stdio, encrypt);
    //cncnet.connect(host, cnc, encrypt)
}

