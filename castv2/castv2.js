import SecureSocket from "securesocket";

const CASTV2_NS_CONNECTION = 'urn:x-cast:com.google.cast.tp.connection';
const CASTV2_NS_HEARTBEAT = 'urn:x-cast:com.google.cast.tp.heartbeat';
const CASTV2_NS_RECEIVER = 'urn:x-cast:com.google.cast.receiver';
const CASTV2_NS_MEDIA = 'urn:x-cast:com.google.cast.media';

const statusArray = [
  'not connected',
  'connecting',
  'sending `CONNECT` packet',
  'sending `PING` packet',
  'sending `LAUNCH` packet',
  'sending `CONNECT` with transportId packet',
  'notifying'
]

class CastV2 @ "xs_castv2_destructor" {
  _serialize(sourceId, destinationId, namespace, data) @ "xs_castv2_serialize"
  _deserialize(sourceId, destinationId, namespace, data) @ "xs_castv2_deserialize"
  constructor() {
  }
  cast(dict) {
    const APP_ID = 'CC1AD845';

    const CASTV2_DATA_CONNECT = '{"type":"CONNECT"}';
    const CASTV2_DATA_PING = '{"type":"PING"}';
    const CASTV2_DATA_PONG = '{"type":"PONG"}';
    const CASTV2_DATA_LAUNCH = `{"type":"LAUNCH","appId":"${APP_ID}","requestId":1}`;
    const CASTV2_DATA_LOAD = `{"type":"LOAD","autoplay":true,"currentTime":0,"activeTrackIds":[],"repeatMode":"REPEAT_OFF","media":{"contentId":"${dict.url}","contentType":"audio/mp3","streamType":"BUFFERED"},"requestId":1}`;
    
    return Promise.resolve()
    .then(() => {
      return  new Promise((res, rej) => {
        let status = 0;
        let transportId = '';
        let clientId = '';
        const socket = new SecureSocket({host: dict.host, port: dict.port, secure: {verify: false, cache: false, protocolVersion: 0x303}});
        status = 1;
        const socketCallback = (message, value) => {

          try {
            if (message === 1) {
              status = 2;
              socket.write(this._serialize('sender-0', 'receiver-0', CASTV2_NS_CONNECTION, CASTV2_DATA_CONNECT));
            } else if (message === 2) {
              const rcvPacket = socket.read(ArrayBuffer);
              const returnValue = this._deserialize(rcvPacket);
              if (returnValue.data === '{"type":"PING"}') {
                socket.write(this._serialize('sender-0', 'receiver-0', CASTV2_NS_HEARTBEAT, CASTV2_DATA_PONG));
                return;
              }
              if (status === 3) {
                status = 4;
                socket.write(this._serialize('sender-0', 'receiver-0', CASTV2_NS_RECEIVER, CASTV2_DATA_LAUNCH));
              } else if (status === 4) {
                if (returnValue.data.indexOf('"type":"RECEIVER_STATUS"') < 0  || returnValue.data.indexOf(`"appId":"${APP_ID}"`) < 0) return;
  
                transportId = returnValue.data.replace(/^.*"transportId":"([^"]+)".*$/, "$1");
                clientId = `client-${Date.now()}`;
                status = 5;
                socket.write(this._serialize(clientId, transportId, CASTV2_NS_CONNECTION, CASTV2_DATA_CONNECT));
                status = 6;
                socket.write(this._serialize(clientId, transportId, CASTV2_NS_MEDIA, CASTV2_DATA_LOAD));
              }
            } else if (message === 3 ) {
              if (status === 2) {
                status = 3;
                socket.write(this._serialize('sender-0', 'receiver-0', CASTV2_NS_HEARTBEAT, CASTV2_DATA_PING));
              } else if (status === 6) {
                socket.close();
                res();
              }
            } else if (message < 0 && status !== 6) {
              rej({message, status});
            }
          } catch(e) {
            rej({status})
          }
        };
        status = 0;
        socket.callback = socketCallback;
      });
    });
  }
}
Object.freeze(CastV2.prototype);

export default CastV2;