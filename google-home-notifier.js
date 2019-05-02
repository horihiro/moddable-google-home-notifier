import MDNS from "mdns";
import googleTTS from 'google-tts';
import CastV2 from "castv2";

const mdns = new MDNS({});

let deviceAddress = "";
let device = "Google Home";
let language = "en";

class GoogleHomeNotifier {
  ip (ip, lang) {
    deviceAddress = ip;
    language = lang || language;
    return this;
  }

  device (name, lang) {
    device = name;
    language = lang || language;
    return this;
  }

  play(dict) {
    return new Promise((res, rej) => {
      try {
        let done = false;
        setTimeout(() => {
          done = true;
          rej(`mDNS timeout.`);
        }, 10000);
        mdns.monitor("_googlecast._tcp", (service, instance) => {
          if (done) return;
          try {
            if (instance.txt.filter(t => t.indexOf(`fn=${device}`) === 0).length === 1) {
              done = true;
              res(instance);
              return;
            }
          } catch (e) {
            rej(e);
          }
        });
      } catch (e) {
        rej(e);
      }
    })
    .then((instance) => {
      dict = Object.assign(dict, {host: instance.address, port: instance.port});
      return new CastV2().cast(dict);
    });
  }

  notify(dict) {
    return googleTTS(dict.text, language).then((url) => {
      dict = Object.assign(dict, {url});
      return this.play(dict);
    });
  }

  notifyAsync(message, callback) {
  }
}

Object.freeze(GoogleHomeNotifier.prototype);
export default new GoogleHomeNotifier();
