const TEA = {};

function tea_decipher(v, k) {
  // [v0, v1] = struct.unpack("=LL", v.slice(0, 8));
  let v0 = v.readUInt32LE(0);
  let v1 = v.readUInt32LE(4);

  // [k1, k2, k3, k4] = struct.unpack("=LLLL", k.slice(0, 16));
  const k1 = k.readUInt32LE(0);
  const k2 = k.readUInt32LE(4);
  const k3 = k.readUInt32LE(8);
  const k4 = k.readUInt32LE(12);
  const op = 0xffffffff;
  const delta = 0x9E3779B9;
  let s = ((delta << 4) & op) >>> 0;
  // let aa = s >>> 0;

  for (let i = 0, round = 16; i < round; i += 1) {
    v1 = ((v1 - (((v0 << 4) + k3) ^ (v0 + s) ^ ((v0 >>> 5) + k4)) >>> 0) & op) >>> 0;
    v0 = ((v0 - (((v1 << 4) + k1) ^ (v1 + s) ^ ((v1 >>> 5) + k2)) >>> 0) & op) >>> 0;
    s = ((s - delta) & op) >>> 0;
  }
  // return struct.pack("=LL", v0, v1);
  const buf = Buffer.allocUnsafe(8);
  buf.writeUInt32LE(v0, 0);
  buf.writeUInt32LE(v1, 4);
  return buf;
}

TEA.decrypt = function (v, k) {
  const num = Math.floor(v.length / 8) * 8;
  let ret = Buffer.alloc(0);
  for (let i = 0, final = num; i < final; i += 8) {
    const x = tea_decipher(v.slice(i, i + 8), k);
    ret = Buffer.concat([ret, x]);
  }
  return Buffer.concat([ret, v.slice(num)]);
};

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

function ByteToUint(byte) {
  if (byte < 0) {
    return (byte + 256);
  }
  return byte;
}

TEA.decrypt2 = function (src, pwdKey) {
  const TIMES = 32;
  const delta = 0x9e3779b9;

  const a = pwdKey.readUInt32LE(0);
  const b = pwdKey.readUInt32LE(4);
  const c = pwdKey.readUInt32LE(8);
  const d = pwdKey.readUInt32LE(12);

  const newbyte = Buffer.alloc(src.length);

  for (let offset = 0; offset < src.length; offset += 8) {
    let y = ByteToUint(src[offset + 3]) | ByteToUint(src[offset + 2]) << 8 | ByteToUint(src[offset + 1]) << 16 | ByteToUint(src[offset]) << 24;
    let z = ByteToUint(src[offset + 7]) | ByteToUint(src[offset + 6]) << 8 | ByteToUint(src[offset + 5]) << 16 | ByteToUint(src[offset + 4]) << 24;

    let sum = 0;
    if (TIMES === 32) {
      sum = 0xC6EF3720;
    } else if (TIMES === 16) {
      sum = 0xE3779B90; // (delta << 4) & 0xFFFFFFFF
    } else {
      sum = delta * TIMES;
    }

    for (let i = 0; i < TIMES; i++) {
      z = (z - ((((y << 4) + c) & 0xFFFFFFFF) ^ ((y + sum) & 0xFFFFFFFF) ^ (((y >> 5) + d) & 0xFFFFFFFF))) & 0xFFFFFFFF;
      y = (y - ((((z << 4) + a) & 0xFFFFFFFF) ^ ((z + sum) & 0xFFFFFFFF) ^ (((z >> 5) + b) & 0xFFFFFFFF))) & 0xFFFFFFFF;
      sum = (sum - delta) & 0xFFFFFFFF;
    }

    newbyte.writeInt32BE((y & 0xFFFFFFFF), offset);
    newbyte.writeInt32BE((z & 0xFFFFFFFF), (offset + 4));
  }

  const n = newbyte[0];
  const ch = Buffer.alloc(src.length - n);

  for (let i = 0; i < src.length - n; i++) {
    ch[i] = newbyte[i + n];
  }
  return ch;
};

TEA.encrypt = function (src, pwdkey) {
  const TIMES = 32;
  const n = 8 - (src.length % 8);
  const byte = Buffer.alloc(src.length + n);
  const cc = n;

  for (var i = 0; i < n; i++) {
    if (i === 0) {
      byte[i] = cc;
    } else {
      byte[i] = 0;
    }
  }

  for (let j = 0; j < src.length; j++) {
    byte.write(src[j], (n + j));
  }
  const delta = 0x9e3779b9;
  const a = pwdkey.readUInt32LE(0);
  const b = pwdkey.readUInt32LE(4);
  const c = pwdkey.readUInt32LE(8);
  const d = pwdkey.readUInt32LE(12);

  const newbyte = Buffer.alloc(src.length + n);

  for (let offset = 0; offset < src.length + n; offset += 8) {
    let y = ByteToUint(byte[offset + 3]) | ByteToUint(byte[offset + 2]) << 8 | ByteToUint(byte[offset + 1]) << 16 | ByteToUint(byte[offset]) << 24;
    let z = ByteToUint(byte[offset + 7]) | ByteToUint(byte[offset + 6]) << 8 | ByteToUint(byte[offset + 5]) << 16 | ByteToUint(byte[offset + 4]) << 24;

    let sum = 0;

    for (var i = 0; i < TIMES; i++) {
      sum = (sum + delta) & 0xFFFFFFFF;
      y = (y + ((((z << 4) + a) & 0xFFFFFFFF) ^ ((z + sum) & 0xFFFFFFFF) ^ (((z >> 5) + b) & 0xFFFFFFFF))) & 0xFFFFFFFF;
      z = (z + ((((y << 4) + c) & 0xFFFFFFFF) ^ ((y + sum) & 0xFFFFFFFF) ^ (((y >> 5) + d) & 0xFFFFFFFF))) & 0xFFFFFFFF;
    }

    newbyte.writeInt32BE((y & 0xFFFFFFFF), offset);
    newbyte.writeInt32BE((z & 0xFFFFFFFF), (offset + 4));
  }

  return newbyte;
};

/*
 * decrypt text using Corrected Block TEA (xxtea) algorithm
 *
 * @param {string} ciphertext String to be decrypted
 * @param {string} password   Password to be used for decryption (1st 16 chars)
 * @returns {string} decrypted text
 */
TEA.decrypt3 = function (ciphertext, password) {
  if (ciphertext.length == 0) return ('');
  const v = TEA.strToLongs(Base64.decode(ciphertext));
  const k = TEA.strToLongs(Utf8.encode(password).slice(0, 16));
  const n = v.length;

  // ---- <TEA decoding> ----

  let z = v[n - 1]; let y = v[0]; const
    delta = 0x9E3779B9;
  let mx; let e; const q = Math.floor(6 + 52 / n); let
    sum = q * delta;

  while (sum != 0) {
    e = sum >>> 2 & 3;
    for (let p = n - 1; p >= 0; p--) {
      z = v[p > 0 ? p - 1 : n - 1];
      mx = (z >>> 5 ^ y << 2) + (y >>> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z);
      y = v[p] -= mx;
    }
    sum -= delta;
  }

  // ---- </TEA> ----

  let plaintext = TEA.longsToStr(v);

  // strip trailing null chars resulting from filling 4-char blocks:
  plaintext = plaintext.replace(/\0+$/, '');

  return Utf8.decode(plaintext);
};

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

// supporting functions

TEA.strToLongs = function (s) { // convert string to array of longs, each containing 4 chars
  // note chars must be within ISO-8859-1 (with Unicode code-point < 256) to fit 4/long
  const l = new Array(Math.ceil(s.length / 4));
  for (let i = 0; i < l.length; i++) {
    // note little-endian encoding - endianness is irrelevant as long as
    // it is the same in longsToStr()
    l[i] = s.charCodeAt(i * 4) + (s.charCodeAt(i * 4 + 1) << 8)
            + (s.charCodeAt(i * 4 + 2) << 16) + (s.charCodeAt(i * 4 + 3) << 24);
  }
  return l; // note running off the end of the string generates nulls since
}; // bitwise operators treat NaN as 0

TEA.longsToStr = function (l) { // convert array of longs back to string
  const a = new Array(l.length);
  for (let i = 0; i < l.length; i++) {
    a[i] = String.fromCharCode(
      l[i] & 0xFF,
      l[i] >>> 8 & 0xFF,
      l[i] >>> 16 & 0xFF,
      l[i] >>> 24 & 0xFF,
    );
  }
  return a.join(''); // use Array.join() rather than repeated string appends for efficiency in IE
};

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/*  Base64 class: Base 64 encoding / decoding (c) Chris Veness 2002-2010                          */
/*    note: depends on Utf8 class                                                                 */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

var Base64 = {}; // Base64 namespace

Base64.code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';

/**
 * Encode string into Base64, as defined by RFC 4648 [http://tools.ietf.org/html/rfc4648]
 * (instance method extending String object). As per RFC 4648, no newlines are added.
 *
 * @param {String} str The string to be encoded as base-64
 * @param {Boolean} [utf8encode=false] Flag to indicate whether str is Unicode string to be encoded
 *   to UTF8 before conversion to base64; otherwise string is assumed to be 8-bit characters
 * @returns {String} Base64-encoded string
 */
Base64.encode = function (str, utf8encode) { // http://tools.ietf.org/html/rfc4648
  utf8encode = (typeof utf8encode === 'undefined') ? false : utf8encode;
  let o1; let o2; let o3; let bits; let h1; let h2; let h3; let h4; const e = []; let pad = ''; let c; let plain; let
    coded;
  const b64 = Base64.code;

  plain = utf8encode ? Utf8.encode(str) : str;

  c = plain.length % 3; // pad string to length of multiple of 3
  if (c > 0) {
    while (c++ < 3) {
      pad += '=';
      plain += '\0';
    }
  }
  // note: doing padding here saves us doing special-case packing for trailing 1 or 2 chars

  for (c = 0; c < plain.length; c += 3) { // pack three octets into four hexets
    o1 = plain.charCodeAt(c);
    o2 = plain.charCodeAt(c + 1);
    o3 = plain.charCodeAt(c + 2);

    bits = o1 << 16 | o2 << 8 | o3;

    h1 = bits >> 18 & 0x3f;
    h2 = bits >> 12 & 0x3f;
    h3 = bits >> 6 & 0x3f;
    h4 = bits & 0x3f;

    // use hextets to index into code string
    e[c / 3] = b64.charAt(h1) + b64.charAt(h2) + b64.charAt(h3) + b64.charAt(h4);
  }
  coded = e.join(''); // join() is far faster than repeated string concatenation in IE

  // replace 'A's from padded nulls with '='s
  coded = coded.slice(0, coded.length - pad.length) + pad;

  return coded;
};

/**
 * Decode string from Base64, as defined by RFC 4648 [http://tools.ietf.org/html/rfc4648]
 * (instance method extending String object). As per RFC 4648, newlines are not catered for.
 *
 * @param {String} str The string to be decoded from base-64
 * @param {Boolean} [utf8decode=false] Flag to indicate whether str is Unicode string to be decoded
 *   from UTF8 after conversion from base64
 * @returns {String} decoded string
 */
Base64.decode = function (str, utf8decode) {
  utf8decode = (typeof utf8decode === 'undefined') ? false : utf8decode;
  let o1; let o2; let o3; let h1; let h2; let h3; let h4; let bits; const d = []; let plain; let
    coded;
  const b64 = Base64.code;

  coded = utf8decode ? Utf8.decode(str) : str;

  for (let c = 0; c < coded.length; c += 4) { // unpack four hexets into three octets
    h1 = b64.indexOf(coded.charAt(c));
    h2 = b64.indexOf(coded.charAt(c + 1));
    h3 = b64.indexOf(coded.charAt(c + 2));
    h4 = b64.indexOf(coded.charAt(c + 3));

    bits = h1 << 18 | h2 << 12 | h3 << 6 | h4;

    o1 = bits >>> 16 & 0xff;
    o2 = bits >>> 8 & 0xff;
    o3 = bits & 0xff;

    d[c / 4] = String.fromCharCode(o1, o2, o3);
    // check for padding
    if (h4 == 0x40) d[c / 4] = String.fromCharCode(o1, o2);
    if (h3 == 0x40) d[c / 4] = String.fromCharCode(o1);
  }
  plain = d.join(''); // join() is far faster than repeated string concatenation in IE

  return utf8decode ? Utf8.decode(plain) : plain;
};

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/*  Utf8 class: encode / decode between multi-byte Unicode characters and UTF-8 multiple          */
/*              single-byte character encoding (c) Chris Veness 2002-2010                         */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

var Utf8 = {}; // Utf8 namespace

/**
 * Encode multi-byte Unicode string into utf-8 multiple single-byte characters
 * (BMP / basic multilingual plane only)
 *
 * Chars in range U+0080 - U+07FF are encoded in 2 chars, U+0800 - U+FFFF in 3 chars
 *
 * @param {String} strUni Unicode string to be encoded as UTF-8
 * @returns {String} encoded string
 */
Utf8.encode = function (strUni) {
  // use regular expressions & String.replace callback function for better efficiency
  // than procedural approaches
  let strUtf = strUni.replace(
    /[\u0080-\u07ff]/g, // U+0080 - U+07FF => 2 bytes 110yyyyy, 10zzzzzz
    (c) => {
      const cc = c.charCodeAt(0);
      return String.fromCharCode(0xc0 | cc >> 6, 0x80 | cc & 0x3f);
    },
  );
  strUtf = strUtf.replace(
    /[\u0800-\uffff]/g, // U+0800 - U+FFFF => 3 bytes 1110xxxx, 10yyyyyy, 10zzzzzz
    (c) => {
      const cc = c.charCodeAt(0);
      return String.fromCharCode(0xe0 | cc >> 12, 0x80 | cc >> 6 & 0x3F, 0x80 | cc & 0x3f);
    },
  );
  return strUtf;
};

/**
 * Decode utf-8 encoded string back into multi-byte Unicode characters
 *
 * @param {String} strUtf UTF-8 string to be decoded back to Unicode
 * @returns {String} decoded string
 */
Utf8.decode = function (strUtf) {
  // note: decode 3-byte chars first as decoded 2-byte strings could appear to be 3-byte char!
  let strUni = strUtf.replace(
    /[\u00e0-\u00ef][\u0080-\u00bf][\u0080-\u00bf]/g, // 3-byte chars
    (c) => { // (note parentheses for precence)
      const cc = ((c.charCodeAt(0) & 0x0f) << 12) | ((c.charCodeAt(1) & 0x3f) << 6) | (c.charCodeAt(2) & 0x3f);
      return String.fromCharCode(cc);
    },
  );
  strUni = strUni.replace(
    /[\u00c0-\u00df][\u0080-\u00bf]/g, // 2-byte chars
    (c) => { // (note parentheses for precence)
      const cc = (c.charCodeAt(0) & 0x1f) << 6 | c.charCodeAt(1) & 0x3f;
      return String.fromCharCode(cc);
    },
  );
  return strUni;
};

module.exports = TEA;
