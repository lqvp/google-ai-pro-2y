(() => {
  var __defProp = Object.defineProperty;
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __esm = (fn, res) => function __init() {
    return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
  };
  var __commonJS = (cb, mod) => function __require() {
    return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
  };
  var __export = (target, all) => {
    for (var name in all)
      __defProp(target, name, { get: all[name], enumerable: true });
  };

  // frida-shim:node_modules/@frida/base64-js/index.js
  function getLens(b64) {
    const len = b64.length;
    if (len % 4 > 0) {
      throw new Error("Invalid string. Length must be a multiple of 4");
    }
    let validLen = b64.indexOf("=");
    if (validLen === -1) validLen = len;
    const placeHoldersLen = validLen === len ? 0 : 4 - validLen % 4;
    return [validLen, placeHoldersLen];
  }
  function _byteLength(b64, validLen, placeHoldersLen) {
    return (validLen + placeHoldersLen) * 3 / 4 - placeHoldersLen;
  }
  function toByteArray(b64) {
    const lens = getLens(b64);
    const validLen = lens[0];
    const placeHoldersLen = lens[1];
    const arr = new Uint8Array(_byteLength(b64, validLen, placeHoldersLen));
    let curByte = 0;
    const len = placeHoldersLen > 0 ? validLen - 4 : validLen;
    let i;
    for (i = 0; i < len; i += 4) {
      const tmp = revLookup[b64.charCodeAt(i)] << 18 | revLookup[b64.charCodeAt(i + 1)] << 12 | revLookup[b64.charCodeAt(i + 2)] << 6 | revLookup[b64.charCodeAt(i + 3)];
      arr[curByte++] = tmp >> 16 & 255;
      arr[curByte++] = tmp >> 8 & 255;
      arr[curByte++] = tmp & 255;
    }
    if (placeHoldersLen === 2) {
      const tmp = revLookup[b64.charCodeAt(i)] << 2 | revLookup[b64.charCodeAt(i + 1)] >> 4;
      arr[curByte++] = tmp & 255;
    }
    if (placeHoldersLen === 1) {
      const tmp = revLookup[b64.charCodeAt(i)] << 10 | revLookup[b64.charCodeAt(i + 1)] << 4 | revLookup[b64.charCodeAt(i + 2)] >> 2;
      arr[curByte++] = tmp >> 8 & 255;
      arr[curByte++] = tmp & 255;
    }
    return arr;
  }
  function tripletToBase64(num) {
    return lookup[num >> 18 & 63] + lookup[num >> 12 & 63] + lookup[num >> 6 & 63] + lookup[num & 63];
  }
  function encodeChunk(uint8, start, end) {
    const output = [];
    for (let i = start; i < end; i += 3) {
      const tmp = (uint8[i] << 16 & 16711680) + (uint8[i + 1] << 8 & 65280) + (uint8[i + 2] & 255);
      output.push(tripletToBase64(tmp));
    }
    return output.join("");
  }
  function fromByteArray(uint8) {
    const len = uint8.length;
    const extraBytes = len % 3;
    const parts = [];
    const maxChunkLength = 16383;
    for (let i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
      parts.push(encodeChunk(uint8, i, i + maxChunkLength > len2 ? len2 : i + maxChunkLength));
    }
    if (extraBytes === 1) {
      const tmp = uint8[len - 1];
      parts.push(
        lookup[tmp >> 2] + lookup[tmp << 4 & 63] + "=="
      );
    } else if (extraBytes === 2) {
      const tmp = (uint8[len - 2] << 8) + uint8[len - 1];
      parts.push(
        lookup[tmp >> 10] + lookup[tmp >> 4 & 63] + lookup[tmp << 2 & 63] + "="
      );
    }
    return parts.join("");
  }
  var lookup, revLookup, code;
  var init_base64_js = __esm({
    "frida-shim:node_modules/@frida/base64-js/index.js"() {
      init_node_globals();
      lookup = [];
      revLookup = [];
      code = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
      for (let i = 0, len = code.length; i < len; ++i) {
        lookup[i] = code[i];
        revLookup[code.charCodeAt(i)] = i;
      }
      revLookup["-".charCodeAt(0)] = 62;
      revLookup["_".charCodeAt(0)] = 63;
    }
  });

  // frida-shim:node_modules/@frida/ieee754/index.js
  function read(buffer, offset, isLE, mLen, nBytes) {
    let e, m;
    const eLen = nBytes * 8 - mLen - 1;
    const eMax = (1 << eLen) - 1;
    const eBias = eMax >> 1;
    let nBits = -7;
    let i = isLE ? nBytes - 1 : 0;
    const d = isLE ? -1 : 1;
    let s = buffer[offset + i];
    i += d;
    e = s & (1 << -nBits) - 1;
    s >>= -nBits;
    nBits += eLen;
    while (nBits > 0) {
      e = e * 256 + buffer[offset + i];
      i += d;
      nBits -= 8;
    }
    m = e & (1 << -nBits) - 1;
    e >>= -nBits;
    nBits += mLen;
    while (nBits > 0) {
      m = m * 256 + buffer[offset + i];
      i += d;
      nBits -= 8;
    }
    if (e === 0) {
      e = 1 - eBias;
    } else if (e === eMax) {
      return m ? NaN : (s ? -1 : 1) * Infinity;
    } else {
      m = m + Math.pow(2, mLen);
      e = e - eBias;
    }
    return (s ? -1 : 1) * m * Math.pow(2, e - mLen);
  }
  function write(buffer, value, offset, isLE, mLen, nBytes) {
    let e, m, c;
    let eLen = nBytes * 8 - mLen - 1;
    const eMax = (1 << eLen) - 1;
    const eBias = eMax >> 1;
    const rt = mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0;
    let i = isLE ? 0 : nBytes - 1;
    const d = isLE ? 1 : -1;
    const s = value < 0 || value === 0 && 1 / value < 0 ? 1 : 0;
    value = Math.abs(value);
    if (isNaN(value) || value === Infinity) {
      m = isNaN(value) ? 1 : 0;
      e = eMax;
    } else {
      e = Math.floor(Math.log(value) / Math.LN2);
      if (value * (c = Math.pow(2, -e)) < 1) {
        e--;
        c *= 2;
      }
      if (e + eBias >= 1) {
        value += rt / c;
      } else {
        value += rt * Math.pow(2, 1 - eBias);
      }
      if (value * c >= 2) {
        e++;
        c /= 2;
      }
      if (e + eBias >= eMax) {
        m = 0;
        e = eMax;
      } else if (e + eBias >= 1) {
        m = (value * c - 1) * Math.pow(2, mLen);
        e = e + eBias;
      } else {
        m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen);
        e = 0;
      }
    }
    while (mLen >= 8) {
      buffer[offset + i] = m & 255;
      i += d;
      m /= 256;
      mLen -= 8;
    }
    e = e << mLen | m;
    eLen += mLen;
    while (eLen > 0) {
      buffer[offset + i] = e & 255;
      i += d;
      e /= 256;
      eLen -= 8;
    }
    buffer[offset + i - d] |= s * 128;
  }
  var init_ieee754 = __esm({
    "frida-shim:node_modules/@frida/ieee754/index.js"() {
      init_node_globals();
    }
  });

  // frida-shim:node_modules/@frida/buffer/index.js
  function createBuffer(length) {
    if (length > K_MAX_LENGTH) {
      throw new RangeError('The value "' + length + '" is invalid for option "size"');
    }
    const buf = new Uint8Array(length);
    Object.setPrototypeOf(buf, Buffer2.prototype);
    return buf;
  }
  function Buffer2(arg, encodingOrOffset, length) {
    if (typeof arg === "number") {
      if (typeof encodingOrOffset === "string") {
        throw new TypeError(
          'The "string" argument must be of type string. Received type number'
        );
      }
      return allocUnsafe(arg);
    }
    return from(arg, encodingOrOffset, length);
  }
  function from(value, encodingOrOffset, length) {
    if (typeof value === "string") {
      return fromString(value, encodingOrOffset);
    }
    if (ArrayBuffer.isView(value)) {
      return fromArrayView(value);
    }
    if (value == null) {
      throw new TypeError(
        "The first argument must be one of type string, Buffer, ArrayBuffer, Array, or Array-like Object. Received type " + typeof value
      );
    }
    if (value instanceof ArrayBuffer || value && value.buffer instanceof ArrayBuffer) {
      return fromArrayBuffer(value, encodingOrOffset, length);
    }
    if (value instanceof SharedArrayBuffer || value && value.buffer instanceof SharedArrayBuffer) {
      return fromArrayBuffer(value, encodingOrOffset, length);
    }
    if (typeof value === "number") {
      throw new TypeError(
        'The "value" argument must not be of type number. Received type number'
      );
    }
    const valueOf = value.valueOf && value.valueOf();
    if (valueOf != null && valueOf !== value) {
      return Buffer2.from(valueOf, encodingOrOffset, length);
    }
    const b = fromObject(value);
    if (b) return b;
    if (typeof Symbol !== "undefined" && Symbol.toPrimitive != null && typeof value[Symbol.toPrimitive] === "function") {
      return Buffer2.from(value[Symbol.toPrimitive]("string"), encodingOrOffset, length);
    }
    throw new TypeError(
      "The first argument must be one of type string, Buffer, ArrayBuffer, Array, or Array-like Object. Received type " + typeof value
    );
  }
  function assertSize(size) {
    if (typeof size !== "number") {
      throw new TypeError('"size" argument must be of type number');
    } else if (size < 0) {
      throw new RangeError('The value "' + size + '" is invalid for option "size"');
    }
  }
  function alloc(size, fill2, encoding) {
    assertSize(size);
    if (size <= 0) {
      return createBuffer(size);
    }
    if (fill2 !== void 0) {
      return typeof encoding === "string" ? createBuffer(size).fill(fill2, encoding) : createBuffer(size).fill(fill2);
    }
    return createBuffer(size);
  }
  function allocUnsafe(size) {
    assertSize(size);
    return createBuffer(size < 0 ? 0 : checked(size) | 0);
  }
  function fromString(string, encoding) {
    if (typeof encoding !== "string" || encoding === "") {
      encoding = "utf8";
    }
    if (!Buffer2.isEncoding(encoding)) {
      throw new TypeError("Unknown encoding: " + encoding);
    }
    const length = byteLength(string, encoding) | 0;
    let buf = createBuffer(length);
    const actual = buf.write(string, encoding);
    if (actual !== length) {
      buf = buf.slice(0, actual);
    }
    return buf;
  }
  function fromArrayLike(array) {
    const length = array.length < 0 ? 0 : checked(array.length) | 0;
    const buf = createBuffer(length);
    for (let i = 0; i < length; i += 1) {
      buf[i] = array[i] & 255;
    }
    return buf;
  }
  function fromArrayView(arrayView) {
    if (arrayView instanceof Uint8Array) {
      const copy2 = new Uint8Array(arrayView);
      return fromArrayBuffer(copy2.buffer, copy2.byteOffset, copy2.byteLength);
    }
    return fromArrayLike(arrayView);
  }
  function fromArrayBuffer(array, byteOffset, length) {
    if (byteOffset < 0 || array.byteLength < byteOffset) {
      throw new RangeError('"offset" is outside of buffer bounds');
    }
    if (array.byteLength < byteOffset + (length || 0)) {
      throw new RangeError('"length" is outside of buffer bounds');
    }
    let buf;
    if (byteOffset === void 0 && length === void 0) {
      buf = new Uint8Array(array);
    } else if (length === void 0) {
      buf = new Uint8Array(array, byteOffset);
    } else {
      buf = new Uint8Array(array, byteOffset, length);
    }
    Object.setPrototypeOf(buf, Buffer2.prototype);
    return buf;
  }
  function fromObject(obj) {
    if (Buffer2.isBuffer(obj)) {
      const len = checked(obj.length) | 0;
      const buf = createBuffer(len);
      if (buf.length === 0) {
        return buf;
      }
      obj.copy(buf, 0, 0, len);
      return buf;
    }
    if (obj.length !== void 0) {
      if (typeof obj.length !== "number" || Number.isNaN(obj.length)) {
        return createBuffer(0);
      }
      return fromArrayLike(obj);
    }
    if (obj.type === "Buffer" && Array.isArray(obj.data)) {
      return fromArrayLike(obj.data);
    }
  }
  function checked(length) {
    if (length >= K_MAX_LENGTH) {
      throw new RangeError("Attempt to allocate Buffer larger than maximum size: 0x" + K_MAX_LENGTH.toString(16) + " bytes");
    }
    return length | 0;
  }
  function byteLength(string, encoding) {
    if (Buffer2.isBuffer(string)) {
      return string.length;
    }
    if (ArrayBuffer.isView(string) || string instanceof ArrayBuffer) {
      return string.byteLength;
    }
    if (typeof string !== "string") {
      throw new TypeError(
        'The "string" argument must be one of type string, Buffer, or ArrayBuffer. Received type ' + typeof string
      );
    }
    const len = string.length;
    const mustMatch = arguments.length > 2 && arguments[2] === true;
    if (!mustMatch && len === 0) return 0;
    let loweredCase = false;
    for (; ; ) {
      switch (encoding) {
        case "ascii":
        case "latin1":
        case "binary":
          return len;
        case "utf8":
        case "utf-8":
          return utf8ToBytes(string).length;
        case "ucs2":
        case "ucs-2":
        case "utf16le":
        case "utf-16le":
          return len * 2;
        case "hex":
          return len >>> 1;
        case "base64":
          return base64ToBytes(string).length;
        default:
          if (loweredCase) {
            return mustMatch ? -1 : utf8ToBytes(string).length;
          }
          encoding = ("" + encoding).toLowerCase();
          loweredCase = true;
      }
    }
  }
  function slowToString(encoding, start, end) {
    let loweredCase = false;
    if (start === void 0 || start < 0) {
      start = 0;
    }
    if (start > this.length) {
      return "";
    }
    if (end === void 0 || end > this.length) {
      end = this.length;
    }
    if (end <= 0) {
      return "";
    }
    end >>>= 0;
    start >>>= 0;
    if (end <= start) {
      return "";
    }
    if (!encoding) encoding = "utf8";
    while (true) {
      switch (encoding) {
        case "hex":
          return hexSlice(this, start, end);
        case "utf8":
        case "utf-8":
          return utf8Slice(this, start, end);
        case "ascii":
          return asciiSlice(this, start, end);
        case "latin1":
        case "binary":
          return latin1Slice(this, start, end);
        case "base64":
          return base64Slice(this, start, end);
        case "ucs2":
        case "ucs-2":
        case "utf16le":
        case "utf-16le":
          return utf16leSlice(this, start, end);
        default:
          if (loweredCase) throw new TypeError("Unknown encoding: " + encoding);
          encoding = (encoding + "").toLowerCase();
          loweredCase = true;
      }
    }
  }
  function swap(b, n, m) {
    const i = b[n];
    b[n] = b[m];
    b[m] = i;
  }
  function bidirectionalIndexOf(buffer, val, byteOffset, encoding, dir) {
    if (buffer.length === 0) return -1;
    if (typeof byteOffset === "string") {
      encoding = byteOffset;
      byteOffset = 0;
    } else if (byteOffset > 2147483647) {
      byteOffset = 2147483647;
    } else if (byteOffset < -2147483648) {
      byteOffset = -2147483648;
    }
    byteOffset = +byteOffset;
    if (Number.isNaN(byteOffset)) {
      byteOffset = dir ? 0 : buffer.length - 1;
    }
    if (byteOffset < 0) byteOffset = buffer.length + byteOffset;
    if (byteOffset >= buffer.length) {
      if (dir) return -1;
      else byteOffset = buffer.length - 1;
    } else if (byteOffset < 0) {
      if (dir) byteOffset = 0;
      else return -1;
    }
    if (typeof val === "string") {
      val = Buffer2.from(val, encoding);
    }
    if (Buffer2.isBuffer(val)) {
      if (val.length === 0) {
        return -1;
      }
      return arrayIndexOf(buffer, val, byteOffset, encoding, dir);
    } else if (typeof val === "number") {
      val = val & 255;
      if (typeof Uint8Array.prototype.indexOf === "function") {
        if (dir) {
          return Uint8Array.prototype.indexOf.call(buffer, val, byteOffset);
        } else {
          return Uint8Array.prototype.lastIndexOf.call(buffer, val, byteOffset);
        }
      }
      return arrayIndexOf(buffer, [val], byteOffset, encoding, dir);
    }
    throw new TypeError("val must be string, number or Buffer");
  }
  function arrayIndexOf(arr, val, byteOffset, encoding, dir) {
    let indexSize = 1;
    let arrLength = arr.length;
    let valLength = val.length;
    if (encoding !== void 0) {
      encoding = String(encoding).toLowerCase();
      if (encoding === "ucs2" || encoding === "ucs-2" || encoding === "utf16le" || encoding === "utf-16le") {
        if (arr.length < 2 || val.length < 2) {
          return -1;
        }
        indexSize = 2;
        arrLength /= 2;
        valLength /= 2;
        byteOffset /= 2;
      }
    }
    function read2(buf, i2) {
      if (indexSize === 1) {
        return buf[i2];
      } else {
        return buf.readUInt16BE(i2 * indexSize);
      }
    }
    let i;
    if (dir) {
      let foundIndex = -1;
      for (i = byteOffset; i < arrLength; i++) {
        if (read2(arr, i) === read2(val, foundIndex === -1 ? 0 : i - foundIndex)) {
          if (foundIndex === -1) foundIndex = i;
          if (i - foundIndex + 1 === valLength) return foundIndex * indexSize;
        } else {
          if (foundIndex !== -1) i -= i - foundIndex;
          foundIndex = -1;
        }
      }
    } else {
      if (byteOffset + valLength > arrLength) byteOffset = arrLength - valLength;
      for (i = byteOffset; i >= 0; i--) {
        let found = true;
        for (let j = 0; j < valLength; j++) {
          if (read2(arr, i + j) !== read2(val, j)) {
            found = false;
            break;
          }
        }
        if (found) return i;
      }
    }
    return -1;
  }
  function hexWrite(buf, string, offset, length) {
    offset = Number(offset) || 0;
    const remaining = buf.length - offset;
    if (!length) {
      length = remaining;
    } else {
      length = Number(length);
      if (length > remaining) {
        length = remaining;
      }
    }
    const strLen = string.length;
    if (length > strLen / 2) {
      length = strLen / 2;
    }
    let i;
    for (i = 0; i < length; ++i) {
      const parsed = parseInt(string.substr(i * 2, 2), 16);
      if (Number.isNaN(parsed)) return i;
      buf[offset + i] = parsed;
    }
    return i;
  }
  function utf8Write(buf, string, offset, length) {
    return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length);
  }
  function asciiWrite(buf, string, offset, length) {
    return blitBuffer(asciiToBytes(string), buf, offset, length);
  }
  function base64Write(buf, string, offset, length) {
    return blitBuffer(base64ToBytes(string), buf, offset, length);
  }
  function ucs2Write(buf, string, offset, length) {
    return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length);
  }
  function base64Slice(buf, start, end) {
    if (start === 0 && end === buf.length) {
      return fromByteArray(buf);
    } else {
      return fromByteArray(buf.slice(start, end));
    }
  }
  function utf8Slice(buf, start, end) {
    end = Math.min(buf.length, end);
    const res = [];
    let i = start;
    while (i < end) {
      const firstByte = buf[i];
      let codePoint = null;
      let bytesPerSequence = firstByte > 239 ? 4 : firstByte > 223 ? 3 : firstByte > 191 ? 2 : 1;
      if (i + bytesPerSequence <= end) {
        let secondByte, thirdByte, fourthByte, tempCodePoint;
        switch (bytesPerSequence) {
          case 1:
            if (firstByte < 128) {
              codePoint = firstByte;
            }
            break;
          case 2:
            secondByte = buf[i + 1];
            if ((secondByte & 192) === 128) {
              tempCodePoint = (firstByte & 31) << 6 | secondByte & 63;
              if (tempCodePoint > 127) {
                codePoint = tempCodePoint;
              }
            }
            break;
          case 3:
            secondByte = buf[i + 1];
            thirdByte = buf[i + 2];
            if ((secondByte & 192) === 128 && (thirdByte & 192) === 128) {
              tempCodePoint = (firstByte & 15) << 12 | (secondByte & 63) << 6 | thirdByte & 63;
              if (tempCodePoint > 2047 && (tempCodePoint < 55296 || tempCodePoint > 57343)) {
                codePoint = tempCodePoint;
              }
            }
            break;
          case 4:
            secondByte = buf[i + 1];
            thirdByte = buf[i + 2];
            fourthByte = buf[i + 3];
            if ((secondByte & 192) === 128 && (thirdByte & 192) === 128 && (fourthByte & 192) === 128) {
              tempCodePoint = (firstByte & 15) << 18 | (secondByte & 63) << 12 | (thirdByte & 63) << 6 | fourthByte & 63;
              if (tempCodePoint > 65535 && tempCodePoint < 1114112) {
                codePoint = tempCodePoint;
              }
            }
        }
      }
      if (codePoint === null) {
        codePoint = 65533;
        bytesPerSequence = 1;
      } else if (codePoint > 65535) {
        codePoint -= 65536;
        res.push(codePoint >>> 10 & 1023 | 55296);
        codePoint = 56320 | codePoint & 1023;
      }
      res.push(codePoint);
      i += bytesPerSequence;
    }
    return decodeCodePointsArray(res);
  }
  function decodeCodePointsArray(codePoints) {
    const len = codePoints.length;
    if (len <= MAX_ARGUMENTS_LENGTH) {
      return String.fromCharCode.apply(String, codePoints);
    }
    let res = "";
    let i = 0;
    while (i < len) {
      res += String.fromCharCode.apply(
        String,
        codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH)
      );
    }
    return res;
  }
  function asciiSlice(buf, start, end) {
    let ret = "";
    end = Math.min(buf.length, end);
    for (let i = start; i < end; ++i) {
      ret += String.fromCharCode(buf[i] & 127);
    }
    return ret;
  }
  function latin1Slice(buf, start, end) {
    let ret = "";
    end = Math.min(buf.length, end);
    for (let i = start; i < end; ++i) {
      ret += String.fromCharCode(buf[i]);
    }
    return ret;
  }
  function hexSlice(buf, start, end) {
    const len = buf.length;
    if (!start || start < 0) start = 0;
    if (!end || end < 0 || end > len) end = len;
    let out = "";
    for (let i = start; i < end; ++i) {
      out += hexSliceLookupTable[buf[i]];
    }
    return out;
  }
  function utf16leSlice(buf, start, end) {
    const bytes = buf.slice(start, end);
    let res = "";
    for (let i = 0; i < bytes.length - 1; i += 2) {
      res += String.fromCharCode(bytes[i] + bytes[i + 1] * 256);
    }
    return res;
  }
  function checkOffset(offset, ext, length) {
    if (offset % 1 !== 0 || offset < 0) throw new RangeError("offset is not uint");
    if (offset + ext > length) throw new RangeError("Trying to access beyond buffer length");
  }
  function checkInt(buf, value, offset, ext, max, min) {
    if (!Buffer2.isBuffer(buf)) throw new TypeError('"buffer" argument must be a Buffer instance');
    if (value > max || value < min) throw new RangeError('"value" argument is out of bounds');
    if (offset + ext > buf.length) throw new RangeError("Index out of range");
  }
  function wrtBigUInt64LE(buf, value, offset, min, max) {
    checkIntBI(value, min, max, buf, offset, 7);
    let lo = Number(value & BigInt(4294967295));
    buf[offset++] = lo;
    lo = lo >> 8;
    buf[offset++] = lo;
    lo = lo >> 8;
    buf[offset++] = lo;
    lo = lo >> 8;
    buf[offset++] = lo;
    let hi = Number(value >> BigInt(32) & BigInt(4294967295));
    buf[offset++] = hi;
    hi = hi >> 8;
    buf[offset++] = hi;
    hi = hi >> 8;
    buf[offset++] = hi;
    hi = hi >> 8;
    buf[offset++] = hi;
    return offset;
  }
  function wrtBigUInt64BE(buf, value, offset, min, max) {
    checkIntBI(value, min, max, buf, offset, 7);
    let lo = Number(value & BigInt(4294967295));
    buf[offset + 7] = lo;
    lo = lo >> 8;
    buf[offset + 6] = lo;
    lo = lo >> 8;
    buf[offset + 5] = lo;
    lo = lo >> 8;
    buf[offset + 4] = lo;
    let hi = Number(value >> BigInt(32) & BigInt(4294967295));
    buf[offset + 3] = hi;
    hi = hi >> 8;
    buf[offset + 2] = hi;
    hi = hi >> 8;
    buf[offset + 1] = hi;
    hi = hi >> 8;
    buf[offset] = hi;
    return offset + 8;
  }
  function checkIEEE754(buf, value, offset, ext, max, min) {
    if (offset + ext > buf.length) throw new RangeError("Index out of range");
    if (offset < 0) throw new RangeError("Index out of range");
  }
  function writeFloat(buf, value, offset, littleEndian, noAssert) {
    value = +value;
    offset = offset >>> 0;
    if (!noAssert) {
      checkIEEE754(buf, value, offset, 4, 34028234663852886e22, -34028234663852886e22);
    }
    write(buf, value, offset, littleEndian, 23, 4);
    return offset + 4;
  }
  function writeDouble(buf, value, offset, littleEndian, noAssert) {
    value = +value;
    offset = offset >>> 0;
    if (!noAssert) {
      checkIEEE754(buf, value, offset, 8, 17976931348623157e292, -17976931348623157e292);
    }
    write(buf, value, offset, littleEndian, 52, 8);
    return offset + 8;
  }
  function E(sym, getMessage, Base) {
    errors[sym] = class NodeError extends Base {
      constructor() {
        super();
        Object.defineProperty(this, "message", {
          value: getMessage.apply(this, arguments),
          writable: true,
          configurable: true
        });
        this.name = `${this.name} [${sym}]`;
        this.stack;
        delete this.name;
      }
      get code() {
        return sym;
      }
      set code(value) {
        Object.defineProperty(this, "code", {
          configurable: true,
          enumerable: true,
          value,
          writable: true
        });
      }
      toString() {
        return `${this.name} [${sym}]: ${this.message}`;
      }
    };
  }
  function addNumericalSeparator(val) {
    let res = "";
    let i = val.length;
    const start = val[0] === "-" ? 1 : 0;
    for (; i >= start + 4; i -= 3) {
      res = `_${val.slice(i - 3, i)}${res}`;
    }
    return `${val.slice(0, i)}${res}`;
  }
  function checkBounds(buf, offset, byteLength2) {
    validateNumber(offset, "offset");
    if (buf[offset] === void 0 || buf[offset + byteLength2] === void 0) {
      boundsError(offset, buf.length - (byteLength2 + 1));
    }
  }
  function checkIntBI(value, min, max, buf, offset, byteLength2) {
    if (value > max || value < min) {
      const n = typeof min === "bigint" ? "n" : "";
      let range;
      if (byteLength2 > 3) {
        if (min === 0 || min === BigInt(0)) {
          range = `>= 0${n} and < 2${n} ** ${(byteLength2 + 1) * 8}${n}`;
        } else {
          range = `>= -(2${n} ** ${(byteLength2 + 1) * 8 - 1}${n}) and < 2 ** ${(byteLength2 + 1) * 8 - 1}${n}`;
        }
      } else {
        range = `>= ${min}${n} and <= ${max}${n}`;
      }
      throw new errors.ERR_OUT_OF_RANGE("value", range, value);
    }
    checkBounds(buf, offset, byteLength2);
  }
  function validateNumber(value, name) {
    if (typeof value !== "number") {
      throw new errors.ERR_INVALID_ARG_TYPE(name, "number", value);
    }
  }
  function boundsError(value, length, type) {
    if (Math.floor(value) !== value) {
      validateNumber(value, type);
      throw new errors.ERR_OUT_OF_RANGE(type || "offset", "an integer", value);
    }
    if (length < 0) {
      throw new errors.ERR_BUFFER_OUT_OF_BOUNDS();
    }
    throw new errors.ERR_OUT_OF_RANGE(
      type || "offset",
      `>= ${type ? 1 : 0} and <= ${length}`,
      value
    );
  }
  function base64clean(str) {
    str = str.split("=")[0];
    str = str.trim().replace(INVALID_BASE64_RE, "");
    if (str.length < 2) return "";
    while (str.length % 4 !== 0) {
      str = str + "=";
    }
    return str;
  }
  function utf8ToBytes(string, units) {
    units = units || Infinity;
    let codePoint;
    const length = string.length;
    let leadSurrogate = null;
    const bytes = [];
    for (let i = 0; i < length; ++i) {
      codePoint = string.charCodeAt(i);
      if (codePoint > 55295 && codePoint < 57344) {
        if (!leadSurrogate) {
          if (codePoint > 56319) {
            if ((units -= 3) > -1) bytes.push(239, 191, 189);
            continue;
          } else if (i + 1 === length) {
            if ((units -= 3) > -1) bytes.push(239, 191, 189);
            continue;
          }
          leadSurrogate = codePoint;
          continue;
        }
        if (codePoint < 56320) {
          if ((units -= 3) > -1) bytes.push(239, 191, 189);
          leadSurrogate = codePoint;
          continue;
        }
        codePoint = (leadSurrogate - 55296 << 10 | codePoint - 56320) + 65536;
      } else if (leadSurrogate) {
        if ((units -= 3) > -1) bytes.push(239, 191, 189);
      }
      leadSurrogate = null;
      if (codePoint < 128) {
        if ((units -= 1) < 0) break;
        bytes.push(codePoint);
      } else if (codePoint < 2048) {
        if ((units -= 2) < 0) break;
        bytes.push(
          codePoint >> 6 | 192,
          codePoint & 63 | 128
        );
      } else if (codePoint < 65536) {
        if ((units -= 3) < 0) break;
        bytes.push(
          codePoint >> 12 | 224,
          codePoint >> 6 & 63 | 128,
          codePoint & 63 | 128
        );
      } else if (codePoint < 1114112) {
        if ((units -= 4) < 0) break;
        bytes.push(
          codePoint >> 18 | 240,
          codePoint >> 12 & 63 | 128,
          codePoint >> 6 & 63 | 128,
          codePoint & 63 | 128
        );
      } else {
        throw new Error("Invalid code point");
      }
    }
    return bytes;
  }
  function asciiToBytes(str) {
    const byteArray = [];
    for (let i = 0; i < str.length; ++i) {
      byteArray.push(str.charCodeAt(i) & 255);
    }
    return byteArray;
  }
  function utf16leToBytes(str, units) {
    let c, hi, lo;
    const byteArray = [];
    for (let i = 0; i < str.length; ++i) {
      if ((units -= 2) < 0) break;
      c = str.charCodeAt(i);
      hi = c >> 8;
      lo = c % 256;
      byteArray.push(lo);
      byteArray.push(hi);
    }
    return byteArray;
  }
  function base64ToBytes(str) {
    return toByteArray(base64clean(str));
  }
  function blitBuffer(src, dst, offset, length) {
    let i;
    for (i = 0; i < length; ++i) {
      if (i + offset >= dst.length || i >= src.length) break;
      dst[i + offset] = src[i];
    }
    return i;
  }
  var config, K_MAX_LENGTH, MAX_ARGUMENTS_LENGTH, errors, INVALID_BASE64_RE, hexSliceLookupTable;
  var init_buffer = __esm({
    "frida-shim:node_modules/@frida/buffer/index.js"() {
      init_node_globals();
      init_base64_js();
      init_ieee754();
      config = {
        INSPECT_MAX_BYTES: 50
      };
      K_MAX_LENGTH = 2147483647;
      Buffer2.TYPED_ARRAY_SUPPORT = true;
      Object.defineProperty(Buffer2.prototype, "parent", {
        enumerable: true,
        get: function() {
          if (!Buffer2.isBuffer(this)) return void 0;
          return this.buffer;
        }
      });
      Object.defineProperty(Buffer2.prototype, "offset", {
        enumerable: true,
        get: function() {
          if (!Buffer2.isBuffer(this)) return void 0;
          return this.byteOffset;
        }
      });
      Buffer2.poolSize = 8192;
      Buffer2.from = function(value, encodingOrOffset, length) {
        return from(value, encodingOrOffset, length);
      };
      Object.setPrototypeOf(Buffer2.prototype, Uint8Array.prototype);
      Object.setPrototypeOf(Buffer2, Uint8Array);
      Buffer2.alloc = function(size, fill2, encoding) {
        return alloc(size, fill2, encoding);
      };
      Buffer2.allocUnsafe = function(size) {
        return allocUnsafe(size);
      };
      Buffer2.allocUnsafeSlow = function(size) {
        return allocUnsafe(size);
      };
      Buffer2.isBuffer = function isBuffer(b) {
        return b != null && b._isBuffer === true && b !== Buffer2.prototype;
      };
      Buffer2.compare = function compare(a, b) {
        if (a instanceof Uint8Array) a = Buffer2.from(a, a.offset, a.byteLength);
        if (b instanceof Uint8Array) b = Buffer2.from(b, b.offset, b.byteLength);
        if (!Buffer2.isBuffer(a) || !Buffer2.isBuffer(b)) {
          throw new TypeError(
            'The "buf1", "buf2" arguments must be one of type Buffer or Uint8Array'
          );
        }
        if (a === b) return 0;
        let x = a.length;
        let y = b.length;
        for (let i = 0, len = Math.min(x, y); i < len; ++i) {
          if (a[i] !== b[i]) {
            x = a[i];
            y = b[i];
            break;
          }
        }
        if (x < y) return -1;
        if (y < x) return 1;
        return 0;
      };
      Buffer2.isEncoding = function isEncoding(encoding) {
        switch (String(encoding).toLowerCase()) {
          case "hex":
          case "utf8":
          case "utf-8":
          case "ascii":
          case "latin1":
          case "binary":
          case "base64":
          case "ucs2":
          case "ucs-2":
          case "utf16le":
          case "utf-16le":
            return true;
          default:
            return false;
        }
      };
      Buffer2.concat = function concat(list, length) {
        if (!Array.isArray(list)) {
          throw new TypeError('"list" argument must be an Array of Buffers');
        }
        if (list.length === 0) {
          return Buffer2.alloc(0);
        }
        let i;
        if (length === void 0) {
          length = 0;
          for (i = 0; i < list.length; ++i) {
            length += list[i].length;
          }
        }
        const buffer = Buffer2.allocUnsafe(length);
        let pos = 0;
        for (i = 0; i < list.length; ++i) {
          let buf = list[i];
          if (buf instanceof Uint8Array) {
            if (pos + buf.length > buffer.length) {
              if (!Buffer2.isBuffer(buf)) {
                buf = Buffer2.from(buf.buffer, buf.byteOffset, buf.byteLength);
              }
              buf.copy(buffer, pos);
            } else {
              Uint8Array.prototype.set.call(
                buffer,
                buf,
                pos
              );
            }
          } else if (!Buffer2.isBuffer(buf)) {
            throw new TypeError('"list" argument must be an Array of Buffers');
          } else {
            buf.copy(buffer, pos);
          }
          pos += buf.length;
        }
        return buffer;
      };
      Buffer2.byteLength = byteLength;
      Buffer2.prototype._isBuffer = true;
      Buffer2.prototype.swap16 = function swap16() {
        const len = this.length;
        if (len % 2 !== 0) {
          throw new RangeError("Buffer size must be a multiple of 16-bits");
        }
        for (let i = 0; i < len; i += 2) {
          swap(this, i, i + 1);
        }
        return this;
      };
      Buffer2.prototype.swap32 = function swap32() {
        const len = this.length;
        if (len % 4 !== 0) {
          throw new RangeError("Buffer size must be a multiple of 32-bits");
        }
        for (let i = 0; i < len; i += 4) {
          swap(this, i, i + 3);
          swap(this, i + 1, i + 2);
        }
        return this;
      };
      Buffer2.prototype.swap64 = function swap64() {
        const len = this.length;
        if (len % 8 !== 0) {
          throw new RangeError("Buffer size must be a multiple of 64-bits");
        }
        for (let i = 0; i < len; i += 8) {
          swap(this, i, i + 7);
          swap(this, i + 1, i + 6);
          swap(this, i + 2, i + 5);
          swap(this, i + 3, i + 4);
        }
        return this;
      };
      Buffer2.prototype.toString = function toString() {
        const length = this.length;
        if (length === 0) return "";
        if (arguments.length === 0) return utf8Slice(this, 0, length);
        return slowToString.apply(this, arguments);
      };
      Buffer2.prototype.toLocaleString = Buffer2.prototype.toString;
      Buffer2.prototype.equals = function equals(b) {
        if (!Buffer2.isBuffer(b)) throw new TypeError("Argument must be a Buffer");
        if (this === b) return true;
        return Buffer2.compare(this, b) === 0;
      };
      Buffer2.prototype.inspect = function inspect() {
        let str = "";
        const max = config.INSPECT_MAX_BYTES;
        str = this.toString("hex", 0, max).replace(/(.{2})/g, "$1 ").trim();
        if (this.length > max) str += " ... ";
        return "<Buffer " + str + ">";
      };
      Buffer2.prototype[Symbol.for("nodejs.util.inspect.custom")] = Buffer2.prototype.inspect;
      Buffer2.prototype.compare = function compare2(target, start, end, thisStart, thisEnd) {
        if (target instanceof Uint8Array) {
          target = Buffer2.from(target, target.offset, target.byteLength);
        }
        if (!Buffer2.isBuffer(target)) {
          throw new TypeError(
            'The "target" argument must be one of type Buffer or Uint8Array. Received type ' + typeof target
          );
        }
        if (start === void 0) {
          start = 0;
        }
        if (end === void 0) {
          end = target ? target.length : 0;
        }
        if (thisStart === void 0) {
          thisStart = 0;
        }
        if (thisEnd === void 0) {
          thisEnd = this.length;
        }
        if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length) {
          throw new RangeError("out of range index");
        }
        if (thisStart >= thisEnd && start >= end) {
          return 0;
        }
        if (thisStart >= thisEnd) {
          return -1;
        }
        if (start >= end) {
          return 1;
        }
        start >>>= 0;
        end >>>= 0;
        thisStart >>>= 0;
        thisEnd >>>= 0;
        if (this === target) return 0;
        let x = thisEnd - thisStart;
        let y = end - start;
        const len = Math.min(x, y);
        const thisCopy = this.slice(thisStart, thisEnd);
        const targetCopy = target.slice(start, end);
        for (let i = 0; i < len; ++i) {
          if (thisCopy[i] !== targetCopy[i]) {
            x = thisCopy[i];
            y = targetCopy[i];
            break;
          }
        }
        if (x < y) return -1;
        if (y < x) return 1;
        return 0;
      };
      Buffer2.prototype.includes = function includes(val, byteOffset, encoding) {
        return this.indexOf(val, byteOffset, encoding) !== -1;
      };
      Buffer2.prototype.indexOf = function indexOf(val, byteOffset, encoding) {
        return bidirectionalIndexOf(this, val, byteOffset, encoding, true);
      };
      Buffer2.prototype.lastIndexOf = function lastIndexOf(val, byteOffset, encoding) {
        return bidirectionalIndexOf(this, val, byteOffset, encoding, false);
      };
      Buffer2.prototype.write = function write2(string, offset, length, encoding) {
        if (offset === void 0) {
          encoding = "utf8";
          length = this.length;
          offset = 0;
        } else if (length === void 0 && typeof offset === "string") {
          encoding = offset;
          length = this.length;
          offset = 0;
        } else if (isFinite(offset)) {
          offset = offset >>> 0;
          if (isFinite(length)) {
            length = length >>> 0;
            if (encoding === void 0) encoding = "utf8";
          } else {
            encoding = length;
            length = void 0;
          }
        } else {
          throw new Error(
            "Buffer.write(string, encoding, offset[, length]) is no longer supported"
          );
        }
        const remaining = this.length - offset;
        if (length === void 0 || length > remaining) length = remaining;
        if (string.length > 0 && (length < 0 || offset < 0) || offset > this.length) {
          throw new RangeError("Attempt to write outside buffer bounds");
        }
        if (!encoding) encoding = "utf8";
        let loweredCase = false;
        for (; ; ) {
          switch (encoding) {
            case "hex":
              return hexWrite(this, string, offset, length);
            case "utf8":
            case "utf-8":
              return utf8Write(this, string, offset, length);
            case "ascii":
            case "latin1":
            case "binary":
              return asciiWrite(this, string, offset, length);
            case "base64":
              return base64Write(this, string, offset, length);
            case "ucs2":
            case "ucs-2":
            case "utf16le":
            case "utf-16le":
              return ucs2Write(this, string, offset, length);
            default:
              if (loweredCase) throw new TypeError("Unknown encoding: " + encoding);
              encoding = ("" + encoding).toLowerCase();
              loweredCase = true;
          }
        }
      };
      Buffer2.prototype.toJSON = function toJSON() {
        return {
          type: "Buffer",
          data: Array.prototype.slice.call(this._arr || this, 0)
        };
      };
      MAX_ARGUMENTS_LENGTH = 4096;
      Buffer2.prototype.slice = function slice(start, end) {
        const len = this.length;
        start = ~~start;
        end = end === void 0 ? len : ~~end;
        if (start < 0) {
          start += len;
          if (start < 0) start = 0;
        } else if (start > len) {
          start = len;
        }
        if (end < 0) {
          end += len;
          if (end < 0) end = 0;
        } else if (end > len) {
          end = len;
        }
        if (end < start) end = start;
        const newBuf = this.subarray(start, end);
        Object.setPrototypeOf(newBuf, Buffer2.prototype);
        return newBuf;
      };
      Buffer2.prototype.readUintLE = Buffer2.prototype.readUIntLE = function readUIntLE(offset, byteLength2, noAssert) {
        offset = offset >>> 0;
        byteLength2 = byteLength2 >>> 0;
        if (!noAssert) checkOffset(offset, byteLength2, this.length);
        let val = this[offset];
        let mul = 1;
        let i = 0;
        while (++i < byteLength2 && (mul *= 256)) {
          val += this[offset + i] * mul;
        }
        return val;
      };
      Buffer2.prototype.readUintBE = Buffer2.prototype.readUIntBE = function readUIntBE(offset, byteLength2, noAssert) {
        offset = offset >>> 0;
        byteLength2 = byteLength2 >>> 0;
        if (!noAssert) {
          checkOffset(offset, byteLength2, this.length);
        }
        let val = this[offset + --byteLength2];
        let mul = 1;
        while (byteLength2 > 0 && (mul *= 256)) {
          val += this[offset + --byteLength2] * mul;
        }
        return val;
      };
      Buffer2.prototype.readUint8 = Buffer2.prototype.readUInt8 = function readUInt8(offset, noAssert) {
        offset = offset >>> 0;
        if (!noAssert) checkOffset(offset, 1, this.length);
        return this[offset];
      };
      Buffer2.prototype.readUint16LE = Buffer2.prototype.readUInt16LE = function readUInt16LE(offset, noAssert) {
        offset = offset >>> 0;
        if (!noAssert) checkOffset(offset, 2, this.length);
        return this[offset] | this[offset + 1] << 8;
      };
      Buffer2.prototype.readUint16BE = Buffer2.prototype.readUInt16BE = function readUInt16BE(offset, noAssert) {
        offset = offset >>> 0;
        if (!noAssert) checkOffset(offset, 2, this.length);
        return this[offset] << 8 | this[offset + 1];
      };
      Buffer2.prototype.readUint32LE = Buffer2.prototype.readUInt32LE = function readUInt32LE(offset, noAssert) {
        offset = offset >>> 0;
        if (!noAssert) checkOffset(offset, 4, this.length);
        return (this[offset] | this[offset + 1] << 8 | this[offset + 2] << 16) + this[offset + 3] * 16777216;
      };
      Buffer2.prototype.readUint32BE = Buffer2.prototype.readUInt32BE = function readUInt32BE(offset, noAssert) {
        offset = offset >>> 0;
        if (!noAssert) checkOffset(offset, 4, this.length);
        return this[offset] * 16777216 + (this[offset + 1] << 16 | this[offset + 2] << 8 | this[offset + 3]);
      };
      Buffer2.prototype.readBigUInt64LE = function readBigUInt64LE(offset) {
        offset = offset >>> 0;
        validateNumber(offset, "offset");
        const first = this[offset];
        const last = this[offset + 7];
        if (first === void 0 || last === void 0) {
          boundsError(offset, this.length - 8);
        }
        const lo = first + this[++offset] * 2 ** 8 + this[++offset] * 2 ** 16 + this[++offset] * 2 ** 24;
        const hi = this[++offset] + this[++offset] * 2 ** 8 + this[++offset] * 2 ** 16 + last * 2 ** 24;
        return BigInt(lo) + (BigInt(hi) << BigInt(32));
      };
      Buffer2.prototype.readBigUInt64BE = function readBigUInt64BE(offset) {
        offset = offset >>> 0;
        validateNumber(offset, "offset");
        const first = this[offset];
        const last = this[offset + 7];
        if (first === void 0 || last === void 0) {
          boundsError(offset, this.length - 8);
        }
        const hi = first * 2 ** 24 + this[++offset] * 2 ** 16 + this[++offset] * 2 ** 8 + this[++offset];
        const lo = this[++offset] * 2 ** 24 + this[++offset] * 2 ** 16 + this[++offset] * 2 ** 8 + last;
        return (BigInt(hi) << BigInt(32)) + BigInt(lo);
      };
      Buffer2.prototype.readIntLE = function readIntLE(offset, byteLength2, noAssert) {
        offset = offset >>> 0;
        byteLength2 = byteLength2 >>> 0;
        if (!noAssert) checkOffset(offset, byteLength2, this.length);
        let val = this[offset];
        let mul = 1;
        let i = 0;
        while (++i < byteLength2 && (mul *= 256)) {
          val += this[offset + i] * mul;
        }
        mul *= 128;
        if (val >= mul) val -= Math.pow(2, 8 * byteLength2);
        return val;
      };
      Buffer2.prototype.readIntBE = function readIntBE(offset, byteLength2, noAssert) {
        offset = offset >>> 0;
        byteLength2 = byteLength2 >>> 0;
        if (!noAssert) checkOffset(offset, byteLength2, this.length);
        let i = byteLength2;
        let mul = 1;
        let val = this[offset + --i];
        while (i > 0 && (mul *= 256)) {
          val += this[offset + --i] * mul;
        }
        mul *= 128;
        if (val >= mul) val -= Math.pow(2, 8 * byteLength2);
        return val;
      };
      Buffer2.prototype.readInt8 = function readInt8(offset, noAssert) {
        offset = offset >>> 0;
        if (!noAssert) checkOffset(offset, 1, this.length);
        if (!(this[offset] & 128)) return this[offset];
        return (255 - this[offset] + 1) * -1;
      };
      Buffer2.prototype.readInt16LE = function readInt16LE(offset, noAssert) {
        offset = offset >>> 0;
        if (!noAssert) checkOffset(offset, 2, this.length);
        const val = this[offset] | this[offset + 1] << 8;
        return val & 32768 ? val | 4294901760 : val;
      };
      Buffer2.prototype.readInt16BE = function readInt16BE(offset, noAssert) {
        offset = offset >>> 0;
        if (!noAssert) checkOffset(offset, 2, this.length);
        const val = this[offset + 1] | this[offset] << 8;
        return val & 32768 ? val | 4294901760 : val;
      };
      Buffer2.prototype.readInt32LE = function readInt32LE(offset, noAssert) {
        offset = offset >>> 0;
        if (!noAssert) checkOffset(offset, 4, this.length);
        return this[offset] | this[offset + 1] << 8 | this[offset + 2] << 16 | this[offset + 3] << 24;
      };
      Buffer2.prototype.readInt32BE = function readInt32BE(offset, noAssert) {
        offset = offset >>> 0;
        if (!noAssert) checkOffset(offset, 4, this.length);
        return this[offset] << 24 | this[offset + 1] << 16 | this[offset + 2] << 8 | this[offset + 3];
      };
      Buffer2.prototype.readBigInt64LE = function readBigInt64LE(offset) {
        offset = offset >>> 0;
        validateNumber(offset, "offset");
        const first = this[offset];
        const last = this[offset + 7];
        if (first === void 0 || last === void 0) {
          boundsError(offset, this.length - 8);
        }
        const val = this[offset + 4] + this[offset + 5] * 2 ** 8 + this[offset + 6] * 2 ** 16 + (last << 24);
        return (BigInt(val) << BigInt(32)) + BigInt(first + this[++offset] * 2 ** 8 + this[++offset] * 2 ** 16 + this[++offset] * 2 ** 24);
      };
      Buffer2.prototype.readBigInt64BE = function readBigInt64BE(offset) {
        offset = offset >>> 0;
        validateNumber(offset, "offset");
        const first = this[offset];
        const last = this[offset + 7];
        if (first === void 0 || last === void 0) {
          boundsError(offset, this.length - 8);
        }
        const val = (first << 24) + // Overflow
        this[++offset] * 2 ** 16 + this[++offset] * 2 ** 8 + this[++offset];
        return (BigInt(val) << BigInt(32)) + BigInt(this[++offset] * 2 ** 24 + this[++offset] * 2 ** 16 + this[++offset] * 2 ** 8 + last);
      };
      Buffer2.prototype.readFloatLE = function readFloatLE(offset, noAssert) {
        offset = offset >>> 0;
        if (!noAssert) checkOffset(offset, 4, this.length);
        return read(this, offset, true, 23, 4);
      };
      Buffer2.prototype.readFloatBE = function readFloatBE(offset, noAssert) {
        offset = offset >>> 0;
        if (!noAssert) checkOffset(offset, 4, this.length);
        return read(this, offset, false, 23, 4);
      };
      Buffer2.prototype.readDoubleLE = function readDoubleLE(offset, noAssert) {
        offset = offset >>> 0;
        if (!noAssert) checkOffset(offset, 8, this.length);
        return read(this, offset, true, 52, 8);
      };
      Buffer2.prototype.readDoubleBE = function readDoubleBE(offset, noAssert) {
        offset = offset >>> 0;
        if (!noAssert) checkOffset(offset, 8, this.length);
        return read(this, offset, false, 52, 8);
      };
      Buffer2.prototype.writeUintLE = Buffer2.prototype.writeUIntLE = function writeUIntLE(value, offset, byteLength2, noAssert) {
        value = +value;
        offset = offset >>> 0;
        byteLength2 = byteLength2 >>> 0;
        if (!noAssert) {
          const maxBytes = Math.pow(2, 8 * byteLength2) - 1;
          checkInt(this, value, offset, byteLength2, maxBytes, 0);
        }
        let mul = 1;
        let i = 0;
        this[offset] = value & 255;
        while (++i < byteLength2 && (mul *= 256)) {
          this[offset + i] = value / mul & 255;
        }
        return offset + byteLength2;
      };
      Buffer2.prototype.writeUintBE = Buffer2.prototype.writeUIntBE = function writeUIntBE(value, offset, byteLength2, noAssert) {
        value = +value;
        offset = offset >>> 0;
        byteLength2 = byteLength2 >>> 0;
        if (!noAssert) {
          const maxBytes = Math.pow(2, 8 * byteLength2) - 1;
          checkInt(this, value, offset, byteLength2, maxBytes, 0);
        }
        let i = byteLength2 - 1;
        let mul = 1;
        this[offset + i] = value & 255;
        while (--i >= 0 && (mul *= 256)) {
          this[offset + i] = value / mul & 255;
        }
        return offset + byteLength2;
      };
      Buffer2.prototype.writeUint8 = Buffer2.prototype.writeUInt8 = function writeUInt8(value, offset, noAssert) {
        value = +value;
        offset = offset >>> 0;
        if (!noAssert) checkInt(this, value, offset, 1, 255, 0);
        this[offset] = value & 255;
        return offset + 1;
      };
      Buffer2.prototype.writeUint16LE = Buffer2.prototype.writeUInt16LE = function writeUInt16LE(value, offset, noAssert) {
        value = +value;
        offset = offset >>> 0;
        if (!noAssert) checkInt(this, value, offset, 2, 65535, 0);
        this[offset] = value & 255;
        this[offset + 1] = value >>> 8;
        return offset + 2;
      };
      Buffer2.prototype.writeUint16BE = Buffer2.prototype.writeUInt16BE = function writeUInt16BE(value, offset, noAssert) {
        value = +value;
        offset = offset >>> 0;
        if (!noAssert) checkInt(this, value, offset, 2, 65535, 0);
        this[offset] = value >>> 8;
        this[offset + 1] = value & 255;
        return offset + 2;
      };
      Buffer2.prototype.writeUint32LE = Buffer2.prototype.writeUInt32LE = function writeUInt32LE(value, offset, noAssert) {
        value = +value;
        offset = offset >>> 0;
        if (!noAssert) checkInt(this, value, offset, 4, 4294967295, 0);
        this[offset + 3] = value >>> 24;
        this[offset + 2] = value >>> 16;
        this[offset + 1] = value >>> 8;
        this[offset] = value & 255;
        return offset + 4;
      };
      Buffer2.prototype.writeUint32BE = Buffer2.prototype.writeUInt32BE = function writeUInt32BE(value, offset, noAssert) {
        value = +value;
        offset = offset >>> 0;
        if (!noAssert) checkInt(this, value, offset, 4, 4294967295, 0);
        this[offset] = value >>> 24;
        this[offset + 1] = value >>> 16;
        this[offset + 2] = value >>> 8;
        this[offset + 3] = value & 255;
        return offset + 4;
      };
      Buffer2.prototype.writeBigUInt64LE = function writeBigUInt64LE(value, offset = 0) {
        return wrtBigUInt64LE(this, value, offset, BigInt(0), BigInt("0xffffffffffffffff"));
      };
      Buffer2.prototype.writeBigUInt64BE = function writeBigUInt64BE(value, offset = 0) {
        return wrtBigUInt64BE(this, value, offset, BigInt(0), BigInt("0xffffffffffffffff"));
      };
      Buffer2.prototype.writeIntLE = function writeIntLE(value, offset, byteLength2, noAssert) {
        value = +value;
        offset = offset >>> 0;
        if (!noAssert) {
          const limit = Math.pow(2, 8 * byteLength2 - 1);
          checkInt(this, value, offset, byteLength2, limit - 1, -limit);
        }
        let i = 0;
        let mul = 1;
        let sub = 0;
        this[offset] = value & 255;
        while (++i < byteLength2 && (mul *= 256)) {
          if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
            sub = 1;
          }
          this[offset + i] = (value / mul >> 0) - sub & 255;
        }
        return offset + byteLength2;
      };
      Buffer2.prototype.writeIntBE = function writeIntBE(value, offset, byteLength2, noAssert) {
        value = +value;
        offset = offset >>> 0;
        if (!noAssert) {
          const limit = Math.pow(2, 8 * byteLength2 - 1);
          checkInt(this, value, offset, byteLength2, limit - 1, -limit);
        }
        let i = byteLength2 - 1;
        let mul = 1;
        let sub = 0;
        this[offset + i] = value & 255;
        while (--i >= 0 && (mul *= 256)) {
          if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
            sub = 1;
          }
          this[offset + i] = (value / mul >> 0) - sub & 255;
        }
        return offset + byteLength2;
      };
      Buffer2.prototype.writeInt8 = function writeInt8(value, offset, noAssert) {
        value = +value;
        offset = offset >>> 0;
        if (!noAssert) checkInt(this, value, offset, 1, 127, -128);
        if (value < 0) value = 255 + value + 1;
        this[offset] = value & 255;
        return offset + 1;
      };
      Buffer2.prototype.writeInt16LE = function writeInt16LE(value, offset, noAssert) {
        value = +value;
        offset = offset >>> 0;
        if (!noAssert) checkInt(this, value, offset, 2, 32767, -32768);
        this[offset] = value & 255;
        this[offset + 1] = value >>> 8;
        return offset + 2;
      };
      Buffer2.prototype.writeInt16BE = function writeInt16BE(value, offset, noAssert) {
        value = +value;
        offset = offset >>> 0;
        if (!noAssert) checkInt(this, value, offset, 2, 32767, -32768);
        this[offset] = value >>> 8;
        this[offset + 1] = value & 255;
        return offset + 2;
      };
      Buffer2.prototype.writeInt32LE = function writeInt32LE(value, offset, noAssert) {
        value = +value;
        offset = offset >>> 0;
        if (!noAssert) checkInt(this, value, offset, 4, 2147483647, -2147483648);
        this[offset] = value & 255;
        this[offset + 1] = value >>> 8;
        this[offset + 2] = value >>> 16;
        this[offset + 3] = value >>> 24;
        return offset + 4;
      };
      Buffer2.prototype.writeInt32BE = function writeInt32BE(value, offset, noAssert) {
        value = +value;
        offset = offset >>> 0;
        if (!noAssert) checkInt(this, value, offset, 4, 2147483647, -2147483648);
        if (value < 0) value = 4294967295 + value + 1;
        this[offset] = value >>> 24;
        this[offset + 1] = value >>> 16;
        this[offset + 2] = value >>> 8;
        this[offset + 3] = value & 255;
        return offset + 4;
      };
      Buffer2.prototype.writeBigInt64LE = function writeBigInt64LE(value, offset = 0) {
        return wrtBigUInt64LE(this, value, offset, -BigInt("0x8000000000000000"), BigInt("0x7fffffffffffffff"));
      };
      Buffer2.prototype.writeBigInt64BE = function writeBigInt64BE(value, offset = 0) {
        return wrtBigUInt64BE(this, value, offset, -BigInt("0x8000000000000000"), BigInt("0x7fffffffffffffff"));
      };
      Buffer2.prototype.writeFloatLE = function writeFloatLE(value, offset, noAssert) {
        return writeFloat(this, value, offset, true, noAssert);
      };
      Buffer2.prototype.writeFloatBE = function writeFloatBE(value, offset, noAssert) {
        return writeFloat(this, value, offset, false, noAssert);
      };
      Buffer2.prototype.writeDoubleLE = function writeDoubleLE(value, offset, noAssert) {
        return writeDouble(this, value, offset, true, noAssert);
      };
      Buffer2.prototype.writeDoubleBE = function writeDoubleBE(value, offset, noAssert) {
        return writeDouble(this, value, offset, false, noAssert);
      };
      Buffer2.prototype.copy = function copy(target, targetStart, start, end) {
        if (!Buffer2.isBuffer(target)) throw new TypeError("argument should be a Buffer");
        if (!start) start = 0;
        if (!end && end !== 0) end = this.length;
        if (targetStart >= target.length) targetStart = target.length;
        if (!targetStart) targetStart = 0;
        if (end > 0 && end < start) end = start;
        if (end === start) return 0;
        if (target.length === 0 || this.length === 0) return 0;
        if (targetStart < 0) {
          throw new RangeError("targetStart out of bounds");
        }
        if (start < 0 || start >= this.length) throw new RangeError("Index out of range");
        if (end < 0) throw new RangeError("sourceEnd out of bounds");
        if (end > this.length) end = this.length;
        if (target.length - targetStart < end - start) {
          end = target.length - targetStart + start;
        }
        const len = end - start;
        if (this === target) {
          this.copyWithin(targetStart, start, end);
        } else {
          Uint8Array.prototype.set.call(
            target,
            this.subarray(start, end),
            targetStart
          );
        }
        return len;
      };
      Buffer2.prototype.fill = function fill(val, start, end, encoding) {
        if (typeof val === "string") {
          if (typeof start === "string") {
            encoding = start;
            start = 0;
            end = this.length;
          } else if (typeof end === "string") {
            encoding = end;
            end = this.length;
          }
          if (encoding !== void 0 && typeof encoding !== "string") {
            throw new TypeError("encoding must be a string");
          }
          if (typeof encoding === "string" && !Buffer2.isEncoding(encoding)) {
            throw new TypeError("Unknown encoding: " + encoding);
          }
          if (val.length === 1) {
            const code3 = val.charCodeAt(0);
            if (encoding === "utf8" && code3 < 128 || encoding === "latin1") {
              val = code3;
            }
          }
        } else if (typeof val === "number") {
          val = val & 255;
        } else if (typeof val === "boolean") {
          val = Number(val);
        }
        if (start < 0 || this.length < start || this.length < end) {
          throw new RangeError("Out of range index");
        }
        if (end <= start) {
          return this;
        }
        start = start >>> 0;
        end = end === void 0 ? this.length : end >>> 0;
        if (!val) val = 0;
        let i;
        if (typeof val === "number") {
          for (i = start; i < end; ++i) {
            this[i] = val;
          }
        } else {
          const bytes = Buffer2.isBuffer(val) ? val : Buffer2.from(val, encoding);
          const len = bytes.length;
          if (len === 0) {
            throw new TypeError('The value "' + val + '" is invalid for argument "value"');
          }
          for (i = 0; i < end - start; ++i) {
            this[i + start] = bytes[i % len];
          }
        }
        return this;
      };
      errors = {};
      E(
        "ERR_BUFFER_OUT_OF_BOUNDS",
        function(name) {
          if (name) {
            return `${name} is outside of buffer bounds`;
          }
          return "Attempt to access memory outside buffer bounds";
        },
        RangeError
      );
      E(
        "ERR_INVALID_ARG_TYPE",
        function(name, actual) {
          return `The "${name}" argument must be of type number. Received type ${typeof actual}`;
        },
        TypeError
      );
      E(
        "ERR_OUT_OF_RANGE",
        function(str, range, input) {
          let msg = `The value of "${str}" is out of range.`;
          let received = input;
          if (Number.isInteger(input) && Math.abs(input) > 2 ** 32) {
            received = addNumericalSeparator(String(input));
          } else if (typeof input === "bigint") {
            received = String(input);
            if (input > BigInt(2) ** BigInt(32) || input < -(BigInt(2) ** BigInt(32))) {
              received = addNumericalSeparator(received);
            }
            received += "n";
          }
          msg += ` It must be ${range}. Received ${received}`;
          return msg;
        },
        RangeError
      );
      INVALID_BASE64_RE = /[^+/0-9A-Za-z-_]/g;
      hexSliceLookupTable = function() {
        const alphabet = "0123456789abcdef";
        const table = new Array(256);
        for (let i = 0; i < 16; ++i) {
          const i16 = i * 16;
          for (let j = 0; j < 16; ++j) {
            table[i16 + j] = alphabet[i] + alphabet[j];
          }
        }
        return table;
      }();
    }
  });

  // frida-builtins:/node-globals.js
  var init_node_globals = __esm({
    "frida-builtins:/node-globals.js"() {
    }
  });

  // node_modules/frida-java-bridge/lib/alloc.js
  function abs(nptr) {
    const shmt = pointerSize === 4 ? 31 : 63;
    const mask = ptr(1).shl(shmt).not();
    return nptr.and(mask);
  }
  function makeAllocator(sliceSize) {
    return new CodeAllocator(sliceSize);
  }
  var pageSize, pointerSize, CodeAllocator;
  var init_alloc = __esm({
    "node_modules/frida-java-bridge/lib/alloc.js"() {
      init_node_globals();
      ({
        pageSize,
        pointerSize
      } = Process);
      CodeAllocator = class {
        constructor(sliceSize) {
          this.sliceSize = sliceSize;
          this.slicesPerPage = pageSize / sliceSize;
          this.pages = [];
          this.free = [];
        }
        allocateSlice(spec, alignment) {
          const anyLocation = spec.near === void 0;
          const anyAlignment = alignment === 1;
          if (anyLocation && anyAlignment) {
            const slice2 = this.free.pop();
            if (slice2 !== void 0) {
              return slice2;
            }
          } else if (alignment < pageSize) {
            const { free } = this;
            const n = free.length;
            const alignMask = anyAlignment ? null : ptr(alignment - 1);
            for (let i = 0; i !== n; i++) {
              const slice2 = free[i];
              const satisfiesLocation = anyLocation || this._isSliceNear(slice2, spec);
              const satisfiesAlignment = anyAlignment || slice2.and(alignMask).isNull();
              if (satisfiesLocation && satisfiesAlignment) {
                return free.splice(i, 1)[0];
              }
            }
          }
          return this._allocatePage(spec);
        }
        _allocatePage(spec) {
          const page = Memory.alloc(pageSize, spec);
          const { sliceSize, slicesPerPage } = this;
          for (let i = 1; i !== slicesPerPage; i++) {
            const slice2 = page.add(i * sliceSize);
            this.free.push(slice2);
          }
          this.pages.push(page);
          return page;
        }
        _isSliceNear(slice2, spec) {
          const sliceEnd = slice2.add(this.sliceSize);
          const { near, maxDistance } = spec;
          const startDistance = abs(near.sub(slice2));
          const endDistance = abs(near.sub(sliceEnd));
          return startDistance.compare(maxDistance) <= 0 && endDistance.compare(maxDistance) <= 0;
        }
        freeSlice(slice2) {
          this.free.push(slice2);
        }
      };
    }
  });

  // node_modules/frida-java-bridge/lib/result.js
  function checkJniResult(name, result) {
    if (result !== JNI_OK) {
      throw new Error(name + " failed: " + result);
    }
  }
  var JNI_OK;
  var init_result = __esm({
    "node_modules/frida-java-bridge/lib/result.js"() {
      init_node_globals();
      JNI_OK = 0;
    }
  });

  // node_modules/frida-java-bridge/lib/jvmti.js
  function EnvJvmti(handle, vm3) {
    this.handle = handle;
    this.vm = vm3;
    this.vtable = handle.readPointer();
  }
  function proxy(offset, retType, argTypes, wrapper) {
    let impl = null;
    return function() {
      if (impl === null) {
        impl = new NativeFunction(this.vtable.add((offset - 1) * pointerSize2).readPointer(), retType, argTypes, nativeFunctionOptions);
      }
      let args = [impl];
      args = args.concat.apply(args, arguments);
      return wrapper.apply(this, args);
    };
  }
  var jvmtiVersion, jvmtiCapabilities, pointerSize2, nativeFunctionOptions;
  var init_jvmti = __esm({
    "node_modules/frida-java-bridge/lib/jvmti.js"() {
      init_node_globals();
      init_result();
      jvmtiVersion = {
        v1_0: 805371904,
        v1_2: 805372416
      };
      jvmtiCapabilities = {
        canTagObjects: 1
      };
      ({ pointerSize: pointerSize2 } = Process);
      nativeFunctionOptions = {
        exceptions: "propagate"
      };
      EnvJvmti.prototype.deallocate = proxy(47, "int32", ["pointer", "pointer"], function(impl, mem) {
        return impl(this.handle, mem);
      });
      EnvJvmti.prototype.getLoadedClasses = proxy(78, "int32", ["pointer", "pointer", "pointer"], function(impl, classCountPtr, classesPtr) {
        const result = impl(this.handle, classCountPtr, classesPtr);
        checkJniResult("EnvJvmti::getLoadedClasses", result);
      });
      EnvJvmti.prototype.iterateOverInstancesOfClass = proxy(112, "int32", ["pointer", "pointer", "int", "pointer", "pointer"], function(impl, klass, objectFilter, heapObjectCallback, userData) {
        const result = impl(this.handle, klass, objectFilter, heapObjectCallback, userData);
        checkJniResult("EnvJvmti::iterateOverInstancesOfClass", result);
      });
      EnvJvmti.prototype.getObjectsWithTags = proxy(114, "int32", ["pointer", "int", "pointer", "pointer", "pointer", "pointer"], function(impl, tagCount, tags, countPtr, objectResultPtr, tagResultPtr) {
        const result = impl(this.handle, tagCount, tags, countPtr, objectResultPtr, tagResultPtr);
        checkJniResult("EnvJvmti::getObjectsWithTags", result);
      });
      EnvJvmti.prototype.addCapabilities = proxy(142, "int32", ["pointer", "pointer"], function(impl, capabilitiesPtr) {
        return impl(this.handle, capabilitiesPtr);
      });
    }
  });

  // node_modules/frida-java-bridge/lib/machine-code.js
  function parseInstructionsAt(address, tryParse, { limit }) {
    let cursor = address;
    let prevInsn = null;
    for (let i = 0; i !== limit; i++) {
      const insn = Instruction.parse(cursor);
      const value = tryParse(insn, prevInsn);
      if (value !== null) {
        return value;
      }
      cursor = insn.next;
      prevInsn = insn;
    }
    return null;
  }
  var init_machine_code = __esm({
    "node_modules/frida-java-bridge/lib/machine-code.js"() {
      init_node_globals();
    }
  });

  // node_modules/frida-java-bridge/lib/memoize.js
  function memoize(compute) {
    let value = null;
    let computed = false;
    return function(...args) {
      if (!computed) {
        value = compute(...args);
        computed = true;
      }
      return value;
    };
  }
  var init_memoize = __esm({
    "node_modules/frida-java-bridge/lib/memoize.js"() {
      init_node_globals();
    }
  });

  // node_modules/frida-java-bridge/lib/env.js
  function Env(handle, vm3) {
    this.handle = handle;
    this.vm = vm3;
  }
  function register(globalRef) {
    globalRefs.push(globalRef);
    return globalRef;
  }
  function vtable(instance) {
    if (cachedVtable === null) {
      cachedVtable = instance.handle.readPointer();
    }
    return cachedVtable;
  }
  function proxy2(offset, retType, argTypes, wrapper) {
    let impl = null;
    return function() {
      if (impl === null) {
        impl = new NativeFunction(vtable(this).add(offset * pointerSize3).readPointer(), retType, argTypes, nativeFunctionOptions2);
      }
      let args = [impl];
      args = args.concat.apply(args, arguments);
      return wrapper.apply(this, args);
    };
  }
  function makeErrorHandleDestructor(vm3, handle) {
    return function() {
      vm3.perform((env) => {
        env.deleteGlobalRef(handle);
      });
    };
  }
  function plainMethod(offset, retType, argTypes, options) {
    return getOrMakeMethod(this, "p", makePlainMethod, offset, retType, argTypes, options);
  }
  function vaMethod(offset, retType, argTypes, options) {
    return getOrMakeMethod(this, "v", makeVaMethod, offset, retType, argTypes, options);
  }
  function nonvirtualVaMethod(offset, retType, argTypes, options) {
    return getOrMakeMethod(this, "n", makeNonvirtualVaMethod, offset, retType, argTypes, options);
  }
  function getOrMakeMethod(env, flavor, construct, offset, retType, argTypes, options) {
    if (options !== void 0) {
      return construct(env, offset, retType, argTypes, options);
    }
    const key = [offset, flavor, retType].concat(argTypes).join("|");
    let m = cachedMethods.get(key);
    if (m === void 0) {
      m = construct(env, offset, retType, argTypes, nativeFunctionOptions2);
      cachedMethods.set(key, m);
    }
    return m;
  }
  function makePlainMethod(env, offset, retType, argTypes, options) {
    return new NativeFunction(
      vtable(env).add(offset * pointerSize3).readPointer(),
      retType,
      ["pointer", "pointer", "pointer"].concat(argTypes),
      options
    );
  }
  function makeVaMethod(env, offset, retType, argTypes, options) {
    return new NativeFunction(
      vtable(env).add(offset * pointerSize3).readPointer(),
      retType,
      ["pointer", "pointer", "pointer", "..."].concat(argTypes),
      options
    );
  }
  function makeNonvirtualVaMethod(env, offset, retType, argTypes, options) {
    return new NativeFunction(
      vtable(env).add(offset * pointerSize3).readPointer(),
      retType,
      ["pointer", "pointer", "pointer", "pointer", "..."].concat(argTypes),
      options
    );
  }
  var pointerSize3, JNI_ABORT, CALL_CONSTRUCTOR_METHOD_OFFSET, CALL_OBJECT_METHOD_OFFSET, CALL_BOOLEAN_METHOD_OFFSET, CALL_BYTE_METHOD_OFFSET, CALL_CHAR_METHOD_OFFSET, CALL_SHORT_METHOD_OFFSET, CALL_INT_METHOD_OFFSET, CALL_LONG_METHOD_OFFSET, CALL_FLOAT_METHOD_OFFSET, CALL_DOUBLE_METHOD_OFFSET, CALL_VOID_METHOD_OFFSET, CALL_NONVIRTUAL_OBJECT_METHOD_OFFSET, CALL_NONVIRTUAL_BOOLEAN_METHOD_OFFSET, CALL_NONVIRTUAL_BYTE_METHOD_OFFSET, CALL_NONVIRTUAL_CHAR_METHOD_OFFSET, CALL_NONVIRTUAL_SHORT_METHOD_OFFSET, CALL_NONVIRTUAL_INT_METHOD_OFFSET, CALL_NONVIRTUAL_LONG_METHOD_OFFSET, CALL_NONVIRTUAL_FLOAT_METHOD_OFFSET, CALL_NONVIRTUAL_DOUBLE_METHOD_OFFSET, CALL_NONVIRTUAL_VOID_METHOD_OFFSET, CALL_STATIC_OBJECT_METHOD_OFFSET, CALL_STATIC_BOOLEAN_METHOD_OFFSET, CALL_STATIC_BYTE_METHOD_OFFSET, CALL_STATIC_CHAR_METHOD_OFFSET, CALL_STATIC_SHORT_METHOD_OFFSET, CALL_STATIC_INT_METHOD_OFFSET, CALL_STATIC_LONG_METHOD_OFFSET, CALL_STATIC_FLOAT_METHOD_OFFSET, CALL_STATIC_DOUBLE_METHOD_OFFSET, CALL_STATIC_VOID_METHOD_OFFSET, GET_OBJECT_FIELD_OFFSET, GET_BOOLEAN_FIELD_OFFSET, GET_BYTE_FIELD_OFFSET, GET_CHAR_FIELD_OFFSET, GET_SHORT_FIELD_OFFSET, GET_INT_FIELD_OFFSET, GET_LONG_FIELD_OFFSET, GET_FLOAT_FIELD_OFFSET, GET_DOUBLE_FIELD_OFFSET, SET_OBJECT_FIELD_OFFSET, SET_BOOLEAN_FIELD_OFFSET, SET_BYTE_FIELD_OFFSET, SET_CHAR_FIELD_OFFSET, SET_SHORT_FIELD_OFFSET, SET_INT_FIELD_OFFSET, SET_LONG_FIELD_OFFSET, SET_FLOAT_FIELD_OFFSET, SET_DOUBLE_FIELD_OFFSET, GET_STATIC_OBJECT_FIELD_OFFSET, GET_STATIC_BOOLEAN_FIELD_OFFSET, GET_STATIC_BYTE_FIELD_OFFSET, GET_STATIC_CHAR_FIELD_OFFSET, GET_STATIC_SHORT_FIELD_OFFSET, GET_STATIC_INT_FIELD_OFFSET, GET_STATIC_LONG_FIELD_OFFSET, GET_STATIC_FLOAT_FIELD_OFFSET, GET_STATIC_DOUBLE_FIELD_OFFSET, SET_STATIC_OBJECT_FIELD_OFFSET, SET_STATIC_BOOLEAN_FIELD_OFFSET, SET_STATIC_BYTE_FIELD_OFFSET, SET_STATIC_CHAR_FIELD_OFFSET, SET_STATIC_SHORT_FIELD_OFFSET, SET_STATIC_INT_FIELD_OFFSET, SET_STATIC_LONG_FIELD_OFFSET, SET_STATIC_FLOAT_FIELD_OFFSET, SET_STATIC_DOUBLE_FIELD_OFFSET, callMethodOffset, callNonvirtualMethodOffset, callStaticMethodOffset, getFieldOffset, setFieldOffset, getStaticFieldOffset, setStaticFieldOffset, nativeFunctionOptions2, cachedVtable, globalRefs, cachedMethods, javaLangClass, javaLangObject, javaLangReflectConstructor, javaLangReflectMethod, javaLangReflectField, javaLangReflectTypeVariable, javaLangReflectWildcardType, javaLangReflectGenericArrayType, javaLangReflectParameterizedType, javaLangString;
  var init_env = __esm({
    "node_modules/frida-java-bridge/lib/env.js"() {
      init_node_globals();
      pointerSize3 = Process.pointerSize;
      JNI_ABORT = 2;
      CALL_CONSTRUCTOR_METHOD_OFFSET = 28;
      CALL_OBJECT_METHOD_OFFSET = 34;
      CALL_BOOLEAN_METHOD_OFFSET = 37;
      CALL_BYTE_METHOD_OFFSET = 40;
      CALL_CHAR_METHOD_OFFSET = 43;
      CALL_SHORT_METHOD_OFFSET = 46;
      CALL_INT_METHOD_OFFSET = 49;
      CALL_LONG_METHOD_OFFSET = 52;
      CALL_FLOAT_METHOD_OFFSET = 55;
      CALL_DOUBLE_METHOD_OFFSET = 58;
      CALL_VOID_METHOD_OFFSET = 61;
      CALL_NONVIRTUAL_OBJECT_METHOD_OFFSET = 64;
      CALL_NONVIRTUAL_BOOLEAN_METHOD_OFFSET = 67;
      CALL_NONVIRTUAL_BYTE_METHOD_OFFSET = 70;
      CALL_NONVIRTUAL_CHAR_METHOD_OFFSET = 73;
      CALL_NONVIRTUAL_SHORT_METHOD_OFFSET = 76;
      CALL_NONVIRTUAL_INT_METHOD_OFFSET = 79;
      CALL_NONVIRTUAL_LONG_METHOD_OFFSET = 82;
      CALL_NONVIRTUAL_FLOAT_METHOD_OFFSET = 85;
      CALL_NONVIRTUAL_DOUBLE_METHOD_OFFSET = 88;
      CALL_NONVIRTUAL_VOID_METHOD_OFFSET = 91;
      CALL_STATIC_OBJECT_METHOD_OFFSET = 114;
      CALL_STATIC_BOOLEAN_METHOD_OFFSET = 117;
      CALL_STATIC_BYTE_METHOD_OFFSET = 120;
      CALL_STATIC_CHAR_METHOD_OFFSET = 123;
      CALL_STATIC_SHORT_METHOD_OFFSET = 126;
      CALL_STATIC_INT_METHOD_OFFSET = 129;
      CALL_STATIC_LONG_METHOD_OFFSET = 132;
      CALL_STATIC_FLOAT_METHOD_OFFSET = 135;
      CALL_STATIC_DOUBLE_METHOD_OFFSET = 138;
      CALL_STATIC_VOID_METHOD_OFFSET = 141;
      GET_OBJECT_FIELD_OFFSET = 95;
      GET_BOOLEAN_FIELD_OFFSET = 96;
      GET_BYTE_FIELD_OFFSET = 97;
      GET_CHAR_FIELD_OFFSET = 98;
      GET_SHORT_FIELD_OFFSET = 99;
      GET_INT_FIELD_OFFSET = 100;
      GET_LONG_FIELD_OFFSET = 101;
      GET_FLOAT_FIELD_OFFSET = 102;
      GET_DOUBLE_FIELD_OFFSET = 103;
      SET_OBJECT_FIELD_OFFSET = 104;
      SET_BOOLEAN_FIELD_OFFSET = 105;
      SET_BYTE_FIELD_OFFSET = 106;
      SET_CHAR_FIELD_OFFSET = 107;
      SET_SHORT_FIELD_OFFSET = 108;
      SET_INT_FIELD_OFFSET = 109;
      SET_LONG_FIELD_OFFSET = 110;
      SET_FLOAT_FIELD_OFFSET = 111;
      SET_DOUBLE_FIELD_OFFSET = 112;
      GET_STATIC_OBJECT_FIELD_OFFSET = 145;
      GET_STATIC_BOOLEAN_FIELD_OFFSET = 146;
      GET_STATIC_BYTE_FIELD_OFFSET = 147;
      GET_STATIC_CHAR_FIELD_OFFSET = 148;
      GET_STATIC_SHORT_FIELD_OFFSET = 149;
      GET_STATIC_INT_FIELD_OFFSET = 150;
      GET_STATIC_LONG_FIELD_OFFSET = 151;
      GET_STATIC_FLOAT_FIELD_OFFSET = 152;
      GET_STATIC_DOUBLE_FIELD_OFFSET = 153;
      SET_STATIC_OBJECT_FIELD_OFFSET = 154;
      SET_STATIC_BOOLEAN_FIELD_OFFSET = 155;
      SET_STATIC_BYTE_FIELD_OFFSET = 156;
      SET_STATIC_CHAR_FIELD_OFFSET = 157;
      SET_STATIC_SHORT_FIELD_OFFSET = 158;
      SET_STATIC_INT_FIELD_OFFSET = 159;
      SET_STATIC_LONG_FIELD_OFFSET = 160;
      SET_STATIC_FLOAT_FIELD_OFFSET = 161;
      SET_STATIC_DOUBLE_FIELD_OFFSET = 162;
      callMethodOffset = {
        pointer: CALL_OBJECT_METHOD_OFFSET,
        uint8: CALL_BOOLEAN_METHOD_OFFSET,
        int8: CALL_BYTE_METHOD_OFFSET,
        uint16: CALL_CHAR_METHOD_OFFSET,
        int16: CALL_SHORT_METHOD_OFFSET,
        int32: CALL_INT_METHOD_OFFSET,
        int64: CALL_LONG_METHOD_OFFSET,
        float: CALL_FLOAT_METHOD_OFFSET,
        double: CALL_DOUBLE_METHOD_OFFSET,
        void: CALL_VOID_METHOD_OFFSET
      };
      callNonvirtualMethodOffset = {
        pointer: CALL_NONVIRTUAL_OBJECT_METHOD_OFFSET,
        uint8: CALL_NONVIRTUAL_BOOLEAN_METHOD_OFFSET,
        int8: CALL_NONVIRTUAL_BYTE_METHOD_OFFSET,
        uint16: CALL_NONVIRTUAL_CHAR_METHOD_OFFSET,
        int16: CALL_NONVIRTUAL_SHORT_METHOD_OFFSET,
        int32: CALL_NONVIRTUAL_INT_METHOD_OFFSET,
        int64: CALL_NONVIRTUAL_LONG_METHOD_OFFSET,
        float: CALL_NONVIRTUAL_FLOAT_METHOD_OFFSET,
        double: CALL_NONVIRTUAL_DOUBLE_METHOD_OFFSET,
        void: CALL_NONVIRTUAL_VOID_METHOD_OFFSET
      };
      callStaticMethodOffset = {
        pointer: CALL_STATIC_OBJECT_METHOD_OFFSET,
        uint8: CALL_STATIC_BOOLEAN_METHOD_OFFSET,
        int8: CALL_STATIC_BYTE_METHOD_OFFSET,
        uint16: CALL_STATIC_CHAR_METHOD_OFFSET,
        int16: CALL_STATIC_SHORT_METHOD_OFFSET,
        int32: CALL_STATIC_INT_METHOD_OFFSET,
        int64: CALL_STATIC_LONG_METHOD_OFFSET,
        float: CALL_STATIC_FLOAT_METHOD_OFFSET,
        double: CALL_STATIC_DOUBLE_METHOD_OFFSET,
        void: CALL_STATIC_VOID_METHOD_OFFSET
      };
      getFieldOffset = {
        pointer: GET_OBJECT_FIELD_OFFSET,
        uint8: GET_BOOLEAN_FIELD_OFFSET,
        int8: GET_BYTE_FIELD_OFFSET,
        uint16: GET_CHAR_FIELD_OFFSET,
        int16: GET_SHORT_FIELD_OFFSET,
        int32: GET_INT_FIELD_OFFSET,
        int64: GET_LONG_FIELD_OFFSET,
        float: GET_FLOAT_FIELD_OFFSET,
        double: GET_DOUBLE_FIELD_OFFSET
      };
      setFieldOffset = {
        pointer: SET_OBJECT_FIELD_OFFSET,
        uint8: SET_BOOLEAN_FIELD_OFFSET,
        int8: SET_BYTE_FIELD_OFFSET,
        uint16: SET_CHAR_FIELD_OFFSET,
        int16: SET_SHORT_FIELD_OFFSET,
        int32: SET_INT_FIELD_OFFSET,
        int64: SET_LONG_FIELD_OFFSET,
        float: SET_FLOAT_FIELD_OFFSET,
        double: SET_DOUBLE_FIELD_OFFSET
      };
      getStaticFieldOffset = {
        pointer: GET_STATIC_OBJECT_FIELD_OFFSET,
        uint8: GET_STATIC_BOOLEAN_FIELD_OFFSET,
        int8: GET_STATIC_BYTE_FIELD_OFFSET,
        uint16: GET_STATIC_CHAR_FIELD_OFFSET,
        int16: GET_STATIC_SHORT_FIELD_OFFSET,
        int32: GET_STATIC_INT_FIELD_OFFSET,
        int64: GET_STATIC_LONG_FIELD_OFFSET,
        float: GET_STATIC_FLOAT_FIELD_OFFSET,
        double: GET_STATIC_DOUBLE_FIELD_OFFSET
      };
      setStaticFieldOffset = {
        pointer: SET_STATIC_OBJECT_FIELD_OFFSET,
        uint8: SET_STATIC_BOOLEAN_FIELD_OFFSET,
        int8: SET_STATIC_BYTE_FIELD_OFFSET,
        uint16: SET_STATIC_CHAR_FIELD_OFFSET,
        int16: SET_STATIC_SHORT_FIELD_OFFSET,
        int32: SET_STATIC_INT_FIELD_OFFSET,
        int64: SET_STATIC_LONG_FIELD_OFFSET,
        float: SET_STATIC_FLOAT_FIELD_OFFSET,
        double: SET_STATIC_DOUBLE_FIELD_OFFSET
      };
      nativeFunctionOptions2 = {
        exceptions: "propagate"
      };
      cachedVtable = null;
      globalRefs = [];
      Env.dispose = function(env) {
        globalRefs.forEach(env.deleteGlobalRef, env);
        globalRefs = [];
      };
      Env.prototype.getVersion = proxy2(4, "int32", ["pointer"], function(impl) {
        return impl(this.handle);
      });
      Env.prototype.findClass = proxy2(6, "pointer", ["pointer", "pointer"], function(impl, name) {
        const result = impl(this.handle, Memory.allocUtf8String(name));
        this.throwIfExceptionPending();
        return result;
      });
      Env.prototype.throwIfExceptionPending = function() {
        const throwable = this.exceptionOccurred();
        if (throwable.isNull()) {
          return;
        }
        this.exceptionClear();
        const handle = this.newGlobalRef(throwable);
        this.deleteLocalRef(throwable);
        const description = this.vaMethod("pointer", [])(this.handle, handle, this.javaLangObject().toString);
        const descriptionStr = this.stringFromJni(description);
        this.deleteLocalRef(description);
        const error = new Error(descriptionStr);
        error.$h = handle;
        Script.bindWeak(error, makeErrorHandleDestructor(this.vm, handle));
        throw error;
      };
      Env.prototype.fromReflectedMethod = proxy2(7, "pointer", ["pointer", "pointer"], function(impl, method) {
        return impl(this.handle, method);
      });
      Env.prototype.fromReflectedField = proxy2(8, "pointer", ["pointer", "pointer"], function(impl, method) {
        return impl(this.handle, method);
      });
      Env.prototype.toReflectedMethod = proxy2(9, "pointer", ["pointer", "pointer", "pointer", "uint8"], function(impl, klass, methodId, isStatic) {
        return impl(this.handle, klass, methodId, isStatic);
      });
      Env.prototype.getSuperclass = proxy2(10, "pointer", ["pointer", "pointer"], function(impl, klass) {
        return impl(this.handle, klass);
      });
      Env.prototype.isAssignableFrom = proxy2(11, "uint8", ["pointer", "pointer", "pointer"], function(impl, klass1, klass2) {
        return !!impl(this.handle, klass1, klass2);
      });
      Env.prototype.toReflectedField = proxy2(12, "pointer", ["pointer", "pointer", "pointer", "uint8"], function(impl, klass, fieldId, isStatic) {
        return impl(this.handle, klass, fieldId, isStatic);
      });
      Env.prototype.throw = proxy2(13, "int32", ["pointer", "pointer"], function(impl, obj) {
        return impl(this.handle, obj);
      });
      Env.prototype.exceptionOccurred = proxy2(15, "pointer", ["pointer"], function(impl) {
        return impl(this.handle);
      });
      Env.prototype.exceptionDescribe = proxy2(16, "void", ["pointer"], function(impl) {
        impl(this.handle);
      });
      Env.prototype.exceptionClear = proxy2(17, "void", ["pointer"], function(impl) {
        impl(this.handle);
      });
      Env.prototype.pushLocalFrame = proxy2(19, "int32", ["pointer", "int32"], function(impl, capacity) {
        return impl(this.handle, capacity);
      });
      Env.prototype.popLocalFrame = proxy2(20, "pointer", ["pointer", "pointer"], function(impl, result) {
        return impl(this.handle, result);
      });
      Env.prototype.newGlobalRef = proxy2(21, "pointer", ["pointer", "pointer"], function(impl, obj) {
        return impl(this.handle, obj);
      });
      Env.prototype.deleteGlobalRef = proxy2(22, "void", ["pointer", "pointer"], function(impl, globalRef) {
        impl(this.handle, globalRef);
      });
      Env.prototype.deleteLocalRef = proxy2(23, "void", ["pointer", "pointer"], function(impl, localRef) {
        impl(this.handle, localRef);
      });
      Env.prototype.isSameObject = proxy2(24, "uint8", ["pointer", "pointer", "pointer"], function(impl, ref1, ref2) {
        return !!impl(this.handle, ref1, ref2);
      });
      Env.prototype.newLocalRef = proxy2(25, "pointer", ["pointer", "pointer"], function(impl, obj) {
        return impl(this.handle, obj);
      });
      Env.prototype.allocObject = proxy2(27, "pointer", ["pointer", "pointer"], function(impl, clazz) {
        return impl(this.handle, clazz);
      });
      Env.prototype.getObjectClass = proxy2(31, "pointer", ["pointer", "pointer"], function(impl, obj) {
        return impl(this.handle, obj);
      });
      Env.prototype.isInstanceOf = proxy2(32, "uint8", ["pointer", "pointer", "pointer"], function(impl, obj, klass) {
        return !!impl(this.handle, obj, klass);
      });
      Env.prototype.getMethodId = proxy2(33, "pointer", ["pointer", "pointer", "pointer", "pointer"], function(impl, klass, name, sig) {
        return impl(this.handle, klass, Memory.allocUtf8String(name), Memory.allocUtf8String(sig));
      });
      Env.prototype.getFieldId = proxy2(94, "pointer", ["pointer", "pointer", "pointer", "pointer"], function(impl, klass, name, sig) {
        return impl(this.handle, klass, Memory.allocUtf8String(name), Memory.allocUtf8String(sig));
      });
      Env.prototype.getIntField = proxy2(100, "int32", ["pointer", "pointer", "pointer"], function(impl, obj, fieldId) {
        return impl(this.handle, obj, fieldId);
      });
      Env.prototype.getStaticMethodId = proxy2(113, "pointer", ["pointer", "pointer", "pointer", "pointer"], function(impl, klass, name, sig) {
        return impl(this.handle, klass, Memory.allocUtf8String(name), Memory.allocUtf8String(sig));
      });
      Env.prototype.getStaticFieldId = proxy2(144, "pointer", ["pointer", "pointer", "pointer", "pointer"], function(impl, klass, name, sig) {
        return impl(this.handle, klass, Memory.allocUtf8String(name), Memory.allocUtf8String(sig));
      });
      Env.prototype.getStaticIntField = proxy2(150, "int32", ["pointer", "pointer", "pointer"], function(impl, obj, fieldId) {
        return impl(this.handle, obj, fieldId);
      });
      Env.prototype.getStringLength = proxy2(164, "int32", ["pointer", "pointer"], function(impl, str) {
        return impl(this.handle, str);
      });
      Env.prototype.getStringChars = proxy2(165, "pointer", ["pointer", "pointer", "pointer"], function(impl, str) {
        return impl(this.handle, str, NULL);
      });
      Env.prototype.releaseStringChars = proxy2(166, "void", ["pointer", "pointer", "pointer"], function(impl, str, utf) {
        impl(this.handle, str, utf);
      });
      Env.prototype.newStringUtf = proxy2(167, "pointer", ["pointer", "pointer"], function(impl, str) {
        const utf = Memory.allocUtf8String(str);
        return impl(this.handle, utf);
      });
      Env.prototype.getStringUtfChars = proxy2(169, "pointer", ["pointer", "pointer", "pointer"], function(impl, str) {
        return impl(this.handle, str, NULL);
      });
      Env.prototype.releaseStringUtfChars = proxy2(170, "void", ["pointer", "pointer", "pointer"], function(impl, str, utf) {
        impl(this.handle, str, utf);
      });
      Env.prototype.getArrayLength = proxy2(171, "int32", ["pointer", "pointer"], function(impl, array) {
        return impl(this.handle, array);
      });
      Env.prototype.newObjectArray = proxy2(172, "pointer", ["pointer", "int32", "pointer", "pointer"], function(impl, length, elementClass, initialElement) {
        return impl(this.handle, length, elementClass, initialElement);
      });
      Env.prototype.getObjectArrayElement = proxy2(173, "pointer", ["pointer", "pointer", "int32"], function(impl, array, index) {
        return impl(this.handle, array, index);
      });
      Env.prototype.setObjectArrayElement = proxy2(174, "void", ["pointer", "pointer", "int32", "pointer"], function(impl, array, index, value) {
        impl(this.handle, array, index, value);
      });
      Env.prototype.newBooleanArray = proxy2(175, "pointer", ["pointer", "int32"], function(impl, length) {
        return impl(this.handle, length);
      });
      Env.prototype.newByteArray = proxy2(176, "pointer", ["pointer", "int32"], function(impl, length) {
        return impl(this.handle, length);
      });
      Env.prototype.newCharArray = proxy2(177, "pointer", ["pointer", "int32"], function(impl, length) {
        return impl(this.handle, length);
      });
      Env.prototype.newShortArray = proxy2(178, "pointer", ["pointer", "int32"], function(impl, length) {
        return impl(this.handle, length);
      });
      Env.prototype.newIntArray = proxy2(179, "pointer", ["pointer", "int32"], function(impl, length) {
        return impl(this.handle, length);
      });
      Env.prototype.newLongArray = proxy2(180, "pointer", ["pointer", "int32"], function(impl, length) {
        return impl(this.handle, length);
      });
      Env.prototype.newFloatArray = proxy2(181, "pointer", ["pointer", "int32"], function(impl, length) {
        return impl(this.handle, length);
      });
      Env.prototype.newDoubleArray = proxy2(182, "pointer", ["pointer", "int32"], function(impl, length) {
        return impl(this.handle, length);
      });
      Env.prototype.getBooleanArrayElements = proxy2(183, "pointer", ["pointer", "pointer", "pointer"], function(impl, array) {
        return impl(this.handle, array, NULL);
      });
      Env.prototype.getByteArrayElements = proxy2(184, "pointer", ["pointer", "pointer", "pointer"], function(impl, array) {
        return impl(this.handle, array, NULL);
      });
      Env.prototype.getCharArrayElements = proxy2(185, "pointer", ["pointer", "pointer", "pointer"], function(impl, array) {
        return impl(this.handle, array, NULL);
      });
      Env.prototype.getShortArrayElements = proxy2(186, "pointer", ["pointer", "pointer", "pointer"], function(impl, array) {
        return impl(this.handle, array, NULL);
      });
      Env.prototype.getIntArrayElements = proxy2(187, "pointer", ["pointer", "pointer", "pointer"], function(impl, array) {
        return impl(this.handle, array, NULL);
      });
      Env.prototype.getLongArrayElements = proxy2(188, "pointer", ["pointer", "pointer", "pointer"], function(impl, array) {
        return impl(this.handle, array, NULL);
      });
      Env.prototype.getFloatArrayElements = proxy2(189, "pointer", ["pointer", "pointer", "pointer"], function(impl, array) {
        return impl(this.handle, array, NULL);
      });
      Env.prototype.getDoubleArrayElements = proxy2(190, "pointer", ["pointer", "pointer", "pointer"], function(impl, array) {
        return impl(this.handle, array, NULL);
      });
      Env.prototype.releaseBooleanArrayElements = proxy2(191, "pointer", ["pointer", "pointer", "pointer", "int32"], function(impl, array, cArray) {
        impl(this.handle, array, cArray, JNI_ABORT);
      });
      Env.prototype.releaseByteArrayElements = proxy2(192, "pointer", ["pointer", "pointer", "pointer", "int32"], function(impl, array, cArray) {
        impl(this.handle, array, cArray, JNI_ABORT);
      });
      Env.prototype.releaseCharArrayElements = proxy2(193, "pointer", ["pointer", "pointer", "pointer", "int32"], function(impl, array, cArray) {
        impl(this.handle, array, cArray, JNI_ABORT);
      });
      Env.prototype.releaseShortArrayElements = proxy2(194, "pointer", ["pointer", "pointer", "pointer", "int32"], function(impl, array, cArray) {
        impl(this.handle, array, cArray, JNI_ABORT);
      });
      Env.prototype.releaseIntArrayElements = proxy2(195, "pointer", ["pointer", "pointer", "pointer", "int32"], function(impl, array, cArray) {
        impl(this.handle, array, cArray, JNI_ABORT);
      });
      Env.prototype.releaseLongArrayElements = proxy2(196, "pointer", ["pointer", "pointer", "pointer", "int32"], function(impl, array, cArray) {
        impl(this.handle, array, cArray, JNI_ABORT);
      });
      Env.prototype.releaseFloatArrayElements = proxy2(197, "pointer", ["pointer", "pointer", "pointer", "int32"], function(impl, array, cArray) {
        impl(this.handle, array, cArray, JNI_ABORT);
      });
      Env.prototype.releaseDoubleArrayElements = proxy2(198, "pointer", ["pointer", "pointer", "pointer", "int32"], function(impl, array, cArray) {
        impl(this.handle, array, cArray, JNI_ABORT);
      });
      Env.prototype.getByteArrayRegion = proxy2(200, "void", ["pointer", "pointer", "int", "int", "pointer"], function(impl, array, start, length, cArray) {
        impl(this.handle, array, start, length, cArray);
      });
      Env.prototype.setBooleanArrayRegion = proxy2(207, "void", ["pointer", "pointer", "int32", "int32", "pointer"], function(impl, array, start, length, cArray) {
        impl(this.handle, array, start, length, cArray);
      });
      Env.prototype.setByteArrayRegion = proxy2(208, "void", ["pointer", "pointer", "int32", "int32", "pointer"], function(impl, array, start, length, cArray) {
        impl(this.handle, array, start, length, cArray);
      });
      Env.prototype.setCharArrayRegion = proxy2(209, "void", ["pointer", "pointer", "int32", "int32", "pointer"], function(impl, array, start, length, cArray) {
        impl(this.handle, array, start, length, cArray);
      });
      Env.prototype.setShortArrayRegion = proxy2(210, "void", ["pointer", "pointer", "int32", "int32", "pointer"], function(impl, array, start, length, cArray) {
        impl(this.handle, array, start, length, cArray);
      });
      Env.prototype.setIntArrayRegion = proxy2(211, "void", ["pointer", "pointer", "int32", "int32", "pointer"], function(impl, array, start, length, cArray) {
        impl(this.handle, array, start, length, cArray);
      });
      Env.prototype.setLongArrayRegion = proxy2(212, "void", ["pointer", "pointer", "int32", "int32", "pointer"], function(impl, array, start, length, cArray) {
        impl(this.handle, array, start, length, cArray);
      });
      Env.prototype.setFloatArrayRegion = proxy2(213, "void", ["pointer", "pointer", "int32", "int32", "pointer"], function(impl, array, start, length, cArray) {
        impl(this.handle, array, start, length, cArray);
      });
      Env.prototype.setDoubleArrayRegion = proxy2(214, "void", ["pointer", "pointer", "int32", "int32", "pointer"], function(impl, array, start, length, cArray) {
        impl(this.handle, array, start, length, cArray);
      });
      Env.prototype.registerNatives = proxy2(215, "int32", ["pointer", "pointer", "pointer", "int32"], function(impl, klass, methods, numMethods) {
        return impl(this.handle, klass, methods, numMethods);
      });
      Env.prototype.monitorEnter = proxy2(217, "int32", ["pointer", "pointer"], function(impl, obj) {
        return impl(this.handle, obj);
      });
      Env.prototype.monitorExit = proxy2(218, "int32", ["pointer", "pointer"], function(impl, obj) {
        return impl(this.handle, obj);
      });
      Env.prototype.getDirectBufferAddress = proxy2(230, "pointer", ["pointer", "pointer"], function(impl, obj) {
        return impl(this.handle, obj);
      });
      Env.prototype.getObjectRefType = proxy2(232, "int32", ["pointer", "pointer"], function(impl, ref) {
        return impl(this.handle, ref);
      });
      cachedMethods = /* @__PURE__ */ new Map();
      Env.prototype.constructor = function(argTypes, options) {
        return vaMethod.call(this, CALL_CONSTRUCTOR_METHOD_OFFSET, "pointer", argTypes, options);
      };
      Env.prototype.vaMethod = function(retType, argTypes, options) {
        const offset = callMethodOffset[retType];
        if (offset === void 0) {
          throw new Error("Unsupported type: " + retType);
        }
        return vaMethod.call(this, offset, retType, argTypes, options);
      };
      Env.prototype.nonvirtualVaMethod = function(retType, argTypes, options) {
        const offset = callNonvirtualMethodOffset[retType];
        if (offset === void 0) {
          throw new Error("Unsupported type: " + retType);
        }
        return nonvirtualVaMethod.call(this, offset, retType, argTypes, options);
      };
      Env.prototype.staticVaMethod = function(retType, argTypes, options) {
        const offset = callStaticMethodOffset[retType];
        if (offset === void 0) {
          throw new Error("Unsupported type: " + retType);
        }
        return vaMethod.call(this, offset, retType, argTypes, options);
      };
      Env.prototype.getField = function(fieldType) {
        const offset = getFieldOffset[fieldType];
        if (offset === void 0) {
          throw new Error("Unsupported type: " + fieldType);
        }
        return plainMethod.call(this, offset, fieldType, []);
      };
      Env.prototype.getStaticField = function(fieldType) {
        const offset = getStaticFieldOffset[fieldType];
        if (offset === void 0) {
          throw new Error("Unsupported type: " + fieldType);
        }
        return plainMethod.call(this, offset, fieldType, []);
      };
      Env.prototype.setField = function(fieldType) {
        const offset = setFieldOffset[fieldType];
        if (offset === void 0) {
          throw new Error("Unsupported type: " + fieldType);
        }
        return plainMethod.call(this, offset, "void", [fieldType]);
      };
      Env.prototype.setStaticField = function(fieldType) {
        const offset = setStaticFieldOffset[fieldType];
        if (offset === void 0) {
          throw new Error("Unsupported type: " + fieldType);
        }
        return plainMethod.call(this, offset, "void", [fieldType]);
      };
      javaLangClass = null;
      Env.prototype.javaLangClass = function() {
        if (javaLangClass === null) {
          const handle = this.findClass("java/lang/Class");
          try {
            const get = this.getMethodId.bind(this, handle);
            javaLangClass = {
              handle: register(this.newGlobalRef(handle)),
              getName: get("getName", "()Ljava/lang/String;"),
              getSimpleName: get("getSimpleName", "()Ljava/lang/String;"),
              getGenericSuperclass: get("getGenericSuperclass", "()Ljava/lang/reflect/Type;"),
              getDeclaredConstructors: get("getDeclaredConstructors", "()[Ljava/lang/reflect/Constructor;"),
              getDeclaredMethods: get("getDeclaredMethods", "()[Ljava/lang/reflect/Method;"),
              getDeclaredFields: get("getDeclaredFields", "()[Ljava/lang/reflect/Field;"),
              isArray: get("isArray", "()Z"),
              isPrimitive: get("isPrimitive", "()Z"),
              isInterface: get("isInterface", "()Z"),
              getComponentType: get("getComponentType", "()Ljava/lang/Class;")
            };
          } finally {
            this.deleteLocalRef(handle);
          }
        }
        return javaLangClass;
      };
      javaLangObject = null;
      Env.prototype.javaLangObject = function() {
        if (javaLangObject === null) {
          const handle = this.findClass("java/lang/Object");
          try {
            const get = this.getMethodId.bind(this, handle);
            javaLangObject = {
              handle: register(this.newGlobalRef(handle)),
              toString: get("toString", "()Ljava/lang/String;"),
              getClass: get("getClass", "()Ljava/lang/Class;")
            };
          } finally {
            this.deleteLocalRef(handle);
          }
        }
        return javaLangObject;
      };
      javaLangReflectConstructor = null;
      Env.prototype.javaLangReflectConstructor = function() {
        if (javaLangReflectConstructor === null) {
          const handle = this.findClass("java/lang/reflect/Constructor");
          try {
            javaLangReflectConstructor = {
              getGenericParameterTypes: this.getMethodId(handle, "getGenericParameterTypes", "()[Ljava/lang/reflect/Type;")
            };
          } finally {
            this.deleteLocalRef(handle);
          }
        }
        return javaLangReflectConstructor;
      };
      javaLangReflectMethod = null;
      Env.prototype.javaLangReflectMethod = function() {
        if (javaLangReflectMethod === null) {
          const handle = this.findClass("java/lang/reflect/Method");
          try {
            const get = this.getMethodId.bind(this, handle);
            javaLangReflectMethod = {
              getName: get("getName", "()Ljava/lang/String;"),
              getGenericParameterTypes: get("getGenericParameterTypes", "()[Ljava/lang/reflect/Type;"),
              getParameterTypes: get("getParameterTypes", "()[Ljava/lang/Class;"),
              getGenericReturnType: get("getGenericReturnType", "()Ljava/lang/reflect/Type;"),
              getGenericExceptionTypes: get("getGenericExceptionTypes", "()[Ljava/lang/reflect/Type;"),
              getModifiers: get("getModifiers", "()I"),
              isVarArgs: get("isVarArgs", "()Z")
            };
          } finally {
            this.deleteLocalRef(handle);
          }
        }
        return javaLangReflectMethod;
      };
      javaLangReflectField = null;
      Env.prototype.javaLangReflectField = function() {
        if (javaLangReflectField === null) {
          const handle = this.findClass("java/lang/reflect/Field");
          try {
            const get = this.getMethodId.bind(this, handle);
            javaLangReflectField = {
              getName: get("getName", "()Ljava/lang/String;"),
              getType: get("getType", "()Ljava/lang/Class;"),
              getGenericType: get("getGenericType", "()Ljava/lang/reflect/Type;"),
              getModifiers: get("getModifiers", "()I"),
              toString: get("toString", "()Ljava/lang/String;")
            };
          } finally {
            this.deleteLocalRef(handle);
          }
        }
        return javaLangReflectField;
      };
      javaLangReflectTypeVariable = null;
      Env.prototype.javaLangReflectTypeVariable = function() {
        if (javaLangReflectTypeVariable === null) {
          const handle = this.findClass("java/lang/reflect/TypeVariable");
          try {
            const get = this.getMethodId.bind(this, handle);
            javaLangReflectTypeVariable = {
              handle: register(this.newGlobalRef(handle)),
              getName: get("getName", "()Ljava/lang/String;"),
              getBounds: get("getBounds", "()[Ljava/lang/reflect/Type;"),
              getGenericDeclaration: get("getGenericDeclaration", "()Ljava/lang/reflect/GenericDeclaration;")
            };
          } finally {
            this.deleteLocalRef(handle);
          }
        }
        return javaLangReflectTypeVariable;
      };
      javaLangReflectWildcardType = null;
      Env.prototype.javaLangReflectWildcardType = function() {
        if (javaLangReflectWildcardType === null) {
          const handle = this.findClass("java/lang/reflect/WildcardType");
          try {
            const get = this.getMethodId.bind(this, handle);
            javaLangReflectWildcardType = {
              handle: register(this.newGlobalRef(handle)),
              getLowerBounds: get("getLowerBounds", "()[Ljava/lang/reflect/Type;"),
              getUpperBounds: get("getUpperBounds", "()[Ljava/lang/reflect/Type;")
            };
          } finally {
            this.deleteLocalRef(handle);
          }
        }
        return javaLangReflectWildcardType;
      };
      javaLangReflectGenericArrayType = null;
      Env.prototype.javaLangReflectGenericArrayType = function() {
        if (javaLangReflectGenericArrayType === null) {
          const handle = this.findClass("java/lang/reflect/GenericArrayType");
          try {
            javaLangReflectGenericArrayType = {
              handle: register(this.newGlobalRef(handle)),
              getGenericComponentType: this.getMethodId(handle, "getGenericComponentType", "()Ljava/lang/reflect/Type;")
            };
          } finally {
            this.deleteLocalRef(handle);
          }
        }
        return javaLangReflectGenericArrayType;
      };
      javaLangReflectParameterizedType = null;
      Env.prototype.javaLangReflectParameterizedType = function() {
        if (javaLangReflectParameterizedType === null) {
          const handle = this.findClass("java/lang/reflect/ParameterizedType");
          try {
            const get = this.getMethodId.bind(this, handle);
            javaLangReflectParameterizedType = {
              handle: register(this.newGlobalRef(handle)),
              getActualTypeArguments: get("getActualTypeArguments", "()[Ljava/lang/reflect/Type;"),
              getRawType: get("getRawType", "()Ljava/lang/reflect/Type;"),
              getOwnerType: get("getOwnerType", "()Ljava/lang/reflect/Type;")
            };
          } finally {
            this.deleteLocalRef(handle);
          }
        }
        return javaLangReflectParameterizedType;
      };
      javaLangString = null;
      Env.prototype.javaLangString = function() {
        if (javaLangString === null) {
          const handle = this.findClass("java/lang/String");
          try {
            javaLangString = {
              handle: register(this.newGlobalRef(handle))
            };
          } finally {
            this.deleteLocalRef(handle);
          }
        }
        return javaLangString;
      };
      Env.prototype.getClassName = function(classHandle) {
        const name = this.vaMethod("pointer", [])(this.handle, classHandle, this.javaLangClass().getName);
        try {
          return this.stringFromJni(name);
        } finally {
          this.deleteLocalRef(name);
        }
      };
      Env.prototype.getObjectClassName = function(objHandle) {
        const jklass = this.getObjectClass(objHandle);
        try {
          return this.getClassName(jklass);
        } finally {
          this.deleteLocalRef(jklass);
        }
      };
      Env.prototype.getActualTypeArgument = function(type) {
        const actualTypeArguments = this.vaMethod("pointer", [])(this.handle, type, this.javaLangReflectParameterizedType().getActualTypeArguments);
        this.throwIfExceptionPending();
        if (!actualTypeArguments.isNull()) {
          try {
            return this.getTypeNameFromFirstTypeElement(actualTypeArguments);
          } finally {
            this.deleteLocalRef(actualTypeArguments);
          }
        }
      };
      Env.prototype.getTypeNameFromFirstTypeElement = function(typeArray) {
        const length = this.getArrayLength(typeArray);
        if (length > 0) {
          const typeArgument0 = this.getObjectArrayElement(typeArray, 0);
          try {
            return this.getTypeName(typeArgument0);
          } finally {
            this.deleteLocalRef(typeArgument0);
          }
        } else {
          return "java.lang.Object";
        }
      };
      Env.prototype.getTypeName = function(type, getGenericsInformation) {
        const invokeObjectMethodNoArgs = this.vaMethod("pointer", []);
        if (this.isInstanceOf(type, this.javaLangClass().handle)) {
          return this.getClassName(type);
        } else if (this.isInstanceOf(type, this.javaLangReflectGenericArrayType().handle)) {
          return this.getArrayTypeName(type);
        } else if (this.isInstanceOf(type, this.javaLangReflectParameterizedType().handle)) {
          const rawType = invokeObjectMethodNoArgs(this.handle, type, this.javaLangReflectParameterizedType().getRawType);
          this.throwIfExceptionPending();
          let result;
          try {
            result = this.getTypeName(rawType);
          } finally {
            this.deleteLocalRef(rawType);
          }
          if (getGenericsInformation) {
            result += "<" + this.getActualTypeArgument(type) + ">";
          }
          return result;
        } else if (this.isInstanceOf(type, this.javaLangReflectTypeVariable().handle)) {
          return "java.lang.Object";
        } else if (this.isInstanceOf(type, this.javaLangReflectWildcardType().handle)) {
          return "java.lang.Object";
        } else {
          return "java.lang.Object";
        }
      };
      Env.prototype.getArrayTypeName = function(type) {
        const invokeObjectMethodNoArgs = this.vaMethod("pointer", []);
        if (this.isInstanceOf(type, this.javaLangClass().handle)) {
          return this.getClassName(type);
        } else if (this.isInstanceOf(type, this.javaLangReflectGenericArrayType().handle)) {
          const componentType = invokeObjectMethodNoArgs(this.handle, type, this.javaLangReflectGenericArrayType().getGenericComponentType);
          this.throwIfExceptionPending();
          try {
            return "[L" + this.getTypeName(componentType) + ";";
          } finally {
            this.deleteLocalRef(componentType);
          }
        } else {
          return "[Ljava.lang.Object;";
        }
      };
      Env.prototype.stringFromJni = function(str) {
        const utf = this.getStringChars(str);
        if (utf.isNull()) {
          throw new Error("Unable to access string");
        }
        try {
          const length = this.getStringLength(str);
          return utf.readUtf16String(length);
        } finally {
          this.releaseStringChars(str, utf);
        }
      };
    }
  });

  // node_modules/frida-java-bridge/lib/vm.js
  function VM(api2) {
    const handle = api2.vm;
    let attachCurrentThread = null;
    let detachCurrentThread = null;
    let getEnv = null;
    function initialize2() {
      const vtable2 = handle.readPointer();
      const options = {
        exceptions: "propagate"
      };
      attachCurrentThread = new NativeFunction(vtable2.add(4 * pointerSize4).readPointer(), "int32", ["pointer", "pointer", "pointer"], options);
      detachCurrentThread = new NativeFunction(vtable2.add(5 * pointerSize4).readPointer(), "int32", ["pointer"], options);
      getEnv = new NativeFunction(vtable2.add(6 * pointerSize4).readPointer(), "int32", ["pointer", "pointer", "int32"], options);
    }
    this.handle = handle;
    this.perform = function(fn) {
      const threadId = Process.getCurrentThreadId();
      const cachedEnv = tryGetCachedEnv(threadId);
      if (cachedEnv !== null) {
        return fn(cachedEnv);
      }
      let env = this._tryGetEnv();
      const alreadyAttached = env !== null;
      if (!alreadyAttached) {
        env = this.attachCurrentThread();
        attachedThreads.set(threadId, true);
      }
      this.link(threadId, env);
      try {
        return fn(env);
      } finally {
        const isJsThread = threadId === jsThreadID;
        if (!isJsThread) {
          this.unlink(threadId);
        }
        if (!alreadyAttached && !isJsThread) {
          const allowedToDetach = attachedThreads.get(threadId);
          attachedThreads.delete(threadId);
          if (allowedToDetach) {
            this.detachCurrentThread();
          }
        }
      }
    };
    this.attachCurrentThread = function() {
      const envBuf = Memory.alloc(pointerSize4);
      checkJniResult("VM::AttachCurrentThread", attachCurrentThread(handle, envBuf, NULL));
      return new Env(envBuf.readPointer(), this);
    };
    this.detachCurrentThread = function() {
      checkJniResult("VM::DetachCurrentThread", detachCurrentThread(handle));
    };
    this.preventDetachDueToClassLoader = function() {
      const threadId = Process.getCurrentThreadId();
      if (attachedThreads.has(threadId)) {
        attachedThreads.set(threadId, false);
      }
    };
    this.getEnv = function() {
      const cachedEnv = tryGetCachedEnv(Process.getCurrentThreadId());
      if (cachedEnv !== null) {
        return cachedEnv;
      }
      const envBuf = Memory.alloc(pointerSize4);
      const result = getEnv(handle, envBuf, JNI_VERSION_1_6);
      if (result === -2) {
        throw new Error("Current thread is not attached to the Java VM; please move this code inside a Java.perform() callback");
      }
      checkJniResult("VM::GetEnv", result);
      return new Env(envBuf.readPointer(), this);
    };
    this.tryGetEnv = function() {
      const cachedEnv = tryGetCachedEnv(Process.getCurrentThreadId());
      if (cachedEnv !== null) {
        return cachedEnv;
      }
      return this._tryGetEnv();
    };
    this._tryGetEnv = function() {
      const h = this.tryGetEnvHandle(JNI_VERSION_1_6);
      if (h === null) {
        return null;
      }
      return new Env(h, this);
    };
    this.tryGetEnvHandle = function(version) {
      const envBuf = Memory.alloc(pointerSize4);
      const result = getEnv(handle, envBuf, version);
      if (result !== JNI_OK) {
        return null;
      }
      return envBuf.readPointer();
    };
    this.makeHandleDestructor = function(handle2) {
      return () => {
        this.perform((env) => {
          env.deleteGlobalRef(handle2);
        });
      };
    };
    this.link = function(tid, env) {
      const entry = activeEnvs.get(tid);
      if (entry === void 0) {
        activeEnvs.set(tid, [env, 1]);
      } else {
        entry[1]++;
      }
    };
    this.unlink = function(tid) {
      const entry = activeEnvs.get(tid);
      if (entry[1] === 1) {
        activeEnvs.delete(tid);
      } else {
        entry[1]--;
      }
    };
    function tryGetCachedEnv(threadId) {
      const entry = activeEnvs.get(threadId);
      if (entry === void 0) {
        return null;
      }
      return entry[0];
    }
    initialize2.call(this);
  }
  var JNI_VERSION_1_6, pointerSize4, jsThreadID, attachedThreads, activeEnvs;
  var init_vm = __esm({
    "node_modules/frida-java-bridge/lib/vm.js"() {
      init_node_globals();
      init_env();
      init_result();
      JNI_VERSION_1_6 = 65542;
      pointerSize4 = Process.pointerSize;
      jsThreadID = Process.getCurrentThreadId();
      attachedThreads = /* @__PURE__ */ new Map();
      activeEnvs = /* @__PURE__ */ new Map();
      VM.dispose = function(vm3) {
        if (attachedThreads.get(jsThreadID) === true) {
          attachedThreads.delete(jsThreadID);
          vm3.detachCurrentThread();
        }
      };
    }
  });

  // node_modules/frida-java-bridge/lib/android.js
  var android_exports = {};
  __export(android_exports, {
    ArtMethod: () => ArtMethod,
    ArtStackVisitor: () => ArtStackVisitor,
    DVM_JNI_ENV_OFFSET_SELF: () => DVM_JNI_ENV_OFFSET_SELF,
    HandleVector: () => HandleVector,
    VariableSizedHandleScope: () => VariableSizedHandleScope,
    backtrace: () => backtrace,
    deoptimizeBootImage: () => deoptimizeBootImage,
    deoptimizeEverything: () => deoptimizeEverything,
    deoptimizeMethod: () => deoptimizeMethod,
    ensureClassInitialized: () => ensureClassInitialized,
    getAndroidApiLevel: () => getAndroidApiLevel,
    getAndroidVersion: () => getAndroidVersion,
    getApi: () => getApi,
    getArtApexVersion: () => getArtApexVersion,
    getArtClassSpec: () => getArtClassSpec,
    getArtFieldSpec: () => getArtFieldSpec,
    getArtMethodSpec: () => getArtMethodSpec,
    getArtThreadFromEnv: () => getArtThreadFromEnv,
    getArtThreadSpec: () => getArtThreadSpec,
    isMethodDeoptimized: () => isMethodDeoptimized,
    makeArtClassLoaderVisitor: () => makeArtClassLoaderVisitor,
    makeArtClassVisitor: () => makeArtClassVisitor,
    makeMethodMangler: () => makeMethodMangler,
    makeObjectVisitorPredicate: () => makeObjectVisitorPredicate,
    revertGlobalPatches: () => revertGlobalPatches,
    translateMethod: () => translateMethod,
    withAllArtThreadsSuspended: () => withAllArtThreadsSuspended,
    withRunnableArtThread: () => withRunnableArtThread
  });
  function getApi() {
    if (cachedApi === null) {
      cachedApi = _getApi();
    }
    return cachedApi;
  }
  function _getApi() {
    const vmModules = Process.enumerateModules().filter((m) => /^lib(art|dvm).so$/.test(m.name)).filter((m) => !/\/system\/fake-libs/.test(m.path));
    if (vmModules.length === 0) {
      return null;
    }
    const vmModule = vmModules[0];
    const flavor = vmModule.name.indexOf("art") !== -1 ? "art" : "dalvik";
    const isArt = flavor === "art";
    const temporaryApi = {
      module: vmModule,
      find(name) {
        const { module } = this;
        let address = module.findExportByName(name);
        if (address === null) {
          address = module.findSymbolByName(name);
        }
        return address;
      },
      flavor,
      addLocalReference: null
    };
    temporaryApi.isApiLevel34OrApexEquivalent = isArt && (temporaryApi.find("_ZN3art7AppInfo29GetPrimaryApkReferenceProfileEv") !== null || temporaryApi.find("_ZN3art6Thread15RunFlipFunctionEPS0_") !== null);
    const pending = isArt ? {
      functions: {
        JNI_GetCreatedJavaVMs: ["JNI_GetCreatedJavaVMs", "int", ["pointer", "int", "pointer"]],
        // Android < 7
        artInterpreterToCompiledCodeBridge: function(address) {
          this.artInterpreterToCompiledCodeBridge = address;
        },
        // Android >= 8
        _ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadENS_6ObjPtrINS_6mirror6ObjectEEE: ["art::JavaVMExt::AddGlobalRef", "pointer", ["pointer", "pointer", "pointer"]],
        // Android >= 6
        _ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadEPNS_6mirror6ObjectE: ["art::JavaVMExt::AddGlobalRef", "pointer", ["pointer", "pointer", "pointer"]],
        // Android < 6: makeAddGlobalRefFallbackForAndroid5() needs these:
        _ZN3art17ReaderWriterMutex13ExclusiveLockEPNS_6ThreadE: ["art::ReaderWriterMutex::ExclusiveLock", "void", ["pointer", "pointer"]],
        _ZN3art17ReaderWriterMutex15ExclusiveUnlockEPNS_6ThreadE: ["art::ReaderWriterMutex::ExclusiveUnlock", "void", ["pointer", "pointer"]],
        // Android <= 7
        _ZN3art22IndirectReferenceTable3AddEjPNS_6mirror6ObjectE: function(address) {
          this["art::IndirectReferenceTable::Add"] = new NativeFunction(address, "pointer", ["pointer", "uint", "pointer"], nativeFunctionOptions3);
        },
        // Android > 7
        _ZN3art22IndirectReferenceTable3AddENS_15IRTSegmentStateENS_6ObjPtrINS_6mirror6ObjectEEE: function(address) {
          this["art::IndirectReferenceTable::Add"] = new NativeFunction(address, "pointer", ["pointer", "uint", "pointer"], nativeFunctionOptions3);
        },
        // Android >= 7
        _ZN3art9JavaVMExt12DecodeGlobalEPv: function(address) {
          let decodeGlobal;
          if (getAndroidApiLevel() >= 26) {
            decodeGlobal = makeCxxMethodWrapperReturningPointerByValue(address, ["pointer", "pointer"]);
          } else {
            decodeGlobal = new NativeFunction(address, "pointer", ["pointer", "pointer"], nativeFunctionOptions3);
          }
          this["art::JavaVMExt::DecodeGlobal"] = function(vm3, thread, ref) {
            return decodeGlobal(vm3, ref);
          };
        },
        // Android >= 6
        _ZN3art9JavaVMExt12DecodeGlobalEPNS_6ThreadEPv: ["art::JavaVMExt::DecodeGlobal", "pointer", ["pointer", "pointer", "pointer"]],
        // makeDecodeGlobalFallback() uses:
        // Android >= 15
        _ZNK3art6Thread19DecodeGlobalJObjectEP8_jobject: ["art::Thread::DecodeJObject", "pointer", ["pointer", "pointer"]],
        // Android < 6
        _ZNK3art6Thread13DecodeJObjectEP8_jobject: ["art::Thread::DecodeJObject", "pointer", ["pointer", "pointer"]],
        // Android >= 6
        _ZN3art10ThreadList10SuspendAllEPKcb: ["art::ThreadList::SuspendAll", "void", ["pointer", "pointer", "bool"]],
        // or fallback:
        _ZN3art10ThreadList10SuspendAllEv: function(address) {
          const suspendAll = new NativeFunction(address, "void", ["pointer"], nativeFunctionOptions3);
          this["art::ThreadList::SuspendAll"] = function(threadList, cause, longSuspend) {
            return suspendAll(threadList);
          };
        },
        _ZN3art10ThreadList9ResumeAllEv: ["art::ThreadList::ResumeAll", "void", ["pointer"]],
        // Android >= 7
        _ZN3art11ClassLinker12VisitClassesEPNS_12ClassVisitorE: ["art::ClassLinker::VisitClasses", "void", ["pointer", "pointer"]],
        // Android < 7
        _ZN3art11ClassLinker12VisitClassesEPFbPNS_6mirror5ClassEPvES4_: function(address) {
          const visitClasses = new NativeFunction(address, "void", ["pointer", "pointer", "pointer"], nativeFunctionOptions3);
          this["art::ClassLinker::VisitClasses"] = function(classLinker, visitor) {
            visitClasses(classLinker, visitor, NULL);
          };
        },
        _ZNK3art11ClassLinker17VisitClassLoadersEPNS_18ClassLoaderVisitorE: ["art::ClassLinker::VisitClassLoaders", "void", ["pointer", "pointer"]],
        _ZN3art2gc4Heap12VisitObjectsEPFvPNS_6mirror6ObjectEPvES5_: ["art::gc::Heap::VisitObjects", "void", ["pointer", "pointer", "pointer"]],
        _ZN3art2gc4Heap12GetInstancesERNS_24VariableSizedHandleScopeENS_6HandleINS_6mirror5ClassEEEiRNSt3__16vectorINS4_INS5_6ObjectEEENS8_9allocatorISB_EEEE: ["art::gc::Heap::GetInstances", "void", ["pointer", "pointer", "pointer", "int", "pointer"]],
        // Android >= 9
        _ZN3art2gc4Heap12GetInstancesERNS_24VariableSizedHandleScopeENS_6HandleINS_6mirror5ClassEEEbiRNSt3__16vectorINS4_INS5_6ObjectEEENS8_9allocatorISB_EEEE: function(address) {
          const getInstances = new NativeFunction(address, "void", ["pointer", "pointer", "pointer", "bool", "int", "pointer"], nativeFunctionOptions3);
          this["art::gc::Heap::GetInstances"] = function(instance, scope, hClass, maxCount, instances) {
            const useIsAssignableFrom = 0;
            getInstances(instance, scope, hClass, useIsAssignableFrom, maxCount, instances);
          };
        },
        _ZN3art12StackVisitorC2EPNS_6ThreadEPNS_7ContextENS0_13StackWalkKindEjb: ["art::StackVisitor::StackVisitor", "void", ["pointer", "pointer", "pointer", "uint", "uint", "bool"]],
        _ZN3art12StackVisitorC2EPNS_6ThreadEPNS_7ContextENS0_13StackWalkKindEmb: ["art::StackVisitor::StackVisitor", "void", ["pointer", "pointer", "pointer", "uint", "size_t", "bool"]],
        _ZN3art12StackVisitor9WalkStackILNS0_16CountTransitionsE0EEEvb: ["art::StackVisitor::WalkStack", "void", ["pointer", "bool"]],
        _ZNK3art12StackVisitor9GetMethodEv: ["art::StackVisitor::GetMethod", "pointer", ["pointer"]],
        _ZNK3art12StackVisitor16DescribeLocationEv: function(address) {
          this["art::StackVisitor::DescribeLocation"] = makeCxxMethodWrapperReturningStdStringByValue(address, ["pointer"]);
        },
        _ZNK3art12StackVisitor24GetCurrentQuickFrameInfoEv: function(address) {
          this["art::StackVisitor::GetCurrentQuickFrameInfo"] = makeArtQuickFrameInfoGetter(address);
        },
        _ZN3art7Context6CreateEv: ["art::Context::Create", "pointer", []],
        _ZN3art6Thread18GetLongJumpContextEv: ["art::Thread::GetLongJumpContext", "pointer", ["pointer"]],
        _ZN3art6mirror5Class13GetDescriptorEPNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE: function(address) {
          this["art::mirror::Class::GetDescriptor"] = address;
        },
        _ZN3art6mirror5Class11GetLocationEv: function(address) {
          this["art::mirror::Class::GetLocation"] = makeCxxMethodWrapperReturningStdStringByValue(address, ["pointer"]);
        },
        _ZN3art9ArtMethod12PrettyMethodEb: function(address) {
          this["art::ArtMethod::PrettyMethod"] = makeCxxMethodWrapperReturningStdStringByValue(address, ["pointer", "bool"]);
        },
        _ZN3art12PrettyMethodEPNS_9ArtMethodEb: function(address) {
          this["art::ArtMethod::PrettyMethodNullSafe"] = makeCxxMethodWrapperReturningStdStringByValue(address, ["pointer", "bool"]);
        },
        // Android < 6 for cloneArtMethod()
        _ZN3art6Thread14CurrentFromGdbEv: ["art::Thread::CurrentFromGdb", "pointer", []],
        _ZN3art6mirror6Object5CloneEPNS_6ThreadE: function(address) {
          this["art::mirror::Object::Clone"] = new NativeFunction(address, "pointer", ["pointer", "pointer"], nativeFunctionOptions3);
        },
        _ZN3art6mirror6Object5CloneEPNS_6ThreadEm: function(address) {
          const clone = new NativeFunction(address, "pointer", ["pointer", "pointer", "pointer"], nativeFunctionOptions3);
          this["art::mirror::Object::Clone"] = function(thisPtr, threadPtr) {
            const numTargetBytes = NULL;
            return clone(thisPtr, threadPtr, numTargetBytes);
          };
        },
        _ZN3art6mirror6Object5CloneEPNS_6ThreadEj: function(address) {
          const clone = new NativeFunction(address, "pointer", ["pointer", "pointer", "uint"], nativeFunctionOptions3);
          this["art::mirror::Object::Clone"] = function(thisPtr, threadPtr) {
            const numTargetBytes = 0;
            return clone(thisPtr, threadPtr, numTargetBytes);
          };
        },
        _ZN3art7Runtime22CreateCalleeSaveMethodEv: ["art::Runtime::CreateCalleeSaveMethod", "pointer", ["pointer"]],
        _ZN3art3Dbg14SetJdwpAllowedEb: ["art::Dbg::SetJdwpAllowed", "void", ["bool"]],
        _ZN3art3Dbg13ConfigureJdwpERKNS_4JDWP11JdwpOptionsE: ["art::Dbg::ConfigureJdwp", "void", ["pointer"]],
        _ZN3art31InternalDebuggerControlCallback13StartDebuggerEv: ["art::InternalDebuggerControlCallback::StartDebugger", "void", ["pointer"]],
        _ZN3art3Dbg9StartJdwpEv: ["art::Dbg::StartJdwp", "void", []],
        _ZN3art3Dbg8GoActiveEv: ["art::Dbg::GoActive", "void", []],
        _ZN3art3Dbg21RequestDeoptimizationERKNS_21DeoptimizationRequestE: ["art::Dbg::RequestDeoptimization", "void", ["pointer"]],
        _ZN3art3Dbg20ManageDeoptimizationEv: ["art::Dbg::ManageDeoptimization", "void", []],
        _ZN3art15instrumentation15Instrumentation20EnableDeoptimizationEv: ["art::Instrumentation::EnableDeoptimization", "void", ["pointer"]],
        // Android >= 6
        _ZN3art15instrumentation15Instrumentation20DeoptimizeEverythingEPKc: ["art::Instrumentation::DeoptimizeEverything", "void", ["pointer", "pointer"]],
        // Android < 6
        _ZN3art15instrumentation15Instrumentation20DeoptimizeEverythingEv: function(address) {
          const deoptimize = new NativeFunction(address, "void", ["pointer"], nativeFunctionOptions3);
          this["art::Instrumentation::DeoptimizeEverything"] = function(instrumentation, key) {
            deoptimize(instrumentation);
          };
        },
        _ZN3art7Runtime19DeoptimizeBootImageEv: ["art::Runtime::DeoptimizeBootImage", "void", ["pointer"]],
        _ZN3art15instrumentation15Instrumentation10DeoptimizeEPNS_9ArtMethodE: ["art::Instrumentation::Deoptimize", "void", ["pointer", "pointer"]],
        _ZN3art15instrumentation15Instrumentation13IsDeoptimizedEPNS_9ArtMethodE: ["art::Instrumentation::IsDeoptimized", "bool", ["pointer", "pointer"]],
        // Android >= 11
        _ZN3art3jni12JniIdManager14DecodeMethodIdEP10_jmethodID: ["art::jni::JniIdManager::DecodeMethodId", "pointer", ["pointer", "pointer"]],
        _ZN3art3jni12JniIdManager13DecodeFieldIdEP9_jfieldID: ["art::jni::JniIdManager::DecodeFieldId", "pointer", ["pointer", "pointer"]],
        _ZN3art11interpreter18GetNterpEntryPointEv: ["art::interpreter::GetNterpEntryPoint", "pointer", []],
        _ZN3art7Monitor17TranslateLocationEPNS_9ArtMethodEjPPKcPi: ["art::Monitor::TranslateLocation", "void", ["pointer", "uint32", "pointer", "pointer"]]
      },
      variables: {
        _ZN3art3Dbg9gRegistryE: function(address) {
          this.isJdwpStarted = () => !address.readPointer().isNull();
        },
        _ZN3art3Dbg15gDebuggerActiveE: function(address) {
          this.isDebuggerActive = () => !!address.readU8();
        },
        _ZN3art15gUseUserfaultfdE: function(address) {
          this.isUserfaultfdGcActive = !!address.readU8();
        }
      },
      optionals: /* @__PURE__ */ new Set([
        "artInterpreterToCompiledCodeBridge",
        "_ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadENS_6ObjPtrINS_6mirror6ObjectEEE",
        "_ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadEPNS_6mirror6ObjectE",
        "_ZN3art9JavaVMExt12DecodeGlobalEPv",
        "_ZN3art9JavaVMExt12DecodeGlobalEPNS_6ThreadEPv",
        "_ZNK3art6Thread19DecodeGlobalJObjectEP8_jobject",
        "_ZNK3art6Thread13DecodeJObjectEP8_jobject",
        "_ZN3art10ThreadList10SuspendAllEPKcb",
        "_ZN3art10ThreadList10SuspendAllEv",
        "_ZN3art11ClassLinker12VisitClassesEPNS_12ClassVisitorE",
        "_ZN3art11ClassLinker12VisitClassesEPFbPNS_6mirror5ClassEPvES4_",
        "_ZNK3art11ClassLinker17VisitClassLoadersEPNS_18ClassLoaderVisitorE",
        "_ZN3art6mirror6Object5CloneEPNS_6ThreadE",
        "_ZN3art6mirror6Object5CloneEPNS_6ThreadEm",
        "_ZN3art6mirror6Object5CloneEPNS_6ThreadEj",
        "_ZN3art7Runtime22CreateCalleeSaveMethodEv",
        "_ZN3art22IndirectReferenceTable3AddEjPNS_6mirror6ObjectE",
        "_ZN3art22IndirectReferenceTable3AddENS_15IRTSegmentStateENS_6ObjPtrINS_6mirror6ObjectEEE",
        "_ZN3art2gc4Heap12VisitObjectsEPFvPNS_6mirror6ObjectEPvES5_",
        "_ZN3art2gc4Heap12GetInstancesERNS_24VariableSizedHandleScopeENS_6HandleINS_6mirror5ClassEEEiRNSt3__16vectorINS4_INS5_6ObjectEEENS8_9allocatorISB_EEEE",
        "_ZN3art2gc4Heap12GetInstancesERNS_24VariableSizedHandleScopeENS_6HandleINS_6mirror5ClassEEEbiRNSt3__16vectorINS4_INS5_6ObjectEEENS8_9allocatorISB_EEEE",
        "_ZN3art12StackVisitorC2EPNS_6ThreadEPNS_7ContextENS0_13StackWalkKindEjb",
        "_ZN3art12StackVisitorC2EPNS_6ThreadEPNS_7ContextENS0_13StackWalkKindEmb",
        "_ZN3art12StackVisitor9WalkStackILNS0_16CountTransitionsE0EEEvb",
        "_ZNK3art12StackVisitor9GetMethodEv",
        "_ZNK3art12StackVisitor16DescribeLocationEv",
        "_ZNK3art12StackVisitor24GetCurrentQuickFrameInfoEv",
        "_ZN3art7Context6CreateEv",
        "_ZN3art6Thread18GetLongJumpContextEv",
        "_ZN3art6mirror5Class13GetDescriptorEPNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE",
        "_ZN3art6mirror5Class11GetLocationEv",
        "_ZN3art9ArtMethod12PrettyMethodEb",
        "_ZN3art12PrettyMethodEPNS_9ArtMethodEb",
        "_ZN3art3Dbg13ConfigureJdwpERKNS_4JDWP11JdwpOptionsE",
        "_ZN3art31InternalDebuggerControlCallback13StartDebuggerEv",
        "_ZN3art3Dbg15gDebuggerActiveE",
        "_ZN3art15gUseUserfaultfdE",
        "_ZN3art15instrumentation15Instrumentation20EnableDeoptimizationEv",
        "_ZN3art15instrumentation15Instrumentation20DeoptimizeEverythingEPKc",
        "_ZN3art15instrumentation15Instrumentation20DeoptimizeEverythingEv",
        "_ZN3art7Runtime19DeoptimizeBootImageEv",
        "_ZN3art15instrumentation15Instrumentation10DeoptimizeEPNS_9ArtMethodE",
        "_ZN3art15instrumentation15Instrumentation13IsDeoptimizedEPNS_9ArtMethodE",
        "_ZN3art3Dbg9StartJdwpEv",
        "_ZN3art3Dbg8GoActiveEv",
        "_ZN3art3Dbg21RequestDeoptimizationERKNS_21DeoptimizationRequestE",
        "_ZN3art3Dbg20ManageDeoptimizationEv",
        "_ZN3art3Dbg9gRegistryE",
        "_ZN3art3jni12JniIdManager14DecodeMethodIdEP10_jmethodID",
        "_ZN3art3jni12JniIdManager13DecodeFieldIdEP9_jfieldID",
        "_ZN3art11interpreter18GetNterpEntryPointEv",
        "_ZN3art7Monitor17TranslateLocationEPNS_9ArtMethodEjPPKcPi"
      ])
    } : {
      functions: {
        _Z20dvmDecodeIndirectRefP6ThreadP8_jobject: ["dvmDecodeIndirectRef", "pointer", ["pointer", "pointer"]],
        _Z15dvmUseJNIBridgeP6MethodPv: ["dvmUseJNIBridge", "void", ["pointer", "pointer"]],
        _Z20dvmHeapSourceGetBasev: ["dvmHeapSourceGetBase", "pointer", []],
        _Z21dvmHeapSourceGetLimitv: ["dvmHeapSourceGetLimit", "pointer", []],
        _Z16dvmIsValidObjectPK6Object: ["dvmIsValidObject", "uint8", ["pointer"]],
        JNI_GetCreatedJavaVMs: ["JNI_GetCreatedJavaVMs", "int", ["pointer", "int", "pointer"]]
      },
      variables: {
        gDvmJni: function(address) {
          this.gDvmJni = address;
        },
        gDvm: function(address) {
          this.gDvm = address;
        }
      }
    };
    const {
      functions = {},
      variables = {},
      optionals = /* @__PURE__ */ new Set()
    } = pending;
    const missing = [];
    for (const [name, signature] of Object.entries(functions)) {
      const address = temporaryApi.find(name);
      if (address !== null) {
        if (typeof signature === "function") {
          signature.call(temporaryApi, address);
        } else {
          temporaryApi[signature[0]] = new NativeFunction(address, signature[1], signature[2], nativeFunctionOptions3);
        }
      } else {
        if (!optionals.has(name)) {
          missing.push(name);
        }
      }
    }
    for (const [name, handler] of Object.entries(variables)) {
      const address = temporaryApi.find(name);
      if (address !== null) {
        handler.call(temporaryApi, address);
      } else {
        if (!optionals.has(name)) {
          missing.push(name);
        }
      }
    }
    if (missing.length > 0) {
      throw new Error("Java API only partially available; please file a bug. Missing: " + missing.join(", "));
    }
    const vms = Memory.alloc(pointerSize5);
    const vmCount = Memory.alloc(jsizeSize);
    checkJniResult("JNI_GetCreatedJavaVMs", temporaryApi.JNI_GetCreatedJavaVMs(vms, 1, vmCount));
    if (vmCount.readInt() === 0) {
      return null;
    }
    temporaryApi.vm = vms.readPointer();
    if (isArt) {
      const apiLevel = getAndroidApiLevel();
      let kAccCompileDontBother;
      if (apiLevel >= 27) {
        kAccCompileDontBother = 33554432;
      } else if (apiLevel >= 24) {
        kAccCompileDontBother = 16777216;
      } else {
        kAccCompileDontBother = 0;
      }
      temporaryApi.kAccCompileDontBother = kAccCompileDontBother;
      const artRuntime = temporaryApi.vm.add(pointerSize5).readPointer();
      temporaryApi.artRuntime = artRuntime;
      const runtimeSpec = getArtRuntimeSpec(temporaryApi);
      const runtimeOffset = runtimeSpec.offset;
      const instrumentationOffset = runtimeOffset.instrumentation;
      temporaryApi.artInstrumentation = instrumentationOffset !== null ? artRuntime.add(instrumentationOffset) : null;
      const instrumentationIsPointer = getArtApexVersion() >= 36e7;
      if (instrumentationIsPointer && temporaryApi.artInstrumentation != null) {
        temporaryApi.artInstrumentation = temporaryApi.artInstrumentation.readPointer();
      }
      temporaryApi.artHeap = artRuntime.add(runtimeOffset.heap).readPointer();
      temporaryApi.artThreadList = artRuntime.add(runtimeOffset.threadList).readPointer();
      const classLinker = artRuntime.add(runtimeOffset.classLinker).readPointer();
      const classLinkerOffsets = getArtClassLinkerSpec(artRuntime, runtimeSpec).offset;
      const quickResolutionTrampoline = classLinker.add(classLinkerOffsets.quickResolutionTrampoline).readPointer();
      const quickImtConflictTrampoline = classLinker.add(classLinkerOffsets.quickImtConflictTrampoline).readPointer();
      const quickGenericJniTrampoline = classLinker.add(classLinkerOffsets.quickGenericJniTrampoline).readPointer();
      const quickToInterpreterBridgeTrampoline = classLinker.add(classLinkerOffsets.quickToInterpreterBridgeTrampoline).readPointer();
      temporaryApi.artClassLinker = {
        address: classLinker,
        quickResolutionTrampoline,
        quickImtConflictTrampoline,
        quickGenericJniTrampoline,
        quickToInterpreterBridgeTrampoline
      };
      const vm3 = new VM(temporaryApi);
      temporaryApi.artQuickGenericJniTrampoline = getArtQuickEntrypointFromTrampoline(quickGenericJniTrampoline, vm3);
      temporaryApi.artQuickToInterpreterBridge = getArtQuickEntrypointFromTrampoline(quickToInterpreterBridgeTrampoline, vm3);
      temporaryApi.artQuickResolutionTrampoline = getArtQuickEntrypointFromTrampoline(quickResolutionTrampoline, vm3);
      if (temporaryApi["art::JavaVMExt::AddGlobalRef"] === void 0) {
        temporaryApi["art::JavaVMExt::AddGlobalRef"] = makeAddGlobalRefFallbackForAndroid5(temporaryApi);
      }
      if (temporaryApi["art::JavaVMExt::DecodeGlobal"] === void 0) {
        temporaryApi["art::JavaVMExt::DecodeGlobal"] = makeDecodeGlobalFallback(temporaryApi);
      }
      if (temporaryApi["art::ArtMethod::PrettyMethod"] === void 0) {
        temporaryApi["art::ArtMethod::PrettyMethod"] = temporaryApi["art::ArtMethod::PrettyMethodNullSafe"];
      }
      if (temporaryApi["art::interpreter::GetNterpEntryPoint"] !== void 0) {
        temporaryApi.artNterpEntryPoint = temporaryApi["art::interpreter::GetNterpEntryPoint"]();
      } else {
        temporaryApi.artNterpEntryPoint = temporaryApi.find("ExecuteNterpImpl");
      }
      artController = makeArtController(temporaryApi, vm3);
      fixupArtQuickDeliverExceptionBug(temporaryApi);
      let cachedJvmti = null;
      Object.defineProperty(temporaryApi, "jvmti", {
        get() {
          if (cachedJvmti === null) {
            cachedJvmti = [tryGetEnvJvmti(vm3, this.artRuntime)];
          }
          return cachedJvmti[0];
        }
      });
    }
    const cxxImports = vmModule.enumerateImports().filter((imp) => imp.name.indexOf("_Z") === 0).reduce((result, imp) => {
      result[imp.name] = imp.address;
      return result;
    }, {});
    temporaryApi.$new = new NativeFunction(cxxImports._Znwm || cxxImports._Znwj, "pointer", ["ulong"], nativeFunctionOptions3);
    temporaryApi.$delete = new NativeFunction(cxxImports._ZdlPv, "void", ["pointer"], nativeFunctionOptions3);
    MethodMangler = isArt ? ArtMethodMangler : DalvikMethodMangler;
    return temporaryApi;
  }
  function tryGetEnvJvmti(vm3, runtime2) {
    let env = null;
    vm3.perform(() => {
      const ensurePluginLoadedAddr = getApi().find("_ZN3art7Runtime18EnsurePluginLoadedEPKcPNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEE");
      if (ensurePluginLoadedAddr === null) {
        return;
      }
      const ensurePluginLoaded = new NativeFunction(
        ensurePluginLoadedAddr,
        "bool",
        ["pointer", "pointer", "pointer"]
      );
      const errorPtr = Memory.alloc(pointerSize5);
      const success = withoutDebuggableTransition(() => ensurePluginLoaded(runtime2, Memory.allocUtf8String("libopenjdkjvmti.so"), errorPtr));
      if (!success) {
        return;
      }
      const kArtTiVersion = jvmtiVersion.v1_2 | 1073741824;
      const handle = vm3.tryGetEnvHandle(kArtTiVersion);
      if (handle === null) {
        return;
      }
      env = new EnvJvmti(handle, vm3);
      const capaBuf = Memory.alloc(8);
      capaBuf.writeU64(jvmtiCapabilities.canTagObjects);
      const result = env.addCapabilities(capaBuf);
      if (result !== JNI_OK) {
        env = null;
      }
    });
    return env;
  }
  function withoutDebuggableTransition(loadPlugin) {
    let finishSetup = null;
    const skipFinishSetup = new NativeCallback(() => {
    }, "void", ["pointer"]);
    const dlsymListener = Interceptor.attach(Process.getModuleByName("libdl.so").getExportByName("dlsym"), {
      onEnter(args) {
        this.isPluginInitializer = args[1].readCString() === "ArtPlugin_Initialize";
      },
      onLeave() {
        if (!this.isPluginInitializer) {
          return;
        }
        finishSetup = Process.getModuleByName("libopenjdkjvmti.so").findExportByName("_ZN12openjdkjvmti12DeoptManager11FinishSetupEv");
        if (finishSetup !== null) {
          Interceptor.replace(finishSetup, skipFinishSetup);
        }
      }
    });
    try {
      return loadPlugin();
    } finally {
      dlsymListener.detach();
      if (finishSetup !== null) {
        Interceptor.revert(finishSetup);
      }
      Interceptor.flush();
    }
  }
  function ensureClassInitialized(env, classRef) {
    const api2 = getApi();
    if (api2.flavor !== "art") {
      return;
    }
    env.getFieldId(classRef, "x", "Z");
    env.exceptionClear();
  }
  function getArtVMSpec(api2) {
    return {
      offset: pointerSize5 === 4 ? {
        globalsLock: 32,
        globals: 72
      } : {
        globalsLock: 64,
        globals: 112
      }
    };
  }
  function _getArtRuntimeSpec(api2) {
    const vm3 = api2.vm;
    const runtime2 = api2.artRuntime;
    const startOffset = pointerSize5 === 4 ? 200 : 384;
    const endOffset = startOffset + 100 * pointerSize5;
    const apiLevel = getAndroidApiLevel();
    const codename = getAndroidCodename();
    const { isApiLevel34OrApexEquivalent } = api2;
    let spec = null;
    for (let offset = startOffset; offset !== endOffset; offset += pointerSize5) {
      const value = runtime2.add(offset).readPointer();
      if (value.equals(vm3)) {
        let classLinkerOffsets;
        let jniIdManagerOffset = null;
        if (apiLevel >= 33 || codename === "Tiramisu" || isApiLevel34OrApexEquivalent) {
          classLinkerOffsets = [offset - 4 * pointerSize5];
          jniIdManagerOffset = offset - pointerSize5;
        } else if (apiLevel >= 30 || codename === "R") {
          classLinkerOffsets = [offset - 3 * pointerSize5, offset - 4 * pointerSize5];
          jniIdManagerOffset = offset - pointerSize5;
        } else if (apiLevel >= 29) {
          classLinkerOffsets = [offset - 2 * pointerSize5];
        } else if (apiLevel >= 27) {
          classLinkerOffsets = [offset - STD_STRING_SIZE - 3 * pointerSize5];
        } else {
          classLinkerOffsets = [offset - STD_STRING_SIZE - 2 * pointerSize5];
        }
        for (const classLinkerOffset of classLinkerOffsets) {
          const internTableOffset = classLinkerOffset - pointerSize5;
          const threadListOffset = internTableOffset - pointerSize5;
          let heapOffset;
          if (isApiLevel34OrApexEquivalent) {
            heapOffset = threadListOffset - 9 * pointerSize5;
          } else if (apiLevel >= 24) {
            heapOffset = threadListOffset - 8 * pointerSize5;
          } else if (apiLevel >= 23) {
            heapOffset = threadListOffset - 7 * pointerSize5;
          } else {
            heapOffset = threadListOffset - 4 * pointerSize5;
          }
          const candidate = {
            offset: {
              heap: heapOffset,
              threadList: threadListOffset,
              internTable: internTableOffset,
              classLinker: classLinkerOffset,
              jniIdManager: jniIdManagerOffset
            }
          };
          if (tryGetArtClassLinkerSpec(runtime2, candidate) !== null) {
            spec = candidate;
            break;
          }
        }
        break;
      }
    }
    if (spec === null) {
      throw new Error("Unable to determine Runtime field offsets");
    }
    const instrumentationIsPointer = getArtApexVersion() >= 36e7;
    spec.offset.instrumentation = instrumentationIsPointer ? tryDetectInstrumentationPointer(api2) : tryDetectInstrumentationOffset(api2);
    spec.offset.jniIdsIndirection = tryDetectJniIdsIndirectionOffset(api2);
    return spec;
  }
  function tryDetectInstrumentationOffset(api2) {
    const impl = api2["art::Runtime::DeoptimizeBootImage"];
    if (impl === void 0) {
      return null;
    }
    return parseInstructionsAt(impl, instrumentationOffsetParsers[Process.arch], { limit: 30 });
  }
  function parsex86InstrumentationOffset(insn) {
    if (insn.mnemonic !== "lea") {
      return null;
    }
    const offset = insn.operands[1].value.disp;
    if (offset < 256 || offset > 1024) {
      return null;
    }
    return offset;
  }
  function parseArmInstrumentationOffset(insn) {
    if (insn.mnemonic !== "add.w") {
      return null;
    }
    const ops = insn.operands;
    if (ops.length !== 3) {
      return null;
    }
    const op2 = ops[2];
    if (op2.type !== "imm") {
      return null;
    }
    return op2.value;
  }
  function parseArm64InstrumentationOffset(insn) {
    if (insn.mnemonic !== "add") {
      return null;
    }
    const ops = insn.operands;
    if (ops.length !== 3) {
      return null;
    }
    if (ops[0].value === "sp" || ops[1].value === "sp") {
      return null;
    }
    const op2 = ops[2];
    if (op2.type !== "imm") {
      return null;
    }
    const offset = op2.value.valueOf();
    if (offset < 256 || offset > 1024) {
      return null;
    }
    return offset;
  }
  function tryDetectInstrumentationPointer(api2) {
    const impl = api2["art::Runtime::DeoptimizeBootImage"];
    if (impl === void 0) {
      return null;
    }
    return parseInstructionsAt(impl, instrumentationPointerParser[Process.arch], { limit: 30 });
  }
  function parsex86InstrumentationPointer(insn) {
    if (insn.mnemonic !== "mov") {
      return null;
    }
    const ops = insn.operands;
    const dst = ops[0];
    if (dst.value !== "rax") {
      return null;
    }
    const src = ops[1];
    if (src.type !== "mem") {
      return null;
    }
    const mem = src.value;
    if (mem.base !== "rdi") {
      return null;
    }
    const offset = mem.disp;
    if (offset < 256 || offset > 1024) {
      return null;
    }
    return offset;
  }
  function parseArmInstrumentationPointer(insn) {
    return null;
  }
  function parseArm64InstrumentationPointer(insn) {
    if (insn.mnemonic !== "ldr") {
      return null;
    }
    const ops = insn.operands;
    if (ops[0].value === "x0") {
      return null;
    }
    const mem = ops[1].value;
    if (mem.base !== "x0") {
      return null;
    }
    const offset = mem.disp;
    if (offset < 256 || offset > 1024) {
      return null;
    }
    return offset;
  }
  function tryDetectJniIdsIndirectionOffset(api2) {
    const impl = api2.find("_ZN3art7Runtime12SetJniIdTypeENS_9JniIdTypeE");
    if (impl === null) {
      return null;
    }
    const offset = parseInstructionsAt(impl, jniIdsIndirectionOffsetParsers[Process.arch], { limit: 20 });
    if (offset === null) {
      throw new Error("Unable to determine Runtime.jni_ids_indirection_ offset");
    }
    return offset;
  }
  function parsex86JniIdsIndirectionOffset(insn) {
    if (insn.mnemonic === "cmp") {
      return insn.operands[0].value.disp;
    }
    return null;
  }
  function parseArmJniIdsIndirectionOffset(insn) {
    if (insn.mnemonic === "ldr.w") {
      return insn.operands[1].value.disp;
    }
    return null;
  }
  function parseArm64JniIdsIndirectionOffset(insn, prevInsn) {
    if (prevInsn === null) {
      return null;
    }
    const { mnemonic } = insn;
    const { mnemonic: prevMnemonic } = prevInsn;
    if (mnemonic === "cmp" && prevMnemonic === "ldr" || mnemonic === "bl" && prevMnemonic === "str") {
      return prevInsn.operands[1].value.disp;
    }
    return null;
  }
  function _getArtInstrumentationSpec() {
    const deoptimizationEnabledOffsets = {
      "4-21": 136,
      "4-22": 136,
      "4-23": 172,
      "4-24": 196,
      "4-25": 196,
      "4-26": 196,
      "4-27": 196,
      "4-28": 212,
      "4-29": 172,
      "4-30": 180,
      "4-31": 180,
      "8-21": 224,
      "8-22": 224,
      "8-23": 296,
      "8-24": 344,
      "8-25": 344,
      "8-26": 352,
      "8-27": 352,
      "8-28": 392,
      "8-29": 328,
      "8-30": 336,
      "8-31": 336
    };
    const deoptEnabledOffset = deoptimizationEnabledOffsets[`${pointerSize5}-${getAndroidApiLevel()}`];
    if (deoptEnabledOffset === void 0) {
      throw new Error("Unable to determine Instrumentation field offsets");
    }
    return {
      offset: {
        forcedInterpretOnly: 4,
        deoptimizationEnabled: deoptEnabledOffset
      }
    };
  }
  function getArtClassLinkerSpec(runtime2, runtimeSpec) {
    const spec = tryGetArtClassLinkerSpec(runtime2, runtimeSpec);
    if (spec === null) {
      throw new Error("Unable to determine ClassLinker field offsets");
    }
    return spec;
  }
  function tryGetArtClassLinkerSpec(runtime2, runtimeSpec) {
    if (cachedArtClassLinkerSpec !== null) {
      return cachedArtClassLinkerSpec;
    }
    const { classLinker: classLinkerOffset, internTable: internTableOffset } = runtimeSpec.offset;
    const classLinker = runtime2.add(classLinkerOffset).readPointer();
    const internTable = runtime2.add(internTableOffset).readPointer();
    const startOffset = pointerSize5 === 4 ? 100 : 200;
    const endOffset = startOffset + 100 * pointerSize5;
    const apiLevel = getAndroidApiLevel();
    let spec = null;
    for (let offset = startOffset; offset !== endOffset; offset += pointerSize5) {
      const value = classLinker.add(offset).readPointer();
      if (value.equals(internTable)) {
        let delta;
        if (apiLevel >= 30 || getAndroidCodename() === "R") {
          delta = 6;
        } else if (apiLevel >= 29) {
          delta = 4;
        } else if (apiLevel >= 23) {
          delta = 3;
        } else {
          delta = 5;
        }
        const quickGenericJniTrampolineOffset = offset + delta * pointerSize5;
        let quickResolutionTrampolineOffset;
        if (apiLevel >= 23) {
          quickResolutionTrampolineOffset = quickGenericJniTrampolineOffset - 2 * pointerSize5;
        } else {
          quickResolutionTrampolineOffset = quickGenericJniTrampolineOffset - 3 * pointerSize5;
        }
        spec = {
          offset: {
            quickResolutionTrampoline: quickResolutionTrampolineOffset,
            quickImtConflictTrampoline: quickGenericJniTrampolineOffset - pointerSize5,
            quickGenericJniTrampoline: quickGenericJniTrampolineOffset,
            quickToInterpreterBridgeTrampoline: quickGenericJniTrampolineOffset + pointerSize5
          }
        };
        break;
      }
    }
    if (spec !== null) {
      cachedArtClassLinkerSpec = spec;
    }
    return spec;
  }
  function getArtClassSpec(vm3) {
    const MAX_OFFSET = 256;
    let spec = null;
    vm3.perform((env) => {
      const fieldSpec = getArtFieldSpec(vm3);
      const methodSpec = getArtMethodSpec(vm3);
      const fInfo = {
        artArrayLengthSize: 4,
        artArrayEntrySize: fieldSpec.size,
        // java/lang/Thread has 36 fields on Android 16.
        artArrayMax: 50
      };
      const mInfo = {
        artArrayLengthSize: pointerSize5,
        artArrayEntrySize: methodSpec.size,
        // java/lang/Thread has 79 methods on Android 16.
        artArrayMax: 100
      };
      const readArtArray = (objectBase, fieldOffset, lengthSize) => {
        const header = objectBase.add(fieldOffset).readPointer();
        if (header.isNull()) {
          return null;
        }
        const length = lengthSize === 4 ? header.readU32() : header.readU64().valueOf();
        if (length <= 0) {
          return null;
        }
        return {
          length,
          data: header.add(lengthSize)
        };
      };
      const hasEntry = (objectBase, offset, needle, info) => {
        try {
          const artArray = readArtArray(objectBase, offset, info.artArrayLengthSize);
          if (artArray === null) {
            return false;
          }
          const artArrayEnd = Math.min(artArray.length, info.artArrayMax);
          for (let i = 0; i !== artArrayEnd; i++) {
            const fieldPtr = artArray.data.add(i * info.artArrayEntrySize);
            if (fieldPtr.equals(needle)) {
              return true;
            }
          }
        } catch {
        }
        return false;
      };
      const clazz = env.findClass("java/lang/Thread");
      const clazzRef = env.newGlobalRef(clazz);
      try {
        let object;
        withRunnableArtThread(vm3, env, (thread) => {
          object = getApi()["art::JavaVMExt::DecodeGlobal"](vm3, thread, clazzRef);
        });
        const fieldInstance = unwrapFieldId(env.getFieldId(clazzRef, "name", "Ljava/lang/String;"));
        const fieldStatic = unwrapFieldId(env.getStaticFieldId(clazzRef, "MAX_PRIORITY", "I"));
        let offsetStatic = -1;
        let offsetInstance = -1;
        for (let offset = 0; offset !== MAX_OFFSET; offset += 4) {
          if (offsetStatic === -1 && hasEntry(object, offset, fieldStatic, fInfo)) {
            offsetStatic = offset;
          }
          if (offsetInstance === -1 && hasEntry(object, offset, fieldInstance, fInfo)) {
            offsetInstance = offset;
          }
        }
        if (offsetInstance === -1 || offsetStatic === -1) {
          throw new Error("Unable to find fields in java/lang/Thread; please file a bug");
        }
        const sfieldOffset = offsetInstance !== offsetStatic ? offsetStatic : 0;
        const ifieldOffset = offsetInstance;
        let offsetMethods = -1;
        const methodInstance = unwrapMethodId(env.getMethodId(clazzRef, "getName", "()Ljava/lang/String;"));
        for (let offset = 0; offset !== MAX_OFFSET; offset += 4) {
          if (offsetMethods === -1 && hasEntry(object, offset, methodInstance, mInfo)) {
            offsetMethods = offset;
          }
        }
        if (offsetMethods === -1) {
          throw new Error("Unable to find methods in java/lang/Thread; please file a bug");
        }
        let offsetCopiedMethods = -1;
        const methodsArray = readArtArray(object, offsetMethods, mInfo.artArrayLengthSize);
        const methodsArraySize = methodsArray.length;
        for (let offset = offsetMethods; offset !== MAX_OFFSET; offset += 4) {
          if (object.add(offset).readU16() === methodsArraySize) {
            offsetCopiedMethods = offset;
            break;
          }
        }
        if (offsetCopiedMethods === -1) {
          throw new Error("Unable to find copied methods in java/lang/Thread; please file a bug");
        }
        spec = {
          offset: {
            ifields: ifieldOffset,
            methods: offsetMethods,
            sfields: sfieldOffset,
            copiedMethodsOffset: offsetCopiedMethods
          }
        };
      } finally {
        env.deleteLocalRef(clazz);
        env.deleteGlobalRef(clazzRef);
      }
    });
    return spec;
  }
  function _getArtMethodSpec(vm3) {
    const api2 = getApi();
    let spec;
    vm3.perform((env) => {
      const process = env.findClass("android/os/Process");
      const getElapsedCpuTime = unwrapMethodId(env.getStaticMethodId(process, "getElapsedCpuTime", "()J"));
      env.deleteLocalRef(process);
      const runtimeModule = Process.getModuleByName("libandroid_runtime.so");
      const runtimeStart = runtimeModule.base;
      const runtimeEnd = runtimeStart.add(runtimeModule.size);
      const apiLevel = getAndroidApiLevel();
      const entrypointFieldSize = apiLevel <= 21 ? 8 : pointerSize5;
      const expectedAccessFlags = kAccPublic | kAccStatic | kAccFinal | kAccNative;
      const relevantAccessFlagsMask = ~(kAccFastInterpreterToInterpreterInvoke | kAccPublicApi | kAccNterpInvokeFastPathFlag | kAccNterpEntryPointFastPathFlag) >>> 0;
      let jniCodeOffset = null;
      let accessFlagsOffset = null;
      let remaining = 2;
      for (let offset = 0; offset !== 64 && remaining !== 0; offset += 4) {
        const field = getElapsedCpuTime.add(offset);
        if (jniCodeOffset === null) {
          const address = field.readPointer();
          if (address.compare(runtimeStart) >= 0 && address.compare(runtimeEnd) < 0) {
            jniCodeOffset = offset;
            remaining--;
          }
        }
        if (accessFlagsOffset === null) {
          const flags = field.readU32();
          if ((flags & relevantAccessFlagsMask) === expectedAccessFlags) {
            accessFlagsOffset = offset;
            remaining--;
          }
        }
      }
      if (remaining !== 0) {
        throw new Error("Unable to determine ArtMethod field offsets");
      }
      const quickCodeOffset = jniCodeOffset + entrypointFieldSize;
      const size = apiLevel <= 21 ? quickCodeOffset + 32 : quickCodeOffset + pointerSize5;
      spec = {
        size,
        offset: {
          jniCode: jniCodeOffset,
          quickCode: quickCodeOffset,
          accessFlags: accessFlagsOffset
        }
      };
      if ("artInterpreterToCompiledCodeBridge" in api2) {
        spec.offset.interpreterCode = jniCodeOffset - entrypointFieldSize;
      }
    });
    return spec;
  }
  function getArtFieldSpec(vm3) {
    const apiLevel = getAndroidApiLevel();
    if (apiLevel >= 23) {
      return {
        size: 16,
        offset: {
          accessFlags: 4
        }
      };
    }
    if (apiLevel >= 21) {
      return {
        size: 24,
        offset: {
          accessFlags: 12
        }
      };
    }
    return null;
  }
  function _getArtThreadSpec(vm3) {
    const apiLevel = getAndroidApiLevel();
    let spec;
    vm3.perform((env) => {
      const threadHandle = getArtThreadFromEnv(env);
      const envHandle = env.handle;
      let isExceptionReportedOffset = null;
      let exceptionOffset = null;
      let throwLocationOffset = null;
      let topHandleScopeOffset = null;
      let managedStackOffset = null;
      let selfOffset = null;
      for (let offset = 144; offset !== 256; offset += pointerSize5) {
        const field = threadHandle.add(offset);
        const value = field.readPointer();
        if (value.equals(envHandle)) {
          exceptionOffset = offset - 6 * pointerSize5;
          managedStackOffset = offset - 4 * pointerSize5;
          selfOffset = offset + 2 * pointerSize5;
          if (apiLevel <= 22) {
            exceptionOffset -= pointerSize5;
            isExceptionReportedOffset = exceptionOffset - pointerSize5 - 9 * 8 - 3 * 4;
            throwLocationOffset = offset + 6 * pointerSize5;
            managedStackOffset -= pointerSize5;
            selfOffset -= pointerSize5;
          }
          topHandleScopeOffset = offset + 9 * pointerSize5;
          if (apiLevel <= 22) {
            topHandleScopeOffset += 2 * pointerSize5 + 4;
            if (pointerSize5 === 8) {
              topHandleScopeOffset += 4;
            }
          }
          if (apiLevel >= 23) {
            topHandleScopeOffset += pointerSize5;
          }
          break;
        }
      }
      if (topHandleScopeOffset === null) {
        throw new Error("Unable to determine ArtThread field offsets");
      }
      spec = {
        offset: {
          isExceptionReportedToInstrumentation: isExceptionReportedOffset,
          exception: exceptionOffset,
          throwLocation: throwLocationOffset,
          topHandleScope: topHandleScopeOffset,
          managedStack: managedStackOffset,
          self: selfOffset
        }
      };
    });
    return spec;
  }
  function _getArtManagedStackSpec() {
    const apiLevel = getAndroidApiLevel();
    if (apiLevel >= 23) {
      return {
        offset: {
          topQuickFrame: 0,
          link: pointerSize5
        }
      };
    } else {
      return {
        offset: {
          topQuickFrame: 2 * pointerSize5,
          link: 0
        }
      };
    }
  }
  function getArtQuickEntrypointFromTrampoline(trampoline, vm3) {
    let address;
    vm3.perform((env) => {
      const thread = getArtThreadFromEnv(env);
      const tryParse = artQuickTrampolineParsers[Process.arch];
      const insn = Instruction.parse(trampoline);
      const offset = tryParse(insn);
      if (offset !== null) {
        address = thread.add(offset).readPointer();
      } else {
        address = trampoline;
      }
    });
    return address;
  }
  function parseArtQuickTrampolineX86(insn) {
    if (insn.mnemonic === "jmp") {
      return insn.operands[0].value.disp;
    }
    return null;
  }
  function parseArtQuickTrampolineArm(insn) {
    if (insn.mnemonic === "ldr.w") {
      return insn.operands[1].value.disp;
    }
    return null;
  }
  function parseArtQuickTrampolineArm64(insn) {
    if (insn.mnemonic === "ldr") {
      return insn.operands[1].value.disp;
    }
    return null;
  }
  function getArtThreadFromEnv(env) {
    return env.handle.add(pointerSize5).readPointer();
  }
  function _getAndroidVersion() {
    return getAndroidSystemProperty("ro.build.version.release");
  }
  function _getAndroidCodename() {
    return getAndroidSystemProperty("ro.build.version.codename");
  }
  function _getAndroidApiLevel() {
    return parseInt(getAndroidSystemProperty("ro.build.version.sdk"), 10);
  }
  function _getArtApexVersion() {
    try {
      const mountInfo = File.readAllText("/proc/self/mountinfo");
      let artSource = null;
      const sourceVersions = /* @__PURE__ */ new Map();
      for (const line of mountInfo.trimEnd().split("\n")) {
        const elements = line.split(" ");
        const mountRoot = elements[4];
        if (!mountRoot.startsWith("/apex/com.android.art")) {
          continue;
        }
        const mountSource = elements[10];
        if (mountRoot.includes("@")) {
          sourceVersions.set(mountSource, mountRoot.split("@")[1]);
        } else {
          artSource = mountSource;
        }
      }
      const strVersion = sourceVersions.get(artSource);
      return strVersion !== void 0 ? parseInt(strVersion) : computeArtApexVersionFromApiLevel();
    } catch {
      return computeArtApexVersionFromApiLevel();
    }
  }
  function computeArtApexVersionFromApiLevel() {
    return getAndroidApiLevel() * 1e7;
  }
  function getAndroidSystemProperty(name) {
    if (systemPropertyGet === null) {
      systemPropertyGet = new NativeFunction(
        Process.getModuleByName("libc.so").getExportByName("__system_property_get"),
        "int",
        ["pointer", "pointer"],
        nativeFunctionOptions3
      );
    }
    const buf = Memory.alloc(PROP_VALUE_MAX);
    systemPropertyGet(Memory.allocUtf8String(name), buf);
    return buf.readUtf8String();
  }
  function withRunnableArtThread(vm3, env, fn) {
    const perform = getArtThreadStateTransitionImpl(vm3, env);
    const id = getArtThreadFromEnv(env).toString();
    artThreadStateTransitions[id] = fn;
    perform(env.handle);
    if (artThreadStateTransitions[id] !== void 0) {
      delete artThreadStateTransitions[id];
      throw new Error("Unable to perform state transition; please file a bug");
    }
  }
  function _getArtThreadStateTransitionImpl(vm3, env) {
    const callback = new NativeCallback(onThreadStateTransitionComplete, "void", ["pointer"]);
    return makeArtThreadStateTransitionImpl(vm3, env, callback);
  }
  function onThreadStateTransitionComplete(thread) {
    const id = thread.toString();
    const fn = artThreadStateTransitions[id];
    delete artThreadStateTransitions[id];
    fn(thread);
  }
  function withAllArtThreadsSuspended(fn) {
    const api2 = getApi();
    const threadList = api2.artThreadList;
    const longSuspend = false;
    api2["art::ThreadList::SuspendAll"](threadList, Memory.allocUtf8String("frida"), longSuspend ? 1 : 0);
    try {
      fn();
    } finally {
      api2["art::ThreadList::ResumeAll"](threadList);
    }
  }
  function makeArtClassVisitor(visit) {
    const api2 = getApi();
    if (api2["art::ClassLinker::VisitClasses"] instanceof NativeFunction) {
      return new ArtClassVisitor(visit);
    }
    return new NativeCallback((klass) => {
      return visit(klass) === true ? 1 : 0;
    }, "bool", ["pointer", "pointer"]);
  }
  function makeArtClassLoaderVisitor(visit) {
    return new ArtClassLoaderVisitor(visit);
  }
  function makeArtQuickFrameInfoGetter(impl) {
    return function(self) {
      const result = Memory.alloc(12);
      getArtQuickFrameInfoGetterThunk(impl)(result, self);
      return {
        frameSizeInBytes: result.readU32(),
        coreSpillMask: result.add(4).readU32(),
        fpSpillMask: result.add(8).readU32()
      };
    };
  }
  function _getArtQuickFrameInfoGetterThunk(impl) {
    let thunk = NULL;
    switch (Process.arch) {
      case "ia32":
        thunk = makeThunk(32, (writer) => {
          writer.putMovRegRegOffsetPtr("ecx", "esp", 4);
          writer.putMovRegRegOffsetPtr("edx", "esp", 8);
          writer.putCallAddressWithArguments(impl, ["ecx", "edx"]);
          writer.putMovRegReg("esp", "ebp");
          writer.putPopReg("ebp");
          writer.putRet();
        });
        break;
      case "x64":
        thunk = makeThunk(32, (writer) => {
          writer.putPushReg("rdi");
          writer.putCallAddressWithArguments(impl, ["rsi"]);
          writer.putPopReg("rdi");
          writer.putMovRegPtrReg("rdi", "rax");
          writer.putMovRegOffsetPtrReg("rdi", 8, "edx");
          writer.putRet();
        });
        break;
      case "arm":
        thunk = makeThunk(16, (writer) => {
          writer.putCallAddressWithArguments(impl, ["r0", "r1"]);
          writer.putPopRegs(["r0", "lr"]);
          writer.putMovRegReg("pc", "lr");
        });
        break;
      case "arm64":
        thunk = makeThunk(64, (writer) => {
          writer.putPushRegReg("x0", "lr");
          writer.putCallAddressWithArguments(impl, ["x1"]);
          writer.putPopRegReg("x2", "lr");
          writer.putStrRegRegOffset("x0", "x2", 0);
          writer.putStrRegRegOffset("w1", "x2", 8);
          writer.putRet();
        });
        break;
    }
    return new NativeFunction(thunk, "void", ["pointer", "pointer"], nativeFunctionOptions3);
  }
  function makeThunk(size, write3) {
    if (thunkPage === null) {
      thunkPage = Memory.alloc(Process.pageSize);
    }
    const thunk = thunkPage.add(thunkOffset);
    const arch = Process.arch;
    const Writer = thunkWriters[arch];
    Memory.patchCode(thunk, size, (code3) => {
      const writer = new Writer(code3, { pc: thunk });
      write3(writer);
      writer.flush();
      if (writer.offset > size) {
        throw new Error(`Wrote ${writer.offset}, exceeding maximum of ${size}`);
      }
    });
    thunkOffset += size;
    return arch === "arm" ? thunk.or(1) : thunk;
  }
  function notifyArtMethodHooked(method, vm3) {
    ensureArtKnowsHowToHandleMethodInstrumentation(vm3);
    ensureArtKnowsHowToHandleReplacementMethods(vm3);
  }
  function makeArtController(api2, vm3) {
    const threadOffsets = getArtThreadSpec(vm3).offset;
    const managedStackOffsets = getArtManagedStackSpec().offset;
    const code3 = `
#include <gum/guminterceptor.h>

extern GMutex lock;
extern GHashTable * methods;
extern GHashTable * replacements;
extern gpointer last_seen_art_method;

extern gpointer get_oat_quick_method_header_impl (gpointer method, gpointer pc);

void
init (void)
{
  g_mutex_init (&lock);
  methods = g_hash_table_new_full (NULL, NULL, NULL, NULL);
  replacements = g_hash_table_new_full (NULL, NULL, NULL, NULL);
}

void
finalize (void)
{
  g_hash_table_unref (replacements);
  g_hash_table_unref (methods);
  g_mutex_clear (&lock);
}

gboolean
is_replacement_method (gpointer method)
{
  gboolean is_replacement;

  g_mutex_lock (&lock);

  is_replacement = g_hash_table_contains (replacements, method);

  g_mutex_unlock (&lock);

  return is_replacement;
}

gpointer
get_replacement_method (gpointer original_method)
{
  gpointer replacement_method;

  g_mutex_lock (&lock);

  replacement_method = g_hash_table_lookup (methods, original_method);

  g_mutex_unlock (&lock);

  return replacement_method;
}

void
set_replacement_method (gpointer original_method,
                        gpointer replacement_method)
{
  g_mutex_lock (&lock);

  g_hash_table_insert (methods, original_method, replacement_method);
  g_hash_table_insert (replacements, replacement_method, original_method);

  g_mutex_unlock (&lock);
}

void
synchronize_replacement_methods (guint quick_code_offset,
                                 void * nterp_entrypoint,
                                 void * quick_to_interpreter_bridge)
{
  GHashTableIter iter;
  gpointer hooked_method, replacement_method;

  g_mutex_lock (&lock);

  g_hash_table_iter_init (&iter, methods);
  while (g_hash_table_iter_next (&iter, &hooked_method, &replacement_method))
  {
    void ** quick_code;

    *((uint32_t *) replacement_method) = *((uint32_t *) hooked_method);

    quick_code = hooked_method + quick_code_offset;
    if (*quick_code == nterp_entrypoint)
      *quick_code = quick_to_interpreter_bridge;
  }

  g_mutex_unlock (&lock);
}

void
delete_replacement_method (gpointer original_method)
{
  gpointer replacement_method;

  g_mutex_lock (&lock);

  replacement_method = g_hash_table_lookup (methods, original_method);
  if (replacement_method != NULL)
  {
    g_hash_table_remove (methods, original_method);
    g_hash_table_remove (replacements, replacement_method);
  }

  g_mutex_unlock (&lock);
}

gpointer
translate_method (gpointer method)
{
  gpointer translated_method;

  g_mutex_lock (&lock);

  translated_method = g_hash_table_lookup (replacements, method);

  g_mutex_unlock (&lock);

  return (translated_method != NULL) ? translated_method : method;
}

gpointer
find_replacement_method_from_quick_code (gpointer method,
                                         gpointer thread)
{
  gpointer replacement_method;
  gpointer managed_stack;
  gpointer top_quick_frame;
  gpointer link_managed_stack;
  gpointer * link_top_quick_frame;

  replacement_method = get_replacement_method (method);
  if (replacement_method == NULL)
    return NULL;

  /*
   * Stack check.
   *
   * Return NULL to indicate that the original method should be invoked, otherwise
   * return a pointer to the replacement ArtMethod.
   *
   * If the caller is our own JNI replacement stub, then a stack transition must
   * have been pushed onto the current thread's linked list.
   *
   * Therefore, we invoke the original method if the following conditions are met:
   *   1- The current managed stack is empty.
   *   2- The ArtMethod * inside the linked managed stack's top quick frame is the
   *      same as our replacement.
   */
  managed_stack = thread + ${threadOffsets.managedStack};
  top_quick_frame = *((gpointer *) (managed_stack + ${managedStackOffsets.topQuickFrame}));
  if (top_quick_frame != NULL)
    return replacement_method;

  link_managed_stack = *((gpointer *) (managed_stack + ${managedStackOffsets.link}));
  if (link_managed_stack == NULL)
    return replacement_method;

  link_top_quick_frame = GSIZE_TO_POINTER (*((gsize *) (link_managed_stack + ${managedStackOffsets.topQuickFrame})) & ~((gsize) 1));
  if (link_top_quick_frame == NULL || *link_top_quick_frame != replacement_method)
    return replacement_method;

  return NULL;
}

void
on_interpreter_do_call (GumInvocationContext * ic)
{
  gpointer method, replacement_method;

  method = gum_invocation_context_get_nth_argument (ic, 0);

  replacement_method = get_replacement_method (method);
  if (replacement_method != NULL)
    gum_invocation_context_replace_nth_argument (ic, 0, replacement_method);
}

gpointer
on_art_method_get_oat_quick_method_header (gpointer method,
                                           gpointer pc)
{
  if (is_replacement_method (method))
    return NULL;

  return get_oat_quick_method_header_impl (method, pc);
}

void
on_art_method_pretty_method (GumInvocationContext * ic)
{
  const guint this_arg_index = ${Process.arch === "arm64" ? 0 : 1};
  gpointer method;

  method = gum_invocation_context_get_nth_argument (ic, this_arg_index);
  if (method == NULL)
    gum_invocation_context_replace_nth_argument (ic, this_arg_index, last_seen_art_method);
  else
    last_seen_art_method = method;
}

void
on_leave_gc_concurrent_copying_copying_phase (GumInvocationContext * ic)
{
  GHashTableIter iter;
  gpointer hooked_method, replacement_method;

  g_mutex_lock (&lock);

  g_hash_table_iter_init (&iter, methods);
  while (g_hash_table_iter_next (&iter, &hooked_method, &replacement_method))
    *((uint32_t *) replacement_method) = *((uint32_t *) hooked_method);

  g_mutex_unlock (&lock);
}
`;
    const lockSize = 8;
    const methodsSize = pointerSize5;
    const replacementsSize = pointerSize5;
    const lastSeenArtMethodSize = pointerSize5;
    const data = Memory.alloc(lockSize + methodsSize + replacementsSize + lastSeenArtMethodSize);
    const lock = data;
    const methods = lock.add(lockSize);
    const replacements = methods.add(methodsSize);
    const lastSeenArtMethod = replacements.add(replacementsSize);
    const getOatQuickMethodHeaderImpl = api2.find(pointerSize5 === 4 ? "_ZN3art9ArtMethod23GetOatQuickMethodHeaderEj" : "_ZN3art9ArtMethod23GetOatQuickMethodHeaderEm");
    const cm2 = new CModule(code3, {
      lock,
      methods,
      replacements,
      last_seen_art_method: lastSeenArtMethod,
      get_oat_quick_method_header_impl: getOatQuickMethodHeaderImpl ?? ptr("0xdeadbeef")
    });
    const fastOptions = { exceptions: "propagate", scheduling: "exclusive" };
    return {
      handle: cm2,
      replacedMethods: {
        isReplacement: new NativeFunction(cm2.is_replacement_method, "bool", ["pointer"], fastOptions),
        get: new NativeFunction(cm2.get_replacement_method, "pointer", ["pointer"], fastOptions),
        set: new NativeFunction(cm2.set_replacement_method, "void", ["pointer", "pointer"], fastOptions),
        synchronize: new NativeFunction(cm2.synchronize_replacement_methods, "void", ["uint", "pointer", "pointer"], fastOptions),
        delete: new NativeFunction(cm2.delete_replacement_method, "void", ["pointer"], fastOptions),
        translate: new NativeFunction(cm2.translate_method, "pointer", ["pointer"], fastOptions),
        findReplacementFromQuickCode: cm2.find_replacement_method_from_quick_code
      },
      getOatQuickMethodHeaderImpl,
      hooks: {
        Interpreter: {
          doCall: cm2.on_interpreter_do_call
        },
        ArtMethod: {
          getOatQuickMethodHeader: cm2.on_art_method_get_oat_quick_method_header,
          prettyMethod: cm2.on_art_method_pretty_method
        },
        Gc: {
          copyingPhase: {
            onLeave: cm2.on_leave_gc_concurrent_copying_copying_phase
          },
          runFlip: {
            onEnter: cm2.on_leave_gc_concurrent_copying_copying_phase
          }
        }
      }
    };
  }
  function ensureArtKnowsHowToHandleMethodInstrumentation(vm3) {
    if (taughtArtAboutMethodInstrumentation) {
      return;
    }
    taughtArtAboutMethodInstrumentation = true;
    instrumentArtQuickEntrypoints(vm3);
    instrumentArtMethodInvocationFromInterpreter();
    instrumentArtGarbageCollection();
    instrumentArtFixupStaticTrampolines();
  }
  function instrumentArtQuickEntrypoints(vm3) {
    const api2 = getApi();
    const quickEntrypoints = [
      api2.artQuickGenericJniTrampoline,
      api2.artQuickToInterpreterBridge,
      api2.artQuickResolutionTrampoline
    ];
    quickEntrypoints.forEach((entrypoint) => {
      Memory.protect(entrypoint, 32, "rwx");
      const interceptor = new ArtQuickCodeInterceptor(entrypoint);
      interceptor.activate(vm3);
      artQuickInterceptors.push(interceptor);
    });
  }
  function instrumentArtMethodInvocationFromInterpreter() {
    const api2 = getApi();
    const apiLevel = getAndroidApiLevel();
    const { isApiLevel34OrApexEquivalent } = api2;
    let artInterpreterDoCallExportRegex;
    if (apiLevel <= 22) {
      artInterpreterDoCallExportRegex = /^_ZN3art11interpreter6DoCallILb[0-1]ELb[0-1]EEEbPNS_6mirror9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtPNS_6JValueE$/;
    } else if (apiLevel <= 33 && !isApiLevel34OrApexEquivalent) {
      artInterpreterDoCallExportRegex = /^_ZN3art11interpreter6DoCallILb[0-1]ELb[0-1]EEEbPNS_9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtPNS_6JValueE$/;
    } else if (isApiLevel34OrApexEquivalent) {
      artInterpreterDoCallExportRegex = /^_ZN3art11interpreter6DoCallILb[0-1]EEEbPNS_9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtbPNS_6JValueE$/;
    } else {
      throw new Error("Unable to find method invocation in ART; please file a bug");
    }
    const art = api2.module;
    const entries = [...art.enumerateExports(), ...art.enumerateSymbols()].filter((entry) => artInterpreterDoCallExportRegex.test(entry.name));
    if (entries.length === 0) {
      throw new Error("Unable to find method invocation in ART; please file a bug");
    }
    for (const entry of entries) {
      Interceptor.attach(entry.address, artController.hooks.Interpreter.doCall);
    }
  }
  function instrumentArtGarbageCollection() {
    const api2 = getApi();
    const art = api2.module;
    const gc = art.findSymbolByName("_ZN3art2gc4Heap22CollectGarbageInternalENS0_9collector6GcTypeENS0_7GcCauseEbj");
    if (gc === null) {
      return;
    }
    const { artNterpEntryPoint, artQuickToInterpreterBridge } = api2;
    const quickCodeOffset = getArtMethodSpec(api2.vm).offset.quickCode;
    Interceptor.attach(gc, {
      onLeave() {
        artController.replacedMethods.synchronize(quickCodeOffset, artNterpEntryPoint, artQuickToInterpreterBridge);
      }
    });
  }
  function instrumentArtFixupStaticTrampolines() {
    const patterns = [
      ["_ZN3art11ClassLinker26VisiblyInitializedCallback22MarkVisiblyInitializedEPNS_6ThreadE", "e90340f8 : ff0ff0ff"],
      ["_ZN3art11ClassLinker26VisiblyInitializedCallback29AdjustThreadVisibilityCounterEPNS_6ThreadEl", "7f0f00f9 : 1ffcffff"]
    ];
    const api2 = getApi();
    const art = api2.module;
    for (const [name, pattern] of patterns) {
      const base = art.findSymbolByName(name);
      if (base === null) {
        continue;
      }
      const matches = Memory.scanSync(base, 8192, pattern);
      if (matches.length === 0) {
        return;
      }
      const { artNterpEntryPoint, artQuickToInterpreterBridge } = api2;
      const quickCodeOffset = getArtMethodSpec(api2.vm).offset.quickCode;
      Interceptor.attach(matches[0].address, function() {
        artController.replacedMethods.synchronize(quickCodeOffset, artNterpEntryPoint, artQuickToInterpreterBridge);
      });
      return;
    }
  }
  function ensureArtKnowsHowToHandleReplacementMethods(vm3) {
    if (taughtArtAboutReplacementMethods) {
      return;
    }
    taughtArtAboutReplacementMethods = true;
    if (!maybeInstrumentGetOatQuickMethodHeaderInlineCopies()) {
      const { getOatQuickMethodHeaderImpl } = artController;
      if (getOatQuickMethodHeaderImpl === null) {
        return;
      }
      try {
        Interceptor.replace(getOatQuickMethodHeaderImpl, artController.hooks.ArtMethod.getOatQuickMethodHeader);
      } catch (e) {
      }
    }
    const apiLevel = getAndroidApiLevel();
    let copyingPhase = null;
    const api2 = getApi();
    if (apiLevel > 28) {
      copyingPhase = api2.find("_ZN3art2gc9collector17ConcurrentCopying12CopyingPhaseEv");
    } else if (apiLevel > 22) {
      copyingPhase = api2.find("_ZN3art2gc9collector17ConcurrentCopying12MarkingPhaseEv");
    }
    if (copyingPhase !== null) {
      Interceptor.attach(copyingPhase, artController.hooks.Gc.copyingPhase);
    }
    let runFlip = null;
    runFlip = api2.find("_ZN3art6Thread15RunFlipFunctionEPS0_");
    if (runFlip === null) {
      runFlip = api2.find("_ZN3art6Thread15RunFlipFunctionEPS0_b");
    }
    if (runFlip !== null) {
      Interceptor.attach(runFlip, artController.hooks.Gc.runFlip);
    }
  }
  function validateGetOatQuickMethodHeaderInlinedMatchArm({ address, size }) {
    const ldr = Instruction.parse(address.or(1));
    const [ldrDst, ldrSrc] = ldr.operands;
    const methodReg = ldrSrc.value.base;
    const scratchReg = ldrDst.value;
    const branch = Instruction.parse(ldr.next.add(2));
    const targetWhenTrue = ptr(branch.operands[0].value);
    const targetWhenFalse = branch.address.add(branch.size);
    let targetWhenRegularMethod, targetWhenRuntimeMethod;
    if (branch.mnemonic === "beq") {
      targetWhenRegularMethod = targetWhenFalse;
      targetWhenRuntimeMethod = targetWhenTrue;
    } else {
      targetWhenRegularMethod = targetWhenTrue;
      targetWhenRuntimeMethod = targetWhenFalse;
    }
    return parseInstructionsAt(targetWhenRegularMethod.or(1), tryParse, { limit: 3 });
    function tryParse(insn) {
      const { mnemonic } = insn;
      if (!(mnemonic === "ldr" || mnemonic === "ldr.w")) {
        return null;
      }
      const { base, disp } = insn.operands[1].value;
      if (!(base === methodReg && disp === 20)) {
        return null;
      }
      return {
        methodReg,
        scratchReg,
        target: {
          whenTrue: targetWhenTrue,
          whenRegularMethod: targetWhenRegularMethod,
          whenRuntimeMethod: targetWhenRuntimeMethod
        }
      };
    }
  }
  function validateGetOatQuickMethodHeaderInlinedMatchArm64({ address, size }) {
    const [ldrDst, ldrSrc] = Instruction.parse(address).operands;
    const methodReg = ldrSrc.value.base;
    const scratchReg = "x" + ldrDst.value.substring(1);
    const branch = Instruction.parse(address.add(8));
    const targetWhenTrue = ptr(branch.operands[0].value);
    const targetWhenFalse = address.add(12);
    let targetWhenRegularMethod, targetWhenRuntimeMethod;
    if (branch.mnemonic === "b.eq") {
      targetWhenRegularMethod = targetWhenFalse;
      targetWhenRuntimeMethod = targetWhenTrue;
    } else {
      targetWhenRegularMethod = targetWhenTrue;
      targetWhenRuntimeMethod = targetWhenFalse;
    }
    return parseInstructionsAt(targetWhenRegularMethod, tryParse, { limit: 3 });
    function tryParse(insn) {
      if (insn.mnemonic !== "ldr") {
        return null;
      }
      const { base, disp } = insn.operands[1].value;
      if (!(base === methodReg && disp === 24)) {
        return null;
      }
      return {
        methodReg,
        scratchReg,
        target: {
          whenTrue: targetWhenTrue,
          whenRegularMethod: targetWhenRegularMethod,
          whenRuntimeMethod: targetWhenRuntimeMethod
        }
      };
    }
  }
  function maybeInstrumentGetOatQuickMethodHeaderInlineCopies() {
    if (getAndroidApiLevel() < 31) {
      return false;
    }
    const handler = artGetOatQuickMethodHeaderInlinedCopyHandler[Process.arch];
    if (handler === void 0) {
      return false;
    }
    const signatures = handler.signatures.map(({ pattern, offset = 0, validateMatch = returnEmptyObject }) => {
      return {
        pattern: new MatchPattern(pattern.join("")),
        offset,
        validateMatch
      };
    });
    const impls = [];
    for (const { base, size } of getApi().module.enumerateRanges("--x")) {
      for (const { pattern, offset, validateMatch } of signatures) {
        const matches = Memory.scanSync(base, size, pattern).map(({ address, size: size2 }) => {
          return { address: address.sub(offset), size: size2 + offset };
        }).filter((match) => {
          const validationResult = validateMatch(match);
          if (validationResult === null) {
            return false;
          }
          match.validationResult = validationResult;
          return true;
        });
        impls.push(...matches);
      }
    }
    if (impls.length === 0) {
      return false;
    }
    impls.forEach(handler.instrument);
    return true;
  }
  function returnEmptyObject() {
    return {};
  }
  function instrumentGetOatQuickMethodHeaderInlinedCopyArm({ address, size, validationResult }) {
    const { methodReg, target } = validationResult;
    const trampoline = Memory.alloc(Process.pageSize);
    let redirectCapacity = size;
    Memory.patchCode(trampoline, 256, (code3) => {
      const writer = new ThumbWriter(code3, { pc: trampoline });
      const relocator = new ThumbRelocator(address, writer);
      for (let i = 0; i !== 2; i++) {
        relocator.readOne();
      }
      relocator.writeAll();
      relocator.readOne();
      relocator.skipOne();
      writer.putBCondLabel("eq", "runtime_or_replacement_method");
      const vpushFpRegs = [45, 237, 16, 10];
      writer.putBytes(vpushFpRegs);
      const savedRegs = ["r0", "r1", "r2", "r3"];
      writer.putPushRegs(savedRegs);
      writer.putCallAddressWithArguments(artController.replacedMethods.isReplacement, [methodReg]);
      writer.putCmpRegImm("r0", 0);
      writer.putPopRegs(savedRegs);
      const vpopFpRegs = [189, 236, 16, 10];
      writer.putBytes(vpopFpRegs);
      writer.putBCondLabel("ne", "runtime_or_replacement_method");
      writer.putBLabel("regular_method");
      relocator.readOne();
      const tailIsRegular = relocator.input.address.equals(target.whenRegularMethod);
      writer.putLabel(tailIsRegular ? "regular_method" : "runtime_or_replacement_method");
      relocator.writeOne();
      while (redirectCapacity < 10) {
        const offset = relocator.readOne();
        if (offset === 0) {
          redirectCapacity = 10;
          break;
        }
        redirectCapacity = offset;
      }
      relocator.writeAll();
      writer.putBranchAddress(address.add(redirectCapacity + 1));
      writer.putLabel(tailIsRegular ? "runtime_or_replacement_method" : "regular_method");
      writer.putBranchAddress(target.whenTrue);
      writer.flush();
    });
    inlineHooks.push(new InlineHook(address, redirectCapacity, trampoline));
    Memory.patchCode(address, redirectCapacity, (code3) => {
      const writer = new ThumbWriter(code3, { pc: address });
      writer.putLdrRegAddress("pc", trampoline.or(1));
      writer.flush();
    });
  }
  function instrumentGetOatQuickMethodHeaderInlinedCopyArm64({ address, size, validationResult }) {
    const { methodReg, scratchReg, target } = validationResult;
    const trampoline = Memory.alloc(Process.pageSize);
    Memory.patchCode(trampoline, 256, (code3) => {
      const writer = new Arm64Writer(code3, { pc: trampoline });
      const relocator = new Arm64Relocator(address, writer);
      for (let i = 0; i !== 2; i++) {
        relocator.readOne();
      }
      relocator.writeAll();
      relocator.readOne();
      relocator.skipOne();
      writer.putBCondLabel("eq", "runtime_or_replacement_method");
      const savedRegs = [
        "d0",
        "d1",
        "d2",
        "d3",
        "d4",
        "d5",
        "d6",
        "d7",
        "x0",
        "x1",
        "x2",
        "x3",
        "x4",
        "x5",
        "x6",
        "x7",
        "x8",
        "x9",
        "x10",
        "x11",
        "x12",
        "x13",
        "x14",
        "x15",
        "x16",
        "x17"
      ];
      const numSavedRegs = savedRegs.length;
      for (let i = 0; i !== numSavedRegs; i += 2) {
        writer.putPushRegReg(savedRegs[i], savedRegs[i + 1]);
      }
      writer.putCallAddressWithArguments(artController.replacedMethods.isReplacement, [methodReg]);
      writer.putCmpRegReg("x0", "xzr");
      for (let i = numSavedRegs - 2; i >= 0; i -= 2) {
        writer.putPopRegReg(savedRegs[i], savedRegs[i + 1]);
      }
      writer.putBCondLabel("ne", "runtime_or_replacement_method");
      writer.putBLabel("regular_method");
      relocator.readOne();
      const tailInstruction = relocator.input;
      const tailIsRegular = tailInstruction.address.equals(target.whenRegularMethod);
      writer.putLabel(tailIsRegular ? "regular_method" : "runtime_or_replacement_method");
      relocator.writeOne();
      writer.putBranchAddress(tailInstruction.next);
      writer.putLabel(tailIsRegular ? "runtime_or_replacement_method" : "regular_method");
      writer.putBranchAddress(target.whenTrue);
      writer.flush();
    });
    inlineHooks.push(new InlineHook(address, size, trampoline));
    Memory.patchCode(address, size, (code3) => {
      const writer = new Arm64Writer(code3, { pc: address });
      writer.putLdrRegAddress(scratchReg, trampoline);
      writer.putBrReg(scratchReg);
      writer.flush();
    });
  }
  function makeMethodMangler(methodId) {
    return new MethodMangler(methodId);
  }
  function translateMethod(methodId) {
    return artController.replacedMethods.translate(methodId);
  }
  function backtrace(vm3, options = {}) {
    const { limit = 16 } = options;
    const env = vm3.getEnv();
    if (backtraceModule === null) {
      backtraceModule = makeBacktraceModule(vm3, env);
    }
    return backtraceModule.backtrace(env, limit);
  }
  function makeBacktraceModule(vm3, env) {
    const api2 = getApi();
    const performImpl = Memory.alloc(Process.pointerSize);
    const cm2 = new CModule(`
#include <glib.h>
#include <stdbool.h>
#include <string.h>
#include <gum/gumtls.h>
#include <json-glib/json-glib.h>

typedef struct _ArtBacktrace ArtBacktrace;
typedef struct _ArtStackFrame ArtStackFrame;

typedef struct _ArtStackVisitor ArtStackVisitor;
typedef struct _ArtStackVisitorVTable ArtStackVisitorVTable;

typedef struct _ArtClass ArtClass;
typedef struct _ArtMethod ArtMethod;
typedef struct _ArtThread ArtThread;
typedef struct _ArtContext ArtContext;

typedef struct _JNIEnv JNIEnv;

typedef struct _StdString StdString;
typedef struct _StdTinyString StdTinyString;
typedef struct _StdLargeString StdLargeString;

typedef enum {
  STACK_WALK_INCLUDE_INLINED_FRAMES,
  STACK_WALK_SKIP_INLINED_FRAMES,
} StackWalkKind;

struct _StdTinyString
{
  guint8 unused;
  gchar data[(3 * sizeof (gpointer)) - 1];
};

struct _StdLargeString
{
  gsize capacity;
  gsize size;
  gchar * data;
};

struct _StdString
{
  union
  {
    guint8 flags;
    StdTinyString tiny;
    StdLargeString large;
  };
};

struct _ArtBacktrace
{
  GChecksum * id;
  GArray * frames;
  gchar * frames_json;
};

struct _ArtStackFrame
{
  ArtMethod * method;
  gsize dexpc;
  StdString description;
};

struct _ArtStackVisitorVTable
{
  void (* unused1) (void);
  void (* unused2) (void);
  bool (* visit) (ArtStackVisitor * visitor);
};

struct _ArtStackVisitor
{
  ArtStackVisitorVTable * vtable;

  guint8 padding[512];

  ArtStackVisitorVTable vtable_storage;

  ArtBacktrace * backtrace;
};

struct _ArtMethod
{
  guint32 declaring_class;
  guint32 access_flags;
};

extern GumTlsKey current_backtrace;

extern void (* perform_art_thread_state_transition) (JNIEnv * env);

extern ArtContext * art_make_context (ArtThread * thread);

extern void art_stack_visitor_init (ArtStackVisitor * visitor, ArtThread * thread, void * context, StackWalkKind walk_kind,
    size_t num_frames, bool check_suspended);
extern void art_stack_visitor_walk_stack (ArtStackVisitor * visitor, bool include_transitions);
extern ArtMethod * art_stack_visitor_get_method (ArtStackVisitor * visitor);
extern void art_stack_visitor_describe_location (StdString * description, ArtStackVisitor * visitor);
extern ArtMethod * translate_method (ArtMethod * method);
extern void translate_location (ArtMethod * method, guint32 pc, const gchar ** source_file, gint32 * line_number);
extern void get_class_location (StdString * result, ArtClass * klass);
extern void cxx_delete (void * mem);
extern unsigned long strtoul (const char * str, char ** endptr, int base);

static bool visit_frame (ArtStackVisitor * visitor);
static void art_stack_frame_destroy (ArtStackFrame * frame);

static void append_jni_type_name (GString * s, const gchar * name, gsize length);

static void std_string_destroy (StdString * str);
static gchar * std_string_get_data (StdString * str);

void
init (void)
{
  current_backtrace = gum_tls_key_new ();
}

void
finalize (void)
{
  gum_tls_key_free (current_backtrace);
}

ArtBacktrace *
_create (JNIEnv * env,
         guint limit)
{
  ArtBacktrace * bt;

  bt = g_new (ArtBacktrace, 1);
  bt->id = g_checksum_new (G_CHECKSUM_SHA1);
  bt->frames = (limit != 0)
      ? g_array_sized_new (FALSE, FALSE, sizeof (ArtStackFrame), limit)
      : g_array_new (FALSE, FALSE, sizeof (ArtStackFrame));
  g_array_set_clear_func (bt->frames, (GDestroyNotify) art_stack_frame_destroy);
  bt->frames_json = NULL;

  gum_tls_key_set_value (current_backtrace, bt);

  perform_art_thread_state_transition (env);

  gum_tls_key_set_value (current_backtrace, NULL);

  return bt;
}

void
_on_thread_state_transition_complete (ArtThread * thread)
{
  ArtContext * context;
  ArtStackVisitor visitor = {
    .vtable_storage = {
      .visit = visit_frame,
    },
  };

  context = art_make_context (thread);

  art_stack_visitor_init (&visitor, thread, context, STACK_WALK_SKIP_INLINED_FRAMES, 0, true);
  visitor.vtable = &visitor.vtable_storage;
  visitor.backtrace = gum_tls_key_get_value (current_backtrace);

  art_stack_visitor_walk_stack (&visitor, false);

  cxx_delete (context);
}

static bool
visit_frame (ArtStackVisitor * visitor)
{
  ArtBacktrace * bt = visitor->backtrace;
  ArtStackFrame frame;
  const gchar * description, * dexpc_part;

  frame.method = art_stack_visitor_get_method (visitor);

  art_stack_visitor_describe_location (&frame.description, visitor);

  description = std_string_get_data (&frame.description);
  if (strstr (description, " '<") != NULL)
    goto skip;

  dexpc_part = strstr (description, " at dex PC 0x");
  if (dexpc_part == NULL)
    goto skip;
  frame.dexpc = strtoul (dexpc_part + 13, NULL, 16);

  g_array_append_val (bt->frames, frame);

  g_checksum_update (bt->id, (guchar *) &frame.method, sizeof (frame.method));
  g_checksum_update (bt->id, (guchar *) &frame.dexpc, sizeof (frame.dexpc));

  return true;

skip:
  std_string_destroy (&frame.description);
  return true;
}

static void
art_stack_frame_destroy (ArtStackFrame * frame)
{
  std_string_destroy (&frame->description);
}

void
_destroy (ArtBacktrace * backtrace)
{
  g_free (backtrace->frames_json);
  g_array_free (backtrace->frames, TRUE);
  g_checksum_free (backtrace->id);
  g_free (backtrace);
}

const gchar *
_get_id (ArtBacktrace * backtrace)
{
  return g_checksum_get_string (backtrace->id);
}

const gchar *
_get_frames (ArtBacktrace * backtrace)
{
  GArray * frames = backtrace->frames;
  JsonBuilder * b;
  guint i;
  JsonNode * root;

  if (backtrace->frames_json != NULL)
    return backtrace->frames_json;

  b = json_builder_new_immutable ();

  json_builder_begin_array (b);

  for (i = 0; i != frames->len; i++)
  {
    ArtStackFrame * frame = &g_array_index (frames, ArtStackFrame, i);
    gchar * description, * ret_type, * paren_open, * paren_close, * arg_types, * token, * method_name, * class_name;
    GString * signature;
    gchar * cursor;
    ArtMethod * translated_method;
    StdString location;
    gsize dexpc;
    const gchar * source_file;
    gint32 line_number;

    description = std_string_get_data (&frame->description);

    ret_type = strchr (description, '\\'') + 1;

    paren_open = strchr (ret_type, '(');
    paren_close = strchr (paren_open, ')');
    *paren_open = '\\0';
    *paren_close = '\\0';

    arg_types = paren_open + 1;

    token = strrchr (ret_type, '.');
    *token = '\\0';

    method_name = token + 1;

    token = strrchr (ret_type, ' ');
    *token = '\\0';

    class_name = token + 1;

    signature = g_string_sized_new (128);

    append_jni_type_name (signature, class_name, method_name - class_name - 1);
    g_string_append_c (signature, ',');
    g_string_append (signature, method_name);
    g_string_append (signature, ",(");

    if (arg_types != paren_close)
    {
      for (cursor = arg_types; cursor != NULL;)
      {
        gsize length;
        gchar * next;

        token = strstr (cursor, ", ");
        if (token != NULL)
        {
          length = token - cursor;
          next = token + 2;
        }
        else
        {
          length = paren_close - cursor;
          next = NULL;
        }

        append_jni_type_name (signature, cursor, length);

        cursor = next;
      }
    }

    g_string_append_c (signature, ')');

    append_jni_type_name (signature, ret_type, class_name - ret_type - 1);

    translated_method = translate_method (frame->method);
    dexpc = (translated_method == frame->method) ? frame->dexpc : 0;

    get_class_location (&location, GSIZE_TO_POINTER (translated_method->declaring_class));

    translate_location (translated_method, dexpc, &source_file, &line_number);

    json_builder_begin_object (b);

    json_builder_set_member_name (b, "signature");
    json_builder_add_string_value (b, signature->str);

    json_builder_set_member_name (b, "origin");
    json_builder_add_string_value (b, std_string_get_data (&location));

    json_builder_set_member_name (b, "className");
    json_builder_add_string_value (b, class_name);

    json_builder_set_member_name (b, "methodName");
    json_builder_add_string_value (b, method_name);

    json_builder_set_member_name (b, "methodFlags");
    json_builder_add_int_value (b, translated_method->access_flags);

    json_builder_set_member_name (b, "fileName");
    json_builder_add_string_value (b, source_file);

    json_builder_set_member_name (b, "lineNumber");
    json_builder_add_int_value (b, line_number);

    json_builder_end_object (b);

    std_string_destroy (&location);
    g_string_free (signature, TRUE);
  }

  json_builder_end_array (b);

  root = json_builder_get_root (b);
  backtrace->frames_json = json_to_string (root, FALSE);
  json_node_unref (root);

  return backtrace->frames_json;
}

static void
append_jni_type_name (GString * s,
                      const gchar * name,
                      gsize length)
{
  gchar shorty = '\\0';
  gsize i;

  switch (name[0])
  {
    case 'b':
      if (strncmp (name, "boolean", length) == 0)
        shorty = 'Z';
      else if (strncmp (name, "byte", length) == 0)
        shorty = 'B';
      break;
    case 'c':
      if (strncmp (name, "char", length) == 0)
        shorty = 'C';
      break;
    case 'd':
      if (strncmp (name, "double", length) == 0)
        shorty = 'D';
      break;
    case 'f':
      if (strncmp (name, "float", length) == 0)
        shorty = 'F';
      break;
    case 'i':
      if (strncmp (name, "int", length) == 0)
        shorty = 'I';
      break;
    case 'l':
      if (strncmp (name, "long", length) == 0)
        shorty = 'J';
      break;
    case 's':
      if (strncmp (name, "short", length) == 0)
        shorty = 'S';
      break;
    case 'v':
      if (strncmp (name, "void", length) == 0)
        shorty = 'V';
      break;
  }

  if (shorty != '\\0')
  {
    g_string_append_c (s, shorty);

    return;
  }

  if (length > 2 && name[length - 2] == '[' && name[length - 1] == ']')
  {
    g_string_append_c (s, '[');
    append_jni_type_name (s, name, length - 2);

    return;
  }

  g_string_append_c (s, 'L');

  for (i = 0; i != length; i++)
  {
    gchar ch = name[i];
    if (ch != '.')
      g_string_append_c (s, ch);
    else
      g_string_append_c (s, '/');
  }

  g_string_append_c (s, ';');
}

static void
std_string_destroy (StdString * str)
{
  bool is_large = (str->flags & 1) != 0;
  if (is_large)
    cxx_delete (str->large.data);
}

static gchar *
std_string_get_data (StdString * str)
{
  bool is_large = (str->flags & 1) != 0;
  return is_large ? str->large.data : str->tiny.data;
}
`, {
      current_backtrace: Memory.alloc(Process.pointerSize),
      perform_art_thread_state_transition: performImpl,
      art_make_context: api2["art::Thread::GetLongJumpContext"] ?? api2["art::Context::Create"],
      art_stack_visitor_init: api2["art::StackVisitor::StackVisitor"],
      art_stack_visitor_walk_stack: api2["art::StackVisitor::WalkStack"],
      art_stack_visitor_get_method: api2["art::StackVisitor::GetMethod"],
      art_stack_visitor_describe_location: api2["art::StackVisitor::DescribeLocation"],
      translate_method: artController.replacedMethods.translate,
      translate_location: api2["art::Monitor::TranslateLocation"],
      get_class_location: api2["art::mirror::Class::GetLocation"],
      cxx_delete: api2.$delete,
      strtoul: Process.getModuleByName("libc.so").getExportByName("strtoul")
    });
    const _create = new NativeFunction(cm2._create, "pointer", ["pointer", "uint"], nativeFunctionOptions3);
    const _destroy = new NativeFunction(cm2._destroy, "void", ["pointer"], nativeFunctionOptions3);
    const fastOptions = { exceptions: "propagate", scheduling: "exclusive" };
    const _getId = new NativeFunction(cm2._get_id, "pointer", ["pointer"], fastOptions);
    const _getFrames = new NativeFunction(cm2._get_frames, "pointer", ["pointer"], fastOptions);
    const performThreadStateTransition = makeArtThreadStateTransitionImpl(vm3, env, cm2._on_thread_state_transition_complete);
    cm2._performData = performThreadStateTransition;
    performImpl.writePointer(performThreadStateTransition);
    cm2.backtrace = (env2, limit) => {
      const handle = _create(env2, limit);
      const bt = new Backtrace(handle);
      Script.bindWeak(bt, destroy.bind(null, handle));
      return bt;
    };
    function destroy(handle) {
      _destroy(handle);
    }
    cm2.getId = (handle) => {
      return _getId(handle).readUtf8String();
    };
    cm2.getFrames = (handle) => {
      return JSON.parse(_getFrames(handle).readUtf8String());
    };
    return cm2;
  }
  function revertGlobalPatches() {
    patchedClasses.forEach((entry) => {
      entry.vtablePtr.writePointer(entry.vtable);
      entry.vtableCountPtr.writeS32(entry.vtableCount);
    });
    patchedClasses.clear();
    for (const interceptor of artQuickInterceptors.splice(0)) {
      interceptor.deactivate();
    }
    for (const hook of inlineHooks.splice(0)) {
      hook.revert();
    }
  }
  function unwrapMethodId(methodId) {
    return unwrapGenericId(methodId, "art::jni::JniIdManager::DecodeMethodId");
  }
  function unwrapFieldId(fieldId) {
    return unwrapGenericId(fieldId, "art::jni::JniIdManager::DecodeFieldId");
  }
  function unwrapGenericId(genericId, apiMethod) {
    const api2 = getApi();
    const runtimeOffset = getArtRuntimeSpec(api2).offset;
    const jniIdManagerOffset = runtimeOffset.jniIdManager;
    const jniIdsIndirectionOffset = runtimeOffset.jniIdsIndirection;
    if (jniIdManagerOffset !== null && jniIdsIndirectionOffset !== null) {
      const runtime2 = api2.artRuntime;
      const jniIdsIndirection = runtime2.add(jniIdsIndirectionOffset).readInt();
      if (jniIdsIndirection !== kPointer) {
        const jniIdManager = runtime2.add(jniIdManagerOffset).readPointer();
        return api2[apiMethod](jniIdManager, genericId);
      }
    }
    return genericId;
  }
  function writeArtQuickCodeReplacementTrampolineIA32(trampoline, target, redirectSize, constraints, vm3) {
    const threadOffsets = getArtThreadSpec(vm3).offset;
    const artMethodOffsets = getArtMethodSpec(vm3).offset;
    let offset;
    Memory.patchCode(trampoline, 128, (code3) => {
      const writer = new X86Writer(code3, { pc: trampoline });
      const relocator = new X86Relocator(target, writer);
      const fxsave = [15, 174, 4, 36];
      const fxrstor = [15, 174, 12, 36];
      writer.putPushax();
      writer.putMovRegReg("ebp", "esp");
      writer.putAndRegU32("esp", 4294967280);
      writer.putSubRegImm("esp", 512);
      writer.putBytes(fxsave);
      writer.putMovRegFsU32Ptr("ebx", threadOffsets.self);
      writer.putCallAddressWithAlignedArguments(artController.replacedMethods.findReplacementFromQuickCode, ["eax", "ebx"]);
      writer.putTestRegReg("eax", "eax");
      writer.putJccShortLabel("je", "restore_registers", "no-hint");
      writer.putMovRegOffsetPtrReg("ebp", 7 * 4, "eax");
      writer.putLabel("restore_registers");
      writer.putBytes(fxrstor);
      writer.putMovRegReg("esp", "ebp");
      writer.putPopax();
      writer.putJccShortLabel("jne", "invoke_replacement", "no-hint");
      do {
        offset = relocator.readOne();
      } while (offset < redirectSize && !relocator.eoi);
      relocator.writeAll();
      if (!relocator.eoi) {
        writer.putJmpAddress(target.add(offset));
      }
      writer.putLabel("invoke_replacement");
      writer.putJmpRegOffsetPtr("eax", artMethodOffsets.quickCode);
      writer.flush();
    });
    return offset;
  }
  function writeArtQuickCodeReplacementTrampolineX64(trampoline, target, redirectSize, constraints, vm3) {
    const threadOffsets = getArtThreadSpec(vm3).offset;
    const artMethodOffsets = getArtMethodSpec(vm3).offset;
    let offset;
    Memory.patchCode(trampoline, 256, (code3) => {
      const writer = new X86Writer(code3, { pc: trampoline });
      const relocator = new X86Relocator(target, writer);
      const fxsave = [15, 174, 4, 36];
      const fxrstor = [15, 174, 12, 36];
      writer.putPushax();
      writer.putMovRegReg("rbp", "rsp");
      writer.putAndRegU32("rsp", 4294967280);
      writer.putSubRegImm("rsp", 512);
      writer.putBytes(fxsave);
      writer.putMovRegGsU32Ptr("rbx", threadOffsets.self);
      writer.putCallAddressWithAlignedArguments(artController.replacedMethods.findReplacementFromQuickCode, ["rdi", "rbx"]);
      writer.putTestRegReg("rax", "rax");
      writer.putJccShortLabel("je", "restore_registers", "no-hint");
      writer.putMovRegOffsetPtrReg("rbp", 8 * 8, "rax");
      writer.putLabel("restore_registers");
      writer.putBytes(fxrstor);
      writer.putMovRegReg("rsp", "rbp");
      writer.putPopax();
      writer.putJccShortLabel("jne", "invoke_replacement", "no-hint");
      do {
        offset = relocator.readOne();
      } while (offset < redirectSize && !relocator.eoi);
      relocator.writeAll();
      if (!relocator.eoi) {
        writer.putJmpAddress(target.add(offset));
      }
      writer.putLabel("invoke_replacement");
      writer.putJmpRegOffsetPtr("rdi", artMethodOffsets.quickCode);
      writer.flush();
    });
    return offset;
  }
  function writeArtQuickCodeReplacementTrampolineArm(trampoline, target, redirectSize, constraints, vm3) {
    const artMethodOffsets = getArtMethodSpec(vm3).offset;
    const targetAddress = target.and(THUMB_BIT_REMOVAL_MASK);
    let offset;
    Memory.patchCode(trampoline, 128, (code3) => {
      const writer = new ThumbWriter(code3, { pc: trampoline });
      const relocator = new ThumbRelocator(targetAddress, writer);
      const vpushFpRegs = [45, 237, 16, 10];
      const vpopFpRegs = [189, 236, 16, 10];
      writer.putPushRegs([
        "r1",
        "r2",
        "r3",
        "r5",
        "r6",
        "r7",
        "r8",
        "r10",
        "r11",
        "lr"
      ]);
      writer.putBytes(vpushFpRegs);
      writer.putSubRegRegImm("sp", "sp", 8);
      writer.putStrRegRegOffset("r0", "sp", 0);
      writer.putCallAddressWithArguments(artController.replacedMethods.findReplacementFromQuickCode, ["r0", "r9"]);
      writer.putCmpRegImm("r0", 0);
      writer.putBCondLabel("eq", "restore_registers");
      writer.putStrRegRegOffset("r0", "sp", 0);
      writer.putLabel("restore_registers");
      writer.putLdrRegRegOffset("r0", "sp", 0);
      writer.putAddRegRegImm("sp", "sp", 8);
      writer.putBytes(vpopFpRegs);
      writer.putPopRegs([
        "lr",
        "r11",
        "r10",
        "r8",
        "r7",
        "r6",
        "r5",
        "r3",
        "r2",
        "r1"
      ]);
      writer.putBCondLabel("ne", "invoke_replacement");
      do {
        offset = relocator.readOne();
      } while (offset < redirectSize && !relocator.eoi);
      relocator.writeAll();
      if (!relocator.eoi) {
        writer.putLdrRegAddress("pc", target.add(offset));
      }
      writer.putLabel("invoke_replacement");
      writer.putLdrRegRegOffset("pc", "r0", artMethodOffsets.quickCode);
      writer.flush();
    });
    return offset;
  }
  function writeArtQuickCodeReplacementTrampolineArm64(trampoline, target, redirectSize, { availableScratchRegs }, vm3) {
    const artMethodOffsets = getArtMethodSpec(vm3).offset;
    let offset;
    Memory.patchCode(trampoline, 256, (code3) => {
      const writer = new Arm64Writer(code3, { pc: trampoline });
      const relocator = new Arm64Relocator(target, writer);
      writer.putPushRegReg("d0", "d1");
      writer.putPushRegReg("d2", "d3");
      writer.putPushRegReg("d4", "d5");
      writer.putPushRegReg("d6", "d7");
      writer.putPushRegReg("x1", "x2");
      writer.putPushRegReg("x3", "x4");
      writer.putPushRegReg("x5", "x6");
      writer.putPushRegReg("x7", "x20");
      writer.putPushRegReg("x21", "x22");
      writer.putPushRegReg("x23", "x24");
      writer.putPushRegReg("x25", "x26");
      writer.putPushRegReg("x27", "x28");
      writer.putPushRegReg("x29", "lr");
      writer.putSubRegRegImm("sp", "sp", 16);
      writer.putStrRegRegOffset("x0", "sp", 0);
      writer.putCallAddressWithArguments(artController.replacedMethods.findReplacementFromQuickCode, ["x0", "x19"]);
      writer.putCmpRegReg("x0", "xzr");
      writer.putBCondLabel("eq", "restore_registers");
      writer.putStrRegRegOffset("x0", "sp", 0);
      writer.putLabel("restore_registers");
      writer.putLdrRegRegOffset("x0", "sp", 0);
      writer.putAddRegRegImm("sp", "sp", 16);
      writer.putPopRegReg("x29", "lr");
      writer.putPopRegReg("x27", "x28");
      writer.putPopRegReg("x25", "x26");
      writer.putPopRegReg("x23", "x24");
      writer.putPopRegReg("x21", "x22");
      writer.putPopRegReg("x7", "x20");
      writer.putPopRegReg("x5", "x6");
      writer.putPopRegReg("x3", "x4");
      writer.putPopRegReg("x1", "x2");
      writer.putPopRegReg("d6", "d7");
      writer.putPopRegReg("d4", "d5");
      writer.putPopRegReg("d2", "d3");
      writer.putPopRegReg("d0", "d1");
      writer.putBCondLabel("ne", "invoke_replacement");
      do {
        offset = relocator.readOne();
      } while (offset < redirectSize && !relocator.eoi);
      relocator.writeAll();
      if (!relocator.eoi) {
        const scratchReg = Array.from(availableScratchRegs)[0];
        writer.putLdrRegAddress(scratchReg, target.add(offset));
        writer.putBrReg(scratchReg);
      }
      writer.putLabel("invoke_replacement");
      writer.putLdrRegRegOffset("x16", "x0", artMethodOffsets.quickCode);
      writer.putBrReg("x16");
      writer.flush();
    });
    return offset;
  }
  function writeArtQuickCodePrologueX86(target, trampoline, redirectSize) {
    Memory.patchCode(target, 16, (code3) => {
      const writer = new X86Writer(code3, { pc: target });
      writer.putJmpAddress(trampoline);
      writer.flush();
    });
  }
  function writeArtQuickCodePrologueArm(target, trampoline, redirectSize) {
    const targetAddress = target.and(THUMB_BIT_REMOVAL_MASK);
    Memory.patchCode(targetAddress, 16, (code3) => {
      const writer = new ThumbWriter(code3, { pc: targetAddress });
      writer.putLdrRegAddress("pc", trampoline.or(1));
      writer.flush();
    });
  }
  function writeArtQuickCodePrologueArm64(target, trampoline, redirectSize) {
    Memory.patchCode(target, 16, (code3) => {
      const writer = new Arm64Writer(code3, { pc: target });
      if (redirectSize === 16) {
        writer.putLdrRegAddress("x16", trampoline);
      } else {
        writer.putAdrpRegAddress("x16", trampoline);
      }
      writer.putBrReg("x16");
      writer.flush();
    });
  }
  function isArtQuickEntrypoint(address) {
    const api2 = getApi();
    const { module: m, artClassLinker } = api2;
    return address.equals(artClassLinker.quickGenericJniTrampoline) || address.equals(artClassLinker.quickToInterpreterBridgeTrampoline) || address.equals(artClassLinker.quickResolutionTrampoline) || address.equals(artClassLinker.quickImtConflictTrampoline) || address.compare(m.base) >= 0 && address.compare(m.base.add(m.size)) < 0;
  }
  function xposedIsSupported() {
    return getAndroidApiLevel() < 28;
  }
  function fetchArtMethod(methodId, vm3) {
    const artMethodSpec = getArtMethodSpec(vm3);
    const artMethodOffset = artMethodSpec.offset;
    return ["jniCode", "accessFlags", "quickCode", "interpreterCode"].reduce((original, name) => {
      const offset = artMethodOffset[name];
      if (offset === void 0) {
        return original;
      }
      const address = methodId.add(offset);
      const read2 = name === "accessFlags" ? readU32 : readPointer;
      original[name] = read2.call(address);
      return original;
    }, {});
  }
  function patchArtMethod(methodId, patches, vm3) {
    const artMethodSpec = getArtMethodSpec(vm3);
    const artMethodOffset = artMethodSpec.offset;
    Object.keys(patches).forEach((name) => {
      const offset = artMethodOffset[name];
      if (offset === void 0) {
        return;
      }
      const address = methodId.add(offset);
      const write3 = name === "accessFlags" ? writeU32 : writePointer;
      write3.call(address, patches[name]);
    });
  }
  function computeDalvikJniArgInfo(methodId) {
    if (Process.arch !== "ia32") {
      return DALVIK_JNI_NO_ARG_INFO;
    }
    const shorty = methodId.add(DVM_METHOD_OFFSET_SHORTY).readPointer().readCString();
    if (shorty === null || shorty.length === 0 || shorty.length > 65535) {
      return DALVIK_JNI_NO_ARG_INFO;
    }
    let returnType;
    switch (shorty[0]) {
      case "V":
        returnType = DALVIK_JNI_RETURN_VOID;
        break;
      case "F":
        returnType = DALVIK_JNI_RETURN_FLOAT;
        break;
      case "D":
        returnType = DALVIK_JNI_RETURN_DOUBLE;
        break;
      case "J":
        returnType = DALVIK_JNI_RETURN_S8;
        break;
      case "Z":
      case "B":
        returnType = DALVIK_JNI_RETURN_S1;
        break;
      case "C":
        returnType = DALVIK_JNI_RETURN_U2;
        break;
      case "S":
        returnType = DALVIK_JNI_RETURN_S2;
        break;
      default:
        returnType = DALVIK_JNI_RETURN_S4;
        break;
    }
    let hints = 0;
    for (let i = shorty.length - 1; i > 0; i--) {
      const ch = shorty[i];
      hints += ch === "D" || ch === "J" ? 2 : 1;
    }
    return returnType << DALVIK_JNI_RETURN_SHIFT | hints;
  }
  function cloneArtMethod(method, vm3) {
    const api2 = getApi();
    if (getAndroidApiLevel() < 23) {
      const thread = api2["art::Thread::CurrentFromGdb"]();
      return api2["art::mirror::Object::Clone"](method, thread);
    }
    if (api2.isUserfaultfdGcActive) {
      return cloneArtMethodInLinearAlloc(method, vm3);
    }
    return Memory.dup(method, getArtMethodSpec(vm3).size);
  }
  function cloneArtMethodInLinearAlloc(method, vm3) {
    const key = method.toString();
    let clone = linearAllocClones.get(key);
    if (clone === void 0) {
      const api2 = getApi();
      vm3.perform((env) => {
        withRunnableArtThread(vm3, env, () => {
          clone = api2["art::Runtime::CreateCalleeSaveMethod"](api2.artRuntime);
          Memory.copy(clone, method, getArtMethodSpec(vm3).size);
        });
      });
      linearAllocClones.set(key, clone);
    }
    return clone;
  }
  function deoptimizeMethod(vm3, env, method) {
    requestDeoptimization(vm3, env, kSelectiveDeoptimization, method);
  }
  function deoptimizeEverything(vm3, env) {
    requestDeoptimization(vm3, env, kFullDeoptimization);
  }
  function deoptimizeBootImage(vm3, env) {
    const api2 = getApi();
    if (getAndroidApiLevel() < 26) {
      throw new Error("This API is only available on Android >= 8.0");
    }
    withRunnableArtThread(vm3, env, (thread) => {
      api2["art::Runtime::DeoptimizeBootImage"](api2.artRuntime);
    });
  }
  function isMethodDeoptimized(vm3, env, method) {
    const api2 = getApi();
    if (getAndroidApiLevel() < 24) {
      throw new Error("This API is only available on Android >= 7.0");
    }
    const instrumentation = api2.artInstrumentation;
    if (instrumentation === null) {
      throw new Error("Unable to find Instrumentation class in ART; please file a bug");
    }
    let deoptimized = false;
    withRunnableArtThread(vm3, env, () => {
      deoptimized = !!api2["art::Instrumentation::IsDeoptimized"](instrumentation, method);
    });
    return deoptimized;
  }
  function requestDeoptimization(vm3, env, kind, method) {
    const api2 = getApi();
    if (getAndroidApiLevel() < 24) {
      throw new Error("This API is only available on Android >= 7.0");
    }
    withRunnableArtThread(vm3, env, (thread) => {
      if (getAndroidApiLevel() < 30) {
        if (!api2.isJdwpStarted()) {
          const session = startJdwp(api2);
          jdwpSessions.push(session);
        }
        if (!api2.isDebuggerActive()) {
          api2["art::Dbg::GoActive"]();
        }
        const request = Memory.alloc(8 + pointerSize5);
        request.writeU32(kind);
        switch (kind) {
          case kFullDeoptimization:
            break;
          case kSelectiveDeoptimization:
            request.add(8).writePointer(method);
            break;
          default:
            throw new Error("Unsupported deoptimization kind");
        }
        api2["art::Dbg::RequestDeoptimization"](request);
        api2["art::Dbg::ManageDeoptimization"]();
      } else {
        const instrumentation = api2.artInstrumentation;
        if (instrumentation === null) {
          throw new Error("Unable to find Instrumentation class in ART; please file a bug");
        }
        const enableDeopt = api2["art::Instrumentation::EnableDeoptimization"];
        if (enableDeopt !== void 0) {
          const deoptimizationEnabled = !!instrumentation.add(getArtInstrumentationSpec().offset.deoptimizationEnabled).readU8();
          if (!deoptimizationEnabled) {
            enableDeopt(instrumentation);
          }
        }
        switch (kind) {
          case kFullDeoptimization:
            api2["art::Instrumentation::DeoptimizeEverything"](instrumentation, Memory.allocUtf8String("frida"));
            break;
          case kSelectiveDeoptimization:
            api2["art::Instrumentation::Deoptimize"](instrumentation, method);
            break;
          default:
            throw new Error("Unsupported deoptimization kind");
        }
      }
    });
  }
  function startJdwp(api2) {
    const session = new JdwpSession();
    api2["art::Dbg::SetJdwpAllowed"](1);
    const options = makeJdwpOptions();
    api2["art::Dbg::ConfigureJdwp"](options);
    const startDebugger = api2["art::InternalDebuggerControlCallback::StartDebugger"];
    if (startDebugger !== void 0) {
      startDebugger(NULL);
    } else {
      api2["art::Dbg::StartJdwp"]();
    }
    return session;
  }
  function makeJdwpOptions() {
    const kJdwpTransportAndroidAdb = getAndroidApiLevel() < 28 ? 2 : 3;
    const kJdwpPortFirstAvailable = 0;
    const transport = kJdwpTransportAndroidAdb;
    const server = true;
    const suspend = false;
    const port = kJdwpPortFirstAvailable;
    const size = 8 + STD_STRING_SIZE + 2;
    const result = Memory.alloc(size);
    result.writeU32(transport).add(4).writeU8(server ? 1 : 0).add(1).writeU8(suspend ? 1 : 0).add(1).add(STD_STRING_SIZE).writeU16(port);
    return result;
  }
  function makeSocketPair() {
    if (socketpair === null) {
      socketpair = new NativeFunction(
        Process.getModuleByName("libc.so").getExportByName("socketpair"),
        "int",
        ["int", "int", "int", "pointer"]
      );
    }
    const buf = Memory.alloc(8);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, buf) === -1) {
      throw new Error("Unable to create socketpair for JDWP");
    }
    return [
      buf.readS32(),
      buf.add(4).readS32()
    ];
  }
  function makeAddGlobalRefFallbackForAndroid5(api2) {
    const offset = getArtVMSpec().offset;
    const lock = api2.vm.add(offset.globalsLock);
    const table = api2.vm.add(offset.globals);
    const add = api2["art::IndirectReferenceTable::Add"];
    const acquire = api2["art::ReaderWriterMutex::ExclusiveLock"];
    const release = api2["art::ReaderWriterMutex::ExclusiveUnlock"];
    const IRT_FIRST_SEGMENT = 0;
    return function(vm3, thread, obj) {
      acquire(lock, thread);
      try {
        return add(table, IRT_FIRST_SEGMENT, obj);
      } finally {
        release(lock, thread);
      }
    };
  }
  function makeDecodeGlobalFallback(api2) {
    const decode = api2["art::Thread::DecodeJObject"];
    if (decode === void 0) {
      throw new Error("art::Thread::DecodeJObject is not available; please file a bug");
    }
    return function(vm3, thread, ref) {
      return decode(thread, ref);
    };
  }
  function makeArtThreadStateTransitionImpl(vm3, env, callback) {
    const api2 = getApi();
    const envVtable = env.handle.readPointer();
    let exceptionClearImpl;
    const innerExceptionClearImpl = api2.find("_ZN3art3JNIILb1EE14ExceptionClearEP7_JNIEnv");
    if (innerExceptionClearImpl !== null) {
      exceptionClearImpl = innerExceptionClearImpl;
    } else {
      exceptionClearImpl = envVtable.add(ENV_VTABLE_OFFSET_EXCEPTION_CLEAR).readPointer();
    }
    let nextFuncImpl;
    const innerNextFuncImpl = api2.find("_ZN3art3JNIILb1EE10FatalErrorEP7_JNIEnvPKc");
    if (innerNextFuncImpl !== null) {
      nextFuncImpl = innerNextFuncImpl;
    } else {
      nextFuncImpl = envVtable.add(ENV_VTABLE_OFFSET_FATAL_ERROR).readPointer();
    }
    const recompile = threadStateTransitionRecompilers[Process.arch];
    if (recompile === void 0) {
      throw new Error("Not yet implemented for " + Process.arch);
    }
    let perform = null;
    const threadOffsets = getArtThreadSpec(vm3).offset;
    const exceptionOffset = threadOffsets.exception;
    const neuteredOffsets = /* @__PURE__ */ new Set();
    const isReportedOffset = threadOffsets.isExceptionReportedToInstrumentation;
    if (isReportedOffset !== null) {
      neuteredOffsets.add(isReportedOffset);
    }
    const throwLocationStartOffset = threadOffsets.throwLocation;
    if (throwLocationStartOffset !== null) {
      neuteredOffsets.add(throwLocationStartOffset);
      neuteredOffsets.add(throwLocationStartOffset + pointerSize5);
      neuteredOffsets.add(throwLocationStartOffset + 2 * pointerSize5);
    }
    const codeSize = 65536;
    const code3 = Memory.alloc(codeSize);
    Memory.patchCode(code3, codeSize, (buffer) => {
      perform = recompile(buffer, code3, exceptionClearImpl, nextFuncImpl, exceptionOffset, neuteredOffsets, callback);
    });
    perform._code = code3;
    perform._callback = callback;
    return perform;
  }
  function recompileExceptionClearForX86(buffer, pc, exceptionClearImpl, nextFuncImpl, exceptionOffset, neuteredOffsets, callback) {
    const blocks = {};
    const branchTargets = /* @__PURE__ */ new Set();
    const pending = [exceptionClearImpl];
    while (pending.length > 0) {
      let current = pending.shift();
      const alreadyCovered = Object.values(blocks).some(({ begin, end }) => current.compare(begin) >= 0 && current.compare(end) < 0);
      if (alreadyCovered) {
        continue;
      }
      const blockAddressKey = current.toString();
      let block = {
        begin: current
      };
      let lastInsn = null;
      let reachedEndOfBlock = false;
      do {
        if (current.equals(nextFuncImpl)) {
          reachedEndOfBlock = true;
          break;
        }
        const insn = Instruction.parse(current);
        lastInsn = insn;
        const existingBlock = blocks[insn.address.toString()];
        if (existingBlock !== void 0) {
          delete blocks[existingBlock.begin.toString()];
          blocks[blockAddressKey] = existingBlock;
          existingBlock.begin = block.begin;
          block = null;
          break;
        }
        let branchTarget = null;
        switch (insn.mnemonic) {
          case "jmp":
            branchTarget = ptr(insn.operands[0].value);
            reachedEndOfBlock = true;
            break;
          case "je":
          case "jg":
          case "jle":
          case "jne":
          case "js":
            branchTarget = ptr(insn.operands[0].value);
            break;
          case "ret":
            reachedEndOfBlock = true;
            break;
        }
        if (branchTarget !== null) {
          branchTargets.add(branchTarget.toString());
          pending.push(branchTarget);
          pending.sort((a, b) => a.compare(b));
        }
        current = insn.next;
      } while (!reachedEndOfBlock);
      if (block !== null) {
        block.end = lastInsn.address.add(lastInsn.size);
        blocks[blockAddressKey] = block;
      }
    }
    const blocksOrdered = Object.keys(blocks).map((key) => blocks[key]);
    blocksOrdered.sort((a, b) => a.begin.compare(b.begin));
    const entryBlock = blocks[exceptionClearImpl.toString()];
    blocksOrdered.splice(blocksOrdered.indexOf(entryBlock), 1);
    blocksOrdered.unshift(entryBlock);
    const writer = new X86Writer(buffer, { pc });
    let foundCore = false;
    let threadReg = null;
    blocksOrdered.forEach((block) => {
      const size = block.end.sub(block.begin).toInt32();
      const relocator = new X86Relocator(block.begin, writer);
      let offset;
      while ((offset = relocator.readOne()) !== 0) {
        const insn = relocator.input;
        const { mnemonic } = insn;
        const insnAddressId = insn.address.toString();
        if (branchTargets.has(insnAddressId)) {
          writer.putLabel(insnAddressId);
        }
        let keep = true;
        switch (mnemonic) {
          case "jmp":
            writer.putJmpNearLabel(branchLabelFromOperand(insn.operands[0]));
            keep = false;
            break;
          case "je":
          case "jg":
          case "jle":
          case "jne":
          case "js":
            writer.putJccNearLabel(mnemonic, branchLabelFromOperand(insn.operands[0]), "no-hint");
            keep = false;
            break;
          /*
           * JNI::ExceptionClear(), when checked JNI is off.
           */
          case "mov": {
            const [dst, src] = insn.operands;
            if (dst.type === "mem" && src.type === "imm") {
              const dstValue = dst.value;
              const dstOffset = dstValue.disp;
              if (dstOffset === exceptionOffset && src.value.valueOf() === 0) {
                threadReg = dstValue.base;
                writer.putPushfx();
                writer.putPushax();
                writer.putMovRegReg("xbp", "xsp");
                if (pointerSize5 === 4) {
                  writer.putAndRegU32("esp", 4294967280);
                } else {
                  const scratchReg = threadReg !== "rdi" ? "rdi" : "rsi";
                  writer.putMovRegU64(scratchReg, uint64("0xfffffffffffffff0"));
                  writer.putAndRegReg("rsp", scratchReg);
                }
                writer.putCallAddressWithAlignedArguments(callback, [threadReg]);
                writer.putMovRegReg("xsp", "xbp");
                writer.putPopax();
                writer.putPopfx();
                foundCore = true;
                keep = false;
              } else if (neuteredOffsets.has(dstOffset) && dstValue.base === threadReg) {
                keep = false;
              }
            }
            break;
          }
          /*
           * CheckJNI::ExceptionClear, when checked JNI is on. Wrapper that calls JNI::ExceptionClear().
           */
          case "call": {
            const target = insn.operands[0];
            if (target.type === "mem" && target.value.disp === ENV_VTABLE_OFFSET_EXCEPTION_CLEAR) {
              if (pointerSize5 === 4) {
                writer.putPopReg("eax");
                writer.putMovRegRegOffsetPtr("eax", "eax", 4);
                writer.putPushReg("eax");
              } else {
                writer.putMovRegRegOffsetPtr("rdi", "rdi", 8);
              }
              writer.putCallAddressWithArguments(callback, []);
              foundCore = true;
              keep = false;
            }
            break;
          }
        }
        if (keep) {
          relocator.writeAll();
        } else {
          relocator.skipOne();
        }
        if (offset === size) {
          break;
        }
      }
      relocator.dispose();
    });
    writer.dispose();
    if (!foundCore) {
      throwThreadStateTransitionParseError();
    }
    return new NativeFunction(pc, "void", ["pointer"], nativeFunctionOptions3);
  }
  function recompileExceptionClearForArm(buffer, pc, exceptionClearImpl, nextFuncImpl, exceptionOffset, neuteredOffsets, callback) {
    const blocks = {};
    const branchTargets = /* @__PURE__ */ new Set();
    const thumbBitRemovalMask = ptr(1).not();
    const pending = [exceptionClearImpl];
    while (pending.length > 0) {
      let current = pending.shift();
      const alreadyCovered = Object.values(blocks).some(({ begin: begin2, end }) => current.compare(begin2) >= 0 && current.compare(end) < 0);
      if (alreadyCovered) {
        continue;
      }
      const begin = current.and(thumbBitRemovalMask);
      const blockId = begin.toString();
      const thumbBit = current.and(1);
      let block = {
        begin
      };
      let lastInsn = null;
      let reachedEndOfBlock = false;
      let ifThenBlockRemaining = 0;
      do {
        if (current.equals(nextFuncImpl)) {
          reachedEndOfBlock = true;
          break;
        }
        let insn;
        try {
          insn = Instruction.parse(current);
        } catch (e) {
          if (lastInsn !== null) {
            reachedEndOfBlock = true;
            break;
          }
          throw e;
        }
        const { mnemonic } = insn;
        lastInsn = insn;
        const currentAddress = current.and(thumbBitRemovalMask);
        const insnId = currentAddress.toString();
        const existingBlock = blocks[insnId];
        if (existingBlock !== void 0) {
          delete blocks[existingBlock.begin.toString()];
          blocks[blockId] = existingBlock;
          existingBlock.begin = block.begin;
          block = null;
          break;
        }
        const isOutsideIfThenBlock = ifThenBlockRemaining === 0;
        let branchTarget = null;
        switch (mnemonic) {
          case "b":
            branchTarget = ptr(insn.operands[0].value);
            reachedEndOfBlock = isOutsideIfThenBlock;
            break;
          case "beq.w":
          case "beq":
          case "bne":
          case "bne.w":
          case "bgt":
            branchTarget = ptr(insn.operands[0].value);
            break;
          case "cbz":
          case "cbnz":
            branchTarget = ptr(insn.operands[1].value);
            break;
          case "pop.w":
            if (isOutsideIfThenBlock) {
              reachedEndOfBlock = insn.operands.filter((op) => op.value === "pc").length === 1;
            }
            break;
        }
        switch (mnemonic) {
          case "it":
            ifThenBlockRemaining = 1;
            break;
          case "itt":
            ifThenBlockRemaining = 2;
            break;
          case "ittt":
            ifThenBlockRemaining = 3;
            break;
          case "itttt":
            ifThenBlockRemaining = 4;
            break;
          default:
            if (ifThenBlockRemaining > 0) {
              ifThenBlockRemaining--;
            }
            break;
        }
        if (branchTarget !== null) {
          branchTargets.add(branchTarget.toString());
          pending.push(branchTarget.or(thumbBit));
          pending.sort((a, b) => a.compare(b));
        }
        current = insn.next;
      } while (!reachedEndOfBlock);
      if (block !== null) {
        block.end = lastInsn.address.add(lastInsn.size);
        blocks[blockId] = block;
      }
    }
    const blocksOrdered = Object.keys(blocks).map((key) => blocks[key]);
    blocksOrdered.sort((a, b) => a.begin.compare(b.begin));
    const entryBlock = blocks[exceptionClearImpl.and(thumbBitRemovalMask).toString()];
    blocksOrdered.splice(blocksOrdered.indexOf(entryBlock), 1);
    blocksOrdered.unshift(entryBlock);
    const writer = new ThumbWriter(buffer, { pc });
    let foundCore = false;
    let threadReg = null;
    let realImplReg = null;
    blocksOrdered.forEach((block) => {
      const relocator = new ThumbRelocator(block.begin, writer);
      let address = block.begin;
      const end = block.end;
      let size = 0;
      do {
        const offset = relocator.readOne();
        if (offset === 0) {
          throw new Error("Unexpected end of block");
        }
        const insn = relocator.input;
        address = insn.address;
        size = insn.size;
        const { mnemonic } = insn;
        const insnAddressId = address.toString();
        if (branchTargets.has(insnAddressId)) {
          writer.putLabel(insnAddressId);
        }
        let keep = true;
        switch (mnemonic) {
          case "b":
            writer.putBLabel(branchLabelFromOperand(insn.operands[0]));
            keep = false;
            break;
          case "beq.w":
            writer.putBCondLabelWide("eq", branchLabelFromOperand(insn.operands[0]));
            keep = false;
            break;
          case "bne.w":
            writer.putBCondLabelWide("ne", branchLabelFromOperand(insn.operands[0]));
            keep = false;
            break;
          case "beq":
          case "bne":
          case "bgt":
            writer.putBCondLabelWide(mnemonic.substr(1), branchLabelFromOperand(insn.operands[0]));
            keep = false;
            break;
          case "cbz": {
            const ops = insn.operands;
            writer.putCbzRegLabel(ops[0].value, branchLabelFromOperand(ops[1]));
            keep = false;
            break;
          }
          case "cbnz": {
            const ops = insn.operands;
            writer.putCbnzRegLabel(ops[0].value, branchLabelFromOperand(ops[1]));
            keep = false;
            break;
          }
          /*
           * JNI::ExceptionClear(), when checked JNI is off.
           */
          case "str":
          case "str.w": {
            const dstValue = insn.operands[1].value;
            const dstOffset = dstValue.disp;
            if (dstOffset === exceptionOffset) {
              threadReg = dstValue.base;
              const nzcvqReg = threadReg !== "r4" ? "r4" : "r5";
              const clobberedRegs = ["r0", "r1", "r2", "r3", nzcvqReg, "r9", "r12", "lr"];
              writer.putPushRegs(clobberedRegs);
              writer.putMrsRegReg(nzcvqReg, "apsr-nzcvq");
              writer.putCallAddressWithArguments(callback, [threadReg]);
              writer.putMsrRegReg("apsr-nzcvq", nzcvqReg);
              writer.putPopRegs(clobberedRegs);
              foundCore = true;
              keep = false;
            } else if (neuteredOffsets.has(dstOffset) && dstValue.base === threadReg) {
              keep = false;
            }
            break;
          }
          /*
           * CheckJNI::ExceptionClear, when checked JNI is on. Wrapper that calls JNI::ExceptionClear().
           */
          case "ldr": {
            const [dstOp, srcOp] = insn.operands;
            if (srcOp.type === "mem") {
              const src = srcOp.value;
              if (src.base[0] === "r" && src.disp === ENV_VTABLE_OFFSET_EXCEPTION_CLEAR) {
                realImplReg = dstOp.value;
              }
            }
            break;
          }
          case "blx":
            if (insn.operands[0].value === realImplReg) {
              writer.putLdrRegRegOffset("r0", "r0", 4);
              writer.putCallAddressWithArguments(callback, ["r0"]);
              foundCore = true;
              realImplReg = null;
              keep = false;
            }
            break;
        }
        if (keep) {
          relocator.writeAll();
        } else {
          relocator.skipOne();
        }
      } while (!address.add(size).equals(end));
      relocator.dispose();
    });
    writer.dispose();
    if (!foundCore) {
      throwThreadStateTransitionParseError();
    }
    return new NativeFunction(pc.or(1), "void", ["pointer"], nativeFunctionOptions3);
  }
  function recompileExceptionClearForArm64(buffer, pc, exceptionClearImpl, nextFuncImpl, exceptionOffset, neuteredOffsets, callback) {
    const blocks = {};
    const branchTargets = /* @__PURE__ */ new Set();
    const pending = [exceptionClearImpl];
    while (pending.length > 0) {
      let current = pending.shift();
      const alreadyCovered = Object.values(blocks).some(({ begin, end }) => current.compare(begin) >= 0 && current.compare(end) < 0);
      if (alreadyCovered) {
        continue;
      }
      const blockAddressKey = current.toString();
      let block = {
        begin: current
      };
      let lastInsn = null;
      let reachedEndOfBlock = false;
      do {
        if (current.equals(nextFuncImpl)) {
          reachedEndOfBlock = true;
          break;
        }
        let insn;
        try {
          insn = Instruction.parse(current);
        } catch (e) {
          if (current.readU32() === 0) {
            reachedEndOfBlock = true;
            break;
          } else {
            throw e;
          }
        }
        lastInsn = insn;
        const existingBlock = blocks[insn.address.toString()];
        if (existingBlock !== void 0) {
          delete blocks[existingBlock.begin.toString()];
          blocks[blockAddressKey] = existingBlock;
          existingBlock.begin = block.begin;
          block = null;
          break;
        }
        let branchTarget = null;
        switch (insn.mnemonic) {
          case "b":
            branchTarget = ptr(insn.operands[0].value);
            reachedEndOfBlock = true;
            break;
          case "b.eq":
          case "b.ne":
          case "b.le":
          case "b.gt":
            branchTarget = ptr(insn.operands[0].value);
            break;
          case "cbz":
          case "cbnz":
            branchTarget = ptr(insn.operands[1].value);
            break;
          case "tbz":
          case "tbnz":
            branchTarget = ptr(insn.operands[2].value);
            break;
          case "ret":
            reachedEndOfBlock = true;
            break;
        }
        if (branchTarget !== null) {
          branchTargets.add(branchTarget.toString());
          pending.push(branchTarget);
          pending.sort((a, b) => a.compare(b));
        }
        current = insn.next;
      } while (!reachedEndOfBlock);
      if (block !== null) {
        block.end = lastInsn.address.add(lastInsn.size);
        blocks[blockAddressKey] = block;
      }
    }
    const blocksOrdered = Object.keys(blocks).map((key) => blocks[key]);
    blocksOrdered.sort((a, b) => a.begin.compare(b.begin));
    const entryBlock = blocks[exceptionClearImpl.toString()];
    blocksOrdered.splice(blocksOrdered.indexOf(entryBlock), 1);
    blocksOrdered.unshift(entryBlock);
    const writer = new Arm64Writer(buffer, { pc });
    const invokeCallback = pc.add(writer.offset);
    writer.putPushAllXRegisters();
    writer.putCallAddressWithArguments(callback, ["x0"]);
    writer.putPopAllXRegisters();
    writer.putRet();
    writer.flush();
    const performEntry = pc.add(writer.offset);
    let foundCore = false;
    let threadReg = null;
    let realImplReg = null;
    blocksOrdered.forEach((block) => {
      const size = block.end.sub(block.begin).toInt32();
      const relocator = new Arm64Relocator(block.begin, writer);
      let offset;
      while ((offset = relocator.readOne()) !== 0) {
        const insn = relocator.input;
        const { mnemonic } = insn;
        const insnAddressId = insn.address.toString();
        if (branchTargets.has(insnAddressId)) {
          writer.putLabel(insnAddressId);
        }
        let keep = true;
        switch (mnemonic) {
          case "b":
            writer.putBLabel(branchLabelFromOperand(insn.operands[0]));
            keep = false;
            break;
          case "b.eq":
          case "b.ne":
          case "b.le":
          case "b.gt":
            writer.putBCondLabel(mnemonic.substr(2), branchLabelFromOperand(insn.operands[0]));
            keep = false;
            break;
          case "cbz": {
            const ops = insn.operands;
            writer.putCbzRegLabel(ops[0].value, branchLabelFromOperand(ops[1]));
            keep = false;
            break;
          }
          case "cbnz": {
            const ops = insn.operands;
            writer.putCbnzRegLabel(ops[0].value, branchLabelFromOperand(ops[1]));
            keep = false;
            break;
          }
          case "tbz": {
            const ops = insn.operands;
            writer.putTbzRegImmLabel(ops[0].value, ops[1].value.valueOf(), branchLabelFromOperand(ops[2]));
            keep = false;
            break;
          }
          case "tbnz": {
            const ops = insn.operands;
            writer.putTbnzRegImmLabel(ops[0].value, ops[1].value.valueOf(), branchLabelFromOperand(ops[2]));
            keep = false;
            break;
          }
          /*
           * JNI::ExceptionClear(), when checked JNI is off.
           */
          case "str": {
            const ops = insn.operands;
            const srcReg = ops[0].value;
            const dstValue = ops[1].value;
            const dstOffset = dstValue.disp;
            if (srcReg === "xzr" && dstOffset === exceptionOffset) {
              threadReg = dstValue.base;
              writer.putPushRegReg("x0", "lr");
              writer.putMovRegReg("x0", threadReg);
              writer.putBlImm(invokeCallback);
              writer.putPopRegReg("x0", "lr");
              foundCore = true;
              keep = false;
            } else if (neuteredOffsets.has(dstOffset) && dstValue.base === threadReg) {
              keep = false;
            }
            break;
          }
          /*
           * CheckJNI::ExceptionClear, when checked JNI is on. Wrapper that calls JNI::ExceptionClear().
           */
          case "ldr": {
            const ops = insn.operands;
            const src = ops[1].value;
            if (src.base[0] === "x" && src.disp === ENV_VTABLE_OFFSET_EXCEPTION_CLEAR) {
              realImplReg = ops[0].value;
            }
            break;
          }
          case "blr":
            if (insn.operands[0].value === realImplReg) {
              writer.putLdrRegRegOffset("x0", "x0", 8);
              writer.putCallAddressWithArguments(callback, ["x0"]);
              foundCore = true;
              realImplReg = null;
              keep = false;
            }
            break;
        }
        if (keep) {
          relocator.writeAll();
        } else {
          relocator.skipOne();
        }
        if (offset === size) {
          break;
        }
      }
      relocator.dispose();
    });
    writer.dispose();
    if (!foundCore) {
      throwThreadStateTransitionParseError();
    }
    return new NativeFunction(performEntry, "void", ["pointer"], nativeFunctionOptions3);
  }
  function throwThreadStateTransitionParseError() {
    throw new Error("Unable to parse ART internals; please file a bug");
  }
  function fixupArtQuickDeliverExceptionBug(api2) {
    const prettyMethod = api2["art::ArtMethod::PrettyMethod"];
    if (prettyMethod === void 0) {
      return;
    }
    Interceptor.attach(prettyMethod.impl, artController.hooks.ArtMethod.prettyMethod);
    Interceptor.flush();
  }
  function branchLabelFromOperand(op) {
    return ptr(op.value).toString();
  }
  function makeCxxMethodWrapperReturningPointerByValueGeneric(address, argTypes) {
    return new NativeFunction(address, "pointer", argTypes, nativeFunctionOptions3);
  }
  function makeCxxMethodWrapperReturningPointerByValueInFirstArg(address, argTypes) {
    const impl = new NativeFunction(address, "void", ["pointer"].concat(argTypes), nativeFunctionOptions3);
    return function() {
      const resultPtr = Memory.alloc(pointerSize5);
      impl(resultPtr, ...arguments);
      return resultPtr.readPointer();
    };
  }
  function makeCxxMethodWrapperReturningStdStringByValue(impl, argTypes) {
    const { arch } = Process;
    switch (arch) {
      case "ia32":
      case "arm64": {
        let thunk;
        if (arch === "ia32") {
          thunk = makeThunk(64, (writer) => {
            const argCount = 1 + argTypes.length;
            const argvSize = argCount * 4;
            writer.putSubRegImm("esp", argvSize);
            for (let i = 0; i !== argCount; i++) {
              const offset = i * 4;
              writer.putMovRegRegOffsetPtr("eax", "esp", argvSize + 4 + offset);
              writer.putMovRegOffsetPtrReg("esp", offset, "eax");
            }
            writer.putCallAddress(impl);
            writer.putAddRegImm("esp", argvSize - 4);
            writer.putRet();
          });
        } else {
          thunk = makeThunk(32, (writer) => {
            writer.putMovRegReg("x8", "x0");
            argTypes.forEach((t, i) => {
              writer.putMovRegReg("x" + i, "x" + (i + 1));
            });
            writer.putLdrRegAddress("x7", impl);
            writer.putBrReg("x7");
          });
        }
        const invokeThunk = new NativeFunction(thunk, "void", ["pointer"].concat(argTypes), nativeFunctionOptions3);
        const wrapper = function(...args) {
          invokeThunk(...args);
        };
        wrapper.handle = thunk;
        wrapper.impl = impl;
        return wrapper;
      }
      default: {
        const result = new NativeFunction(impl, "void", ["pointer"].concat(argTypes), nativeFunctionOptions3);
        result.impl = impl;
        return result;
      }
    }
  }
  function makeObjectVisitorPredicate(needle, onMatch) {
    const factory = objectVisitorPredicateFactories[Process.arch] || makeGenericObjectVisitorPredicate;
    return factory(needle, onMatch);
  }
  function makeGenericObjectVisitorPredicate(needle, onMatch) {
    return new NativeCallback((object) => {
      const klass = object.readS32();
      if (klass === needle) {
        onMatch(object);
      }
    }, "void", ["pointer", "pointer"]);
  }
  function alignPointerOffset(offset) {
    const remainder = offset % pointerSize5;
    if (remainder !== 0) {
      return offset + pointerSize5 - remainder;
    }
    return offset;
  }
  var jsizeSize, pointerSize5, readU32, readPointer, writeU32, writePointer, kAccPublic, kAccStatic, kAccFinal, kAccNative, kAccFastNative, kAccCriticalNative, kAccFastInterpreterToInterpreterInvoke, kAccSkipAccessChecks, kAccSingleImplementation, kAccNterpEntryPointFastPathFlag, kAccNterpInvokeFastPathFlag, kAccPublicApi, kAccXposedHookedMethod, kPointer, kFullDeoptimization, kSelectiveDeoptimization, THUMB_BIT_REMOVAL_MASK, X86_JMP_MAX_DISTANCE, ARM64_ADRP_MAX_DISTANCE, ENV_VTABLE_OFFSET_EXCEPTION_CLEAR, ENV_VTABLE_OFFSET_FATAL_ERROR, DVM_JNI_ENV_OFFSET_SELF, DVM_CLASS_OBJECT_OFFSET_VTABLE_COUNT, DVM_CLASS_OBJECT_OFFSET_VTABLE, DVM_OBJECT_OFFSET_CLAZZ, DVM_METHOD_SIZE, DVM_METHOD_OFFSET_ACCESS_FLAGS, DVM_METHOD_OFFSET_METHOD_INDEX, DVM_METHOD_OFFSET_REGISTERS_SIZE, DVM_METHOD_OFFSET_OUTS_SIZE, DVM_METHOD_OFFSET_INS_SIZE, DVM_METHOD_OFFSET_SHORTY, DVM_METHOD_OFFSET_JNI_ARG_INFO, DALVIK_JNI_RETURN_VOID, DALVIK_JNI_RETURN_FLOAT, DALVIK_JNI_RETURN_DOUBLE, DALVIK_JNI_RETURN_S8, DALVIK_JNI_RETURN_S4, DALVIK_JNI_RETURN_S2, DALVIK_JNI_RETURN_U2, DALVIK_JNI_RETURN_S1, DALVIK_JNI_NO_ARG_INFO, DALVIK_JNI_RETURN_SHIFT, STD_STRING_SIZE, STD_VECTOR_SIZE, AF_UNIX, SOCK_STREAM, getArtRuntimeSpec, getArtInstrumentationSpec, getArtMethodSpec, getArtThreadSpec, getArtManagedStackSpec, getArtThreadStateTransitionImpl, getAndroidVersion, getAndroidCodename, getAndroidApiLevel, getArtApexVersion, getArtQuickFrameInfoGetterThunk, makeCxxMethodWrapperReturningPointerByValue, nativeFunctionOptions3, artThreadStateTransitions, cachedApi, cachedArtClassLinkerSpec, MethodMangler, artController, inlineHooks, patchedClasses, linearAllocClones, artQuickInterceptors, thunkPage, thunkOffset, taughtArtAboutReplacementMethods, taughtArtAboutMethodInstrumentation, backtraceModule, jdwpSessions, socketpair, trampolineAllocator, instrumentationOffsetParsers, instrumentationPointerParser, jniIdsIndirectionOffsetParsers, artQuickTrampolineParsers, systemPropertyGet, PROP_VALUE_MAX, ArtClassVisitor, ArtClassLoaderVisitor, WalkKind, ArtStackVisitor, ArtMethod, thunkRelocators, thunkWriters, artGetOatQuickMethodHeaderInlinedCopyHandler, InlineHook, Backtrace, artQuickCodeReplacementTrampolineWriters, artQuickCodePrologueWriters, artQuickCodeHookRedirectSize, ArtQuickCodeInterceptor, ArtMethodMangler, DalvikMethodMangler, JdwpSession, threadStateTransitionRecompilers, StdString, StdVector, HandleVector, BHS_OFFSET_LINK, BHS_OFFSET_NUM_REFS, BHS_SIZE, kNumReferencesVariableSized, BaseHandleScope, VSHS_OFFSET_SELF, VSHS_OFFSET_CURRENT_SCOPE, VSHS_SIZE, VariableSizedHandleScope, FixedSizeHandleScope, objectVisitorPredicateFactories;
  var init_android = __esm({
    "node_modules/frida-java-bridge/lib/android.js"() {
      init_node_globals();
      init_alloc();
      init_jvmti();
      init_machine_code();
      init_memoize();
      init_result();
      init_vm();
      jsizeSize = 4;
      pointerSize5 = Process.pointerSize;
      ({
        readU32,
        readPointer,
        writeU32,
        writePointer
      } = NativePointer.prototype);
      kAccPublic = 1;
      kAccStatic = 8;
      kAccFinal = 16;
      kAccNative = 256;
      kAccFastNative = 524288;
      kAccCriticalNative = 2097152;
      kAccFastInterpreterToInterpreterInvoke = 1073741824;
      kAccSkipAccessChecks = 524288;
      kAccSingleImplementation = 134217728;
      kAccNterpEntryPointFastPathFlag = 1048576;
      kAccNterpInvokeFastPathFlag = 2097152;
      kAccPublicApi = 268435456;
      kAccXposedHookedMethod = 268435456;
      kPointer = 0;
      kFullDeoptimization = 3;
      kSelectiveDeoptimization = 5;
      THUMB_BIT_REMOVAL_MASK = ptr(1).not();
      X86_JMP_MAX_DISTANCE = 2147467263;
      ARM64_ADRP_MAX_DISTANCE = 4294963200;
      ENV_VTABLE_OFFSET_EXCEPTION_CLEAR = 17 * pointerSize5;
      ENV_VTABLE_OFFSET_FATAL_ERROR = 18 * pointerSize5;
      DVM_JNI_ENV_OFFSET_SELF = 12;
      DVM_CLASS_OBJECT_OFFSET_VTABLE_COUNT = 112;
      DVM_CLASS_OBJECT_OFFSET_VTABLE = 116;
      DVM_OBJECT_OFFSET_CLAZZ = 0;
      DVM_METHOD_SIZE = 56;
      DVM_METHOD_OFFSET_ACCESS_FLAGS = 4;
      DVM_METHOD_OFFSET_METHOD_INDEX = 8;
      DVM_METHOD_OFFSET_REGISTERS_SIZE = 10;
      DVM_METHOD_OFFSET_OUTS_SIZE = 12;
      DVM_METHOD_OFFSET_INS_SIZE = 14;
      DVM_METHOD_OFFSET_SHORTY = 28;
      DVM_METHOD_OFFSET_JNI_ARG_INFO = 36;
      DALVIK_JNI_RETURN_VOID = 0;
      DALVIK_JNI_RETURN_FLOAT = 1;
      DALVIK_JNI_RETURN_DOUBLE = 2;
      DALVIK_JNI_RETURN_S8 = 3;
      DALVIK_JNI_RETURN_S4 = 4;
      DALVIK_JNI_RETURN_S2 = 5;
      DALVIK_JNI_RETURN_U2 = 6;
      DALVIK_JNI_RETURN_S1 = 7;
      DALVIK_JNI_NO_ARG_INFO = 2147483648;
      DALVIK_JNI_RETURN_SHIFT = 28;
      STD_STRING_SIZE = 3 * pointerSize5;
      STD_VECTOR_SIZE = 3 * pointerSize5;
      AF_UNIX = 1;
      SOCK_STREAM = 1;
      getArtRuntimeSpec = memoize(_getArtRuntimeSpec);
      getArtInstrumentationSpec = memoize(_getArtInstrumentationSpec);
      getArtMethodSpec = memoize(_getArtMethodSpec);
      getArtThreadSpec = memoize(_getArtThreadSpec);
      getArtManagedStackSpec = memoize(_getArtManagedStackSpec);
      getArtThreadStateTransitionImpl = memoize(_getArtThreadStateTransitionImpl);
      getAndroidVersion = memoize(_getAndroidVersion);
      getAndroidCodename = memoize(_getAndroidCodename);
      getAndroidApiLevel = memoize(_getAndroidApiLevel);
      getArtApexVersion = memoize(_getArtApexVersion);
      getArtQuickFrameInfoGetterThunk = memoize(_getArtQuickFrameInfoGetterThunk);
      makeCxxMethodWrapperReturningPointerByValue = Process.arch === "ia32" ? makeCxxMethodWrapperReturningPointerByValueInFirstArg : makeCxxMethodWrapperReturningPointerByValueGeneric;
      nativeFunctionOptions3 = {
        exceptions: "propagate"
      };
      artThreadStateTransitions = {};
      cachedApi = null;
      cachedArtClassLinkerSpec = null;
      MethodMangler = null;
      artController = null;
      inlineHooks = [];
      patchedClasses = /* @__PURE__ */ new Map();
      linearAllocClones = /* @__PURE__ */ new Map();
      artQuickInterceptors = [];
      thunkPage = null;
      thunkOffset = 0;
      taughtArtAboutReplacementMethods = false;
      taughtArtAboutMethodInstrumentation = false;
      backtraceModule = null;
      jdwpSessions = [];
      socketpair = null;
      trampolineAllocator = null;
      instrumentationOffsetParsers = {
        ia32: parsex86InstrumentationOffset,
        x64: parsex86InstrumentationOffset,
        arm: parseArmInstrumentationOffset,
        arm64: parseArm64InstrumentationOffset
      };
      instrumentationPointerParser = {
        ia32: parsex86InstrumentationPointer,
        x64: parsex86InstrumentationPointer,
        arm: parseArmInstrumentationPointer,
        arm64: parseArm64InstrumentationPointer
      };
      jniIdsIndirectionOffsetParsers = {
        ia32: parsex86JniIdsIndirectionOffset,
        x64: parsex86JniIdsIndirectionOffset,
        arm: parseArmJniIdsIndirectionOffset,
        arm64: parseArm64JniIdsIndirectionOffset
      };
      artQuickTrampolineParsers = {
        ia32: parseArtQuickTrampolineX86,
        x64: parseArtQuickTrampolineX86,
        arm: parseArtQuickTrampolineArm,
        arm64: parseArtQuickTrampolineArm64
      };
      systemPropertyGet = null;
      PROP_VALUE_MAX = 92;
      ArtClassVisitor = class {
        constructor(visit) {
          const visitor = Memory.alloc(4 * pointerSize5);
          const vtable2 = visitor.add(pointerSize5);
          visitor.writePointer(vtable2);
          const onVisit = new NativeCallback((self, klass) => {
            return visit(klass) === true ? 1 : 0;
          }, "bool", ["pointer", "pointer"]);
          vtable2.add(2 * pointerSize5).writePointer(onVisit);
          this.handle = visitor;
          this._onVisit = onVisit;
        }
      };
      ArtClassLoaderVisitor = class {
        constructor(visit) {
          const visitor = Memory.alloc(4 * pointerSize5);
          const vtable2 = visitor.add(pointerSize5);
          visitor.writePointer(vtable2);
          const onVisit = new NativeCallback((self, klass) => {
            visit(klass);
          }, "void", ["pointer", "pointer"]);
          vtable2.add(2 * pointerSize5).writePointer(onVisit);
          this.handle = visitor;
          this._onVisit = onVisit;
        }
      };
      WalkKind = {
        "include-inlined-frames": 0,
        "skip-inlined-frames": 1
      };
      ArtStackVisitor = class {
        constructor(thread, context, walkKind, numFrames = 0, checkSuspended = true) {
          const api2 = getApi();
          const baseSize = 512;
          const vtableSize = 3 * pointerSize5;
          const visitor = Memory.alloc(baseSize + vtableSize);
          api2["art::StackVisitor::StackVisitor"](
            visitor,
            thread,
            context,
            WalkKind[walkKind],
            numFrames,
            checkSuspended ? 1 : 0
          );
          const vtable2 = visitor.add(baseSize);
          visitor.writePointer(vtable2);
          const onVisitFrame = new NativeCallback(this._visitFrame.bind(this), "bool", ["pointer"]);
          vtable2.add(2 * pointerSize5).writePointer(onVisitFrame);
          this.handle = visitor;
          this._onVisitFrame = onVisitFrame;
          const curShadowFrame = visitor.add(pointerSize5 === 4 ? 12 : 24);
          this._curShadowFrame = curShadowFrame;
          this._curQuickFrame = curShadowFrame.add(pointerSize5);
          this._curQuickFramePc = curShadowFrame.add(2 * pointerSize5);
          this._curOatQuickMethodHeader = curShadowFrame.add(3 * pointerSize5);
          this._getMethodImpl = api2["art::StackVisitor::GetMethod"];
          this._descLocImpl = api2["art::StackVisitor::DescribeLocation"];
          this._getCQFIImpl = api2["art::StackVisitor::GetCurrentQuickFrameInfo"];
        }
        walkStack(includeTransitions = false) {
          getApi()["art::StackVisitor::WalkStack"](this.handle, includeTransitions ? 1 : 0);
        }
        _visitFrame() {
          return this.visitFrame() ? 1 : 0;
        }
        visitFrame() {
          throw new Error("Subclass must implement visitFrame");
        }
        getMethod() {
          const methodHandle = this._getMethodImpl(this.handle);
          if (methodHandle.isNull()) {
            return null;
          }
          return new ArtMethod(methodHandle);
        }
        getCurrentQuickFramePc() {
          return this._curQuickFramePc.readPointer();
        }
        getCurrentQuickFrame() {
          return this._curQuickFrame.readPointer();
        }
        getCurrentShadowFrame() {
          return this._curShadowFrame.readPointer();
        }
        describeLocation() {
          const result = new StdString();
          this._descLocImpl(result, this.handle);
          return result.disposeToString();
        }
        getCurrentOatQuickMethodHeader() {
          return this._curOatQuickMethodHeader.readPointer();
        }
        getCurrentQuickFrameInfo() {
          return this._getCQFIImpl(this.handle);
        }
      };
      ArtMethod = class {
        constructor(handle) {
          this.handle = handle;
        }
        prettyMethod(withSignature = true) {
          const result = new StdString();
          getApi()["art::ArtMethod::PrettyMethod"](result, this.handle, withSignature ? 1 : 0);
          return result.disposeToString();
        }
        toString() {
          return `ArtMethod(handle=${this.handle})`;
        }
      };
      thunkRelocators = {
        ia32: globalThis.X86Relocator,
        x64: globalThis.X86Relocator,
        arm: globalThis.ThumbRelocator,
        arm64: globalThis.Arm64Relocator
      };
      thunkWriters = {
        ia32: globalThis.X86Writer,
        x64: globalThis.X86Writer,
        arm: globalThis.ThumbWriter,
        arm64: globalThis.Arm64Writer
      };
      artGetOatQuickMethodHeaderInlinedCopyHandler = {
        arm: {
          signatures: [
            {
              pattern: [
                "b0 68",
                // ldr r0, [r6, #8]
                "01 30",
                // adds r0, #1
                "0c d0",
                // beq #0x16fcd4
                "1b 98",
                // ldr r0, [sp, #0x6c]
                ":",
                "c0 ff",
                "c0 ff",
                "00 ff",
                "00 2f"
              ],
              validateMatch: validateGetOatQuickMethodHeaderInlinedMatchArm
            },
            {
              pattern: [
                "d8 f8 08 00",
                // ldr r0, [r8, #8]
                "01 30",
                // adds r0, #1
                "0c d0",
                // beq #0x16fcd4
                "1b 98",
                // ldr r0, [sp, #0x6c]
                ":",
                "f0 ff ff 0f",
                "ff ff",
                "00 ff",
                "00 2f"
              ],
              validateMatch: validateGetOatQuickMethodHeaderInlinedMatchArm
            },
            {
              pattern: [
                "b0 68",
                // ldr r0, [r6, #8]
                "01 30",
                // adds r0, #1
                "40 f0 c3 80",
                // bne #0x203bf0
                "00 25",
                // movs r5, #0
                ":",
                "c0 ff",
                "c0 ff",
                "c0 fb 00 d0",
                "ff f8"
              ],
              validateMatch: validateGetOatQuickMethodHeaderInlinedMatchArm
            }
          ],
          instrument: instrumentGetOatQuickMethodHeaderInlinedCopyArm
        },
        arm64: {
          signatures: [
            {
              pattern: [
                /* e8 */
                "0a 40 b9",
                // ldr w8, [x23, #0x8]
                "1f 05 00 31",
                // cmn w8, #0x1
                "40 01 00 54",
                // b.eq 0x2e4204
                "88 39 00 f0",
                // adrp x8, 0xa17000
                ":",
                /* 00 */
                "fc ff ff",
                "1f fc ff ff",
                "1f 00 00 ff",
                "00 00 00 9f"
              ],
              offset: 1,
              validateMatch: validateGetOatQuickMethodHeaderInlinedMatchArm64
            },
            {
              pattern: [
                /* e8 */
                "0a 40 b9",
                // ldr w8, [x?, #0x8]
                "1f 05 00 31",
                // cmn w8, #0x1
                "40 01 00 54",
                // b.eq <target>
                "00 0e 40 f9",
                // ldr x?, [x?, #0x18]
                ":",
                /* 00 */
                "fc ff ff",
                "1f fc ff ff",
                "1f 00 00 ff",
                "00 fc ff ff"
              ],
              offset: 1,
              validateMatch: validateGetOatQuickMethodHeaderInlinedMatchArm64
            },
            {
              pattern: [
                /* e8 */
                "0a 40 b9",
                // ldr w8, [x23, #0x8]
                "1f 05 00 31",
                // cmn w8, #0x1
                "01 34 00 54",
                // b.ne 0x3d8e50
                "e0 03 1f aa",
                // mov x0, xzr
                ":",
                /* 00 */
                "fc ff ff",
                "1f fc ff ff",
                "1f 00 00 ff",
                "e0 ff ff ff"
              ],
              offset: 1,
              validateMatch: validateGetOatQuickMethodHeaderInlinedMatchArm64
            }
          ],
          instrument: instrumentGetOatQuickMethodHeaderInlinedCopyArm64
        }
      };
      InlineHook = class {
        constructor(address, size, trampoline) {
          this.address = address;
          this.size = size;
          this.originalCode = address.readByteArray(size);
          this.trampoline = trampoline;
        }
        revert() {
          Memory.patchCode(this.address, this.size, (code3) => {
            code3.writeByteArray(this.originalCode);
          });
        }
      };
      Backtrace = class {
        constructor(handle) {
          this.handle = handle;
        }
        get id() {
          return backtraceModule.getId(this.handle);
        }
        get frames() {
          return backtraceModule.getFrames(this.handle);
        }
      };
      artQuickCodeReplacementTrampolineWriters = {
        ia32: writeArtQuickCodeReplacementTrampolineIA32,
        x64: writeArtQuickCodeReplacementTrampolineX64,
        arm: writeArtQuickCodeReplacementTrampolineArm,
        arm64: writeArtQuickCodeReplacementTrampolineArm64
      };
      artQuickCodePrologueWriters = {
        ia32: writeArtQuickCodePrologueX86,
        x64: writeArtQuickCodePrologueX86,
        arm: writeArtQuickCodePrologueArm,
        arm64: writeArtQuickCodePrologueArm64
      };
      artQuickCodeHookRedirectSize = {
        ia32: 5,
        x64: 16,
        arm: 8,
        arm64: 16
      };
      ArtQuickCodeInterceptor = class {
        constructor(quickCode) {
          this.quickCode = quickCode;
          this.quickCodeAddress = Process.arch === "arm" ? quickCode.and(THUMB_BIT_REMOVAL_MASK) : quickCode;
          this.redirectSize = 0;
          this.trampoline = null;
          this.overwrittenPrologue = null;
          this.overwrittenPrologueLength = 0;
        }
        _canRelocateCode(relocationSize, constraints) {
          const Writer = thunkWriters[Process.arch];
          const Relocator = thunkRelocators[Process.arch];
          const { quickCodeAddress } = this;
          const writer = new Writer(quickCodeAddress);
          const relocator = new Relocator(quickCodeAddress, writer);
          let offset;
          if (Process.arch === "arm64") {
            let availableScratchRegs = /* @__PURE__ */ new Set(["x16", "x17"]);
            do {
              const nextOffset = relocator.readOne();
              const nextScratchRegs = new Set(availableScratchRegs);
              const { read: read2, written } = relocator.input.regsAccessed;
              for (const regs of [read2, written]) {
                for (const reg of regs) {
                  let name;
                  if (reg.startsWith("w")) {
                    name = "x" + reg.substring(1);
                  } else {
                    name = reg;
                  }
                  nextScratchRegs.delete(name);
                }
              }
              if (nextScratchRegs.size === 0) {
                break;
              }
              offset = nextOffset;
              availableScratchRegs = nextScratchRegs;
            } while (offset < relocationSize && !relocator.eoi);
            constraints.availableScratchRegs = availableScratchRegs;
          } else {
            do {
              offset = relocator.readOne();
            } while (offset < relocationSize && !relocator.eoi);
          }
          return offset >= relocationSize;
        }
        _allocateTrampoline() {
          if (trampolineAllocator === null) {
            const trampolineSize = pointerSize5 === 4 ? 128 : 256;
            trampolineAllocator = makeAllocator(trampolineSize);
          }
          const maxRedirectSize = artQuickCodeHookRedirectSize[Process.arch];
          let redirectSize, spec;
          let alignment = 1;
          const constraints = {};
          if (pointerSize5 === 4 || this._canRelocateCode(maxRedirectSize, constraints)) {
            redirectSize = maxRedirectSize;
            spec = {};
          } else {
            let maxDistance;
            if (Process.arch === "x64") {
              redirectSize = 5;
              maxDistance = X86_JMP_MAX_DISTANCE;
            } else if (Process.arch === "arm64") {
              redirectSize = 8;
              maxDistance = ARM64_ADRP_MAX_DISTANCE;
              alignment = 4096;
            }
            spec = { near: this.quickCodeAddress, maxDistance };
          }
          this.redirectSize = redirectSize;
          this.trampoline = trampolineAllocator.allocateSlice(spec, alignment);
          return constraints;
        }
        _destroyTrampoline() {
          trampolineAllocator.freeSlice(this.trampoline);
        }
        activate(vm3) {
          const constraints = this._allocateTrampoline();
          const { trampoline, quickCode, redirectSize } = this;
          const writeTrampoline = artQuickCodeReplacementTrampolineWriters[Process.arch];
          const prologueLength = writeTrampoline(trampoline, quickCode, redirectSize, constraints, vm3);
          this.overwrittenPrologueLength = prologueLength;
          this.overwrittenPrologue = Memory.dup(this.quickCodeAddress, prologueLength);
          const writePrologue = artQuickCodePrologueWriters[Process.arch];
          writePrologue(quickCode, trampoline, redirectSize);
        }
        deactivate() {
          const { quickCodeAddress, overwrittenPrologueLength: prologueLength } = this;
          const Writer = thunkWriters[Process.arch];
          Memory.patchCode(quickCodeAddress, prologueLength, (code3) => {
            const writer = new Writer(code3, { pc: quickCodeAddress });
            const { overwrittenPrologue } = this;
            writer.putBytes(overwrittenPrologue.readByteArray(prologueLength));
            writer.flush();
          });
          this._destroyTrampoline();
        }
      };
      ArtMethodMangler = class {
        constructor(opaqueMethodId) {
          const methodId = unwrapMethodId(opaqueMethodId);
          this.methodId = methodId;
          this.originalMethod = null;
          this.hookedMethodId = methodId;
          this.replacementMethodId = null;
          this.interceptor = null;
        }
        replace(impl, isInstanceMethod, argTypes, vm3, api2) {
          const { kAccCompileDontBother, artNterpEntryPoint } = api2;
          this.originalMethod = fetchArtMethod(this.methodId, vm3);
          const originalFlags = this.originalMethod.accessFlags;
          if ((originalFlags & kAccXposedHookedMethod) !== 0 && xposedIsSupported()) {
            const hookInfo = this.originalMethod.jniCode;
            this.hookedMethodId = hookInfo.add(2 * pointerSize5).readPointer();
            this.originalMethod = fetchArtMethod(this.hookedMethodId, vm3);
          }
          const { hookedMethodId } = this;
          const replacementMethodId = cloneArtMethod(hookedMethodId, vm3);
          this.replacementMethodId = replacementMethodId;
          patchArtMethod(replacementMethodId, {
            jniCode: impl,
            accessFlags: (originalFlags & ~(kAccCriticalNative | kAccFastNative | kAccNterpEntryPointFastPathFlag) | kAccNative | kAccCompileDontBother) >>> 0,
            quickCode: api2.artClassLinker.quickGenericJniTrampoline,
            interpreterCode: api2.artInterpreterToCompiledCodeBridge
          }, vm3);
          let hookedMethodRemovedFlags = kAccFastInterpreterToInterpreterInvoke | kAccSingleImplementation | kAccNterpEntryPointFastPathFlag;
          if ((originalFlags & kAccNative) === 0) {
            hookedMethodRemovedFlags |= kAccSkipAccessChecks;
          }
          patchArtMethod(hookedMethodId, {
            accessFlags: (originalFlags & ~hookedMethodRemovedFlags | kAccCompileDontBother) >>> 0
          }, vm3);
          const quickCode = this.originalMethod.quickCode;
          if (artNterpEntryPoint !== null && quickCode.equals(artNterpEntryPoint)) {
            patchArtMethod(hookedMethodId, {
              quickCode: api2.artQuickToInterpreterBridge
            }, vm3);
          }
          if (!isArtQuickEntrypoint(quickCode)) {
            const interceptor = new ArtQuickCodeInterceptor(quickCode);
            interceptor.activate(vm3);
            this.interceptor = interceptor;
          }
          artController.replacedMethods.set(hookedMethodId, replacementMethodId);
          notifyArtMethodHooked(hookedMethodId, vm3);
        }
        revert(vm3) {
          const { hookedMethodId, interceptor } = this;
          patchArtMethod(hookedMethodId, this.originalMethod, vm3);
          artController.replacedMethods.delete(hookedMethodId);
          if (interceptor !== null) {
            interceptor.deactivate();
            this.interceptor = null;
          }
        }
        resolveTarget(wrapper, isInstanceMethod, env, api2) {
          return this.hookedMethodId;
        }
      };
      DalvikMethodMangler = class {
        constructor(methodId) {
          this.methodId = methodId;
          this.originalMethod = null;
        }
        replace(impl, isInstanceMethod, argTypes, vm3, api2) {
          const { methodId } = this;
          this.originalMethod = Memory.dup(methodId, DVM_METHOD_SIZE);
          let argsSize = argTypes.reduce((acc, t) => acc + t.size, 0);
          if (isInstanceMethod) {
            argsSize++;
          }
          const accessFlags = (methodId.add(DVM_METHOD_OFFSET_ACCESS_FLAGS).readU32() | kAccNative) >>> 0;
          const registersSize = argsSize;
          const outsSize = 0;
          const insSize = argsSize;
          methodId.add(DVM_METHOD_OFFSET_ACCESS_FLAGS).writeU32(accessFlags);
          methodId.add(DVM_METHOD_OFFSET_REGISTERS_SIZE).writeU16(registersSize);
          methodId.add(DVM_METHOD_OFFSET_OUTS_SIZE).writeU16(outsSize);
          methodId.add(DVM_METHOD_OFFSET_INS_SIZE).writeU16(insSize);
          methodId.add(DVM_METHOD_OFFSET_JNI_ARG_INFO).writeU32(computeDalvikJniArgInfo(methodId));
          api2.dvmUseJNIBridge(methodId, impl);
        }
        revert(vm3) {
          Memory.copy(this.methodId, this.originalMethod, DVM_METHOD_SIZE);
        }
        resolveTarget(wrapper, isInstanceMethod, env, api2) {
          const thread = env.handle.add(DVM_JNI_ENV_OFFSET_SELF).readPointer();
          let objectPtr;
          if (isInstanceMethod) {
            objectPtr = api2.dvmDecodeIndirectRef(thread, wrapper.$h);
          } else {
            const h = wrapper.$borrowClassHandle(env);
            objectPtr = api2.dvmDecodeIndirectRef(thread, h.value);
            h.unref(env);
          }
          let classObject;
          if (isInstanceMethod) {
            classObject = objectPtr.add(DVM_OBJECT_OFFSET_CLAZZ).readPointer();
          } else {
            classObject = objectPtr;
          }
          const classKey = classObject.toString(16);
          let entry = patchedClasses.get(classKey);
          if (entry === void 0) {
            const vtablePtr = classObject.add(DVM_CLASS_OBJECT_OFFSET_VTABLE);
            const vtableCountPtr = classObject.add(DVM_CLASS_OBJECT_OFFSET_VTABLE_COUNT);
            const vtable2 = vtablePtr.readPointer();
            const vtableCount = vtableCountPtr.readS32();
            const vtableSize = vtableCount * pointerSize5;
            const shadowVtable = Memory.alloc(2 * vtableSize);
            Memory.copy(shadowVtable, vtable2, vtableSize);
            vtablePtr.writePointer(shadowVtable);
            entry = {
              classObject,
              vtablePtr,
              vtableCountPtr,
              vtable: vtable2,
              vtableCount,
              shadowVtable,
              shadowVtableCount: vtableCount,
              targetMethods: /* @__PURE__ */ new Map()
            };
            patchedClasses.set(classKey, entry);
          }
          const methodKey = this.methodId.toString(16);
          let targetMethod = entry.targetMethods.get(methodKey);
          if (targetMethod === void 0) {
            targetMethod = Memory.dup(this.originalMethod, DVM_METHOD_SIZE);
            const methodIndex = entry.shadowVtableCount++;
            entry.shadowVtable.add(methodIndex * pointerSize5).writePointer(targetMethod);
            targetMethod.add(DVM_METHOD_OFFSET_METHOD_INDEX).writeU16(methodIndex);
            entry.vtableCountPtr.writeS32(entry.shadowVtableCount);
            entry.targetMethods.set(methodKey, targetMethod);
          }
          return targetMethod;
        }
      };
      JdwpSession = class {
        constructor() {
          const libart = Process.getModuleByName("libart.so");
          const acceptImpl = libart.getExportByName("_ZN3art4JDWP12JdwpAdbState6AcceptEv");
          const receiveClientFdImpl = libart.getExportByName("_ZN3art4JDWP12JdwpAdbState15ReceiveClientFdEv");
          const controlPair = makeSocketPair();
          const clientPair = makeSocketPair();
          this._controlFd = controlPair[0];
          this._clientFd = clientPair[0];
          let acceptListener = null;
          acceptListener = Interceptor.attach(acceptImpl, function(args) {
            const state = args[0];
            const controlSockPtr = Memory.scanSync(state.add(8252), 256, "00 ff ff ff ff 00")[0].address.add(1);
            controlSockPtr.writeS32(controlPair[1]);
            acceptListener.detach();
          });
          Interceptor.replace(receiveClientFdImpl, new NativeCallback(function(state) {
            Interceptor.revert(receiveClientFdImpl);
            return clientPair[1];
          }, "int", ["pointer"]));
          Interceptor.flush();
          this._handshakeRequest = this._performHandshake();
        }
        async _performHandshake() {
          const input = new UnixInputStream(this._clientFd, { autoClose: false });
          const output = new UnixOutputStream(this._clientFd, { autoClose: false });
          const handshakePacket = [74, 68, 87, 80, 45, 72, 97, 110, 100, 115, 104, 97, 107, 101];
          try {
            await output.writeAll(handshakePacket);
            await input.readAll(handshakePacket.length);
          } catch (e) {
          }
        }
      };
      threadStateTransitionRecompilers = {
        ia32: recompileExceptionClearForX86,
        x64: recompileExceptionClearForX86,
        arm: recompileExceptionClearForArm,
        arm64: recompileExceptionClearForArm64
      };
      StdString = class {
        constructor() {
          this.handle = Memory.alloc(STD_STRING_SIZE);
        }
        dispose() {
          const [data, isTiny] = this._getData();
          if (!isTiny) {
            getApi().$delete(data);
          }
        }
        disposeToString() {
          const result = this.toString();
          this.dispose();
          return result;
        }
        toString() {
          const [data] = this._getData();
          return data.readUtf8String();
        }
        _getData() {
          const str = this.handle;
          const isTiny = (str.readU8() & 1) === 0;
          const data = isTiny ? str.add(1) : str.add(2 * pointerSize5).readPointer();
          return [data, isTiny];
        }
      };
      StdVector = class {
        $delete() {
          this.dispose();
          getApi().$delete(this);
        }
        constructor(storage, elementSize) {
          this.handle = storage;
          this._begin = storage;
          this._end = storage.add(pointerSize5);
          this._storage = storage.add(2 * pointerSize5);
          this._elementSize = elementSize;
        }
        init() {
          this.begin = NULL;
          this.end = NULL;
          this.storage = NULL;
        }
        dispose() {
          getApi().$delete(this.begin);
        }
        get begin() {
          return this._begin.readPointer();
        }
        set begin(value) {
          this._begin.writePointer(value);
        }
        get end() {
          return this._end.readPointer();
        }
        set end(value) {
          this._end.writePointer(value);
        }
        get storage() {
          return this._storage.readPointer();
        }
        set storage(value) {
          this._storage.writePointer(value);
        }
        get size() {
          return this.end.sub(this.begin).toInt32() / this._elementSize;
        }
      };
      HandleVector = class _HandleVector extends StdVector {
        static $new() {
          const vector = new _HandleVector(getApi().$new(STD_VECTOR_SIZE));
          vector.init();
          return vector;
        }
        constructor(storage) {
          super(storage, pointerSize5);
        }
        get handles() {
          const result = [];
          let cur = this.begin;
          const end = this.end;
          while (!cur.equals(end)) {
            result.push(cur.readPointer());
            cur = cur.add(pointerSize5);
          }
          return result;
        }
      };
      BHS_OFFSET_LINK = 0;
      BHS_OFFSET_NUM_REFS = pointerSize5;
      BHS_SIZE = BHS_OFFSET_NUM_REFS + 4;
      kNumReferencesVariableSized = -1;
      BaseHandleScope = class _BaseHandleScope {
        $delete() {
          this.dispose();
          getApi().$delete(this);
        }
        constructor(storage) {
          this.handle = storage;
          this._link = storage.add(BHS_OFFSET_LINK);
          this._numberOfReferences = storage.add(BHS_OFFSET_NUM_REFS);
        }
        init(link, numberOfReferences) {
          this.link = link;
          this.numberOfReferences = numberOfReferences;
        }
        dispose() {
        }
        get link() {
          return new _BaseHandleScope(this._link.readPointer());
        }
        set link(value) {
          this._link.writePointer(value);
        }
        get numberOfReferences() {
          return this._numberOfReferences.readS32();
        }
        set numberOfReferences(value) {
          this._numberOfReferences.writeS32(value);
        }
      };
      VSHS_OFFSET_SELF = alignPointerOffset(BHS_SIZE);
      VSHS_OFFSET_CURRENT_SCOPE = VSHS_OFFSET_SELF + pointerSize5;
      VSHS_SIZE = VSHS_OFFSET_CURRENT_SCOPE + pointerSize5;
      VariableSizedHandleScope = class _VariableSizedHandleScope extends BaseHandleScope {
        static $new(thread, vm3) {
          const scope = new _VariableSizedHandleScope(getApi().$new(VSHS_SIZE));
          scope.init(thread, vm3);
          return scope;
        }
        constructor(storage) {
          super(storage);
          this._self = storage.add(VSHS_OFFSET_SELF);
          this._currentScope = storage.add(VSHS_OFFSET_CURRENT_SCOPE);
          const kLocalScopeSize = 64;
          const kSizeOfReferencesPerScope = kLocalScopeSize - pointerSize5 - 4 - 4;
          const kNumReferencesPerScope = kSizeOfReferencesPerScope / 4;
          this._scopeLayout = FixedSizeHandleScope.layoutForCapacity(kNumReferencesPerScope);
          this._topHandleScopePtr = null;
        }
        init(thread, vm3) {
          const topHandleScopePtr = thread.add(getArtThreadSpec(vm3).offset.topHandleScope);
          this._topHandleScopePtr = topHandleScopePtr;
          super.init(topHandleScopePtr.readPointer(), kNumReferencesVariableSized);
          this.self = thread;
          this.currentScope = FixedSizeHandleScope.$new(this._scopeLayout);
          topHandleScopePtr.writePointer(this);
        }
        dispose() {
          this._topHandleScopePtr.writePointer(this.link);
          let scope;
          while ((scope = this.currentScope) !== null) {
            const next = scope.link;
            scope.$delete();
            this.currentScope = next;
          }
        }
        get self() {
          return this._self.readPointer();
        }
        set self(value) {
          this._self.writePointer(value);
        }
        get currentScope() {
          const storage = this._currentScope.readPointer();
          if (storage.isNull()) {
            return null;
          }
          return new FixedSizeHandleScope(storage, this._scopeLayout);
        }
        set currentScope(value) {
          this._currentScope.writePointer(value);
        }
        newHandle(object) {
          return this.currentScope.newHandle(object);
        }
      };
      FixedSizeHandleScope = class _FixedSizeHandleScope extends BaseHandleScope {
        static $new(layout) {
          const scope = new _FixedSizeHandleScope(getApi().$new(layout.size), layout);
          scope.init();
          return scope;
        }
        constructor(storage, layout) {
          super(storage);
          const { offset } = layout;
          this._refsStorage = storage.add(offset.refsStorage);
          this._pos = storage.add(offset.pos);
          this._layout = layout;
        }
        init() {
          super.init(NULL, this._layout.numberOfReferences);
          this.pos = 0;
        }
        get pos() {
          return this._pos.readU32();
        }
        set pos(value) {
          this._pos.writeU32(value);
        }
        newHandle(object) {
          const pos = this.pos;
          const handle = this._refsStorage.add(pos * 4);
          handle.writeS32(object.toInt32());
          this.pos = pos + 1;
          return handle;
        }
        static layoutForCapacity(numRefs) {
          const refsStorage = BHS_SIZE;
          const pos = refsStorage + numRefs * 4;
          return {
            size: pos + 4,
            numberOfReferences: numRefs,
            offset: {
              refsStorage,
              pos
            }
          };
        }
      };
      objectVisitorPredicateFactories = {
        arm: function(needle, onMatch) {
          const size = Process.pageSize;
          const predicate = Memory.alloc(size);
          Memory.protect(predicate, size, "rwx");
          const onMatchCallback = new NativeCallback(onMatch, "void", ["pointer"]);
          predicate._onMatchCallback = onMatchCallback;
          const instructions = [
            26625,
            // ldr r1, [r0]
            18947,
            // ldr r2, =needle
            17041,
            // cmp r1, r2
            53505,
            // bne mismatch
            19202,
            // ldr r3, =onMatch
            18200,
            // bx r3
            18288,
            // bx lr
            48896
            // nop
          ];
          const needleOffset = instructions.length * 2;
          const onMatchOffset = needleOffset + 4;
          const codeSize = onMatchOffset + 4;
          Memory.patchCode(predicate, codeSize, function(address) {
            instructions.forEach((instruction, index) => {
              address.add(index * 2).writeU16(instruction);
            });
            address.add(needleOffset).writeS32(needle);
            address.add(onMatchOffset).writePointer(onMatchCallback);
          });
          return predicate.or(1);
        },
        arm64: function(needle, onMatch) {
          const size = Process.pageSize;
          const predicate = Memory.alloc(size);
          Memory.protect(predicate, size, "rwx");
          const onMatchCallback = new NativeCallback(onMatch, "void", ["pointer"]);
          predicate._onMatchCallback = onMatchCallback;
          const instructions = [
            3107979265,
            // ldr w1, [x0]
            402653378,
            // ldr w2, =needle
            1795293247,
            // cmp w1, w2
            1409286241,
            // b.ne mismatch
            1476395139,
            // ldr x3, =onMatch
            3592355936,
            // br x3
            3596551104
            // ret
          ];
          const needleOffset = instructions.length * 4;
          const onMatchOffset = needleOffset + 4;
          const codeSize = onMatchOffset + 8;
          Memory.patchCode(predicate, codeSize, function(address) {
            instructions.forEach((instruction, index) => {
              address.add(index * 4).writeU32(instruction);
            });
            address.add(needleOffset).writeS32(needle);
            address.add(onMatchOffset).writePointer(onMatchCallback);
          });
          return predicate;
        }
      };
    }
  });

  // node_modules/frida-java-bridge/lib/jvm.js
  function getApi2() {
    if (cachedApi2 === null) {
      cachedApi2 = _getApi2();
    }
    return cachedApi2;
  }
  function _getApi2() {
    const vmModules = Process.enumerateModules().filter((m) => /jvm.(dll|dylib|so)$/.test(m.name));
    if (vmModules.length === 0) {
      return null;
    }
    const vmModule = vmModules[0];
    const temporaryApi = {
      flavor: "jvm"
    };
    const pending = Process.platform === "windows" ? [{
      module: vmModule,
      functions: {
        JNI_GetCreatedJavaVMs: ["JNI_GetCreatedJavaVMs", "int", ["pointer", "int", "pointer"]],
        JVM_Sleep: ["JVM_Sleep", "void", ["pointer", "pointer", "long"]],
        "VMThread::execute": ["VMThread::execute", "void", ["pointer"]],
        "Method::size": ["Method::size", "int", ["int"]],
        "Method::set_native_function": ["Method::set_native_function", "void", ["pointer", "pointer", "int"]],
        "Method::clear_native_function": ["Method::clear_native_function", "void", ["pointer"]],
        "Method::jmethod_id": ["Method::jmethod_id", "pointer", ["pointer"]],
        "ClassLoaderDataGraph::classes_do": ["ClassLoaderDataGraph::classes_do", "void", ["pointer"]],
        "NMethodSweeper::sweep_code_cache": ["NMethodSweeper::sweep_code_cache", "void", []],
        "OopMapCache::flush_obsolete_entries": ["OopMapCache::flush_obsolete_entries", "void", ["pointer"]]
      },
      variables: {
        "VM_RedefineClasses::`vftable'": function(address) {
          this.vtableRedefineClasses = address;
        },
        "VM_RedefineClasses::doit": function(address) {
          this.redefineClassesDoIt = address;
        },
        "VM_RedefineClasses::doit_prologue": function(address) {
          this.redefineClassesDoItPrologue = address;
        },
        "VM_RedefineClasses::doit_epilogue": function(address) {
          this.redefineClassesDoItEpilogue = address;
        },
        "VM_RedefineClasses::allow_nested_vm_operations": function(address) {
          this.redefineClassesAllow = address;
        },
        "NMethodSweeper::_traversals": function(address) {
          this.traversals = address;
        },
        "NMethodSweeper::_should_sweep": function(address) {
          this.shouldSweep = address;
        }
      },
      optionals: []
    }] : [{
      module: vmModule,
      functions: {
        JNI_GetCreatedJavaVMs: ["JNI_GetCreatedJavaVMs", "int", ["pointer", "int", "pointer"]],
        _ZN6Method4sizeEb: ["Method::size", "int", ["int"]],
        _ZN6Method19set_native_functionEPhb: ["Method::set_native_function", "void", ["pointer", "pointer", "int"]],
        _ZN6Method21clear_native_functionEv: ["Method::clear_native_function", "void", ["pointer"]],
        // JDK >= 17
        _ZN6Method24restore_unshareable_infoEP10JavaThread: ["Method::restore_unshareable_info", "void", ["pointer", "pointer"]],
        // JDK < 17
        _ZN6Method24restore_unshareable_infoEP6Thread: ["Method::restore_unshareable_info", "void", ["pointer", "pointer"]],
        _ZN6Method11link_methodERK12methodHandleP10JavaThread: ["Method::link_method", "void", ["pointer", "pointer", "pointer"]],
        _ZN6Method10jmethod_idEv: ["Method::jmethod_id", "pointer", ["pointer"]],
        _ZN6Method10clear_codeEv: function(address) {
          const clearCode = new NativeFunction(address, "void", ["pointer"], nativeFunctionOptions4);
          this["Method::clear_code"] = function(thisPtr) {
            clearCode(thisPtr);
          };
        },
        _ZN6Method10clear_codeEb: function(address) {
          const clearCode = new NativeFunction(address, "void", ["pointer", "int"], nativeFunctionOptions4);
          const lock = 0;
          this["Method::clear_code"] = function(thisPtr) {
            clearCode(thisPtr, lock);
          };
        },
        // JDK >= 13
        _ZN18VM_RedefineClasses19mark_dependent_codeEP13InstanceKlass: ["VM_RedefineClasses::mark_dependent_code", "void", ["pointer", "pointer"]],
        _ZN18VM_RedefineClasses20flush_dependent_codeEv: ["VM_RedefineClasses::flush_dependent_code", "void", []],
        // JDK < 13
        _ZN18VM_RedefineClasses20flush_dependent_codeEP13InstanceKlassP6Thread: ["VM_RedefineClasses::flush_dependent_code", "void", ["pointer", "pointer", "pointer"]],
        // JDK < 10
        _ZN18VM_RedefineClasses20flush_dependent_codeE19instanceKlassHandleP6Thread: ["VM_RedefineClasses::flush_dependent_code", "void", ["pointer", "pointer", "pointer"]],
        _ZN19ResolvedMethodTable21adjust_method_entriesEPb: ["ResolvedMethodTable::adjust_method_entries", "void", ["pointer"]],
        // JDK < 10
        _ZN15MemberNameTable21adjust_method_entriesEP13InstanceKlassPb: ["MemberNameTable::adjust_method_entries", "void", ["pointer", "pointer", "pointer"]],
        _ZN17ConstantPoolCache21adjust_method_entriesEPb: function(address) {
          const adjustMethod = new NativeFunction(address, "void", ["pointer", "pointer"], nativeFunctionOptions4);
          this["ConstantPoolCache::adjust_method_entries"] = function(thisPtr, holderPtr, tracePtr) {
            adjustMethod(thisPtr, tracePtr);
          };
        },
        // JDK < 13
        _ZN17ConstantPoolCache21adjust_method_entriesEP13InstanceKlassPb: function(address) {
          const adjustMethod = new NativeFunction(address, "void", ["pointer", "pointer", "pointer"], nativeFunctionOptions4);
          this["ConstantPoolCache::adjust_method_entries"] = function(thisPtr, holderPtr, tracePtr) {
            adjustMethod(thisPtr, holderPtr, tracePtr);
          };
        },
        _ZN20ClassLoaderDataGraph10classes_doEP12KlassClosure: ["ClassLoaderDataGraph::classes_do", "void", ["pointer"]],
        _ZN20ClassLoaderDataGraph22clean_deallocate_listsEb: ["ClassLoaderDataGraph::clean_deallocate_lists", "void", ["int"]],
        _ZN10JavaThread27thread_from_jni_environmentEP7JNIEnv_: ["JavaThread::thread_from_jni_environment", "pointer", ["pointer"]],
        _ZN8VMThread7executeEP12VM_Operation: ["VMThread::execute", "void", ["pointer"]],
        _ZN11OopMapCache22flush_obsolete_entriesEv: ["OopMapCache::flush_obsolete_entries", "void", ["pointer"]],
        _ZN14NMethodSweeper11force_sweepEv: ["NMethodSweeper::force_sweep", "void", []],
        _ZN14NMethodSweeper16sweep_code_cacheEv: ["NMethodSweeper::sweep_code_cache", "void", []],
        _ZN14NMethodSweeper17sweep_in_progressEv: ["NMethodSweeper::sweep_in_progress", "bool", []],
        JVM_Sleep: ["JVM_Sleep", "void", ["pointer", "pointer", "long"]]
      },
      variables: {
        // JDK <= 9
        _ZN18VM_RedefineClasses14_the_class_oopE: function(address) {
          this.redefineClass = address;
        },
        // 9 < JDK < 13
        _ZN18VM_RedefineClasses10_the_classE: function(address) {
          this.redefineClass = address;
        },
        // JDK < 13
        _ZN18VM_RedefineClasses25AdjustCpoolCacheAndVtable8do_klassEP5Klass: function(address) {
          this.doKlass = address;
        },
        // JDK >= 13
        _ZN18VM_RedefineClasses22AdjustAndCleanMetadata8do_klassEP5Klass: function(address) {
          this.doKlass = address;
        },
        _ZTV18VM_RedefineClasses: function(address) {
          this.vtableRedefineClasses = address;
        },
        _ZN18VM_RedefineClasses4doitEv: function(address) {
          this.redefineClassesDoIt = address;
        },
        _ZN18VM_RedefineClasses13doit_prologueEv: function(address) {
          this.redefineClassesDoItPrologue = address;
        },
        _ZN18VM_RedefineClasses13doit_epilogueEv: function(address) {
          this.redefineClassesDoItEpilogue = address;
        },
        _ZN18VM_RedefineClassesD0Ev: function(address) {
          this.redefineClassesDispose0 = address;
        },
        _ZN18VM_RedefineClassesD1Ev: function(address) {
          this.redefineClassesDispose1 = address;
        },
        _ZNK18VM_RedefineClasses26allow_nested_vm_operationsEv: function(address) {
          this.redefineClassesAllow = address;
        },
        _ZNK18VM_RedefineClasses14print_on_errorEP12outputStream: function(address) {
          this.redefineClassesOnError = address;
        },
        // JDK >= 17
        _ZN13InstanceKlass33create_new_default_vtable_indicesEiP10JavaThread: function(address) {
          this.createNewDefaultVtableIndices = address;
        },
        // JDK < 17
        _ZN13InstanceKlass33create_new_default_vtable_indicesEiP6Thread: function(address) {
          this.createNewDefaultVtableIndices = address;
        },
        _ZN19Abstract_VM_Version19jre_release_versionEv: function(address) {
          const getVersion = new NativeFunction(address, "pointer", [], nativeFunctionOptions4);
          const versionS = getVersion().readCString();
          this.version = versionS.startsWith("1.8") ? 8 : versionS.startsWith("9.") ? 9 : parseInt(versionS.slice(0, 2), 10);
          this.versionS = versionS;
        },
        _ZN14NMethodSweeper11_traversalsE: function(address) {
          this.traversals = address;
        },
        _ZN14NMethodSweeper21_sweep_fractions_leftE: function(address) {
          this.fractions = address;
        },
        _ZN14NMethodSweeper13_should_sweepE: function(address) {
          this.shouldSweep = address;
        }
      },
      optionals: [
        "_ZN6Method24restore_unshareable_infoEP10JavaThread",
        "_ZN6Method24restore_unshareable_infoEP6Thread",
        "_ZN6Method11link_methodERK12methodHandleP10JavaThread",
        "_ZN6Method10clear_codeEv",
        "_ZN6Method10clear_codeEb",
        "_ZN18VM_RedefineClasses19mark_dependent_codeEP13InstanceKlass",
        "_ZN18VM_RedefineClasses20flush_dependent_codeEv",
        "_ZN18VM_RedefineClasses20flush_dependent_codeEP13InstanceKlassP6Thread",
        "_ZN18VM_RedefineClasses20flush_dependent_codeE19instanceKlassHandleP6Thread",
        "_ZN19ResolvedMethodTable21adjust_method_entriesEPb",
        "_ZN15MemberNameTable21adjust_method_entriesEP13InstanceKlassPb",
        "_ZN17ConstantPoolCache21adjust_method_entriesEPb",
        "_ZN17ConstantPoolCache21adjust_method_entriesEP13InstanceKlassPb",
        "_ZN20ClassLoaderDataGraph22clean_deallocate_listsEb",
        "_ZN10JavaThread27thread_from_jni_environmentEP7JNIEnv_",
        "_ZN14NMethodSweeper11force_sweepEv",
        "_ZN14NMethodSweeper17sweep_in_progressEv",
        "_ZN18VM_RedefineClasses14_the_class_oopE",
        "_ZN18VM_RedefineClasses10_the_classE",
        "_ZN18VM_RedefineClasses25AdjustCpoolCacheAndVtable8do_klassEP5Klass",
        "_ZN18VM_RedefineClasses22AdjustAndCleanMetadata8do_klassEP5Klass",
        "_ZN18VM_RedefineClassesD0Ev",
        "_ZN18VM_RedefineClassesD1Ev",
        "_ZNK18VM_RedefineClasses14print_on_errorEP12outputStream",
        "_ZN13InstanceKlass33create_new_default_vtable_indicesEiP10JavaThread",
        "_ZN13InstanceKlass33create_new_default_vtable_indicesEiP6Thread",
        "_ZN14NMethodSweeper21_sweep_fractions_leftE"
      ]
    }];
    const missing = [];
    pending.forEach(function(api2) {
      const module = api2.module;
      const functions = api2.functions || {};
      const variables = api2.variables || {};
      const optionals = new Set(api2.optionals || []);
      const tmp = module.enumerateExports().reduce(function(result, exp) {
        result[exp.name] = exp;
        return result;
      }, {});
      const exportByName = module.enumerateSymbols().reduce(function(result, exp) {
        result[exp.name] = exp;
        return result;
      }, tmp);
      Object.keys(functions).forEach(function(name) {
        const exp = exportByName[name];
        if (exp !== void 0) {
          const signature = functions[name];
          if (typeof signature === "function") {
            signature.call(temporaryApi, exp.address);
          } else {
            temporaryApi[signature[0]] = new NativeFunction(exp.address, signature[1], signature[2], nativeFunctionOptions4);
          }
        } else {
          if (!optionals.has(name)) {
            missing.push(name);
          }
        }
      });
      Object.keys(variables).forEach(function(name) {
        const exp = exportByName[name];
        if (exp !== void 0) {
          const handler = variables[name];
          handler.call(temporaryApi, exp.address);
        } else {
          if (!optionals.has(name)) {
            missing.push(name);
          }
        }
      });
    });
    if (missing.length > 0) {
      throw new Error("Java API only partially available; please file a bug. Missing: " + missing.join(", "));
    }
    const vms = Memory.alloc(pointerSize6);
    const vmCount = Memory.alloc(jsizeSize2);
    checkJniResult("JNI_GetCreatedJavaVMs", temporaryApi.JNI_GetCreatedJavaVMs(vms, 1, vmCount));
    if (vmCount.readInt() === 0) {
      return null;
    }
    temporaryApi.vm = vms.readPointer();
    const allocatorFunctions = Process.platform === "windows" ? {
      $new: ["??2@YAPEAX_K@Z", "pointer", ["ulong"]],
      $delete: ["??3@YAXPEAX@Z", "void", ["pointer"]]
    } : {
      $new: ["_Znwm", "pointer", ["ulong"]],
      $delete: ["_ZdlPv", "void", ["pointer"]]
    };
    for (const [name, [rawName, retType, argTypes]] of Object.entries(allocatorFunctions)) {
      let address = Module.findGlobalExportByName(rawName);
      if (address === null) {
        address = DebugSymbol.fromName(rawName).address;
        if (address.isNull()) {
          throw new Error(`unable to find C++ allocator API, missing: '${rawName}'`);
        }
      }
      temporaryApi[name] = new NativeFunction(address, retType, argTypes, nativeFunctionOptions4);
    }
    temporaryApi.jvmti = getEnvJvmti(temporaryApi);
    if (temporaryApi["JavaThread::thread_from_jni_environment"] === void 0) {
      temporaryApi["JavaThread::thread_from_jni_environment"] = makeThreadFromJniHelper(temporaryApi);
    }
    return temporaryApi;
  }
  function getEnvJvmti(api2) {
    const vm3 = new VM(api2);
    let env;
    vm3.perform(() => {
      const handle = vm3.tryGetEnvHandle(jvmtiVersion.v1_0);
      if (handle === null) {
        throw new Error("JVMTI not available");
      }
      env = new EnvJvmti(handle, vm3);
      const capaBuf = Memory.alloc(8);
      capaBuf.writeU64(jvmtiCapabilities.canTagObjects);
      const result = env.addCapabilities(capaBuf);
      checkJniResult("getEnvJvmti::AddCapabilities", result);
    });
    return env;
  }
  function makeThreadFromJniHelper(api2) {
    let offset = null;
    const tryParse = threadOffsetParsers[Process.arch];
    if (tryParse !== void 0) {
      const vm3 = new VM(api2);
      const findClassImpl = vm3.perform((env) => env.handle.readPointer().add(6 * pointerSize6).readPointer());
      offset = parseInstructionsAt(findClassImpl, tryParse, { limit: 11 });
    }
    if (offset === null) {
      return () => {
        throw new Error("Unable to make thread_from_jni_environment() helper for the current architecture");
      };
    }
    return (env) => {
      return env.add(offset);
    };
  }
  function parseX64ThreadOffset(insn) {
    if (insn.mnemonic !== "lea") {
      return null;
    }
    const { base, disp } = insn.operands[1].value;
    if (!(base === "rdi" && disp < 0)) {
      return null;
    }
    return disp;
  }
  function ensureClassInitialized2(env, classRef) {
  }
  function ensureManglersScheduled(vm3) {
    if (!manglersScheduled) {
      manglersScheduled = true;
      Script.nextTick(doManglers, vm3);
    }
  }
  function doManglers(vm3) {
    const localReplaceManglers = new Map(replaceManglers);
    const localRevertManglers = new Map(revertManglers);
    replaceManglers.clear();
    revertManglers.clear();
    manglersScheduled = false;
    vm3.perform((env) => {
      const api2 = getApi2();
      const thread = api2["JavaThread::thread_from_jni_environment"](env.handle);
      let force = false;
      withJvmThread(() => {
        localReplaceManglers.forEach((mangler) => {
          const { method, originalMethod, impl, methodId, newMethod } = mangler;
          if (originalMethod === null) {
            mangler.originalMethod = fetchJvmMethod(method);
            mangler.newMethod = nativeJvmMethod(method, impl, thread);
            installJvmMethod(mangler.newMethod, methodId, thread);
          } else {
            api2["Method::set_native_function"](newMethod.method, impl, 0);
          }
        });
        localRevertManglers.forEach((mangler) => {
          const { originalMethod, methodId, newMethod } = mangler;
          if (originalMethod !== null) {
            revertJvmMethod(originalMethod);
            const revert = originalMethod.oldMethod;
            revert.oldMethod = newMethod;
            installJvmMethod(revert, methodId, thread);
            force = true;
          }
        });
      });
      if (force) {
        forceSweep(env.handle);
      }
    });
  }
  function forceSweep(env) {
    const {
      fractions,
      shouldSweep,
      traversals,
      "NMethodSweeper::sweep_code_cache": sweep,
      "NMethodSweeper::sweep_in_progress": inProgress,
      "NMethodSweeper::force_sweep": force,
      JVM_Sleep: sleep
    } = getApi2();
    if (force !== void 0) {
      Thread.sleep(0.05);
      force();
      Thread.sleep(0.05);
      force();
    } else {
      let trav = traversals.readS64();
      const endTrav = trav + 2;
      while (endTrav > trav) {
        fractions.writeS32(1);
        sleep(env, NULL, 50);
        if (!inProgress()) {
          withJvmThread(() => {
            Thread.sleep(0.05);
          });
        }
        const sweepNotAlreadyInProgress = shouldSweep.readU8() === 0;
        if (sweepNotAlreadyInProgress) {
          fractions.writeS32(1);
          sweep();
        }
        trav = traversals.readS64();
      }
    }
  }
  function withJvmThread(fn, fnPrologue, fnEpilogue) {
    const {
      execute,
      vtable: vtable2,
      vtableSize,
      doItOffset,
      prologueOffset,
      epilogueOffset
    } = getJvmThreadSpec();
    const vtableDup = Memory.dup(vtable2, vtableSize);
    const vmOperation = Memory.alloc(pointerSize6 * 25);
    vmOperation.writePointer(vtableDup);
    const doIt = new NativeCallback(fn, "void", ["pointer"]);
    vtableDup.add(doItOffset).writePointer(doIt);
    let prologue = null;
    if (fnPrologue !== void 0) {
      prologue = new NativeCallback(fnPrologue, "int", ["pointer"]);
      vtableDup.add(prologueOffset).writePointer(prologue);
    }
    let epilogue = null;
    if (fnEpilogue !== void 0) {
      epilogue = new NativeCallback(fnEpilogue, "void", ["pointer"]);
      vtableDup.add(epilogueOffset).writePointer(epilogue);
    }
    execute(vmOperation);
  }
  function _getJvmThreadSpec() {
    const {
      vtableRedefineClasses,
      redefineClassesDoIt,
      redefineClassesDoItPrologue,
      redefineClassesDoItEpilogue,
      redefineClassesOnError,
      redefineClassesAllow,
      redefineClassesDispose0,
      redefineClassesDispose1,
      "VMThread::execute": execute
    } = getApi2();
    const vtablePtr = vtableRedefineClasses.add(2 * pointerSize6);
    const vtableSize = 15 * pointerSize6;
    const vtable2 = Memory.dup(vtablePtr, vtableSize);
    const emptyCallback = new NativeCallback(() => {
    }, "void", ["pointer"]);
    let doItOffset, prologueOffset, epilogueOffset;
    for (let offset = 0; offset !== vtableSize; offset += pointerSize6) {
      const element = vtable2.add(offset);
      const value = element.readPointer();
      if (redefineClassesOnError !== void 0 && value.equals(redefineClassesOnError) || redefineClassesDispose0 !== void 0 && value.equals(redefineClassesDispose0) || redefineClassesDispose1 !== void 0 && value.equals(redefineClassesDispose1)) {
        element.writePointer(emptyCallback);
      } else if (value.equals(redefineClassesDoIt)) {
        doItOffset = offset;
      } else if (value.equals(redefineClassesDoItPrologue)) {
        prologueOffset = offset;
        element.writePointer(redefineClassesAllow);
      } else if (value.equals(redefineClassesDoItEpilogue)) {
        epilogueOffset = offset;
        element.writePointer(emptyCallback);
      }
    }
    return {
      execute,
      emptyCallback,
      vtable: vtable2,
      vtableSize,
      doItOffset,
      prologueOffset,
      epilogueOffset
    };
  }
  function makeMethodMangler2(methodId) {
    return new JvmMethodMangler(methodId);
  }
  function installJvmMethod(method, methodId, thread) {
    const { method: handle, oldMethod: old } = method;
    const api2 = getApi2();
    method.methodsArray.add(method.methodIndex * pointerSize6).writePointer(handle);
    if (method.vtableIndex >= 0) {
      method.vtable.add(method.vtableIndex * pointerSize6).writePointer(handle);
    }
    methodId.writePointer(handle);
    old.accessFlagsPtr.writeU32((old.accessFlags | JVM_ACC_IS_OLD | JVM_ACC_IS_OBSOLETE) >>> 0);
    const flushObs = api2["OopMapCache::flush_obsolete_entries"];
    if (flushObs !== void 0) {
      const { oopMapCache } = method;
      if (!oopMapCache.isNull()) {
        flushObs(oopMapCache);
      }
    }
    const mark = api2["VM_RedefineClasses::mark_dependent_code"];
    const flush = api2["VM_RedefineClasses::flush_dependent_code"];
    if (mark !== void 0) {
      mark(NULL, method.instanceKlass);
      flush();
    } else {
      flush(NULL, method.instanceKlass, thread);
    }
    const traceNamePrinted = Memory.alloc(1);
    traceNamePrinted.writeU8(1);
    api2["ConstantPoolCache::adjust_method_entries"](method.cache, method.instanceKlass, traceNamePrinted);
    const klassClosure = Memory.alloc(3 * pointerSize6);
    const doKlassPtr = Memory.alloc(pointerSize6);
    doKlassPtr.writePointer(api2.doKlass);
    klassClosure.writePointer(doKlassPtr);
    klassClosure.add(pointerSize6).writePointer(thread);
    klassClosure.add(2 * pointerSize6).writePointer(thread);
    if (api2.redefineClass !== void 0) {
      api2.redefineClass.writePointer(method.instanceKlass);
    }
    api2["ClassLoaderDataGraph::classes_do"](klassClosure);
    const rmtAdjustMethodEntries = api2["ResolvedMethodTable::adjust_method_entries"];
    if (rmtAdjustMethodEntries !== void 0) {
      rmtAdjustMethodEntries(traceNamePrinted);
    } else {
      const { memberNames } = method;
      if (!memberNames.isNull()) {
        const mntAdjustMethodEntries = api2["MemberNameTable::adjust_method_entries"];
        if (mntAdjustMethodEntries !== void 0) {
          mntAdjustMethodEntries(memberNames, method.instanceKlass, traceNamePrinted);
        }
      }
    }
    const clean = api2["ClassLoaderDataGraph::clean_deallocate_lists"];
    if (clean !== void 0) {
      clean(0);
    }
  }
  function nativeJvmMethod(method, impl, thread) {
    const api2 = getApi2();
    const newMethod = fetchJvmMethod(method);
    newMethod.constPtr.writePointer(newMethod.const);
    const flags = (newMethod.accessFlags | JVM_ACC_NATIVE | JVM_ACC_NOT_C2_COMPILABLE | JVM_ACC_NOT_C1_COMPILABLE | JVM_ACC_NOT_C2_OSR_COMPILABLE) >>> 0;
    newMethod.accessFlagsPtr.writeU32(flags);
    newMethod.signatureHandler.writePointer(NULL);
    newMethod.adapter.writePointer(NULL);
    newMethod.i2iEntry.writePointer(NULL);
    api2["Method::clear_code"](newMethod.method);
    newMethod.dataPtr.writePointer(NULL);
    newMethod.countersPtr.writePointer(NULL);
    newMethod.stackmapPtr.writePointer(NULL);
    api2["Method::clear_native_function"](newMethod.method);
    api2["Method::set_native_function"](newMethod.method, impl, 0);
    api2["Method::restore_unshareable_info"](newMethod.method, thread);
    if (api2.version >= 17) {
      const methodHandle = Memory.alloc(2 * pointerSize6);
      methodHandle.writePointer(newMethod.method);
      methodHandle.add(pointerSize6).writePointer(thread);
      api2["Method::link_method"](newMethod.method, methodHandle, thread);
    }
    return newMethod;
  }
  function fetchJvmMethod(method) {
    const spec = getJvmMethodSpec();
    const constMethod = method.add(spec.method.constMethodOffset).readPointer();
    const constMethodSize = constMethod.add(spec.constMethod.sizeOffset).readS32() * pointerSize6;
    const newConstMethod = Memory.alloc(constMethodSize + spec.method.size);
    Memory.copy(newConstMethod, constMethod, constMethodSize);
    const newMethod = newConstMethod.add(constMethodSize);
    Memory.copy(newMethod, method, spec.method.size);
    const result = readJvmMethod(newMethod, newConstMethod, constMethodSize);
    const oldMethod = readJvmMethod(method, constMethod, constMethodSize);
    result.oldMethod = oldMethod;
    return result;
  }
  function readJvmMethod(method, constMethod, constMethodSize) {
    const api2 = getApi2();
    const spec = getJvmMethodSpec();
    const constPtr = method.add(spec.method.constMethodOffset);
    const dataPtr = method.add(spec.method.methodDataOffset);
    const countersPtr = method.add(spec.method.methodCountersOffset);
    const accessFlagsPtr = method.add(spec.method.accessFlagsOffset);
    const accessFlags = accessFlagsPtr.readU32();
    const adapter = spec.getAdapterPointer(method, constMethod);
    const i2iEntry = method.add(spec.method.i2iEntryOffset);
    const signatureHandler = method.add(spec.method.signatureHandlerOffset);
    const constantPool = constMethod.add(spec.constMethod.constantPoolOffset).readPointer();
    const stackmapPtr = constMethod.add(spec.constMethod.stackmapDataOffset);
    const instanceKlass = constantPool.add(spec.constantPool.instanceKlassOffset).readPointer();
    const cache = constantPool.add(spec.constantPool.cacheOffset).readPointer();
    const instanceKlassSpec = getJvmInstanceKlassSpec();
    const methods = instanceKlass.add(instanceKlassSpec.methodsOffset).readPointer();
    const methodsCount = methods.readS32();
    const methodsArray = methods.add(pointerSize6);
    const methodIndex = constMethod.add(spec.constMethod.methodIdnumOffset).readU16();
    const vtableIndexPtr = method.add(spec.method.vtableIndexOffset);
    const vtableIndex = vtableIndexPtr.readS32();
    const vtable2 = instanceKlass.add(instanceKlassSpec.vtableOffset);
    const oopMapCache = instanceKlass.add(instanceKlassSpec.oopMapCacheOffset).readPointer();
    const memberNames = api2.version >= 10 ? instanceKlass.add(instanceKlassSpec.memberNamesOffset).readPointer() : NULL;
    return {
      method,
      methodSize: spec.method.size,
      const: constMethod,
      constSize: constMethodSize,
      constPtr,
      dataPtr,
      countersPtr,
      stackmapPtr,
      instanceKlass,
      methodsArray,
      methodsCount,
      methodIndex,
      vtableIndex,
      vtableIndexPtr,
      vtable: vtable2,
      accessFlags,
      accessFlagsPtr,
      adapter,
      i2iEntry,
      signatureHandler,
      memberNames,
      cache,
      oopMapCache
    };
  }
  function revertJvmMethod(method) {
    const { oldMethod: old } = method;
    old.accessFlagsPtr.writeU32(old.accessFlags);
    old.vtableIndexPtr.writeS32(old.vtableIndex);
  }
  function _getJvmMethodSpec() {
    const api2 = getApi2();
    const { version } = api2;
    let adapterHandlerLocation;
    if (version >= 17) {
      adapterHandlerLocation = "method:early";
    } else if (version >= 9 && version <= 16) {
      adapterHandlerLocation = "const-method";
    } else {
      adapterHandlerLocation = "method:late";
    }
    const isNative = 1;
    const methodSize = api2["Method::size"](isNative) * pointerSize6;
    const constMethodOffset = pointerSize6;
    const methodDataOffset = 2 * pointerSize6;
    const methodCountersOffset = 3 * pointerSize6;
    const adapterInMethodEarlyOffset = 4 * pointerSize6;
    const adapterInMethodEarlySize = adapterHandlerLocation === "method:early" ? pointerSize6 : 0;
    const accessFlagsOffset = adapterInMethodEarlyOffset + adapterInMethodEarlySize;
    const vtableIndexOffset = accessFlagsOffset + 4;
    const i2iEntryOffset = vtableIndexOffset + 4 + 8;
    const adapterInMethodLateOffset = i2iEntryOffset + pointerSize6;
    const adapterInMethodOffset = adapterInMethodEarlySize !== 0 ? adapterInMethodEarlyOffset : adapterInMethodLateOffset;
    const nativeFunctionOffset = methodSize - 2 * pointerSize6;
    const signatureHandlerOffset = methodSize - pointerSize6;
    const constantPoolOffset = 8;
    const stackmapDataOffset = constantPoolOffset + pointerSize6;
    const adapterInConstMethodOffset = stackmapDataOffset + pointerSize6;
    const adapterInConstMethodSize = adapterHandlerLocation === "const-method" ? pointerSize6 : 0;
    const constMethodSizeOffset = adapterInConstMethodOffset + adapterInConstMethodSize;
    const methodIdnumOffset = constMethodSizeOffset + 14;
    const cacheOffset = 2 * pointerSize6;
    const instanceKlassOffset = 3 * pointerSize6;
    const getAdapterPointer = adapterInConstMethodSize !== 0 ? function(method, constMethod) {
      return constMethod.add(adapterInConstMethodOffset);
    } : function(method, constMethod) {
      return method.add(adapterInMethodOffset);
    };
    return {
      getAdapterPointer,
      method: {
        size: methodSize,
        constMethodOffset,
        methodDataOffset,
        methodCountersOffset,
        accessFlagsOffset,
        vtableIndexOffset,
        i2iEntryOffset,
        nativeFunctionOffset,
        signatureHandlerOffset
      },
      constMethod: {
        constantPoolOffset,
        stackmapDataOffset,
        sizeOffset: constMethodSizeOffset,
        methodIdnumOffset
      },
      constantPool: {
        cacheOffset,
        instanceKlassOffset
      }
    };
  }
  function _getJvmInstanceKlassSpec() {
    const { version: jvmVersion, createNewDefaultVtableIndices } = getApi2();
    const tryParse = vtableOffsetParsers[Process.arch];
    if (tryParse === void 0) {
      throw new Error(`Missing vtable offset parser for ${Process.arch}`);
    }
    const vtableOffset = parseInstructionsAt(createNewDefaultVtableIndices, tryParse, { limit: 32 });
    if (vtableOffset === null) {
      throw new Error("Unable to deduce vtable offset");
    }
    const oopMultiplier = jvmVersion >= 10 && jvmVersion <= 11 || jvmVersion >= 15 ? 17 : 18;
    const methodsOffset = vtableOffset - 7 * pointerSize6;
    const memberNamesOffset = vtableOffset - 17 * pointerSize6;
    const oopMapCacheOffset = vtableOffset - oopMultiplier * pointerSize6;
    return {
      vtableOffset,
      methodsOffset,
      memberNamesOffset,
      oopMapCacheOffset
    };
  }
  function parseX64VTableOffset(insn) {
    if (insn.mnemonic !== "mov") {
      return null;
    }
    const dst = insn.operands[0];
    if (dst.type !== "mem") {
      return null;
    }
    const { value: dstValue } = dst;
    if (dstValue.scale !== 1) {
      return null;
    }
    const { disp } = dstValue;
    if (disp < 256) {
      return null;
    }
    const defaultVtableIndicesOffset = disp;
    return defaultVtableIndicesOffset + 16;
  }
  var jsizeSize2, pointerSize6, JVM_ACC_NATIVE, JVM_ACC_IS_OLD, JVM_ACC_IS_OBSOLETE, JVM_ACC_NOT_C2_COMPILABLE, JVM_ACC_NOT_C1_COMPILABLE, JVM_ACC_NOT_C2_OSR_COMPILABLE, nativeFunctionOptions4, getJvmMethodSpec, getJvmInstanceKlassSpec, getJvmThreadSpec, cachedApi2, manglersScheduled, replaceManglers, revertManglers, threadOffsetParsers, JvmMethodMangler, vtableOffsetParsers;
  var init_jvm = __esm({
    "node_modules/frida-java-bridge/lib/jvm.js"() {
      init_node_globals();
      init_jvmti();
      init_machine_code();
      init_memoize();
      init_result();
      init_vm();
      jsizeSize2 = 4;
      ({ pointerSize: pointerSize6 } = Process);
      JVM_ACC_NATIVE = 256;
      JVM_ACC_IS_OLD = 65536;
      JVM_ACC_IS_OBSOLETE = 131072;
      JVM_ACC_NOT_C2_COMPILABLE = 33554432;
      JVM_ACC_NOT_C1_COMPILABLE = 67108864;
      JVM_ACC_NOT_C2_OSR_COMPILABLE = 134217728;
      nativeFunctionOptions4 = {
        exceptions: "propagate"
      };
      getJvmMethodSpec = memoize(_getJvmMethodSpec);
      getJvmInstanceKlassSpec = memoize(_getJvmInstanceKlassSpec);
      getJvmThreadSpec = memoize(_getJvmThreadSpec);
      cachedApi2 = null;
      manglersScheduled = false;
      replaceManglers = /* @__PURE__ */ new Map();
      revertManglers = /* @__PURE__ */ new Map();
      threadOffsetParsers = {
        x64: parseX64ThreadOffset
      };
      JvmMethodMangler = class {
        constructor(methodId) {
          this.methodId = methodId;
          this.method = methodId.readPointer();
          this.originalMethod = null;
          this.newMethod = null;
          this.resolved = null;
          this.impl = null;
          this.key = methodId.toString(16);
        }
        replace(impl, isInstanceMethod, argTypes, vm3, api2) {
          const { key } = this;
          const mangler = revertManglers.get(key);
          if (mangler !== void 0) {
            revertManglers.delete(key);
            this.method = mangler.method;
            this.originalMethod = mangler.originalMethod;
            this.newMethod = mangler.newMethod;
            this.resolved = mangler.resolved;
          }
          this.impl = impl;
          replaceManglers.set(key, this);
          ensureManglersScheduled(vm3);
        }
        revert(vm3) {
          const { key } = this;
          replaceManglers.delete(key);
          revertManglers.set(key, this);
          ensureManglersScheduled(vm3);
        }
        resolveTarget(wrapper, isInstanceMethod, env, api2) {
          const { resolved, originalMethod, methodId } = this;
          if (resolved !== null) {
            return resolved;
          }
          if (originalMethod === null) {
            return methodId;
          }
          const vip = originalMethod.oldMethod.vtableIndexPtr;
          vip.writeS32(-2);
          const jmethodID = Memory.alloc(pointerSize6);
          jmethodID.writePointer(this.method);
          this.resolved = jmethodID;
          return jmethodID;
        }
      };
      vtableOffsetParsers = {
        x64: parseX64VTableOffset
      };
    }
  });

  // node_modules/frida-java-bridge/lib/api.js
  var getApi3, api_default;
  var init_api = __esm({
    "node_modules/frida-java-bridge/lib/api.js"() {
      init_node_globals();
      init_android();
      init_jvm();
      getApi3 = getApi;
      try {
        getAndroidVersion();
      } catch (e) {
        getApi3 = getApi2;
      }
      api_default = getApi3;
    }
  });

  // node_modules/frida-java-bridge/lib/class-model.js
  function ensureInitialized(env) {
    if (cm === null) {
      cm = compileModule(env);
      unwrap = makeHandleUnwrapper(cm, env.vm);
    }
  }
  function compileModule(env) {
    const api2 = api_default();
    const { jvmti = null } = api2;
    const { pointerSize: pointerSize9 } = Process;
    const lockSize = 8;
    const modelsSize = pointerSize9;
    const javaApiSize = 7 * pointerSize9;
    const artApiSize = 10 * 4 + 5 * pointerSize9;
    const dataSize = lockSize + modelsSize + javaApiSize + artApiSize;
    const data = Memory.alloc(dataSize);
    const lock = data;
    const models = lock.add(lockSize);
    const javaApi = models.add(modelsSize);
    const { getDeclaredMethods, getDeclaredFields } = env.javaLangClass();
    const method = env.javaLangReflectMethod();
    const field = env.javaLangReflectField();
    let j = javaApi;
    [
      jvmti !== null ? jvmti : NULL,
      getDeclaredMethods,
      getDeclaredFields,
      method.getName,
      method.getModifiers,
      field.getName,
      field.getModifiers
    ].forEach((value) => {
      j = j.writePointer(value).add(pointerSize9);
    });
    const artApi = javaApi.add(javaApiSize);
    const { vm: vm3 } = env;
    if (api2.flavor === "art") {
      let artClassOffsets;
      if (jvmti !== null) {
        artClassOffsets = [0, 0, 0, 0];
      } else {
        const c = getArtClassSpec(vm3).offset;
        artClassOffsets = [c.ifields, c.methods, c.sfields, c.copiedMethodsOffset];
      }
      const m = getArtMethodSpec(vm3);
      const f = getArtFieldSpec(vm3);
      let s = artApi;
      [
        1,
        ...artClassOffsets,
        m.size,
        m.offset.accessFlags,
        f.size,
        f.offset.accessFlags,
        4294967295
      ].forEach((value) => {
        s = s.writeUInt(value).add(4);
      });
      [
        api2.artClassLinker.address,
        api2["art::ClassLinker::VisitClasses"],
        api2["art::mirror::Class::GetDescriptor"],
        api2["art::ArtMethod::PrettyMethod"],
        Process.getModuleByName("libc.so").getExportByName("free")
      ].forEach((value, i) => {
        if (value === void 0) {
          value = NULL;
        }
        s = s.writePointer(value).add(pointerSize9);
      });
    }
    const cm2 = new CModule(code2, {
      lock,
      models,
      java_api: javaApi,
      art_api: artApi
    });
    const reentrantOptions = { exceptions: "propagate" };
    const fastOptions = { exceptions: "propagate", scheduling: "exclusive" };
    return {
      handle: cm2,
      new: new NativeFunction(cm2.model_new, "pointer", ["pointer", "pointer", "pointer"], reentrantOptions),
      has: new NativeFunction(cm2.model_has, "bool", ["pointer", "pointer"], fastOptions),
      find: new NativeFunction(cm2.model_find, "pointer", ["pointer", "pointer"], fastOptions),
      list: new NativeFunction(cm2.model_list, "pointer", ["pointer"], fastOptions),
      enumerateMethodsArt: new NativeFunction(
        cm2.enumerate_methods_art,
        "pointer",
        ["pointer", "pointer", "bool", "bool", "bool"],
        reentrantOptions
      ),
      enumerateMethodsJvm: new NativeFunction(cm2.enumerate_methods_jvm, "pointer", [
        "pointer",
        "pointer",
        "bool",
        "bool",
        "bool",
        "pointer"
      ], reentrantOptions),
      dealloc: new NativeFunction(cm2.dealloc, "void", ["pointer"], fastOptions)
    };
  }
  function makeHandleUnwrapper(cm2, vm3) {
    const api2 = api_default();
    if (api2.flavor !== "art") {
      return nullUnwrap;
    }
    const decodeGlobal = api2["art::JavaVMExt::DecodeGlobal"];
    return function(handle, env, fn) {
      let result;
      withRunnableArtThread(vm3, env, (thread) => {
        const object = decodeGlobal(vm3, thread, handle);
        result = fn(object);
      });
      return result;
    };
  }
  function nullUnwrap(handle, env, fn) {
    return fn(NULL);
  }
  function boolToNative(val) {
    return val ? 1 : 0;
  }
  var code2, methodQueryPattern, cm, unwrap, Model;
  var init_class_model = __esm({
    "node_modules/frida-java-bridge/lib/class-model.js"() {
      init_node_globals();
      init_android();
      init_api();
      code2 = `#include <json-glib/json-glib.h>
#include <string.h>

#define kAccStatic 0x0008
#define kAccConstructor 0x00010000

typedef struct _Model Model;
typedef struct _EnumerateMethodsContext EnumerateMethodsContext;

typedef struct _JavaApi JavaApi;
typedef struct _JavaClassApi JavaClassApi;
typedef struct _JavaMethodApi JavaMethodApi;
typedef struct _JavaFieldApi JavaFieldApi;

typedef struct _JNIEnv JNIEnv;
typedef guint8 jboolean;
typedef gint32 jint;
typedef jint jsize;
typedef gpointer jobject;
typedef jobject jclass;
typedef jobject jstring;
typedef jobject jarray;
typedef jarray jobjectArray;
typedef gpointer jfieldID;
typedef gpointer jmethodID;

typedef struct _jvmtiEnv jvmtiEnv;
typedef enum
{
  JVMTI_ERROR_NONE = 0
} jvmtiError;

typedef struct _ArtApi ArtApi;
typedef guint32 ArtHeapReference;
typedef struct _ArtObject ArtObject;
typedef struct _ArtClass ArtClass;
typedef struct _ArtClassLinker ArtClassLinker;
typedef struct _ArtClassVisitor ArtClassVisitor;
typedef struct _ArtClassVisitorVTable ArtClassVisitorVTable;
typedef struct _ArtMethod ArtMethod;
typedef struct _ArtString ArtString;

typedef union _StdString StdString;
typedef struct _StdStringShort StdStringShort;
typedef struct _StdStringLong StdStringLong;

typedef void (* ArtVisitClassesFunc) (ArtClassLinker * linker, ArtClassVisitor * visitor);
typedef const char * (* ArtGetClassDescriptorFunc) (ArtClass * klass, StdString * storage);
typedef void (* ArtPrettyMethodFunc) (StdString * result, ArtMethod * method, jboolean with_signature);

struct _Model
{
  GHashTable * members;
};

struct _EnumerateMethodsContext
{
  GPatternSpec * class_query;
  GPatternSpec * method_query;
  jboolean include_signature;
  jboolean ignore_case;
  jboolean skip_system_classes;
  GHashTable * groups;
};

struct _JavaClassApi
{
  jmethodID get_declared_methods;
  jmethodID get_declared_fields;
};

struct _JavaMethodApi
{
  jmethodID get_name;
  jmethodID get_modifiers;
};

struct _JavaFieldApi
{
  jmethodID get_name;
  jmethodID get_modifiers;
};

struct _JavaApi
{
  jvmtiEnv * jvmti;
  JavaClassApi clazz;
  JavaMethodApi method;
  JavaFieldApi field;
};

struct _JNIEnv
{
  gpointer * functions;
};

struct _jvmtiEnv
{
  gpointer * functions;
};

struct _ArtApi
{
  gboolean available;

  guint class_offset_ifields;
  guint class_offset_methods;
  guint class_offset_sfields;
  guint class_offset_copied_methods_offset;

  guint method_size;
  guint method_offset_access_flags;

  guint field_size;
  guint field_offset_access_flags;

  guint alignment_padding;

  ArtClassLinker * linker;
  ArtVisitClassesFunc visit_classes;
  ArtGetClassDescriptorFunc get_class_descriptor;
  ArtPrettyMethodFunc pretty_method;

  void (* free) (gpointer mem);
};

struct _ArtObject
{
  ArtHeapReference klass;
  ArtHeapReference monitor;
};

struct _ArtClass
{
  ArtObject parent;

  ArtHeapReference class_loader;
};

struct _ArtClassVisitor
{
  ArtClassVisitorVTable * vtable;
  gpointer user_data;
};

struct _ArtClassVisitorVTable
{
  void (* reserved1) (ArtClassVisitor * self);
  void (* reserved2) (ArtClassVisitor * self);
  jboolean (* visit) (ArtClassVisitor * self, ArtClass * klass);
};

struct _ArtString
{
  ArtObject parent;

  gint32 count;
  guint32 hash_code;

  union
  {
    guint16 value[0];
    guint8 value_compressed[0];
  };
};

struct _StdStringShort
{
  guint8 size;
  gchar data[(3 * sizeof (gpointer)) - sizeof (guint8)];
};

struct _StdStringLong
{
  gsize capacity;
  gsize size;
  gchar * data;
};

union _StdString
{
  StdStringShort s;
  StdStringLong l;
};

static void model_add_method (Model * self, const gchar * name, jmethodID id, jint modifiers);
static void model_add_field (Model * self, const gchar * name, jfieldID id, jint modifiers);
static void model_free (Model * model);

static jboolean collect_matching_class_methods (ArtClassVisitor * self, ArtClass * klass);
static gchar * finalize_method_groups_to_json (GHashTable * groups);
static GPatternSpec * make_pattern_spec (const gchar * pattern, jboolean ignore_case);
static gchar * class_name_from_signature (const gchar * signature);
static gchar * format_method_signature (const gchar * name, const gchar * signature);
static void append_type (GString * output, const gchar ** type);

static gpointer read_art_array (gpointer object_base, guint field_offset, guint length_size, guint * length);

static void std_string_destroy (StdString * str);
static gchar * std_string_c_str (StdString * self);

extern GMutex lock;
extern GArray * models;
extern JavaApi java_api;
extern ArtApi art_api;

void
init (void)
{
  g_mutex_init (&lock);
  models = g_array_new (FALSE, FALSE, sizeof (Model *));
}

void
finalize (void)
{
  guint n, i;

  n = models->len;
  for (i = 0; i != n; i++)
  {
    Model * model = g_array_index (models, Model *, i);
    model_free (model);
  }

  g_array_unref (models);
  g_mutex_clear (&lock);
}

Model *
model_new (jclass class_handle,
           gpointer class_object,
           JNIEnv * env)
{
  Model * model;
  GHashTable * members;
  jvmtiEnv * jvmti = java_api.jvmti;
  gpointer * funcs = env->functions;
  jmethodID (* from_reflected_method) (JNIEnv *, jobject) = funcs[7];
  jfieldID (* from_reflected_field) (JNIEnv *, jobject) = funcs[8];
  jobject (* to_reflected_method) (JNIEnv *, jclass, jmethodID, jboolean) = funcs[9];
  jobject (* to_reflected_field) (JNIEnv *, jclass, jfieldID, jboolean) = funcs[12];
  void (* delete_local_ref) (JNIEnv *, jobject) = funcs[23];
  jobject (* call_object_method) (JNIEnv *, jobject, jmethodID, ...) = funcs[34];
  jint (* call_int_method) (JNIEnv *, jobject, jmethodID, ...) = funcs[49];
  const char * (* get_string_utf_chars) (JNIEnv *, jstring, jboolean *) = funcs[169];
  void (* release_string_utf_chars) (JNIEnv *, jstring, const char *) = funcs[170];
  jsize (* get_array_length) (JNIEnv *, jarray) = funcs[171];
  jobject (* get_object_array_element) (JNIEnv *, jobjectArray, jsize) = funcs[173];
  jsize n, i;

  model = g_new (Model, 1);

  members = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
  model->members = members;

  if (jvmti != NULL)
  {
    gpointer * jf = jvmti->functions - 1;
    jvmtiError (* deallocate) (jvmtiEnv *, void * mem) = jf[47];
    jvmtiError (* get_class_methods) (jvmtiEnv *, jclass, jint *, jmethodID **) = jf[52];
    jvmtiError (* get_class_fields) (jvmtiEnv *, jclass, jint *, jfieldID **) = jf[53];
    jvmtiError (* get_field_name) (jvmtiEnv *, jclass, jfieldID, char **, char **, char **) = jf[60];
    jvmtiError (* get_field_modifiers) (jvmtiEnv *, jclass, jfieldID, jint *) = jf[62];
    jvmtiError (* get_method_name) (jvmtiEnv *, jmethodID, char **, char **, char **) = jf[64];
    jvmtiError (* get_method_modifiers) (jvmtiEnv *, jmethodID, jint *) = jf[66];
    jint method_count;
    jmethodID * methods;
    jint field_count;
    jfieldID * fields;
    char * name;
    jint modifiers;

    get_class_methods (jvmti, class_handle, &method_count, &methods);
    for (i = 0; i != method_count; i++)
    {
      jmethodID method = methods[i];

      get_method_name (jvmti, method, &name, NULL, NULL);
      get_method_modifiers (jvmti, method, &modifiers);

      model_add_method (model, name, method, modifiers);

      deallocate (jvmti, name);
    }
    deallocate (jvmti, methods);

    get_class_fields (jvmti, class_handle, &field_count, &fields);
    for (i = 0; i != field_count; i++)
    {
      jfieldID field = fields[i];

      get_field_name (jvmti, class_handle, field, &name, NULL, NULL);
      get_field_modifiers (jvmti, class_handle, field, &modifiers);

      model_add_field (model, name, field, modifiers);

      deallocate (jvmti, name);
    }
    deallocate (jvmti, fields);
  }
  else if (art_api.available)
  {
    gpointer elements;
    guint n, i;
    const guint field_arrays[] = {
      art_api.class_offset_ifields,
      art_api.class_offset_sfields
    };
    guint field_array_cursor;
    gboolean merged_fields = art_api.class_offset_sfields == 0;

    elements = read_art_array (class_object, art_api.class_offset_methods, sizeof (gsize), NULL);
    n = *(guint16 *) (class_object + art_api.class_offset_copied_methods_offset);
    for (i = 0; i != n; i++)
    {
      jmethodID id;
      guint32 access_flags;
      jboolean is_static;
      jobject method, name;
      const char * name_str;
      jint modifiers;

      id = elements + (i * art_api.method_size);

      access_flags = *(guint32 *) (id + art_api.method_offset_access_flags);
      if ((access_flags & kAccConstructor) != 0)
        continue;
      is_static = (access_flags & kAccStatic) != 0;
      method = to_reflected_method (env, class_handle, id, is_static);
      name = call_object_method (env, method, java_api.method.get_name);
      name_str = get_string_utf_chars (env, name, NULL);
      modifiers = access_flags & 0xffff;

      model_add_method (model, name_str, id, modifiers);

      release_string_utf_chars (env, name, name_str);
      delete_local_ref (env, name);
      delete_local_ref (env, method);
    }

    for (field_array_cursor = 0; field_array_cursor != G_N_ELEMENTS (field_arrays); field_array_cursor++)
    {
      jboolean is_static;

      if (field_arrays[field_array_cursor] == 0)
        continue;

      if (!merged_fields)
        is_static = field_array_cursor == 1;

      elements = read_art_array (class_object, field_arrays[field_array_cursor], sizeof (guint32), &n);
      for (i = 0; i != n; i++)
      {
        jfieldID id;
        guint32 access_flags;
        jobject field, name;
        const char * name_str;
        jint modifiers;

        id = elements + (i * art_api.field_size);

        access_flags = *(guint32 *) (id + art_api.field_offset_access_flags);
        if (merged_fields)
          is_static = (access_flags & kAccStatic) != 0;
        field = to_reflected_field (env, class_handle, id, is_static);
        name = call_object_method (env, field, java_api.field.get_name);
        name_str = get_string_utf_chars (env, name, NULL);
        modifiers = access_flags & 0xffff;

        model_add_field (model, name_str, id, modifiers);

        release_string_utf_chars (env, name, name_str);
        delete_local_ref (env, name);
        delete_local_ref (env, field);
      }
    }
  }
  else
  {
    jobject elements;

    elements = call_object_method (env, class_handle, java_api.clazz.get_declared_methods);
    n = get_array_length (env, elements);
    for (i = 0; i != n; i++)
    {
      jobject method, name;
      const char * name_str;
      jmethodID id;
      jint modifiers;

      method = get_object_array_element (env, elements, i);
      name = call_object_method (env, method, java_api.method.get_name);
      name_str = get_string_utf_chars (env, name, NULL);
      id = from_reflected_method (env, method);
      modifiers = call_int_method (env, method, java_api.method.get_modifiers);

      model_add_method (model, name_str, id, modifiers);

      release_string_utf_chars (env, name, name_str);
      delete_local_ref (env, name);
      delete_local_ref (env, method);
    }
    delete_local_ref (env, elements);

    elements = call_object_method (env, class_handle, java_api.clazz.get_declared_fields);
    n = get_array_length (env, elements);
    for (i = 0; i != n; i++)
    {
      jobject field, name;
      const char * name_str;
      jfieldID id;
      jint modifiers;

      field = get_object_array_element (env, elements, i);
      name = call_object_method (env, field, java_api.field.get_name);
      name_str = get_string_utf_chars (env, name, NULL);
      id = from_reflected_field (env, field);
      modifiers = call_int_method (env, field, java_api.field.get_modifiers);

      model_add_field (model, name_str, id, modifiers);

      release_string_utf_chars (env, name, name_str);
      delete_local_ref (env, name);
      delete_local_ref (env, field);
    }
    delete_local_ref (env, elements);
  }

  g_mutex_lock (&lock);
  g_array_append_val (models, model);
  g_mutex_unlock (&lock);

  return model;
}

static void
model_add_method (Model * self,
                  const gchar * name,
                  jmethodID id,
                  jint modifiers)
{
  GHashTable * members = self->members;
  gchar * key, type;
  const gchar * value;

  if (name[0] == '$')
    key = g_strdup_printf ("_%s", name);
  else
    key = g_strdup (name);

  type = (modifiers & kAccStatic) != 0 ? 's' : 'i';

  value = g_hash_table_lookup (members, key);
  if (value == NULL)
    g_hash_table_insert (members, key, g_strdup_printf ("m:%c0x%zx", type, id));
  else
    g_hash_table_insert (members, key, g_strdup_printf ("%s:%c0x%zx", value, type, id));
}

static void
model_add_field (Model * self,
                 const gchar * name,
                 jfieldID id,
                 jint modifiers)
{
  GHashTable * members = self->members;
  gchar * key, type;

  if (name[0] == '$')
    key = g_strdup_printf ("_%s", name);
  else
    key = g_strdup (name);
  while (g_hash_table_contains (members, key))
  {
    gchar * new_key = g_strdup_printf ("_%s", key);
    g_free (key);
    key = new_key;
  }

  type = (modifiers & kAccStatic) != 0 ? 's' : 'i';

  g_hash_table_insert (members, key, g_strdup_printf ("f:%c0x%zx", type, id));
}

static void
model_free (Model * model)
{
  g_hash_table_unref (model->members);

  g_free (model);
}

gboolean
model_has (Model * self,
           const gchar * member)
{
  return g_hash_table_contains (self->members, member);
}

const gchar *
model_find (Model * self,
            const gchar * member)
{
  return g_hash_table_lookup (self->members, member);
}

gchar *
model_list (Model * self)
{
  GString * result;
  GHashTableIter iter;
  guint i;
  const gchar * name;

  result = g_string_sized_new (128);

  g_string_append_c (result, '[');

  g_hash_table_iter_init (&iter, self->members);
  for (i = 0; g_hash_table_iter_next (&iter, (gpointer *) &name, NULL); i++)
  {
    if (i > 0)
      g_string_append_c (result, ',');

    g_string_append_c (result, '"');
    g_string_append (result, name);
    g_string_append_c (result, '"');
  }

  g_string_append_c (result, ']');

  return g_string_free (result, FALSE);
}

gchar *
enumerate_methods_art (const gchar * class_query,
                       const gchar * method_query,
                       jboolean include_signature,
                       jboolean ignore_case,
                       jboolean skip_system_classes)
{
  gchar * result;
  EnumerateMethodsContext ctx;
  ArtClassVisitor visitor;
  ArtClassVisitorVTable visitor_vtable = { NULL, };

  ctx.class_query = make_pattern_spec (class_query, ignore_case);
  ctx.method_query = make_pattern_spec (method_query, ignore_case);
  ctx.include_signature = include_signature;
  ctx.ignore_case = ignore_case;
  ctx.skip_system_classes = skip_system_classes;
  ctx.groups = g_hash_table_new_full (NULL, NULL, NULL, NULL);

  visitor.vtable = &visitor_vtable;
  visitor.user_data = &ctx;

  visitor_vtable.visit = collect_matching_class_methods;

  art_api.visit_classes (art_api.linker, &visitor);

  result = finalize_method_groups_to_json (ctx.groups);

  g_hash_table_unref (ctx.groups);
  g_pattern_spec_free (ctx.method_query);
  g_pattern_spec_free (ctx.class_query);

  return result;
}

static jboolean
collect_matching_class_methods (ArtClassVisitor * self,
                                ArtClass * klass)
{
  EnumerateMethodsContext * ctx = self->user_data;
  const char * descriptor;
  StdString descriptor_storage = { 0, };
  gchar * class_name = NULL;
  gchar * class_name_copy = NULL;
  const gchar * normalized_class_name;
  JsonBuilder * group;
  size_t class_name_length;
  GHashTable * seen_method_names;
  gpointer elements;
  guint n, i;

  if (ctx->skip_system_classes && klass->class_loader == 0)
    goto skip_class;

  descriptor = art_api.get_class_descriptor (klass, &descriptor_storage);
  if (descriptor[0] != 'L')
    goto skip_class;

  class_name = class_name_from_signature (descriptor);

  if (ctx->ignore_case)
  {
    class_name_copy = g_utf8_strdown (class_name, -1);
    normalized_class_name = class_name_copy;
  }
  else
  {
    normalized_class_name = class_name;
  }

  if (!g_pattern_match_string (ctx->class_query, normalized_class_name))
    goto skip_class;

  group = NULL;
  class_name_length = strlen (class_name);
  seen_method_names = ctx->include_signature ? NULL : g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

  elements = read_art_array (klass, art_api.class_offset_methods, sizeof (gsize), NULL);
  n = *(guint16 *) ((gpointer) klass + art_api.class_offset_copied_methods_offset);
  for (i = 0; i != n; i++)
  {
    ArtMethod * method;
    guint32 access_flags;
    jboolean is_constructor;
    StdString method_name = { 0, };
    const gchar * bare_method_name;
    gchar * bare_method_name_copy = NULL;
    const gchar * normalized_method_name;
    gchar * normalized_method_name_copy = NULL;

    method = elements + (i * art_api.method_size);

    access_flags = *(guint32 *) ((gpointer) method + art_api.method_offset_access_flags);
    is_constructor = (access_flags & kAccConstructor) != 0;

    art_api.pretty_method (&method_name, method, ctx->include_signature);
    bare_method_name = std_string_c_str (&method_name);
    if (ctx->include_signature)
    {
      const gchar * return_type_end, * name_begin;
      GString * name;

      return_type_end = strchr (bare_method_name, ' ');
      name_begin = return_type_end + 1 + class_name_length + 1;
      if (is_constructor && g_str_has_prefix (name_begin, "<clinit>"))
        goto skip_method;

      name = g_string_sized_new (64);

      if (is_constructor)
      {
        g_string_append (name, "$init");
        g_string_append (name, strchr (name_begin, '>') + 1);
      }
      else
      {
        g_string_append (name, name_begin);
      }
      g_string_append (name, ": ");
      g_string_append_len (name, bare_method_name, return_type_end - bare_method_name);

      bare_method_name_copy = g_string_free (name, FALSE);
      bare_method_name = bare_method_name_copy;
    }
    else
    {
      const gchar * name_begin;

      name_begin = bare_method_name + class_name_length + 1;
      if (is_constructor && strcmp (name_begin, "<clinit>") == 0)
        goto skip_method;

      if (is_constructor)
        bare_method_name = "$init";
      else
        bare_method_name += class_name_length + 1;
    }

    if (seen_method_names != NULL && g_hash_table_contains (seen_method_names, bare_method_name))
      goto skip_method;

    if (ctx->ignore_case)
    {
      normalized_method_name_copy = g_utf8_strdown (bare_method_name, -1);
      normalized_method_name = normalized_method_name_copy;
    }
    else
    {
      normalized_method_name = bare_method_name;
    }

    if (!g_pattern_match_string (ctx->method_query, normalized_method_name))
      goto skip_method;

    if (group == NULL)
    {
      group = g_hash_table_lookup (ctx->groups, GUINT_TO_POINTER (klass->class_loader));
      if (group == NULL)
      {
        group = json_builder_new_immutable ();
        g_hash_table_insert (ctx->groups, GUINT_TO_POINTER (klass->class_loader), group);

        json_builder_begin_object (group);

        json_builder_set_member_name (group, "loader");
        json_builder_add_int_value (group, klass->class_loader);

        json_builder_set_member_name (group, "classes");
        json_builder_begin_array (group);
      }

      json_builder_begin_object (group);

      json_builder_set_member_name (group, "name");
      json_builder_add_string_value (group, class_name);

      json_builder_set_member_name (group, "methods");
      json_builder_begin_array (group);
    }

    json_builder_add_string_value (group, bare_method_name);

    if (seen_method_names != NULL)
      g_hash_table_add (seen_method_names, g_strdup (bare_method_name));

skip_method:
    g_free (normalized_method_name_copy);
    g_free (bare_method_name_copy);
    std_string_destroy (&method_name);
  }

  if (seen_method_names != NULL)
    g_hash_table_unref (seen_method_names);

  if (group == NULL)
    goto skip_class;

  json_builder_end_array (group);
  json_builder_end_object (group);

skip_class:
  g_free (class_name_copy);
  g_free (class_name);
  std_string_destroy (&descriptor_storage);

  return TRUE;
}

gchar *
enumerate_methods_jvm (const gchar * class_query,
                       const gchar * method_query,
                       jboolean include_signature,
                       jboolean ignore_case,
                       jboolean skip_system_classes,
                       JNIEnv * env)
{
  gchar * result;
  GPatternSpec * class_pattern, * method_pattern;
  GHashTable * groups;
  gpointer * ef = env->functions;
  jobject (* new_global_ref) (JNIEnv *, jobject) = ef[21];
  void (* delete_local_ref) (JNIEnv *, jobject) = ef[23];
  jboolean (* is_same_object) (JNIEnv *, jobject, jobject) = ef[24];
  jvmtiEnv * jvmti = java_api.jvmti;
  gpointer * jf = jvmti->functions - 1;
  jvmtiError (* deallocate) (jvmtiEnv *, void * mem) = jf[47];
  jvmtiError (* get_class_signature) (jvmtiEnv *, jclass, char **, char **) = jf[48];
  jvmtiError (* get_class_methods) (jvmtiEnv *, jclass, jint *, jmethodID **) = jf[52];
  jvmtiError (* get_class_loader) (jvmtiEnv *, jclass, jobject *) = jf[57];
  jvmtiError (* get_method_name) (jvmtiEnv *, jmethodID, char **, char **, char **) = jf[64];
  jvmtiError (* get_loaded_classes) (jvmtiEnv *, jint *, jclass **) = jf[78];
  jint class_count, class_index;
  jclass * classes;

  class_pattern = make_pattern_spec (class_query, ignore_case);
  method_pattern = make_pattern_spec (method_query, ignore_case);
  groups = g_hash_table_new_full (NULL, NULL, NULL, NULL);

  if (get_loaded_classes (jvmti, &class_count, &classes) != JVMTI_ERROR_NONE)
    goto emit_results;

  for (class_index = 0; class_index != class_count; class_index++)
  {
    jclass klass = classes[class_index];
    jobject loader = NULL;
    gboolean have_loader = FALSE;
    char * signature = NULL;
    gchar * class_name = NULL;
    gchar * class_name_copy = NULL;
    const gchar * normalized_class_name;
    jint method_count, method_index;
    jmethodID * methods = NULL;
    JsonBuilder * group = NULL;
    GHashTable * seen_method_names = NULL;

    if (skip_system_classes)
    {
      if (get_class_loader (jvmti, klass, &loader) != JVMTI_ERROR_NONE)
        goto skip_class;
      have_loader = TRUE;

      if (loader == NULL)
        goto skip_class;
    }

    if (get_class_signature (jvmti, klass, &signature, NULL) != JVMTI_ERROR_NONE)
      goto skip_class;

    class_name = class_name_from_signature (signature);

    if (ignore_case)
    {
      class_name_copy = g_utf8_strdown (class_name, -1);
      normalized_class_name = class_name_copy;
    }
    else
    {
      normalized_class_name = class_name;
    }

    if (!g_pattern_match_string (class_pattern, normalized_class_name))
      goto skip_class;

    if (get_class_methods (jvmti, klass, &method_count, &methods) != JVMTI_ERROR_NONE)
      goto skip_class;

    if (!include_signature)
      seen_method_names = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

    for (method_index = 0; method_index != method_count; method_index++)
    {
      jmethodID method = methods[method_index];
      const gchar * method_name;
      char * method_name_value = NULL;
      char * method_signature_value = NULL;
      gchar * method_name_copy = NULL;
      const gchar * normalized_method_name;
      gchar * normalized_method_name_copy = NULL;

      if (get_method_name (jvmti, method, &method_name_value, include_signature ? &method_signature_value : NULL, NULL) != JVMTI_ERROR_NONE)
        goto skip_method;
      method_name = method_name_value;

      if (method_name[0] == '<')
      {
        if (strcmp (method_name, "<init>") == 0)
          method_name = "$init";
        else if (strcmp (method_name, "<clinit>") == 0)
          goto skip_method;
      }

      if (include_signature)
      {
        method_name_copy = format_method_signature (method_name, method_signature_value);
        method_name = method_name_copy;
      }

      if (seen_method_names != NULL && g_hash_table_contains (seen_method_names, method_name))
        goto skip_method;

      if (ignore_case)
      {
        normalized_method_name_copy = g_utf8_strdown (method_name, -1);
        normalized_method_name = normalized_method_name_copy;
      }
      else
      {
        normalized_method_name = method_name;
      }

      if (!g_pattern_match_string (method_pattern, normalized_method_name))
        goto skip_method;

      if (group == NULL)
      {
        if (!have_loader && get_class_loader (jvmti, klass, &loader) != JVMTI_ERROR_NONE)
          goto skip_method;

        if (loader == NULL)
        {
          group = g_hash_table_lookup (groups, NULL);
        }
        else
        {
          GHashTableIter iter;
          jobject cur_loader;
          JsonBuilder * cur_group;

          g_hash_table_iter_init (&iter, groups);
          while (g_hash_table_iter_next (&iter, (gpointer *) &cur_loader, (gpointer *) &cur_group))
          {
            if (cur_loader != NULL && is_same_object (env, cur_loader, loader))
            {
              group = cur_group;
              break;
            }
          }
        }

        if (group == NULL)
        {
          jobject l;
          gchar * str;

          l = (loader != NULL) ? new_global_ref (env, loader) : NULL;

          group = json_builder_new_immutable ();
          g_hash_table_insert (groups, l, group);

          json_builder_begin_object (group);

          json_builder_set_member_name (group, "loader");
          str = g_strdup_printf ("0x%" G_GSIZE_MODIFIER "x", GPOINTER_TO_SIZE (l));
          json_builder_add_string_value (group, str);
          g_free (str);

          json_builder_set_member_name (group, "classes");
          json_builder_begin_array (group);
        }

        json_builder_begin_object (group);

        json_builder_set_member_name (group, "name");
        json_builder_add_string_value (group, class_name);

        json_builder_set_member_name (group, "methods");
        json_builder_begin_array (group);
      }

      json_builder_add_string_value (group, method_name);

      if (seen_method_names != NULL)
        g_hash_table_add (seen_method_names, g_strdup (method_name));

skip_method:
      g_free (normalized_method_name_copy);
      g_free (method_name_copy);
      deallocate (jvmti, method_signature_value);
      deallocate (jvmti, method_name_value);
    }

skip_class:
    if (group != NULL)
    {
      json_builder_end_array (group);
      json_builder_end_object (group);
    }

    if (seen_method_names != NULL)
      g_hash_table_unref (seen_method_names);

    deallocate (jvmti, methods);

    g_free (class_name_copy);
    g_free (class_name);
    deallocate (jvmti, signature);

    if (loader != NULL)
      delete_local_ref (env, loader);

    delete_local_ref (env, klass);
  }

  deallocate (jvmti, classes);

emit_results:
  result = finalize_method_groups_to_json (groups);

  g_hash_table_unref (groups);
  g_pattern_spec_free (method_pattern);
  g_pattern_spec_free (class_pattern);

  return result;
}

static gchar *
finalize_method_groups_to_json (GHashTable * groups)
{
  GString * result;
  GHashTableIter iter;
  guint i;
  JsonBuilder * group;

  result = g_string_sized_new (1024);

  g_string_append_c (result, '[');

  g_hash_table_iter_init (&iter, groups);
  for (i = 0; g_hash_table_iter_next (&iter, NULL, (gpointer *) &group); i++)
  {
    JsonNode * root;
    gchar * json;

    if (i > 0)
      g_string_append_c (result, ',');

    json_builder_end_array (group);
    json_builder_end_object (group);

    root = json_builder_get_root (group);
    json = json_to_string (root, FALSE);
    g_string_append (result, json);
    g_free (json);
    json_node_unref (root);

    g_object_unref (group);
  }

  g_string_append_c (result, ']');

  return g_string_free (result, FALSE);
}

static GPatternSpec *
make_pattern_spec (const gchar * pattern,
                   jboolean ignore_case)
{
  GPatternSpec * spec;

  if (ignore_case)
  {
    gchar * str = g_utf8_strdown (pattern, -1);
    spec = g_pattern_spec_new (str);
    g_free (str);
  }
  else
  {
    spec = g_pattern_spec_new (pattern);
  }

  return spec;
}

static gchar *
class_name_from_signature (const gchar * descriptor)
{
  gchar * result, * c;

  result = g_strdup (descriptor + 1);

  for (c = result; *c != '\\0'; c++)
  {
    if (*c == '/')
      *c = '.';
  }

  c[-1] = '\\0';

  return result;
}

static gchar *
format_method_signature (const gchar * name,
                         const gchar * signature)
{
  GString * sig;
  const gchar * cursor;
  gint arg_index;

  sig = g_string_sized_new (128);

  g_string_append (sig, name);

  cursor = signature;
  arg_index = -1;
  while (TRUE)
  {
    const gchar c = *cursor;

    if (c == '(')
    {
      g_string_append_c (sig, c);
      cursor++;
      arg_index = 0;
    }
    else if (c == ')')
    {
      g_string_append_c (sig, c);
      cursor++;
      break;
    }
    else
    {
      if (arg_index >= 1)
        g_string_append (sig, ", ");

      append_type (sig, &cursor);

      if (arg_index != -1)
        arg_index++;
    }
  }

  g_string_append (sig, ": ");
  append_type (sig, &cursor);

  return g_string_free (sig, FALSE);
}

static void
append_type (GString * output,
             const gchar ** type)
{
  const gchar * cursor = *type;

  switch (*cursor)
  {
    case 'Z':
      g_string_append (output, "boolean");
      cursor++;
      break;
    case 'B':
      g_string_append (output, "byte");
      cursor++;
      break;
    case 'C':
      g_string_append (output, "char");
      cursor++;
      break;
    case 'S':
      g_string_append (output, "short");
      cursor++;
      break;
    case 'I':
      g_string_append (output, "int");
      cursor++;
      break;
    case 'J':
      g_string_append (output, "long");
      cursor++;
      break;
    case 'F':
      g_string_append (output, "float");
      cursor++;
      break;
    case 'D':
      g_string_append (output, "double");
      cursor++;
      break;
    case 'V':
      g_string_append (output, "void");
      cursor++;
      break;
    case 'L':
    {
      gchar ch;

      cursor++;
      for (; (ch = *cursor) != ';'; cursor++)
      {
        g_string_append_c (output, (ch != '/') ? ch : '.');
      }
      cursor++;

      break;
    }
    case '[':
      *type = cursor + 1;
      append_type (output, type);
      g_string_append (output, "[]");
      return;
    default:
      g_string_append (output, "BUG");
      cursor++;
  }

  *type = cursor;
}

void
dealloc (gpointer mem)
{
  g_free (mem);
}

static gpointer
read_art_array (gpointer object_base,
                guint field_offset,
                guint length_size,
                guint * length)
{
  gpointer result, header;
  guint n;

  header = GSIZE_TO_POINTER (*(guint64 *) (object_base + field_offset));
  if (header != NULL)
  {
    result = header + length_size;
    if (length_size == sizeof (guint32))
      n = *(guint32 *) header;
    else
      n = *(guint64 *) header;
  }
  else
  {
    result = NULL;
    n = 0;
  }

  if (length != NULL)
    *length = n;

  return result;
}

static void
std_string_destroy (StdString * str)
{
  if ((str->l.capacity & 1) != 0)
    art_api.free (str->l.data);
}

static gchar *
std_string_c_str (StdString * self)
{
  if ((self->l.capacity & 1) != 0)
    return self->l.data;

  return self->s.data;
}
`;
      methodQueryPattern = /(.+)!([^/]+)\/?([isu]+)?/;
      cm = null;
      unwrap = null;
      Model = class _Model {
        static build(handle, env) {
          ensureInitialized(env);
          return unwrap(handle, env, (object) => {
            return new _Model(cm.new(handle, object, env));
          });
        }
        static enumerateMethods(query, api2, env) {
          ensureInitialized(env);
          const params = query.match(methodQueryPattern);
          if (params === null) {
            throw new Error("Invalid query; format is: class!method -- see documentation of Java.enumerateMethods(query) for details");
          }
          const classQuery = Memory.allocUtf8String(params[1]);
          const methodQuery = Memory.allocUtf8String(params[2]);
          let includeSignature = false;
          let ignoreCase = false;
          let skipSystemClasses = false;
          const modifiers = params[3];
          if (modifiers !== void 0) {
            includeSignature = modifiers.indexOf("s") !== -1;
            ignoreCase = modifiers.indexOf("i") !== -1;
            skipSystemClasses = modifiers.indexOf("u") !== -1;
          }
          let result;
          if (api2.jvmti !== null) {
            const json = cm.enumerateMethodsJvm(
              classQuery,
              methodQuery,
              boolToNative(includeSignature),
              boolToNative(ignoreCase),
              boolToNative(skipSystemClasses),
              env
            );
            try {
              result = JSON.parse(json.readUtf8String()).map((group) => {
                const loaderRef = ptr(group.loader);
                group.loader = !loaderRef.isNull() ? loaderRef : null;
                return group;
              });
            } finally {
              cm.dealloc(json);
            }
          } else {
            withRunnableArtThread(env.vm, env, (thread) => {
              const json = cm.enumerateMethodsArt(
                classQuery,
                methodQuery,
                boolToNative(includeSignature),
                boolToNative(ignoreCase),
                boolToNative(skipSystemClasses)
              );
              try {
                const addGlobalReference = api2["art::JavaVMExt::AddGlobalRef"];
                const { vm: vmHandle } = api2;
                result = JSON.parse(json.readUtf8String()).map((group) => {
                  const loaderObj = group.loader;
                  group.loader = loaderObj !== 0 ? addGlobalReference(vmHandle, thread, ptr(loaderObj)) : null;
                  return group;
                });
              } finally {
                cm.dealloc(json);
              }
            });
          }
          return result;
        }
        constructor(handle) {
          this.handle = handle;
        }
        has(member) {
          return cm.has(this.handle, Memory.allocUtf8String(member)) !== 0;
        }
        find(member) {
          return cm.find(this.handle, Memory.allocUtf8String(member)).readUtf8String();
        }
        list() {
          const str = cm.list(this.handle);
          try {
            return JSON.parse(str.readUtf8String());
          } finally {
            cm.dealloc(str);
          }
        }
      };
    }
  });

  // node_modules/frida-java-bridge/lib/lru.js
  var LRU;
  var init_lru = __esm({
    "node_modules/frida-java-bridge/lib/lru.js"() {
      init_node_globals();
      LRU = class {
        constructor(capacity, destroy) {
          this.items = /* @__PURE__ */ new Map();
          this.capacity = capacity;
          this.destroy = destroy;
        }
        dispose(env) {
          const { items, destroy } = this;
          items.forEach((val) => {
            destroy(val, env);
          });
          items.clear();
        }
        get(key) {
          const { items } = this;
          const item = items.get(key);
          if (item !== void 0) {
            items.delete(key);
            items.set(key, item);
          }
          return item;
        }
        set(key, val, env) {
          const { items } = this;
          const existingVal = items.get(key);
          if (existingVal !== void 0) {
            items.delete(key);
            this.destroy(existingVal, env);
          } else if (items.size === this.capacity) {
            const oldestKey = items.keys().next().value;
            const oldestVal = items.get(oldestKey);
            items.delete(oldestKey);
            this.destroy(oldestVal, env);
          }
          items.set(key, val);
        }
      };
    }
  });

  // node_modules/frida-java-bridge/lib/mkdex.js
  function mkdex(spec) {
    const builder = new DexBuilder();
    const fullSpec = Object.assign({}, spec);
    builder.addClass(fullSpec);
    return builder.build();
  }
  function makeClassData(klass) {
    const { instanceFields, constructorMethods, virtualMethods } = klass.classData;
    const staticFieldsSize = 0;
    return Buffer2.from([
      staticFieldsSize
    ].concat(createUleb128(instanceFields.length)).concat(createUleb128(constructorMethods.length)).concat(createUleb128(virtualMethods.length)).concat(instanceFields.reduce((result, [indexDiff, accessFlags]) => {
      return result.concat(createUleb128(indexDiff)).concat(createUleb128(accessFlags));
    }, [])).concat(constructorMethods.reduce((result, [indexDiff, accessFlags, , codeOffset]) => {
      return result.concat(createUleb128(indexDiff)).concat(createUleb128(accessFlags)).concat(createUleb128(codeOffset || 0));
    }, [])).concat(virtualMethods.reduce((result, [indexDiff, accessFlags]) => {
      const codeOffset = 0;
      return result.concat(createUleb128(indexDiff)).concat(createUleb128(accessFlags)).concat([codeOffset]);
    }, [])));
  }
  function makeThrowsAnnotation(annotation) {
    const { thrownTypes } = annotation;
    return Buffer2.from(
      [
        VISIBILITY_SYSTEM
      ].concat(createUleb128(annotation.type)).concat([1]).concat(createUleb128(annotation.value)).concat([VALUE_ARRAY, thrownTypes.length]).concat(thrownTypes.reduce((result, type) => {
        result.push(VALUE_TYPE, type);
        return result;
      }, []))
    );
  }
  function computeModel(classes) {
    const strings = /* @__PURE__ */ new Set();
    const types = /* @__PURE__ */ new Set();
    const protos = {};
    const fields = [];
    const methods = [];
    const throwsAnnotations = {};
    const javaConstructors = /* @__PURE__ */ new Set();
    const superConstructors = /* @__PURE__ */ new Set();
    classes.forEach((klass) => {
      const { name, superClass, sourceFileName } = klass;
      strings.add("this");
      strings.add(name);
      types.add(name);
      strings.add(superClass);
      types.add(superClass);
      strings.add(sourceFileName);
      klass.interfaces.forEach((iface) => {
        strings.add(iface);
        types.add(iface);
      });
      klass.fields.forEach((field) => {
        const [fieldName, fieldType] = field;
        strings.add(fieldName);
        strings.add(fieldType);
        types.add(fieldType);
        fields.push([klass.name, fieldType, fieldName]);
      });
      if (!klass.methods.some(([methodName]) => methodName === "<init>")) {
        klass.methods.unshift(["<init>", "V", []]);
        javaConstructors.add(name);
      }
      klass.methods.forEach((method) => {
        const [methodName, retType, argTypes, thrownTypes = [], accessFlags] = method;
        strings.add(methodName);
        const protoId = addProto(retType, argTypes);
        let throwsAnnotationId = null;
        if (thrownTypes.length > 0) {
          const typesNormalized = thrownTypes.slice();
          typesNormalized.sort();
          throwsAnnotationId = typesNormalized.join("|");
          let throwsAnnotation = throwsAnnotations[throwsAnnotationId];
          if (throwsAnnotation === void 0) {
            throwsAnnotation = {
              id: throwsAnnotationId,
              types: typesNormalized
            };
            throwsAnnotations[throwsAnnotationId] = throwsAnnotation;
          }
          strings.add(kDalvikAnnotationTypeThrows);
          types.add(kDalvikAnnotationTypeThrows);
          thrownTypes.forEach((type) => {
            strings.add(type);
            types.add(type);
          });
          strings.add("value");
        }
        methods.push([klass.name, protoId, methodName, throwsAnnotationId, accessFlags]);
        if (methodName === "<init>") {
          superConstructors.add(name + "|" + protoId);
          const superConstructorId = superClass + "|" + protoId;
          if (javaConstructors.has(name) && !superConstructors.has(superConstructorId)) {
            methods.push([superClass, protoId, methodName, null, 0]);
            superConstructors.add(superConstructorId);
          }
        }
      });
    });
    function addProto(retType, argTypes) {
      const signature = [retType].concat(argTypes);
      const id = signature.join("|");
      if (protos[id] !== void 0) {
        return id;
      }
      strings.add(retType);
      types.add(retType);
      argTypes.forEach((argType) => {
        strings.add(argType);
        types.add(argType);
      });
      const shorty = signature.map(typeToShorty).join("");
      strings.add(shorty);
      protos[id] = [id, shorty, retType, argTypes];
      return id;
    }
    const stringItems = Array.from(strings);
    stringItems.sort();
    const stringToIndex = stringItems.reduce((result, string, index) => {
      result[string] = index;
      return result;
    }, {});
    const typeItems = Array.from(types).map((name) => stringToIndex[name]);
    typeItems.sort(compareNumbers);
    const typeToIndex = typeItems.reduce((result, stringIndex, typeIndex) => {
      result[stringItems[stringIndex]] = typeIndex;
      return result;
    }, {});
    const literalProtoItems = Object.keys(protos).map((id) => protos[id]);
    literalProtoItems.sort(compareProtoItems);
    const parameters = {};
    const protoItems = literalProtoItems.map((item) => {
      const [, shorty, retType, argTypes] = item;
      let params;
      if (argTypes.length > 0) {
        const argTypesSig = argTypes.join("|");
        params = parameters[argTypesSig];
        if (params === void 0) {
          params = {
            types: argTypes.map((type) => typeToIndex[type]),
            offset: -1
          };
          parameters[argTypesSig] = params;
        }
      } else {
        params = null;
      }
      return [
        stringToIndex[shorty],
        typeToIndex[retType],
        params
      ];
    });
    const protoToIndex = literalProtoItems.reduce((result, item, index) => {
      const [id] = item;
      result[id] = index;
      return result;
    }, {});
    const parameterItems = Object.keys(parameters).map((id) => parameters[id]);
    const fieldItems = fields.map((field) => {
      const [klass, fieldType, fieldName] = field;
      return [
        typeToIndex[klass],
        typeToIndex[fieldType],
        stringToIndex[fieldName]
      ];
    });
    fieldItems.sort(compareFieldItems);
    const methodItems = methods.map((method) => {
      const [klass, protoId, name, annotationsId, accessFlags] = method;
      return [
        typeToIndex[klass],
        protoToIndex[protoId],
        stringToIndex[name],
        annotationsId,
        accessFlags
      ];
    });
    methodItems.sort(compareMethodItems);
    const throwsAnnotationItems = Object.keys(throwsAnnotations).map((id) => throwsAnnotations[id]).map((item) => {
      return {
        id: item.id,
        type: typeToIndex[kDalvikAnnotationTypeThrows],
        value: stringToIndex.value,
        thrownTypes: item.types.map((type) => typeToIndex[type]),
        offset: -1
      };
    });
    const annotationSetItems = throwsAnnotationItems.map((item) => {
      return {
        id: item.id,
        items: [item],
        offset: -1
      };
    });
    const annotationSetIdToIndex = annotationSetItems.reduce((result, item, index) => {
      result[item.id] = index;
      return result;
    }, {});
    const interfaceLists = {};
    const annotationDirectories = [];
    const classItems = classes.map((klass) => {
      const classIndex = typeToIndex[klass.name];
      const accessFlags = kAccPublic2;
      const superClassIndex = typeToIndex[klass.superClass];
      let ifaceList;
      const ifaces = klass.interfaces.map((type) => typeToIndex[type]);
      if (ifaces.length > 0) {
        ifaces.sort(compareNumbers);
        const ifacesId = ifaces.join("|");
        ifaceList = interfaceLists[ifacesId];
        if (ifaceList === void 0) {
          ifaceList = {
            types: ifaces,
            offset: -1
          };
          interfaceLists[ifacesId] = ifaceList;
        }
      } else {
        ifaceList = null;
      }
      const sourceFileIndex = stringToIndex[klass.sourceFileName];
      const classMethods = methodItems.reduce((result, method, index) => {
        const [holder, protoIndex, name, annotationsId, accessFlags2] = method;
        if (holder === classIndex) {
          result.push([index, name, annotationsId, protoIndex, accessFlags2]);
        }
        return result;
      }, []);
      let annotationsDirectory = null;
      const methodAnnotations = classMethods.filter(([, , annotationsId]) => {
        return annotationsId !== null;
      }).map(([index, , annotationsId]) => {
        return [index, annotationSetItems[annotationSetIdToIndex[annotationsId]]];
      });
      if (methodAnnotations.length > 0) {
        annotationsDirectory = {
          methods: methodAnnotations,
          offset: -1
        };
        annotationDirectories.push(annotationsDirectory);
      }
      const instanceFields = fieldItems.reduce((result, field, index) => {
        const [holder] = field;
        if (holder === classIndex) {
          result.push([index > 0 ? 1 : 0, kAccPublic2]);
        }
        return result;
      }, []);
      const constructorNameIndex = stringToIndex["<init>"];
      const constructorMethods = classMethods.filter(([, name]) => name === constructorNameIndex).map(([index, , , protoIndex]) => {
        if (javaConstructors.has(klass.name)) {
          let superConstructor = -1;
          const numMethodItems = methodItems.length;
          for (let i = 0; i !== numMethodItems; i++) {
            const [methodClass, methodProto, methodName] = methodItems[i];
            if (methodClass === superClassIndex && methodName === constructorNameIndex && methodProto === protoIndex) {
              superConstructor = i;
              break;
            }
          }
          return [index, kAccPublic2 | kAccConstructor, superConstructor];
        } else {
          return [index, kAccPublic2 | kAccConstructor | kAccNative2, -1];
        }
      });
      const virtualMethods = compressClassMethodIndexes(classMethods.filter(([, name]) => name !== constructorNameIndex).map(([index, , , , accessFlags2]) => {
        return [index, accessFlags2 | kAccPublic2 | kAccNative2];
      }));
      const classData = {
        instanceFields,
        constructorMethods,
        virtualMethods,
        offset: -1
      };
      return {
        index: classIndex,
        accessFlags,
        superClassIndex,
        interfaces: ifaceList,
        sourceFileIndex,
        annotationsDirectory,
        classData
      };
    });
    const interfaceItems = Object.keys(interfaceLists).map((id) => interfaceLists[id]);
    return {
      classes: classItems,
      interfaces: interfaceItems,
      fields: fieldItems,
      methods: methodItems,
      protos: protoItems,
      parameters: parameterItems,
      annotationDirectories,
      annotationSets: annotationSetItems,
      throwsAnnotations: throwsAnnotationItems,
      types: typeItems,
      strings: stringItems
    };
  }
  function compressClassMethodIndexes(items) {
    let previousIndex = 0;
    return items.map(([index, accessFlags], elementIndex) => {
      let result;
      if (elementIndex === 0) {
        result = [index, accessFlags];
      } else {
        result = [index - previousIndex, accessFlags];
      }
      previousIndex = index;
      return result;
    });
  }
  function compareNumbers(a, b) {
    return a - b;
  }
  function compareProtoItems(a, b) {
    const [, , aRetType, aArgTypes] = a;
    const [, , bRetType, bArgTypes] = b;
    if (aRetType < bRetType) {
      return -1;
    }
    if (aRetType > bRetType) {
      return 1;
    }
    const aArgTypesSig = aArgTypes.join("|");
    const bArgTypesSig = bArgTypes.join("|");
    if (aArgTypesSig < bArgTypesSig) {
      return -1;
    }
    if (aArgTypesSig > bArgTypesSig) {
      return 1;
    }
    return 0;
  }
  function compareFieldItems(a, b) {
    const [aClass, aType, aName] = a;
    const [bClass, bType, bName] = b;
    if (aClass !== bClass) {
      return aClass - bClass;
    }
    if (aName !== bName) {
      return aName - bName;
    }
    return aType - bType;
  }
  function compareMethodItems(a, b) {
    const [aClass, aProto, aName] = a;
    const [bClass, bProto, bName] = b;
    if (aClass !== bClass) {
      return aClass - bClass;
    }
    if (aName !== bName) {
      return aName - bName;
    }
    return aProto - bProto;
  }
  function typeToShorty(type) {
    const firstCharacter = type[0];
    return firstCharacter === "L" || firstCharacter === "[" ? "L" : type;
  }
  function createUleb128(value) {
    if (value <= 127) {
      return [value];
    }
    const result = [];
    let moreSlicesNeeded = false;
    do {
      let slice2 = value & 127;
      value >>= 7;
      moreSlicesNeeded = value !== 0;
      if (moreSlicesNeeded) {
        slice2 |= 128;
      }
      result.push(slice2);
    } while (moreSlicesNeeded);
    return result;
  }
  function align(value, alignment) {
    const alignmentDelta = value % alignment;
    if (alignmentDelta === 0) {
      return value;
    }
    return value + alignment - alignmentDelta;
  }
  function adler32(buffer, offset) {
    let a = 1;
    let b = 0;
    const length = buffer.length;
    for (let i = offset; i < length; i++) {
      a = (a + buffer[i]) % 65521;
      b = (b + a) % 65521;
    }
    return (b << 16 | a) >>> 0;
  }
  var kAccPublic2, kAccNative2, kAccConstructor, kEndianTag, kClassDefSize, kProtoIdSize, kFieldIdSize, kMethodIdSize, kTypeIdSize, kStringIdSize, kMapItemSize, TYPE_HEADER_ITEM, TYPE_STRING_ID_ITEM, TYPE_TYPE_ID_ITEM, TYPE_PROTO_ID_ITEM, TYPE_FIELD_ID_ITEM, TYPE_METHOD_ID_ITEM, TYPE_CLASS_DEF_ITEM, TYPE_MAP_LIST, TYPE_TYPE_LIST, TYPE_ANNOTATION_SET_ITEM, TYPE_CLASS_DATA_ITEM, TYPE_CODE_ITEM, TYPE_STRING_DATA_ITEM, TYPE_DEBUG_INFO_ITEM, TYPE_ANNOTATION_ITEM, TYPE_ANNOTATIONS_DIRECTORY_ITEM, VALUE_TYPE, VALUE_ARRAY, VISIBILITY_SYSTEM, kDefaultConstructorSize, kDefaultConstructorDebugInfo, kDalvikAnnotationTypeThrows, kNullTerminator, DexBuilder, mkdex_default;
  var init_mkdex = __esm({
    "node_modules/frida-java-bridge/lib/mkdex.js"() {
      init_node_globals();
      init_buffer();
      kAccPublic2 = 1;
      kAccNative2 = 256;
      kAccConstructor = 65536;
      kEndianTag = 305419896;
      kClassDefSize = 32;
      kProtoIdSize = 12;
      kFieldIdSize = 8;
      kMethodIdSize = 8;
      kTypeIdSize = 4;
      kStringIdSize = 4;
      kMapItemSize = 12;
      TYPE_HEADER_ITEM = 0;
      TYPE_STRING_ID_ITEM = 1;
      TYPE_TYPE_ID_ITEM = 2;
      TYPE_PROTO_ID_ITEM = 3;
      TYPE_FIELD_ID_ITEM = 4;
      TYPE_METHOD_ID_ITEM = 5;
      TYPE_CLASS_DEF_ITEM = 6;
      TYPE_MAP_LIST = 4096;
      TYPE_TYPE_LIST = 4097;
      TYPE_ANNOTATION_SET_ITEM = 4099;
      TYPE_CLASS_DATA_ITEM = 8192;
      TYPE_CODE_ITEM = 8193;
      TYPE_STRING_DATA_ITEM = 8194;
      TYPE_DEBUG_INFO_ITEM = 8195;
      TYPE_ANNOTATION_ITEM = 8196;
      TYPE_ANNOTATIONS_DIRECTORY_ITEM = 8198;
      VALUE_TYPE = 24;
      VALUE_ARRAY = 28;
      VISIBILITY_SYSTEM = 2;
      kDefaultConstructorSize = 24;
      kDefaultConstructorDebugInfo = Buffer2.from([3, 0, 7, 14, 0]);
      kDalvikAnnotationTypeThrows = "Ldalvik/annotation/Throws;";
      kNullTerminator = Buffer2.from([0]);
      DexBuilder = class {
        constructor() {
          this.classes = [];
        }
        addClass(spec) {
          this.classes.push(spec);
        }
        build() {
          const model = computeModel(this.classes);
          const {
            classes,
            interfaces,
            fields,
            methods,
            protos,
            parameters,
            annotationDirectories,
            annotationSets,
            throwsAnnotations,
            types,
            strings
          } = model;
          let offset = 0;
          const headerOffset = 0;
          const checksumOffset = 8;
          const signatureOffset = 12;
          const signatureSize = 20;
          const headerSize = 112;
          offset += headerSize;
          const stringIdsOffset = offset;
          const stringIdsSize = strings.length * kStringIdSize;
          offset += stringIdsSize;
          const typeIdsOffset = offset;
          const typeIdsSize = types.length * kTypeIdSize;
          offset += typeIdsSize;
          const protoIdsOffset = offset;
          const protoIdsSize = protos.length * kProtoIdSize;
          offset += protoIdsSize;
          const fieldIdsOffset = offset;
          const fieldIdsSize = fields.length * kFieldIdSize;
          offset += fieldIdsSize;
          const methodIdsOffset = offset;
          const methodIdsSize = methods.length * kMethodIdSize;
          offset += methodIdsSize;
          const classDefsOffset = offset;
          const classDefsSize = classes.length * kClassDefSize;
          offset += classDefsSize;
          const dataOffset = offset;
          const annotationSetOffsets = annotationSets.map((set) => {
            const setOffset = offset;
            set.offset = setOffset;
            offset += 4 + set.items.length * 4;
            return setOffset;
          });
          const javaCodeItems = classes.reduce((result, klass) => {
            const constructorMethods = klass.classData.constructorMethods;
            constructorMethods.forEach((method) => {
              const [, accessFlags, superConstructor] = method;
              if ((accessFlags & kAccNative2) === 0 && superConstructor >= 0) {
                method.push(offset);
                result.push({ offset, superConstructor });
                offset += kDefaultConstructorSize;
              }
            });
            return result;
          }, []);
          annotationDirectories.forEach((dir) => {
            dir.offset = offset;
            offset += 16 + dir.methods.length * 8;
          });
          const interfaceOffsets = interfaces.map((iface) => {
            offset = align(offset, 4);
            const ifaceOffset = offset;
            iface.offset = ifaceOffset;
            offset += 4 + 2 * iface.types.length;
            return ifaceOffset;
          });
          const parameterOffsets = parameters.map((param) => {
            offset = align(offset, 4);
            const paramOffset = offset;
            param.offset = paramOffset;
            offset += 4 + 2 * param.types.length;
            return paramOffset;
          });
          const stringChunks = [];
          const stringOffsets = strings.map((str) => {
            const strOffset = offset;
            const header = Buffer2.from(createUleb128(str.length));
            const data = Buffer2.from(str, "utf8");
            const chunk = Buffer2.concat([header, data, kNullTerminator]);
            stringChunks.push(chunk);
            offset += chunk.length;
            return strOffset;
          });
          const debugInfoOffsets = javaCodeItems.map((codeItem) => {
            const debugOffset = offset;
            offset += kDefaultConstructorDebugInfo.length;
            return debugOffset;
          });
          const throwsAnnotationBlobs = throwsAnnotations.map((annotation) => {
            const blob = makeThrowsAnnotation(annotation);
            annotation.offset = offset;
            offset += blob.length;
            return blob;
          });
          const classDataBlobs = classes.map((klass, index) => {
            klass.classData.offset = offset;
            const blob = makeClassData(klass);
            offset += blob.length;
            return blob;
          });
          const linkSize = 0;
          const linkOffset = 0;
          offset = align(offset, 4);
          const mapOffset = offset;
          const typeListLength = interfaces.length + parameters.length;
          const mapNumItems = 4 + (fields.length > 0 ? 1 : 0) + 2 + annotationSets.length + javaCodeItems.length + annotationDirectories.length + (typeListLength > 0 ? 1 : 0) + 1 + debugInfoOffsets.length + throwsAnnotations.length + classes.length + 1;
          const mapSize = 4 + mapNumItems * kMapItemSize;
          offset += mapSize;
          const dataSize = offset - dataOffset;
          const fileSize = offset;
          const dex = Buffer2.alloc(fileSize);
          dex.write("dex\n035");
          dex.writeUInt32LE(fileSize, 32);
          dex.writeUInt32LE(headerSize, 36);
          dex.writeUInt32LE(kEndianTag, 40);
          dex.writeUInt32LE(linkSize, 44);
          dex.writeUInt32LE(linkOffset, 48);
          dex.writeUInt32LE(mapOffset, 52);
          dex.writeUInt32LE(strings.length, 56);
          dex.writeUInt32LE(stringIdsOffset, 60);
          dex.writeUInt32LE(types.length, 64);
          dex.writeUInt32LE(typeIdsOffset, 68);
          dex.writeUInt32LE(protos.length, 72);
          dex.writeUInt32LE(protoIdsOffset, 76);
          dex.writeUInt32LE(fields.length, 80);
          dex.writeUInt32LE(fields.length > 0 ? fieldIdsOffset : 0, 84);
          dex.writeUInt32LE(methods.length, 88);
          dex.writeUInt32LE(methodIdsOffset, 92);
          dex.writeUInt32LE(classes.length, 96);
          dex.writeUInt32LE(classDefsOffset, 100);
          dex.writeUInt32LE(dataSize, 104);
          dex.writeUInt32LE(dataOffset, 108);
          stringOffsets.forEach((offset2, index) => {
            dex.writeUInt32LE(offset2, stringIdsOffset + index * kStringIdSize);
          });
          types.forEach((id, index) => {
            dex.writeUInt32LE(id, typeIdsOffset + index * kTypeIdSize);
          });
          protos.forEach((proto, index) => {
            const [shortyIndex, returnTypeIndex, params] = proto;
            const protoOffset = protoIdsOffset + index * kProtoIdSize;
            dex.writeUInt32LE(shortyIndex, protoOffset);
            dex.writeUInt32LE(returnTypeIndex, protoOffset + 4);
            dex.writeUInt32LE(params !== null ? params.offset : 0, protoOffset + 8);
          });
          fields.forEach((field, index) => {
            const [classIndex, typeIndex, nameIndex] = field;
            const fieldOffset = fieldIdsOffset + index * kFieldIdSize;
            dex.writeUInt16LE(classIndex, fieldOffset);
            dex.writeUInt16LE(typeIndex, fieldOffset + 2);
            dex.writeUInt32LE(nameIndex, fieldOffset + 4);
          });
          methods.forEach((method, index) => {
            const [classIndex, protoIndex, nameIndex] = method;
            const methodOffset = methodIdsOffset + index * kMethodIdSize;
            dex.writeUInt16LE(classIndex, methodOffset);
            dex.writeUInt16LE(protoIndex, methodOffset + 2);
            dex.writeUInt32LE(nameIndex, methodOffset + 4);
          });
          classes.forEach((klass, index) => {
            const { interfaces: interfaces2, annotationsDirectory } = klass;
            const interfacesOffset = interfaces2 !== null ? interfaces2.offset : 0;
            const annotationsOffset = annotationsDirectory !== null ? annotationsDirectory.offset : 0;
            const staticValuesOffset = 0;
            const classOffset = classDefsOffset + index * kClassDefSize;
            dex.writeUInt32LE(klass.index, classOffset);
            dex.writeUInt32LE(klass.accessFlags, classOffset + 4);
            dex.writeUInt32LE(klass.superClassIndex, classOffset + 8);
            dex.writeUInt32LE(interfacesOffset, classOffset + 12);
            dex.writeUInt32LE(klass.sourceFileIndex, classOffset + 16);
            dex.writeUInt32LE(annotationsOffset, classOffset + 20);
            dex.writeUInt32LE(klass.classData.offset, classOffset + 24);
            dex.writeUInt32LE(staticValuesOffset, classOffset + 28);
          });
          annotationSets.forEach((set, index) => {
            const { items } = set;
            const setOffset = annotationSetOffsets[index];
            dex.writeUInt32LE(items.length, setOffset);
            items.forEach((item, index2) => {
              dex.writeUInt32LE(item.offset, setOffset + 4 + index2 * 4);
            });
          });
          javaCodeItems.forEach((codeItem, index) => {
            const { offset: offset2, superConstructor } = codeItem;
            const registersSize = 1;
            const insSize = 1;
            const outsSize = 1;
            const triesSize = 0;
            const insnsSize = 4;
            dex.writeUInt16LE(registersSize, offset2);
            dex.writeUInt16LE(insSize, offset2 + 2);
            dex.writeUInt16LE(outsSize, offset2 + 4);
            dex.writeUInt16LE(triesSize, offset2 + 6);
            dex.writeUInt32LE(debugInfoOffsets[index], offset2 + 8);
            dex.writeUInt32LE(insnsSize, offset2 + 12);
            dex.writeUInt16LE(4208, offset2 + 16);
            dex.writeUInt16LE(superConstructor, offset2 + 18);
            dex.writeUInt16LE(0, offset2 + 20);
            dex.writeUInt16LE(14, offset2 + 22);
          });
          annotationDirectories.forEach((dir) => {
            const dirOffset = dir.offset;
            const classAnnotationsOffset = 0;
            const fieldsSize = 0;
            const annotatedMethodsSize = dir.methods.length;
            const annotatedParametersSize = 0;
            dex.writeUInt32LE(classAnnotationsOffset, dirOffset);
            dex.writeUInt32LE(fieldsSize, dirOffset + 4);
            dex.writeUInt32LE(annotatedMethodsSize, dirOffset + 8);
            dex.writeUInt32LE(annotatedParametersSize, dirOffset + 12);
            dir.methods.forEach((method, index) => {
              const entryOffset = dirOffset + 16 + index * 8;
              const [methodIndex, annotationSet] = method;
              dex.writeUInt32LE(methodIndex, entryOffset);
              dex.writeUInt32LE(annotationSet.offset, entryOffset + 4);
            });
          });
          interfaces.forEach((iface, index) => {
            const ifaceOffset = interfaceOffsets[index];
            dex.writeUInt32LE(iface.types.length, ifaceOffset);
            iface.types.forEach((type, typeIndex) => {
              dex.writeUInt16LE(type, ifaceOffset + 4 + typeIndex * 2);
            });
          });
          parameters.forEach((param, index) => {
            const paramOffset = parameterOffsets[index];
            dex.writeUInt32LE(param.types.length, paramOffset);
            param.types.forEach((type, typeIndex) => {
              dex.writeUInt16LE(type, paramOffset + 4 + typeIndex * 2);
            });
          });
          stringChunks.forEach((chunk, index) => {
            chunk.copy(dex, stringOffsets[index]);
          });
          debugInfoOffsets.forEach((debugInfoOffset) => {
            kDefaultConstructorDebugInfo.copy(dex, debugInfoOffset);
          });
          throwsAnnotationBlobs.forEach((annotationBlob, index) => {
            annotationBlob.copy(dex, throwsAnnotations[index].offset);
          });
          classDataBlobs.forEach((classDataBlob, index) => {
            classDataBlob.copy(dex, classes[index].classData.offset);
          });
          dex.writeUInt32LE(mapNumItems, mapOffset);
          const mapItems = [
            [TYPE_HEADER_ITEM, 1, headerOffset],
            [TYPE_STRING_ID_ITEM, strings.length, stringIdsOffset],
            [TYPE_TYPE_ID_ITEM, types.length, typeIdsOffset],
            [TYPE_PROTO_ID_ITEM, protos.length, protoIdsOffset]
          ];
          if (fields.length > 0) {
            mapItems.push([TYPE_FIELD_ID_ITEM, fields.length, fieldIdsOffset]);
          }
          mapItems.push([TYPE_METHOD_ID_ITEM, methods.length, methodIdsOffset]);
          mapItems.push([TYPE_CLASS_DEF_ITEM, classes.length, classDefsOffset]);
          annotationSets.forEach((set, index) => {
            mapItems.push([TYPE_ANNOTATION_SET_ITEM, set.items.length, annotationSetOffsets[index]]);
          });
          javaCodeItems.forEach((codeItem) => {
            mapItems.push([TYPE_CODE_ITEM, 1, codeItem.offset]);
          });
          annotationDirectories.forEach((dir) => {
            mapItems.push([TYPE_ANNOTATIONS_DIRECTORY_ITEM, 1, dir.offset]);
          });
          if (typeListLength > 0) {
            mapItems.push([TYPE_TYPE_LIST, typeListLength, interfaceOffsets.concat(parameterOffsets)[0]]);
          }
          mapItems.push([TYPE_STRING_DATA_ITEM, strings.length, stringOffsets[0]]);
          debugInfoOffsets.forEach((debugInfoOffset) => {
            mapItems.push([TYPE_DEBUG_INFO_ITEM, 1, debugInfoOffset]);
          });
          throwsAnnotations.forEach((annotation) => {
            mapItems.push([TYPE_ANNOTATION_ITEM, 1, annotation.offset]);
          });
          classes.forEach((klass) => {
            mapItems.push([TYPE_CLASS_DATA_ITEM, 1, klass.classData.offset]);
          });
          mapItems.push([TYPE_MAP_LIST, 1, mapOffset]);
          mapItems.forEach((item, index) => {
            const [type, size, offset2] = item;
            const itemOffset = mapOffset + 4 + index * kMapItemSize;
            dex.writeUInt16LE(type, itemOffset);
            dex.writeUInt32LE(size, itemOffset + 4);
            dex.writeUInt32LE(offset2, itemOffset + 8);
          });
          const hash = new Checksum("sha1");
          hash.update(dex.slice(signatureOffset + signatureSize));
          Buffer2.from(hash.getDigest()).copy(dex, signatureOffset);
          dex.writeUInt32LE(adler32(dex, signatureOffset), checksumOffset);
          return dex;
        }
      };
      mkdex_default = mkdex;
    }
  });

  // node_modules/frida-java-bridge/lib/types.js
  function initialize(_vm) {
    vm = _vm;
  }
  function getType(typeName, unbox, factory) {
    let type = getPrimitiveType(typeName);
    if (type === null) {
      if (typeName.indexOf("[") === 0) {
        type = getArrayType(typeName, unbox, factory);
      } else {
        if (typeName[0] === "L" && typeName[typeName.length - 1] === ";") {
          typeName = typeName.substring(1, typeName.length - 1);
        }
        type = getObjectType(typeName, unbox, factory);
      }
    }
    return Object.assign({ className: typeName }, type);
  }
  function getPrimitiveType(name) {
    const result = primitiveTypes[name];
    return result !== void 0 ? result : null;
  }
  function getObjectType(typeName, unbox, factory) {
    const cache = factory._types[unbox ? 1 : 0];
    let type = cache[typeName];
    if (type !== void 0) {
      return type;
    }
    if (typeName === "java.lang.Object") {
      type = getJavaLangObjectType(factory);
    } else {
      type = getAnyObjectType(typeName, unbox, factory);
    }
    cache[typeName] = type;
    return type;
  }
  function getJavaLangObjectType(factory) {
    return {
      name: "Ljava/lang/Object;",
      type: "pointer",
      size: 1,
      defaultValue: NULL,
      isCompatible(v) {
        if (v === null) {
          return true;
        }
        if (v === void 0) {
          return false;
        }
        const isWrapper = v.$h instanceof NativePointer;
        if (isWrapper) {
          return true;
        }
        return typeof v === "string";
      },
      fromJni(h, env, owned) {
        if (h.isNull()) {
          return null;
        }
        return factory.cast(h, factory.use("java.lang.Object"), owned);
      },
      toJni(o, env) {
        if (o === null) {
          return NULL;
        }
        if (typeof o === "string") {
          return env.newStringUtf(o);
        }
        return o.$h;
      }
    };
  }
  function getAnyObjectType(typeName, unbox, factory) {
    let cachedClass = null;
    let cachedIsInstance = null;
    let cachedIsDefaultString = null;
    function getClass() {
      if (cachedClass === null) {
        cachedClass = factory.use(typeName).class;
      }
      return cachedClass;
    }
    function isInstance(v) {
      const klass = getClass();
      if (cachedIsInstance === null) {
        cachedIsInstance = klass.isInstance.overload("java.lang.Object");
      }
      return cachedIsInstance.call(klass, v);
    }
    function typeIsDefaultString() {
      if (cachedIsDefaultString === null) {
        const x = getClass();
        cachedIsDefaultString = factory.use("java.lang.String").class.isAssignableFrom(x);
      }
      return cachedIsDefaultString;
    }
    return {
      name: makeJniObjectTypeName(typeName),
      type: "pointer",
      size: 1,
      defaultValue: NULL,
      isCompatible(v) {
        if (v === null) {
          return true;
        }
        if (v === void 0) {
          return false;
        }
        const isWrapper = v.$h instanceof NativePointer;
        if (isWrapper) {
          return isInstance(v);
        }
        return typeof v === "string" && typeIsDefaultString();
      },
      fromJni(h, env, owned) {
        if (h.isNull()) {
          return null;
        }
        if (typeIsDefaultString() && unbox) {
          return env.stringFromJni(h);
        }
        return factory.cast(h, factory.use(typeName), owned);
      },
      toJni(o, env) {
        if (o === null) {
          return NULL;
        }
        if (typeof o === "string") {
          return env.newStringUtf(o);
        }
        return o.$h;
      },
      toString() {
        return this.name;
      }
    };
  }
  function makePrimitiveArrayType(shorty, name) {
    const envProto = Env.prototype;
    const nameTitled = toTitleCase(name);
    const spec = {
      typeName: name,
      newArray: envProto["new" + nameTitled + "Array"],
      setRegion: envProto["set" + nameTitled + "ArrayRegion"],
      getElements: envProto["get" + nameTitled + "ArrayElements"],
      releaseElements: envProto["release" + nameTitled + "ArrayElements"]
    };
    return {
      name: shorty,
      type: "pointer",
      size: 1,
      defaultValue: NULL,
      isCompatible(v) {
        return isCompatiblePrimitiveArray(v, name);
      },
      fromJni(h, env, owned) {
        return fromJniPrimitiveArray(h, spec, env, owned);
      },
      toJni(arr, env) {
        return toJniPrimitiveArray(arr, spec, env);
      }
    };
  }
  function getArrayType(typeName, unbox, factory) {
    const primitiveType = primitiveArrayTypes[typeName];
    if (primitiveType !== void 0) {
      return primitiveType;
    }
    if (typeName.indexOf("[") !== 0) {
      throw new Error("Unsupported type: " + typeName);
    }
    let elementTypeName = typeName.substring(1);
    const elementType = getType(elementTypeName, unbox, factory);
    let numInternalArrays = 0;
    const end = elementTypeName.length;
    while (numInternalArrays !== end && elementTypeName[numInternalArrays] === "[") {
      numInternalArrays++;
    }
    elementTypeName = elementTypeName.substring(numInternalArrays);
    if (elementTypeName[0] === "L" && elementTypeName[elementTypeName.length - 1] === ";") {
      elementTypeName = elementTypeName.substring(1, elementTypeName.length - 1);
    }
    let internalElementTypeName = elementTypeName.replace(/\./g, "/");
    if (primitiveTypesNames.has(internalElementTypeName)) {
      internalElementTypeName = "[".repeat(numInternalArrays) + internalElementTypeName;
    } else {
      internalElementTypeName = "[".repeat(numInternalArrays) + "L" + internalElementTypeName + ";";
    }
    const internalTypeName = "[" + internalElementTypeName;
    elementTypeName = "[".repeat(numInternalArrays) + elementTypeName;
    return {
      name: typeName.replace(/\./g, "/"),
      type: "pointer",
      size: 1,
      defaultValue: NULL,
      isCompatible(v) {
        if (v === null) {
          return true;
        }
        if (typeof v !== "object" || v.length === void 0) {
          return false;
        }
        return v.every(function(element) {
          return elementType.isCompatible(element);
        });
      },
      fromJni(arr, env, owned) {
        if (arr.isNull()) {
          return null;
        }
        const result = [];
        const n = env.getArrayLength(arr);
        for (let i = 0; i !== n; i++) {
          const element = env.getObjectArrayElement(arr, i);
          try {
            result.push(elementType.fromJni(element, env));
          } finally {
            env.deleteLocalRef(element);
          }
        }
        try {
          result.$w = factory.cast(arr, factory.use(internalTypeName), owned);
        } catch (e) {
          factory.use("java.lang.reflect.Array").newInstance(factory.use(elementTypeName).class, 0);
          result.$w = factory.cast(arr, factory.use(internalTypeName), owned);
        }
        result.$dispose = disposeObjectArray;
        return result;
      },
      toJni(elements, env) {
        if (elements === null) {
          return NULL;
        }
        if (!(elements instanceof Array)) {
          throw new Error("Expected an array");
        }
        const wrapper = elements.$w;
        if (wrapper !== void 0) {
          return wrapper.$h;
        }
        const n = elements.length;
        const klassObj = factory.use(elementTypeName);
        const classHandle = klassObj.$borrowClassHandle(env);
        try {
          const result = env.newObjectArray(n, classHandle.value, NULL);
          env.throwIfExceptionPending();
          for (let i = 0; i !== n; i++) {
            const handle = elementType.toJni(elements[i], env);
            try {
              env.setObjectArrayElement(result, i, handle);
            } finally {
              if (elementType.type === "pointer" && env.getObjectRefType(handle) === JNILocalRefType) {
                env.deleteLocalRef(handle);
              }
            }
            env.throwIfExceptionPending();
          }
          return result;
        } finally {
          classHandle.unref(env);
        }
      }
    };
  }
  function disposeObjectArray() {
    const n = this.length;
    for (let i = 0; i !== n; i++) {
      const obj = this[i];
      if (obj === null) {
        continue;
      }
      const dispose = obj.$dispose;
      if (dispose === void 0) {
        break;
      }
      dispose.call(obj);
    }
    this.$w.$dispose();
  }
  function fromJniPrimitiveArray(arr, spec, env, owned) {
    if (arr.isNull()) {
      return null;
    }
    const type = getPrimitiveType(spec.typeName);
    const length = env.getArrayLength(arr);
    return new PrimitiveArray(arr, spec, type, length, env, owned);
  }
  function toJniPrimitiveArray(arr, spec, env) {
    if (arr === null) {
      return NULL;
    }
    const handle = arr.$h;
    if (handle !== void 0) {
      return handle;
    }
    const length = arr.length;
    const type = getPrimitiveType(spec.typeName);
    const result = spec.newArray.call(env, length);
    if (result.isNull()) {
      throw new Error("Unable to construct array");
    }
    if (length > 0) {
      const elementSize = type.byteSize;
      const writeElement = type.write;
      const unparseElementValue = type.toJni;
      const elements = Memory.alloc(length * type.byteSize);
      for (let index = 0; index !== length; index++) {
        writeElement(elements.add(index * elementSize), unparseElementValue(arr[index]));
      }
      spec.setRegion.call(env, result, 0, length, elements);
      env.throwIfExceptionPending();
    }
    return result;
  }
  function isCompatiblePrimitiveArray(value, typeName) {
    if (value === null) {
      return true;
    }
    if (value instanceof PrimitiveArray) {
      return value.$s.typeName === typeName;
    }
    const isArrayLike = typeof value === "object" && value.length !== void 0;
    if (!isArrayLike) {
      return false;
    }
    const elementType = getPrimitiveType(typeName);
    return Array.prototype.every.call(value, (element) => elementType.isCompatible(element));
  }
  function PrimitiveArray(handle, spec, type, length, env, owned = true) {
    if (owned) {
      const h = env.newGlobalRef(handle);
      this.$h = h;
      this.$r = Script.bindWeak(this, env.vm.makeHandleDestructor(h));
    } else {
      this.$h = handle;
      this.$r = null;
    }
    this.$s = spec;
    this.$t = type;
    this.length = length;
    return new Proxy(this, primitiveArrayHandler);
  }
  function makeJniObjectTypeName(typeName) {
    return "L" + typeName.replace(/\./g, "/") + ";";
  }
  function toTitleCase(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
  }
  function identity(value) {
    return value;
  }
  var JNILocalRefType, vm, primitiveArrayHandler, primitiveTypes, primitiveTypesNames, primitiveArrayTypes;
  var init_types = __esm({
    "node_modules/frida-java-bridge/lib/types.js"() {
      init_node_globals();
      init_env();
      JNILocalRefType = 1;
      vm = null;
      primitiveArrayHandler = null;
      primitiveTypes = {
        boolean: {
          name: "Z",
          type: "uint8",
          size: 1,
          byteSize: 1,
          defaultValue: false,
          isCompatible(v) {
            return typeof v === "boolean";
          },
          fromJni(v) {
            return !!v;
          },
          toJni(v) {
            return v ? 1 : 0;
          },
          read(address) {
            return address.readU8();
          },
          write(address, value) {
            address.writeU8(value);
          },
          toString() {
            return this.name;
          }
        },
        byte: {
          name: "B",
          type: "int8",
          size: 1,
          byteSize: 1,
          defaultValue: 0,
          isCompatible(v) {
            return Number.isInteger(v) && v >= -128 && v <= 127;
          },
          fromJni: identity,
          toJni: identity,
          read(address) {
            return address.readS8();
          },
          write(address, value) {
            address.writeS8(value);
          },
          toString() {
            return this.name;
          }
        },
        char: {
          name: "C",
          type: "uint16",
          size: 1,
          byteSize: 2,
          defaultValue: 0,
          isCompatible(v) {
            if (typeof v !== "string" || v.length !== 1) {
              return false;
            }
            const code3 = v.charCodeAt(0);
            return code3 >= 0 && code3 <= 65535;
          },
          fromJni(c) {
            return String.fromCharCode(c);
          },
          toJni(s) {
            return s.charCodeAt(0);
          },
          read(address) {
            return address.readU16();
          },
          write(address, value) {
            address.writeU16(value);
          },
          toString() {
            return this.name;
          }
        },
        short: {
          name: "S",
          type: "int16",
          size: 1,
          byteSize: 2,
          defaultValue: 0,
          isCompatible(v) {
            return Number.isInteger(v) && v >= -32768 && v <= 32767;
          },
          fromJni: identity,
          toJni: identity,
          read(address) {
            return address.readS16();
          },
          write(address, value) {
            address.writeS16(value);
          },
          toString() {
            return this.name;
          }
        },
        int: {
          name: "I",
          type: "int32",
          size: 1,
          byteSize: 4,
          defaultValue: 0,
          isCompatible(v) {
            return Number.isInteger(v) && v >= -2147483648 && v <= 2147483647;
          },
          fromJni: identity,
          toJni: identity,
          read(address) {
            return address.readS32();
          },
          write(address, value) {
            address.writeS32(value);
          },
          toString() {
            return this.name;
          }
        },
        long: {
          name: "J",
          type: "int64",
          size: 2,
          byteSize: 8,
          defaultValue: 0,
          isCompatible(v) {
            return typeof v === "number" || v instanceof Int64;
          },
          fromJni: identity,
          toJni: identity,
          read(address) {
            return address.readS64();
          },
          write(address, value) {
            address.writeS64(value);
          },
          toString() {
            return this.name;
          }
        },
        float: {
          name: "F",
          type: "float",
          size: 1,
          byteSize: 4,
          defaultValue: 0,
          isCompatible(v) {
            return typeof v === "number";
          },
          fromJni: identity,
          toJni: identity,
          read(address) {
            return address.readFloat();
          },
          write(address, value) {
            address.writeFloat(value);
          },
          toString() {
            return this.name;
          }
        },
        double: {
          name: "D",
          type: "double",
          size: 2,
          byteSize: 8,
          defaultValue: 0,
          isCompatible(v) {
            return typeof v === "number";
          },
          fromJni: identity,
          toJni: identity,
          read(address) {
            return address.readDouble();
          },
          write(address, value) {
            address.writeDouble(value);
          },
          toString() {
            return this.name;
          }
        },
        void: {
          name: "V",
          type: "void",
          size: 0,
          byteSize: 0,
          defaultValue: void 0,
          isCompatible(v) {
            return v === void 0;
          },
          fromJni() {
            return void 0;
          },
          toJni() {
            return NULL;
          },
          toString() {
            return this.name;
          }
        }
      };
      primitiveTypesNames = new Set(Object.values(primitiveTypes).map((t) => t.name));
      primitiveArrayTypes = [
        ["Z", "boolean"],
        ["B", "byte"],
        ["C", "char"],
        ["D", "double"],
        ["F", "float"],
        ["I", "int"],
        ["J", "long"],
        ["S", "short"]
      ].reduce((result, [shorty, name]) => {
        result["[" + shorty] = makePrimitiveArrayType("[" + shorty, name);
        return result;
      }, {});
      primitiveArrayHandler = {
        has(target, property) {
          if (property in target) {
            return true;
          }
          return target.tryParseIndex(property) !== null;
        },
        get(target, property, receiver) {
          const index = target.tryParseIndex(property);
          if (index === null) {
            return target[property];
          }
          return target.readElement(index);
        },
        set(target, property, value, receiver) {
          const index = target.tryParseIndex(property);
          if (index === null) {
            target[property] = value;
            return true;
          }
          target.writeElement(index, value);
          return true;
        },
        ownKeys(target) {
          const keys = [];
          const { length } = target;
          for (let i = 0; i !== length; i++) {
            const key = i.toString();
            keys.push(key);
          }
          keys.push("length");
          return keys;
        },
        getOwnPropertyDescriptor(target, property) {
          const index = target.tryParseIndex(property);
          if (index !== null) {
            return {
              writable: true,
              configurable: true,
              enumerable: true
            };
          }
          return Object.getOwnPropertyDescriptor(target, property);
        }
      };
      Object.defineProperties(PrimitiveArray.prototype, {
        $dispose: {
          enumerable: true,
          value() {
            const ref = this.$r;
            if (ref !== null) {
              this.$r = null;
              Script.unbindWeak(ref);
            }
          }
        },
        $clone: {
          value(env) {
            return new PrimitiveArray(this.$h, this.$s, this.$t, this.length, env);
          }
        },
        tryParseIndex: {
          value(rawIndex) {
            if (typeof rawIndex === "symbol") {
              return null;
            }
            const index = parseInt(rawIndex);
            if (isNaN(index) || index < 0 || index >= this.length) {
              return null;
            }
            return index;
          }
        },
        readElement: {
          value(index) {
            return this.withElements((elements) => {
              const type = this.$t;
              return type.fromJni(type.read(elements.add(index * type.byteSize)));
            });
          }
        },
        writeElement: {
          value(index, value) {
            const { $h: handle, $s: spec, $t: type } = this;
            const env = vm.getEnv();
            const element = Memory.alloc(type.byteSize);
            type.write(element, type.toJni(value));
            spec.setRegion.call(env, handle, index, 1, element);
          }
        },
        withElements: {
          value(perform) {
            const { $h: handle, $s: spec } = this;
            const env = vm.getEnv();
            const elements = spec.getElements.call(env, handle);
            if (elements.isNull()) {
              throw new Error("Unable to get array elements");
            }
            try {
              return perform(elements);
            } finally {
              spec.releaseElements.call(env, handle, elements);
            }
          }
        },
        toJSON: {
          value() {
            const { length, $t: type } = this;
            const { byteSize: elementSize, fromJni, read: read2 } = type;
            return this.withElements((elements) => {
              const values = [];
              for (let i = 0; i !== length; i++) {
                const value = fromJni(read2(elements.add(i * elementSize)));
                values.push(value);
              }
              return values;
            });
          }
        },
        toString: {
          value() {
            return this.toJSON().toString();
          }
        }
      });
    }
  });

  // node_modules/frida-java-bridge/lib/class-factory.js
  function makeClassWrapperConstructor() {
    return function(handle, strategy, env, owned) {
      return Wrapper.call(this, handle, strategy, env, owned);
    };
  }
  function Wrapper(handle, strategy, env, owned = true) {
    if (handle !== null) {
      if (owned) {
        const h = env.newGlobalRef(handle);
        this.$h = h;
        this.$r = Script.bindWeak(this, vm2.makeHandleDestructor(h));
      } else {
        this.$h = handle;
        this.$r = null;
      }
    } else {
      this.$h = null;
      this.$r = null;
    }
    this.$t = strategy;
    return new Proxy(this, wrapperHandler);
  }
  function ClassHandle(value, env) {
    this.value = env.newGlobalRef(value);
    env.deleteLocalRef(value);
    this.refs = 1;
  }
  function releaseClassHandle(handle, env) {
    handle.unref(env);
  }
  function makeBasicClassHandleGetter(className) {
    const canonicalClassName = className.replace(/\./g, "/");
    return function(env) {
      const tid = getCurrentThreadId();
      ignore(tid);
      try {
        return env.findClass(canonicalClassName);
      } finally {
        unignore(tid);
      }
    };
  }
  function makeLoaderClassHandleGetter(className, usedLoader, callerEnv) {
    if (cachedLoaderMethod === null) {
      cachedLoaderInvoke = callerEnv.vaMethod("pointer", ["pointer"]);
      cachedLoaderMethod = usedLoader.loadClass.overload("java.lang.String").handle;
    }
    callerEnv = null;
    return function(env) {
      const classNameValue = env.newStringUtf(className);
      const tid = getCurrentThreadId();
      ignore(tid);
      try {
        const result = cachedLoaderInvoke(env.handle, usedLoader.$h, cachedLoaderMethod, classNameValue);
        env.throwIfExceptionPending();
        return result;
      } finally {
        unignore(tid);
        env.deleteLocalRef(classNameValue);
      }
    };
  }
  function makeSuperHandleGetter(classWrapper) {
    return function(env) {
      const h = classWrapper.$borrowClassHandle(env);
      try {
        return env.getSuperclass(h.value);
      } finally {
        h.unref(env);
      }
    };
  }
  function makeConstructor(classHandle, classWrapper, env) {
    const { $n: className, $f: factory } = classWrapper;
    const methodName = basename(className);
    const Class = env.javaLangClass();
    const Constructor = env.javaLangReflectConstructor();
    const invokeObjectMethodNoArgs = env.vaMethod("pointer", []);
    const invokeUInt8MethodNoArgs = env.vaMethod("uint8", []);
    const jsCtorMethods = [];
    const jsInitMethods = [];
    const jsRetType = factory._getType(className, false);
    const jsVoidType = factory._getType("void", false);
    const constructors = invokeObjectMethodNoArgs(env.handle, classHandle, Class.getDeclaredConstructors);
    try {
      const n = env.getArrayLength(constructors);
      if (n !== 0) {
        for (let i = 0; i !== n; i++) {
          let methodId, types;
          const constructor = env.getObjectArrayElement(constructors, i);
          try {
            methodId = env.fromReflectedMethod(constructor);
            types = invokeObjectMethodNoArgs(env.handle, constructor, Constructor.getGenericParameterTypes);
          } finally {
            env.deleteLocalRef(constructor);
          }
          let jsArgTypes;
          try {
            jsArgTypes = readTypeNames(env, types).map((name) => factory._getType(name));
          } finally {
            env.deleteLocalRef(types);
          }
          jsCtorMethods.push(makeMethod(methodName, classWrapper, CONSTRUCTOR_METHOD, methodId, jsRetType, jsArgTypes, env));
          jsInitMethods.push(makeMethod(methodName, classWrapper, INSTANCE_METHOD, methodId, jsVoidType, jsArgTypes, env));
        }
      } else {
        const isInterface = invokeUInt8MethodNoArgs(env.handle, classHandle, Class.isInterface);
        if (isInterface) {
          throw new Error("cannot instantiate an interface");
        }
        const defaultClass = env.javaLangObject();
        const defaultConstructor = env.getMethodId(defaultClass, "<init>", "()V");
        jsCtorMethods.push(makeMethod(methodName, classWrapper, CONSTRUCTOR_METHOD, defaultConstructor, jsRetType, [], env));
        jsInitMethods.push(makeMethod(methodName, classWrapper, INSTANCE_METHOD, defaultConstructor, jsVoidType, [], env));
      }
    } finally {
      env.deleteLocalRef(constructors);
    }
    if (jsInitMethods.length === 0) {
      throw new Error("no supported overloads");
    }
    return {
      allocAndInit: makeMethodDispatcher(jsCtorMethods),
      initOnly: makeMethodDispatcher(jsInitMethods)
    };
  }
  function makeMember(name, spec, classHandle, classWrapper, env) {
    if (spec.startsWith("m")) {
      return makeMethodFromSpec(name, spec, classHandle, classWrapper, env);
    }
    return makeFieldFromSpec(name, spec, classHandle, classWrapper, env);
  }
  function makeMethodFromSpec(name, spec, classHandle, classWrapper, env) {
    const { $f: factory } = classWrapper;
    const overloads = spec.split(":").slice(1);
    const Method = env.javaLangReflectMethod();
    const invokeObjectMethodNoArgs = env.vaMethod("pointer", []);
    const invokeUInt8MethodNoArgs = env.vaMethod("uint8", []);
    const methods = overloads.map((params) => {
      const type = params[0] === "s" ? STATIC_METHOD : INSTANCE_METHOD;
      const methodId = ptr(params.substr(1));
      let jsRetType;
      const jsArgTypes = [];
      const handle = env.toReflectedMethod(classHandle, methodId, type === STATIC_METHOD ? 1 : 0);
      try {
        const isVarArgs = !!invokeUInt8MethodNoArgs(env.handle, handle, Method.isVarArgs);
        const retType = invokeObjectMethodNoArgs(env.handle, handle, Method.getGenericReturnType);
        env.throwIfExceptionPending();
        try {
          jsRetType = factory._getType(env.getTypeName(retType));
        } finally {
          env.deleteLocalRef(retType);
        }
        const argTypes = invokeObjectMethodNoArgs(env.handle, handle, Method.getParameterTypes);
        try {
          const n = env.getArrayLength(argTypes);
          for (let i = 0; i !== n; i++) {
            const t = env.getObjectArrayElement(argTypes, i);
            let argClassName;
            try {
              argClassName = isVarArgs && i === n - 1 ? env.getArrayTypeName(t) : env.getTypeName(t);
            } finally {
              env.deleteLocalRef(t);
            }
            const argType = factory._getType(argClassName);
            jsArgTypes.push(argType);
          }
        } finally {
          env.deleteLocalRef(argTypes);
        }
      } catch (e) {
        return null;
      } finally {
        env.deleteLocalRef(handle);
      }
      return makeMethod(name, classWrapper, type, methodId, jsRetType, jsArgTypes, env);
    }).filter((m) => m !== null);
    if (methods.length === 0) {
      throw new Error("No supported overloads");
    }
    if (name === "valueOf") {
      ensureDefaultValueOfImplemented(methods);
    }
    const result = makeMethodDispatcher(methods);
    return function(receiver) {
      return result;
    };
  }
  function makeMethodDispatcher(overloads) {
    const m = makeMethodDispatcherCallable();
    Object.setPrototypeOf(m, dispatcherPrototype);
    m._o = overloads;
    return m;
  }
  function makeMethodDispatcherCallable() {
    const m = function() {
      return m.invoke(this, arguments);
    };
    return m;
  }
  function makeOverloadId(name, returnType, argumentTypes) {
    return `${returnType.className} ${name}(${argumentTypes.map((t) => t.className).join(", ")})`;
  }
  function throwIfDispatcherAmbiguous(dispatcher) {
    const methods = dispatcher._o;
    if (methods.length > 1) {
      throwOverloadError(methods[0].methodName, methods, "has more than one overload, use .overload(<signature>) to choose from:");
    }
  }
  function throwOverloadError(name, methods, message) {
    const methodsSortedByArity = methods.slice().sort((a, b) => a.argumentTypes.length - b.argumentTypes.length);
    const overloads = methodsSortedByArity.map((m) => {
      const argTypes = m.argumentTypes;
      if (argTypes.length > 0) {
        return ".overload('" + m.argumentTypes.map((t) => t.className).join("', '") + "')";
      } else {
        return ".overload()";
      }
    });
    throw new Error(`${name}(): ${message}
	${overloads.join("\n	")}`);
  }
  function makeMethod(methodName, classWrapper, type, methodId, retType, argTypes, env, invocationOptions) {
    const rawRetType = retType.type;
    const rawArgTypes = argTypes.map((t) => t.type);
    if (env === null) {
      env = vm2.getEnv();
    }
    let callVirtually, callDirectly;
    if (type === INSTANCE_METHOD) {
      callVirtually = env.vaMethod(rawRetType, rawArgTypes, invocationOptions);
      callDirectly = env.nonvirtualVaMethod(rawRetType, rawArgTypes, invocationOptions);
    } else if (type === STATIC_METHOD) {
      callVirtually = env.staticVaMethod(rawRetType, rawArgTypes, invocationOptions);
      callDirectly = callVirtually;
    } else {
      callVirtually = env.constructor(rawArgTypes, invocationOptions);
      callDirectly = callVirtually;
    }
    return makeMethodInstance([methodName, classWrapper, type, methodId, retType, argTypes, callVirtually, callDirectly]);
  }
  function makeMethodInstance(params) {
    const m = makeMethodCallable();
    Object.setPrototypeOf(m, methodPrototype);
    m._p = params;
    return m;
  }
  function makeMethodCallable() {
    const m = function() {
      return m.invoke(this, arguments);
    };
    return m;
  }
  function implement(methodName, classWrapper, type, retType, argTypes, handler, fallback = null) {
    const pendingCalls = /* @__PURE__ */ new Set();
    const f = makeMethodImplementation([methodName, classWrapper, type, retType, argTypes, handler, fallback, pendingCalls]);
    const impl = new NativeCallback(f, retType.type, ["pointer", "pointer"].concat(argTypes.map((t) => t.type)));
    impl._c = pendingCalls;
    return impl;
  }
  function makeMethodImplementation(params) {
    return function() {
      return handleMethodInvocation(arguments, params);
    };
  }
  function handleMethodInvocation(jniArgs, params) {
    const env = new Env(jniArgs[0], vm2);
    const [methodName, classWrapper, type, retType, argTypes, handler, fallback, pendingCalls] = params;
    const ownedObjects = [];
    let self;
    if (type === INSTANCE_METHOD) {
      const C = classWrapper.$C;
      self = new C(jniArgs[1], STRATEGY_VIRTUAL, env, false);
    } else {
      self = classWrapper;
    }
    const tid = getCurrentThreadId();
    env.pushLocalFrame(3);
    let haveFrame = true;
    vm2.link(tid, env);
    try {
      pendingCalls.add(tid);
      let fn;
      if (fallback === null || !ignoredThreads.has(tid)) {
        fn = handler;
      } else {
        fn = fallback;
      }
      const args = [];
      const numArgs = jniArgs.length - 2;
      for (let i = 0; i !== numArgs; i++) {
        const t = argTypes[i];
        const value = t.fromJni(jniArgs[2 + i], env, false);
        args.push(value);
        ownedObjects.push(value);
      }
      const retval = fn.apply(self, args);
      if (!retType.isCompatible(retval)) {
        throw new Error(`Implementation for ${methodName} expected return value compatible with ${retType.className}`);
      }
      let jniRetval = retType.toJni(retval, env);
      if (retType.type === "pointer") {
        jniRetval = env.popLocalFrame(jniRetval);
        haveFrame = false;
        ownedObjects.push(retval);
      }
      return jniRetval;
    } catch (e) {
      const jniException = e.$h;
      if (jniException !== void 0) {
        env.throw(jniException);
      } else {
        Script.nextTick(() => {
          throw e;
        });
      }
      return retType.defaultValue;
    } finally {
      vm2.unlink(tid);
      if (haveFrame) {
        env.popLocalFrame(NULL);
      }
      pendingCalls.delete(tid);
      ownedObjects.forEach((obj) => {
        if (obj === null) {
          return;
        }
        const dispose = obj.$dispose;
        if (dispose !== void 0) {
          dispose.call(obj);
        }
      });
    }
  }
  function ensureDefaultValueOfImplemented(methods) {
    const { holder, type } = methods[0];
    const hasDefaultValueOf = methods.some((m) => m.type === type && m.argumentTypes.length === 0);
    if (hasDefaultValueOf) {
      return;
    }
    methods.push(makeValueOfMethod([holder, type]));
  }
  function makeValueOfMethod(params) {
    const m = makeValueOfCallable();
    Object.setPrototypeOf(m, valueOfPrototype);
    m._p = params;
    return m;
  }
  function makeValueOfCallable() {
    const m = function() {
      return this;
    };
    return m;
  }
  function makeFieldFromSpec(name, spec, classHandle, classWrapper, env) {
    const type = spec[2] === "s" ? STATIC_FIELD : INSTANCE_FIELD;
    const id = ptr(spec.substr(3));
    const { $f: factory } = classWrapper;
    let fieldType;
    const field = env.toReflectedField(classHandle, id, type === STATIC_FIELD ? 1 : 0);
    try {
      fieldType = env.vaMethod("pointer", [])(env.handle, field, env.javaLangReflectField().getGenericType);
      env.throwIfExceptionPending();
    } finally {
      env.deleteLocalRef(field);
    }
    let rtype;
    try {
      rtype = factory._getType(env.getTypeName(fieldType));
    } finally {
      env.deleteLocalRef(fieldType);
    }
    let getValue, setValue;
    const rtypeJni = rtype.type;
    if (type === STATIC_FIELD) {
      getValue = env.getStaticField(rtypeJni);
      setValue = env.setStaticField(rtypeJni);
    } else {
      getValue = env.getField(rtypeJni);
      setValue = env.setField(rtypeJni);
    }
    return makeFieldFromParams([type, rtype, id, getValue, setValue]);
  }
  function makeFieldFromParams(params) {
    return function(receiver) {
      return new Field([receiver].concat(params));
    };
  }
  function Field(params) {
    this._p = params;
  }
  function createTemporaryDex(factory) {
    const { cacheDir, tempFileNaming } = factory;
    const JFile = factory.use("java.io.File");
    const cacheDirValue = JFile.$new(cacheDir);
    cacheDirValue.mkdirs();
    return JFile.createTempFile(tempFileNaming.prefix, tempFileNaming.suffix + ".dex", cacheDirValue);
  }
  function setReadOnlyDex(filePath, factory) {
    const JFile = factory.use("java.io.File");
    const file = JFile.$new(filePath);
    file.setWritable(false, false);
  }
  function getFactoryCache() {
    switch (factoryCache.state) {
      case "empty": {
        factoryCache.state = "pending";
        const defaultFactory = factoryCache.factories[0];
        const HashMap = defaultFactory.use("java.util.HashMap");
        const Integer = defaultFactory.use("java.lang.Integer");
        factoryCache.loaders = HashMap.$new();
        factoryCache.Integer = Integer;
        const loader = defaultFactory.loader;
        if (loader !== null) {
          addFactoryToCache(defaultFactory, loader);
        }
        factoryCache.state = "ready";
        return factoryCache;
      }
      case "pending":
        do {
          Thread.sleep(0.05);
        } while (factoryCache.state === "pending");
        return factoryCache;
      case "ready":
        return factoryCache;
    }
  }
  function addFactoryToCache(factory, loader) {
    const { factories, loaders, Integer } = factoryCache;
    const index = Integer.$new(factories.indexOf(factory));
    loaders.put(loader, index);
    for (let l = loader.getParent(); l !== null; l = l.getParent()) {
      if (loaders.containsKey(l)) {
        break;
      }
      loaders.put(l, index);
    }
  }
  function ignore(threadId) {
    let count = ignoredThreads.get(threadId);
    if (count === void 0) {
      count = 0;
    }
    count++;
    ignoredThreads.set(threadId, count);
  }
  function unignore(threadId) {
    let count = ignoredThreads.get(threadId);
    if (count === void 0) {
      throw new Error(`Thread ${threadId} is not ignored`);
    }
    count--;
    if (count === 0) {
      ignoredThreads.delete(threadId);
    } else {
      ignoredThreads.set(threadId, count);
    }
  }
  function basename(className) {
    return className.slice(className.lastIndexOf(".") + 1);
  }
  function readTypeNames(env, types) {
    const names = [];
    const n = env.getArrayLength(types);
    for (let i = 0; i !== n; i++) {
      const t = env.getObjectArrayElement(types, i);
      try {
        names.push(env.getTypeName(t));
      } finally {
        env.deleteLocalRef(t);
      }
    }
    return names;
  }
  function makeSourceFileName(className) {
    const tokens = className.split(".");
    return tokens[tokens.length - 1] + ".java";
  }
  var jsizeSize3, ensureClassInitialized3, makeMethodMangler3, kAccStatic2, CONSTRUCTOR_METHOD, STATIC_METHOD, INSTANCE_METHOD, STATIC_FIELD, INSTANCE_FIELD, STRATEGY_VIRTUAL, STRATEGY_DIRECT, PENDING_USE, DEFAULT_CACHE_DIR, getCurrentThreadId, pointerSize7, factoryCache, vm2, api, isArtVm, wrapperHandler, dispatcherPrototype, methodPrototype, valueOfPrototype, cachedLoaderInvoke, cachedLoaderMethod, ignoredThreads, ClassFactory, DexFile;
  var init_class_factory = __esm({
    "node_modules/frida-java-bridge/lib/class-factory.js"() {
      init_node_globals();
      init_env();
      init_android();
      init_jvm();
      init_class_model();
      init_lru();
      init_mkdex();
      init_types();
      jsizeSize3 = 4;
      ({
        ensureClassInitialized: ensureClassInitialized3,
        makeMethodMangler: makeMethodMangler3
      } = android_exports);
      kAccStatic2 = 8;
      CONSTRUCTOR_METHOD = 1;
      STATIC_METHOD = 2;
      INSTANCE_METHOD = 3;
      STATIC_FIELD = 1;
      INSTANCE_FIELD = 2;
      STRATEGY_VIRTUAL = 1;
      STRATEGY_DIRECT = 2;
      PENDING_USE = Symbol("PENDING_USE");
      DEFAULT_CACHE_DIR = "/data/local/tmp";
      ({
        getCurrentThreadId,
        pointerSize: pointerSize7
      } = Process);
      factoryCache = {
        state: "empty",
        factories: [],
        loaders: null,
        Integer: null
      };
      vm2 = null;
      api = null;
      isArtVm = null;
      wrapperHandler = null;
      dispatcherPrototype = null;
      methodPrototype = null;
      valueOfPrototype = null;
      cachedLoaderInvoke = null;
      cachedLoaderMethod = null;
      ignoredThreads = /* @__PURE__ */ new Map();
      ClassFactory = class _ClassFactory {
        static _initialize(_vm, _api) {
          vm2 = _vm;
          api = _api;
          isArtVm = _api.flavor === "art";
          if (_api.flavor === "jvm") {
            ensureClassInitialized3 = ensureClassInitialized2;
            makeMethodMangler3 = makeMethodMangler2;
          }
        }
        static _disposeAll(env) {
          factoryCache.factories.forEach((factory) => {
            factory._dispose(env);
          });
        }
        static get(classLoader) {
          const cache = getFactoryCache();
          const defaultFactory = cache.factories[0];
          if (classLoader === null) {
            return defaultFactory;
          }
          const indexObj = cache.loaders.get(classLoader);
          if (indexObj !== null) {
            const index = defaultFactory.cast(indexObj, cache.Integer);
            return cache.factories[index.intValue()];
          }
          const factory = new _ClassFactory();
          factory.loader = classLoader;
          factory.cacheDir = defaultFactory.cacheDir;
          addFactoryToCache(factory, classLoader);
          return factory;
        }
        constructor() {
          this.cacheDir = DEFAULT_CACHE_DIR;
          this.codeCacheDir = DEFAULT_CACHE_DIR + "/dalvik-cache";
          this.tempFileNaming = {
            prefix: "frida",
            suffix: ""
          };
          this._classes = {};
          this._classHandles = new LRU(10, releaseClassHandle);
          this._patchedMethods = /* @__PURE__ */ new Set();
          this._loader = null;
          this._types = [{}, {}];
          factoryCache.factories.push(this);
        }
        _dispose(env) {
          Array.from(this._patchedMethods).forEach((method) => {
            method.implementation = null;
          });
          this._patchedMethods.clear();
          revertGlobalPatches();
          this._classHandles.dispose(env);
          this._classes = {};
        }
        get loader() {
          return this._loader;
        }
        set loader(value) {
          const isInitial = this._loader === null && value !== null;
          this._loader = value;
          if (isInitial && factoryCache.state === "ready" && this === factoryCache.factories[0]) {
            addFactoryToCache(this, value);
          }
        }
        use(className, options = {}) {
          const allowCached = options.cache !== "skip";
          let C = allowCached ? this._getUsedClass(className) : void 0;
          if (C === void 0) {
            try {
              const env = vm2.getEnv();
              const { _loader: loader } = this;
              const getClassHandle = loader !== null ? makeLoaderClassHandleGetter(className, loader, env) : makeBasicClassHandleGetter(className);
              C = this._make(className, getClassHandle, env);
            } finally {
              if (allowCached) {
                this._setUsedClass(className, C);
              }
            }
          }
          return C;
        }
        _getUsedClass(className) {
          let c;
          while ((c = this._classes[className]) === PENDING_USE) {
            Thread.sleep(0.05);
          }
          if (c === void 0) {
            this._classes[className] = PENDING_USE;
          }
          return c;
        }
        _setUsedClass(className, c) {
          if (c !== void 0) {
            this._classes[className] = c;
          } else {
            delete this._classes[className];
          }
        }
        _make(name, getClassHandle, env) {
          const C = makeClassWrapperConstructor();
          const proto = Object.create(Wrapper.prototype, {
            [Symbol.for("n")]: {
              value: name
            },
            $n: {
              get() {
                return this[Symbol.for("n")];
              }
            },
            [Symbol.for("C")]: {
              value: C
            },
            $C: {
              get() {
                return this[Symbol.for("C")];
              }
            },
            [Symbol.for("w")]: {
              value: null,
              writable: true
            },
            $w: {
              get() {
                return this[Symbol.for("w")];
              },
              set(val) {
                this[Symbol.for("w")] = val;
              }
            },
            [Symbol.for("_s")]: {
              writable: true
            },
            $_s: {
              get() {
                return this[Symbol.for("_s")];
              },
              set(val) {
                this[Symbol.for("_s")] = val;
              }
            },
            [Symbol.for("c")]: {
              value: [null]
            },
            $c: {
              get() {
                return this[Symbol.for("c")];
              }
            },
            [Symbol.for("m")]: {
              value: /* @__PURE__ */ new Map()
            },
            $m: {
              get() {
                return this[Symbol.for("m")];
              }
            },
            [Symbol.for("l")]: {
              value: null,
              writable: true
            },
            $l: {
              get() {
                return this[Symbol.for("l")];
              },
              set(val) {
                this[Symbol.for("l")] = val;
              }
            },
            [Symbol.for("gch")]: {
              value: getClassHandle
            },
            $gch: {
              get() {
                return this[Symbol.for("gch")];
              }
            },
            [Symbol.for("f")]: {
              value: this
            },
            $f: {
              get() {
                return this[Symbol.for("f")];
              }
            }
          });
          C.prototype = proto;
          const classWrapper = new C(null);
          proto[Symbol.for("w")] = classWrapper;
          proto.$w = classWrapper;
          const h = classWrapper.$borrowClassHandle(env);
          try {
            const classHandle = h.value;
            ensureClassInitialized3(env, classHandle);
            proto.$l = Model.build(classHandle, env);
          } finally {
            h.unref(env);
          }
          return classWrapper;
        }
        retain(obj) {
          const env = vm2.getEnv();
          return obj.$clone(env);
        }
        cast(obj, klass, owned) {
          const env = vm2.getEnv();
          let handle = obj.$h;
          if (handle === void 0) {
            handle = obj;
          }
          const h = klass.$borrowClassHandle(env);
          try {
            const isValidCast = env.isInstanceOf(handle, h.value);
            if (!isValidCast) {
              throw new Error(`Cast from '${env.getObjectClassName(handle)}' to '${klass.$n}' isn't possible`);
            }
          } finally {
            h.unref(env);
          }
          const C = klass.$C;
          return new C(handle, STRATEGY_VIRTUAL, env, owned);
        }
        wrap(handle, klass, env) {
          const C = klass.$C;
          const wrapper = new C(handle, STRATEGY_VIRTUAL, env, false);
          wrapper.$r = Script.bindWeak(wrapper, vm2.makeHandleDestructor(handle));
          return wrapper;
        }
        array(type, elements) {
          const env = vm2.getEnv();
          const primitiveType = getPrimitiveType(type);
          if (primitiveType !== null) {
            type = primitiveType.name;
          }
          const arrayType = getArrayType("[" + type, false, this);
          const rawArray = arrayType.toJni(elements, env);
          return arrayType.fromJni(rawArray, env, true);
        }
        registerClass(spec) {
          const env = vm2.getEnv();
          const tempHandles = [];
          try {
            const Class = this.use("java.lang.Class");
            const Method = env.javaLangReflectMethod();
            const invokeObjectMethodNoArgs = env.vaMethod("pointer", []);
            const className = spec.name;
            const interfaces = spec.implements || [];
            const superClass = spec.superClass || this.use("java.lang.Object");
            const dexFields = [];
            const dexMethods = [];
            const dexSpec = {
              name: makeJniObjectTypeName(className),
              sourceFileName: makeSourceFileName(className),
              superClass: makeJniObjectTypeName(superClass.$n),
              interfaces: interfaces.map((iface) => makeJniObjectTypeName(iface.$n)),
              fields: dexFields,
              methods: dexMethods
            };
            const allInterfaces = interfaces.slice();
            if (spec.skipInterfaceExpansion !== true) {
              interfaces.forEach((iface) => {
                Array.prototype.slice.call(iface.class.getInterfaces()).forEach((baseIface) => {
                  const baseIfaceName = this.cast(baseIface, Class).getCanonicalName();
                  allInterfaces.push(this.use(baseIfaceName));
                });
              });
            }
            const fields = spec.fields || {};
            Object.getOwnPropertyNames(fields).forEach((name) => {
              const fieldType = this._getType(fields[name]);
              dexFields.push([name, fieldType.name]);
            });
            const baseMethods = {};
            const pendingOverloads = {};
            allInterfaces.forEach((iface) => {
              const h = iface.$borrowClassHandle(env);
              tempHandles.push(h);
              const ifaceHandle = h.value;
              iface.$ownMembers.filter((name) => {
                return iface[name].overloads !== void 0;
              }).forEach((name) => {
                const method = iface[name];
                const overloads = method.overloads;
                const overloadIds = overloads.map((overload) => makeOverloadId(name, overload.returnType, overload.argumentTypes));
                baseMethods[name] = [method, overloadIds, ifaceHandle];
                overloads.forEach((overload, index) => {
                  const id = overloadIds[index];
                  pendingOverloads[id] = [overload, ifaceHandle];
                });
              });
            });
            const methods = spec.methods || {};
            const methodNames = Object.keys(methods);
            const methodEntries = methodNames.reduce((result, name) => {
              const entry = methods[name];
              const rawName = name === "$init" ? "<init>" : name;
              if (entry instanceof Array) {
                result.push(...entry.map((e) => [rawName, e]));
              } else {
                result.push([rawName, entry]);
              }
              return result;
            }, []);
            const implMethods = [];
            methodEntries.forEach(([name, methodValue]) => {
              let type = INSTANCE_METHOD;
              let returnType;
              let argumentTypes;
              let thrownTypeNames = [];
              let impl;
              if (typeof methodValue === "function") {
                const m = baseMethods[name];
                if (m !== void 0 && Array.isArray(m)) {
                  const [baseMethod, overloadIds, parentTypeHandle] = m;
                  if (overloadIds.length > 1) {
                    throw new Error(`More than one overload matching '${name}': signature must be specified`);
                  }
                  delete pendingOverloads[overloadIds[0]];
                  const overload = baseMethod.overloads[0];
                  type = overload.type;
                  returnType = overload.returnType;
                  argumentTypes = overload.argumentTypes;
                  impl = methodValue;
                  const reflectedMethod = env.toReflectedMethod(parentTypeHandle, overload.handle, 0);
                  const thrownTypes = invokeObjectMethodNoArgs(env.handle, reflectedMethod, Method.getGenericExceptionTypes);
                  thrownTypeNames = readTypeNames(env, thrownTypes).map(makeJniObjectTypeName);
                  env.deleteLocalRef(thrownTypes);
                  env.deleteLocalRef(reflectedMethod);
                } else {
                  returnType = this._getType("void");
                  argumentTypes = [];
                  impl = methodValue;
                }
              } else {
                if (methodValue.isStatic) {
                  type = STATIC_METHOD;
                }
                returnType = this._getType(methodValue.returnType || "void");
                argumentTypes = (methodValue.argumentTypes || []).map((name2) => this._getType(name2));
                impl = methodValue.implementation;
                if (typeof impl !== "function") {
                  throw new Error("Expected a function implementation for method: " + name);
                }
                const id = makeOverloadId(name, returnType, argumentTypes);
                const pendingOverload = pendingOverloads[id];
                if (pendingOverload !== void 0) {
                  const [overload, parentTypeHandle] = pendingOverload;
                  delete pendingOverloads[id];
                  type = overload.type;
                  returnType = overload.returnType;
                  argumentTypes = overload.argumentTypes;
                  const reflectedMethod = env.toReflectedMethod(parentTypeHandle, overload.handle, 0);
                  const thrownTypes = invokeObjectMethodNoArgs(env.handle, reflectedMethod, Method.getGenericExceptionTypes);
                  thrownTypeNames = readTypeNames(env, thrownTypes).map(makeJniObjectTypeName);
                  env.deleteLocalRef(thrownTypes);
                  env.deleteLocalRef(reflectedMethod);
                }
              }
              const returnTypeName = returnType.name;
              const argumentTypeNames = argumentTypes.map((t) => t.name);
              const signature = "(" + argumentTypeNames.join("") + ")" + returnTypeName;
              dexMethods.push([name, returnTypeName, argumentTypeNames, thrownTypeNames, type === STATIC_METHOD ? kAccStatic2 : 0]);
              implMethods.push([name, signature, type, returnType, argumentTypes, impl]);
            });
            const unimplementedMethodIds = Object.keys(pendingOverloads);
            if (unimplementedMethodIds.length > 0) {
              throw new Error("Missing implementation for: " + unimplementedMethodIds.join(", "));
            }
            const dex = DexFile.fromBuffer(mkdex_default(dexSpec), this);
            try {
              dex.load();
            } finally {
              dex.file.delete();
            }
            const classWrapper = this.use(spec.name);
            const numMethods = methodEntries.length;
            if (numMethods > 0) {
              const methodElementSize = 3 * pointerSize7;
              const methodElements = Memory.alloc(numMethods * methodElementSize);
              const nativeMethods = [];
              const temporaryHandles = [];
              implMethods.forEach(([name, signature, type, returnType, argumentTypes, impl], index) => {
                const rawName = Memory.allocUtf8String(name);
                const rawSignature = Memory.allocUtf8String(signature);
                const rawImpl = implement(name, classWrapper, type, returnType, argumentTypes, impl);
                methodElements.add(index * methodElementSize).writePointer(rawName);
                methodElements.add(index * methodElementSize + pointerSize7).writePointer(rawSignature);
                methodElements.add(index * methodElementSize + 2 * pointerSize7).writePointer(rawImpl);
                temporaryHandles.push(rawName, rawSignature);
                nativeMethods.push(rawImpl);
              });
              const h = classWrapper.$borrowClassHandle(env);
              tempHandles.push(h);
              const classHandle = h.value;
              env.registerNatives(classHandle, methodElements, numMethods);
              env.throwIfExceptionPending();
              classWrapper.$nativeMethods = nativeMethods;
            }
            return classWrapper;
          } finally {
            tempHandles.forEach((h) => {
              h.unref(env);
            });
          }
        }
        choose(specifier, callbacks) {
          const env = vm2.getEnv();
          const { flavor } = api;
          if (flavor === "jvm") {
            this._chooseObjectsJvm(specifier, env, callbacks);
          } else if (flavor === "art") {
            const legacyApiMissing = api["art::gc::Heap::VisitObjects"] === void 0;
            if (legacyApiMissing) {
              const preA12ApiMissing = api["art::gc::Heap::GetInstances"] === void 0;
              if (preA12ApiMissing) {
                return this._chooseObjectsJvm(specifier, env, callbacks);
              }
            }
            withRunnableArtThread(vm2, env, (thread) => {
              if (legacyApiMissing) {
                this._chooseObjectsArtPreA12(specifier, env, thread, callbacks);
              } else {
                this._chooseObjectsArtLegacy(specifier, env, thread, callbacks);
              }
            });
          } else {
            this._chooseObjectsDalvik(specifier, env, callbacks);
          }
        }
        _chooseObjectsJvm(className, env, callbacks) {
          const classWrapper = this.use(className);
          const { jvmti } = api;
          const JVMTI_ITERATION_CONTINUE = 1;
          const JVMTI_HEAP_OBJECT_EITHER = 3;
          const h = classWrapper.$borrowClassHandle(env);
          const tag = int64(h.value.toString());
          try {
            const heapObjectCallback = new NativeCallback((classTag, size, tagPtr2, userData) => {
              tagPtr2.writeS64(tag);
              return JVMTI_ITERATION_CONTINUE;
            }, "int", ["int64", "int64", "pointer", "pointer"]);
            jvmti.iterateOverInstancesOfClass(h.value, JVMTI_HEAP_OBJECT_EITHER, heapObjectCallback, h.value);
            const tagPtr = Memory.alloc(8);
            tagPtr.writeS64(tag);
            const countPtr = Memory.alloc(jsizeSize3);
            const objectsPtr = Memory.alloc(pointerSize7);
            jvmti.getObjectsWithTags(1, tagPtr, countPtr, objectsPtr, NULL);
            const count = countPtr.readS32();
            const objects = objectsPtr.readPointer();
            const handles = [];
            for (let i = 0; i !== count; i++) {
              handles.push(objects.add(i * pointerSize7).readPointer());
            }
            jvmti.deallocate(objects);
            try {
              for (const handle of handles) {
                const instance = this.cast(handle, classWrapper);
                const result = callbacks.onMatch(instance);
                if (result === "stop") {
                  break;
                }
              }
              callbacks.onComplete();
            } finally {
              handles.forEach((handle) => {
                env.deleteLocalRef(handle);
              });
            }
          } finally {
            h.unref(env);
          }
        }
        _chooseObjectsArtPreA12(className, env, thread, callbacks) {
          const classWrapper = this.use(className);
          const scope = VariableSizedHandleScope.$new(thread, vm2);
          let needle;
          const h = classWrapper.$borrowClassHandle(env);
          try {
            const object = api["art::JavaVMExt::DecodeGlobal"](api.vm, thread, h.value);
            needle = scope.newHandle(object);
          } finally {
            h.unref(env);
          }
          const maxCount = 0;
          const instances = HandleVector.$new();
          api["art::gc::Heap::GetInstances"](api.artHeap, scope, needle, maxCount, instances);
          const instanceHandles = instances.handles.map((handle) => env.newGlobalRef(handle));
          instances.$delete();
          scope.$delete();
          try {
            for (const handle of instanceHandles) {
              const instance = this.cast(handle, classWrapper);
              const result = callbacks.onMatch(instance);
              if (result === "stop") {
                break;
              }
            }
            callbacks.onComplete();
          } finally {
            instanceHandles.forEach((handle) => {
              env.deleteGlobalRef(handle);
            });
          }
        }
        _chooseObjectsArtLegacy(className, env, thread, callbacks) {
          const classWrapper = this.use(className);
          const instanceHandles = [];
          const addGlobalReference = api["art::JavaVMExt::AddGlobalRef"];
          const vmHandle = api.vm;
          let needle;
          const h = classWrapper.$borrowClassHandle(env);
          try {
            needle = api["art::JavaVMExt::DecodeGlobal"](vmHandle, thread, h.value).toInt32();
          } finally {
            h.unref(env);
          }
          const collectMatchingInstanceHandles = makeObjectVisitorPredicate(needle, (object) => {
            instanceHandles.push(addGlobalReference(vmHandle, thread, object));
          });
          api["art::gc::Heap::VisitObjects"](api.artHeap, collectMatchingInstanceHandles, NULL);
          try {
            for (const handle of instanceHandles) {
              const instance = this.cast(handle, classWrapper);
              const result = callbacks.onMatch(instance);
              if (result === "stop") {
                break;
              }
            }
          } finally {
            instanceHandles.forEach((handle) => {
              env.deleteGlobalRef(handle);
            });
          }
          callbacks.onComplete();
        }
        _chooseObjectsDalvik(className, callerEnv, callbacks) {
          const classWrapper = this.use(className);
          if (api.addLocalReference === null) {
            const libdvm = Process.getModuleByName("libdvm.so");
            let pattern;
            switch (Process.arch) {
              case "arm":
                pattern = "2d e9 f0 41 05 46 15 4e 0c 46 7e 44 11 b3 43 68";
                break;
              case "ia32":
                pattern = "8d 64 24 d4 89 5c 24 1c 89 74 24 20 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 85 d2";
                break;
            }
            Memory.scan(libdvm.base, libdvm.size, pattern, {
              onMatch: (address, size) => {
                let wrapper;
                if (Process.arch === "arm") {
                  address = address.or(1);
                  wrapper = new NativeFunction(address, "pointer", ["pointer", "pointer"]);
                } else {
                  const thunk = Memory.alloc(Process.pageSize);
                  Memory.patchCode(thunk, 16, (code3) => {
                    const cw = new X86Writer(code3, { pc: thunk });
                    cw.putMovRegRegOffsetPtr("eax", "esp", 4);
                    cw.putMovRegRegOffsetPtr("edx", "esp", 8);
                    cw.putJmpAddress(address);
                    cw.flush();
                  });
                  wrapper = new NativeFunction(thunk, "pointer", ["pointer", "pointer"]);
                  wrapper._thunk = thunk;
                }
                api.addLocalReference = wrapper;
                vm2.perform((env) => {
                  enumerateInstances(this, env);
                });
                return "stop";
              },
              onError(reason) {
              },
              onComplete() {
                if (api.addLocalReference === null) {
                  callbacks.onComplete();
                }
              }
            });
          } else {
            enumerateInstances(this, callerEnv);
          }
          function enumerateInstances(factory, env) {
            const { DVM_JNI_ENV_OFFSET_SELF: DVM_JNI_ENV_OFFSET_SELF2 } = android_exports;
            const thread = env.handle.add(DVM_JNI_ENV_OFFSET_SELF2).readPointer();
            let ptrClassObject;
            const h = classWrapper.$borrowClassHandle(env);
            try {
              ptrClassObject = api.dvmDecodeIndirectRef(thread, h.value);
            } finally {
              h.unref(env);
            }
            const pattern = ptrClassObject.toMatchPattern();
            const heapSourceBase = api.dvmHeapSourceGetBase();
            const heapSourceLimit = api.dvmHeapSourceGetLimit();
            const size = heapSourceLimit.sub(heapSourceBase).toInt32();
            Memory.scan(heapSourceBase, size, pattern, {
              onMatch: (address, size2) => {
                if (api.dvmIsValidObject(address)) {
                  vm2.perform((env2) => {
                    const thread2 = env2.handle.add(DVM_JNI_ENV_OFFSET_SELF2).readPointer();
                    let instance;
                    const localReference = api.addLocalReference(thread2, address);
                    try {
                      instance = factory.cast(localReference, classWrapper);
                    } finally {
                      env2.deleteLocalRef(localReference);
                    }
                    const result = callbacks.onMatch(instance);
                    if (result === "stop") {
                      return "stop";
                    }
                  });
                }
              },
              onError(reason) {
              },
              onComplete() {
                callbacks.onComplete();
              }
            });
          }
        }
        openClassFile(filePath) {
          return new DexFile(filePath, null, this);
        }
        _getType(typeName, unbox = true) {
          return getType(typeName, unbox, this);
        }
      };
      wrapperHandler = {
        has(target, property) {
          if (property in target) {
            return true;
          }
          return target.$has(property);
        },
        get(target, property, receiver) {
          if (typeof property !== "string" || property.startsWith("$") || property === "class") {
            return target[property];
          }
          const unwrap2 = target.$find(property);
          if (unwrap2 !== null) {
            return unwrap2(receiver);
          }
          return target[property];
        },
        set(target, property, value, receiver) {
          target[property] = value;
          return true;
        },
        ownKeys(target) {
          return target.$list();
        },
        getOwnPropertyDescriptor(target, property) {
          if (Object.prototype.hasOwnProperty.call(target, property)) {
            return Object.getOwnPropertyDescriptor(target, property);
          }
          return {
            writable: false,
            configurable: true,
            enumerable: true
          };
        }
      };
      Object.defineProperties(Wrapper.prototype, {
        [Symbol.for("new")]: {
          enumerable: false,
          get() {
            return this.$getCtor("allocAndInit");
          }
        },
        $new: {
          enumerable: true,
          get() {
            return this[Symbol.for("new")];
          }
        },
        [Symbol.for("alloc")]: {
          enumerable: false,
          value() {
            const env = vm2.getEnv();
            const h = this.$borrowClassHandle(env);
            try {
              const obj = env.allocObject(h.value);
              const factory = this.$f;
              return factory.cast(obj, this);
            } finally {
              h.unref(env);
            }
          }
        },
        $alloc: {
          enumerable: true,
          get() {
            return this[Symbol.for("alloc")];
          }
        },
        [Symbol.for("init")]: {
          enumerable: false,
          get() {
            return this.$getCtor("initOnly");
          }
        },
        $init: {
          enumerable: true,
          get() {
            return this[Symbol.for("init")];
          }
        },
        [Symbol.for("dispose")]: {
          enumerable: false,
          value() {
            const ref = this.$r;
            if (ref !== null) {
              this.$r = null;
              Script.unbindWeak(ref);
            }
            if (this.$h !== null) {
              this.$h = void 0;
            }
          }
        },
        $dispose: {
          enumerable: true,
          get() {
            return this[Symbol.for("dispose")];
          }
        },
        [Symbol.for("clone")]: {
          enumerable: false,
          value(env) {
            const C = this.$C;
            return new C(this.$h, this.$t, env);
          }
        },
        $clone: {
          value(env) {
            return this[Symbol.for("clone")](env);
          }
        },
        [Symbol.for("class")]: {
          enumerable: false,
          get() {
            const env = vm2.getEnv();
            const h = this.$borrowClassHandle(env);
            try {
              const factory = this.$f;
              return factory.cast(h.value, factory.use("java.lang.Class"));
            } finally {
              h.unref(env);
            }
          }
        },
        class: {
          enumerable: true,
          get() {
            return this[Symbol.for("class")];
          }
        },
        [Symbol.for("className")]: {
          enumerable: false,
          get() {
            const handle = this.$h;
            if (handle === null) {
              return this.$n;
            }
            return vm2.getEnv().getObjectClassName(handle);
          }
        },
        $className: {
          enumerable: true,
          get() {
            return this[Symbol.for("className")];
          }
        },
        [Symbol.for("ownMembers")]: {
          enumerable: false,
          get() {
            const model = this.$l;
            return model.list();
          }
        },
        $ownMembers: {
          enumerable: true,
          get() {
            return this[Symbol.for("ownMembers")];
          }
        },
        [Symbol.for("super")]: {
          enumerable: false,
          get() {
            const env = vm2.getEnv();
            const C = this.$s.$C;
            return new C(this.$h, STRATEGY_DIRECT, env);
          }
        },
        $super: {
          enumerable: true,
          get() {
            return this[Symbol.for("super")];
          }
        },
        [Symbol.for("s")]: {
          enumerable: false,
          get() {
            const proto = Object.getPrototypeOf(this);
            let superWrapper = proto.$_s;
            if (superWrapper === void 0) {
              const env = vm2.getEnv();
              const h = this.$borrowClassHandle(env);
              try {
                const superHandle = env.getSuperclass(h.value);
                if (!superHandle.isNull()) {
                  try {
                    const superClassName = env.getClassName(superHandle);
                    const factory = proto.$f;
                    superWrapper = factory._getUsedClass(superClassName);
                    if (superWrapper === void 0) {
                      try {
                        const getSuperClassHandle = makeSuperHandleGetter(this);
                        superWrapper = factory._make(superClassName, getSuperClassHandle, env);
                      } finally {
                        factory._setUsedClass(superClassName, superWrapper);
                      }
                    }
                  } finally {
                    env.deleteLocalRef(superHandle);
                  }
                } else {
                  superWrapper = null;
                }
              } finally {
                h.unref(env);
              }
              proto.$_s = superWrapper;
            }
            return superWrapper;
          }
        },
        $s: {
          get() {
            return this[Symbol.for("s")];
          }
        },
        [Symbol.for("isSameObject")]: {
          enumerable: false,
          value(obj) {
            const env = vm2.getEnv();
            return env.isSameObject(obj.$h, this.$h);
          }
        },
        $isSameObject: {
          value(obj) {
            return this[Symbol.for("isSameObject")](obj);
          }
        },
        [Symbol.for("getCtor")]: {
          enumerable: false,
          value(type) {
            const slot = this.$c;
            let ctor = slot[0];
            if (ctor === null) {
              const env = vm2.getEnv();
              const h = this.$borrowClassHandle(env);
              try {
                ctor = makeConstructor(h.value, this.$w, env);
                slot[0] = ctor;
              } finally {
                h.unref(env);
              }
            }
            return ctor[type];
          }
        },
        $getCtor: {
          value(type) {
            return this[Symbol.for("getCtor")](type);
          }
        },
        [Symbol.for("borrowClassHandle")]: {
          enumerable: false,
          value(env) {
            const className = this.$n;
            const classHandles = this.$f._classHandles;
            let handle = classHandles.get(className);
            if (handle === void 0) {
              handle = new ClassHandle(this.$gch(env), env);
              classHandles.set(className, handle, env);
            }
            return handle.ref();
          }
        },
        $borrowClassHandle: {
          value(env) {
            return this[Symbol.for("borrowClassHandle")](env);
          }
        },
        [Symbol.for("copyClassHandle")]: {
          enumerable: false,
          value(env) {
            const h = this.$borrowClassHandle(env);
            try {
              return env.newLocalRef(h.value);
            } finally {
              h.unref(env);
            }
          }
        },
        $copyClassHandle: {
          value(env) {
            return this[Symbol.for("copyClassHandle")](env);
          }
        },
        [Symbol.for("getHandle")]: {
          enumerable: false,
          value(env) {
            const handle = this.$h;
            const isDisposed = handle === void 0;
            if (isDisposed) {
              throw new Error("Wrapper is disposed; perhaps it was borrowed from a hook instead of calling Java.retain() to make a long-lived wrapper?");
            }
            return handle;
          }
        },
        $getHandle: {
          value(env) {
            return this[Symbol.for("getHandle")](env);
          }
        },
        [Symbol.for("list")]: {
          enumerable: false,
          value() {
            const superWrapper = this.$s;
            const superMembers = superWrapper !== null ? superWrapper.$list() : [];
            const model = this.$l;
            return Array.from(new Set(superMembers.concat(model.list())));
          }
        },
        $list: {
          get() {
            return this[Symbol.for("list")];
          }
        },
        [Symbol.for("has")]: {
          enumerable: false,
          value(member) {
            const members = this.$m;
            if (members.has(member)) {
              return true;
            }
            const model = this.$l;
            if (model.has(member)) {
              return true;
            }
            const superWrapper = this.$s;
            if (superWrapper !== null && superWrapper.$has(member)) {
              return true;
            }
            return false;
          }
        },
        $has: {
          value(member) {
            return this[Symbol.for("has")](member);
          }
        },
        [Symbol.for("find")]: {
          enumerable: false,
          value(member) {
            const members = this.$m;
            let value = members.get(member);
            if (value !== void 0) {
              return value;
            }
            const model = this.$l;
            const spec = model.find(member);
            if (spec !== null) {
              const env = vm2.getEnv();
              const h = this.$borrowClassHandle(env);
              try {
                value = makeMember(member, spec, h.value, this.$w, env);
              } finally {
                h.unref(env);
              }
              members.set(member, value);
              return value;
            }
            const superWrapper = this.$s;
            if (superWrapper !== null) {
              return superWrapper.$find(member);
            }
            return null;
          }
        },
        $find: {
          value(member) {
            return this[Symbol.for("find")](member);
          }
        },
        [Symbol.for("toJSON")]: {
          enumerable: false,
          value() {
            const wrapperName = this.$n;
            const handle = this.$h;
            if (handle === null) {
              return `<class: ${wrapperName}>`;
            }
            const actualName = this.$className;
            if (wrapperName === actualName) {
              return `<instance: ${wrapperName}>`;
            }
            return `<instance: ${wrapperName}, $className: ${actualName}>`;
          }
        },
        toJSON: {
          get() {
            return this[Symbol.for("toJSON")];
          }
        }
      });
      ClassHandle.prototype.ref = function() {
        this.refs++;
        return this;
      };
      ClassHandle.prototype.unref = function(env) {
        if (--this.refs === 0) {
          env.deleteGlobalRef(this.value);
        }
      };
      dispatcherPrototype = Object.create(Function.prototype, {
        overloads: {
          enumerable: true,
          get() {
            return this._o;
          }
        },
        overload: {
          value(...args) {
            const overloads = this._o;
            const numArgs = args.length;
            const signature = args.join(":");
            for (let i = 0; i !== overloads.length; i++) {
              const method = overloads[i];
              const { argumentTypes } = method;
              if (argumentTypes.length !== numArgs) {
                continue;
              }
              const s = argumentTypes.map((t) => t.className).join(":");
              if (s === signature) {
                return method;
              }
            }
            throwOverloadError(this.methodName, this.overloads, "specified argument types do not match any of:");
          }
        },
        methodName: {
          enumerable: true,
          get() {
            return this._o[0].methodName;
          }
        },
        holder: {
          enumerable: true,
          get() {
            return this._o[0].holder;
          }
        },
        type: {
          enumerable: true,
          get() {
            return this._o[0].type;
          }
        },
        handle: {
          enumerable: true,
          get() {
            throwIfDispatcherAmbiguous(this);
            return this._o[0].handle;
          }
        },
        implementation: {
          enumerable: true,
          get() {
            throwIfDispatcherAmbiguous(this);
            return this._o[0].implementation;
          },
          set(fn) {
            throwIfDispatcherAmbiguous(this);
            this._o[0].implementation = fn;
          }
        },
        returnType: {
          enumerable: true,
          get() {
            throwIfDispatcherAmbiguous(this);
            return this._o[0].returnType;
          }
        },
        argumentTypes: {
          enumerable: true,
          get() {
            throwIfDispatcherAmbiguous(this);
            return this._o[0].argumentTypes;
          }
        },
        canInvokeWith: {
          enumerable: true,
          get(args) {
            throwIfDispatcherAmbiguous(this);
            return this._o[0].canInvokeWith;
          }
        },
        clone: {
          enumerable: true,
          value(options) {
            throwIfDispatcherAmbiguous(this);
            return this._o[0].clone(options);
          }
        },
        invoke: {
          value(receiver, args) {
            const overloads = this._o;
            const isInstance = receiver.$h !== null;
            for (let i = 0; i !== overloads.length; i++) {
              const method = overloads[i];
              if (!method.canInvokeWith(args)) {
                continue;
              }
              if (method.type === INSTANCE_METHOD && !isInstance) {
                const name = this.methodName;
                if (name === "toString") {
                  return `<class: ${receiver.$n}>`;
                }
                throw new Error(name + ": cannot call instance method without an instance");
              }
              return method.apply(receiver, args);
            }
            if (this.methodName === "toString") {
              return `<class: ${receiver.$n}>`;
            }
            throwOverloadError(this.methodName, this.overloads, "argument types do not match any of:");
          }
        }
      });
      methodPrototype = Object.create(Function.prototype, {
        methodName: {
          enumerable: true,
          get() {
            return this._p[0];
          }
        },
        holder: {
          enumerable: true,
          get() {
            return this._p[1];
          }
        },
        type: {
          enumerable: true,
          get() {
            return this._p[2];
          }
        },
        handle: {
          enumerable: true,
          get() {
            return this._p[3];
          }
        },
        implementation: {
          enumerable: true,
          get() {
            const replacement = this._r;
            return replacement !== void 0 ? replacement : null;
          },
          set(fn) {
            const params = this._p;
            const holder = params[1];
            const type = params[2];
            if (type === CONSTRUCTOR_METHOD) {
              throw new Error("Reimplementing $new is not possible; replace implementation of $init instead");
            }
            const existingReplacement = this._r;
            if (existingReplacement !== void 0) {
              holder.$f._patchedMethods.delete(this);
              const mangler = existingReplacement._m;
              mangler.revert(vm2);
              this._r = void 0;
            }
            if (fn !== null) {
              const [methodName, classWrapper, type2, methodId, retType, argTypes] = params;
              const replacement = implement(methodName, classWrapper, type2, retType, argTypes, fn, this);
              const mangler = makeMethodMangler3(methodId);
              replacement._m = mangler;
              this._r = replacement;
              mangler.replace(replacement, type2 === INSTANCE_METHOD, argTypes, vm2, api);
              holder.$f._patchedMethods.add(this);
            }
          }
        },
        returnType: {
          enumerable: true,
          get() {
            return this._p[4];
          }
        },
        argumentTypes: {
          enumerable: true,
          get() {
            return this._p[5];
          }
        },
        canInvokeWith: {
          enumerable: true,
          value(args) {
            const argTypes = this._p[5];
            if (args.length !== argTypes.length) {
              return false;
            }
            return argTypes.every((t, i) => {
              return t.isCompatible(args[i]);
            });
          }
        },
        clone: {
          enumerable: true,
          value(options) {
            const params = this._p.slice(0, 6);
            return makeMethod(...params, null, options);
          }
        },
        invoke: {
          value(receiver, args) {
            const env = vm2.getEnv();
            const params = this._p;
            const type = params[2];
            const retType = params[4];
            const argTypes = params[5];
            const replacement = this._r;
            const isInstanceMethod = type === INSTANCE_METHOD;
            const numArgs = args.length;
            const frameCapacity = 2 + numArgs;
            env.pushLocalFrame(frameCapacity);
            let borrowedHandle = null;
            try {
              let jniThis;
              if (isInstanceMethod) {
                jniThis = receiver.$getHandle();
              } else {
                borrowedHandle = receiver.$borrowClassHandle(env);
                jniThis = borrowedHandle.value;
              }
              let methodId;
              let strategy = receiver.$t;
              if (replacement === void 0) {
                methodId = params[3];
              } else {
                const mangler = replacement._m;
                methodId = mangler.resolveTarget(receiver, isInstanceMethod, env, api);
                if (isArtVm) {
                  const pendingCalls = replacement._c;
                  if (pendingCalls.has(getCurrentThreadId())) {
                    strategy = STRATEGY_DIRECT;
                  }
                }
              }
              const jniArgs = [
                env.handle,
                jniThis,
                methodId
              ];
              for (let i = 0; i !== numArgs; i++) {
                jniArgs.push(argTypes[i].toJni(args[i], env));
              }
              let jniCall;
              if (strategy === STRATEGY_VIRTUAL) {
                jniCall = params[6];
              } else {
                jniCall = params[7];
                if (isInstanceMethod) {
                  jniArgs.splice(2, 0, receiver.$copyClassHandle(env));
                }
              }
              const jniRetval = jniCall.apply(null, jniArgs);
              env.throwIfExceptionPending();
              return retType.fromJni(jniRetval, env, true);
            } finally {
              if (borrowedHandle !== null) {
                borrowedHandle.unref(env);
              }
              env.popLocalFrame(NULL);
            }
          }
        },
        toString: {
          enumerable: true,
          value() {
            return `function ${this.methodName}(${this.argumentTypes.map((t) => t.className).join(", ")}): ${this.returnType.className}`;
          }
        }
      });
      valueOfPrototype = Object.create(Function.prototype, {
        methodName: {
          enumerable: true,
          get() {
            return "valueOf";
          }
        },
        holder: {
          enumerable: true,
          get() {
            return this._p[0];
          }
        },
        type: {
          enumerable: true,
          get() {
            return this._p[1];
          }
        },
        handle: {
          enumerable: true,
          get() {
            return NULL;
          }
        },
        implementation: {
          enumerable: true,
          get() {
            return null;
          },
          set(fn) {
          }
        },
        returnType: {
          enumerable: true,
          get() {
            const classWrapper = this.holder;
            return classWrapper.$f.use(classWrapper.$n);
          }
        },
        argumentTypes: {
          enumerable: true,
          get() {
            return [];
          }
        },
        canInvokeWith: {
          enumerable: true,
          value(args) {
            return args.length === 0;
          }
        },
        clone: {
          enumerable: true,
          value(options) {
            throw new Error("Invalid operation");
          }
        }
      });
      Object.defineProperties(Field.prototype, {
        value: {
          enumerable: true,
          get() {
            const [holder, type, rtype, id, getValue] = this._p;
            const env = vm2.getEnv();
            env.pushLocalFrame(4);
            let borrowedHandle = null;
            try {
              let jniThis;
              if (type === INSTANCE_FIELD) {
                jniThis = holder.$getHandle();
                if (jniThis === null) {
                  throw new Error("Cannot access an instance field without an instance");
                }
              } else {
                borrowedHandle = holder.$borrowClassHandle(env);
                jniThis = borrowedHandle.value;
              }
              const jniRetval = getValue(env.handle, jniThis, id);
              env.throwIfExceptionPending();
              return rtype.fromJni(jniRetval, env, true);
            } finally {
              if (borrowedHandle !== null) {
                borrowedHandle.unref(env);
              }
              env.popLocalFrame(NULL);
            }
          },
          set(value) {
            const [holder, type, rtype, id, , setValue] = this._p;
            const env = vm2.getEnv();
            env.pushLocalFrame(4);
            let borrowedHandle = null;
            try {
              let jniThis;
              if (type === INSTANCE_FIELD) {
                jniThis = holder.$getHandle();
                if (jniThis === null) {
                  throw new Error("Cannot access an instance field without an instance");
                }
              } else {
                borrowedHandle = holder.$borrowClassHandle(env);
                jniThis = borrowedHandle.value;
              }
              if (!rtype.isCompatible(value)) {
                throw new Error(`Expected value compatible with ${rtype.className}`);
              }
              const jniValue = rtype.toJni(value, env);
              setValue(env.handle, jniThis, id, jniValue);
              env.throwIfExceptionPending();
            } finally {
              if (borrowedHandle !== null) {
                borrowedHandle.unref(env);
              }
              env.popLocalFrame(NULL);
            }
          }
        },
        holder: {
          enumerable: true,
          get() {
            return this._p[0];
          }
        },
        fieldType: {
          enumerable: true,
          get() {
            return this._p[1];
          }
        },
        fieldReturnType: {
          enumerable: true,
          get() {
            return this._p[2];
          }
        },
        toString: {
          enumerable: true,
          value() {
            const inlineString = `Java.Field{holder: ${this.holder}, fieldType: ${this.fieldType}, fieldReturnType: ${this.fieldReturnType}, value: ${this.value}}`;
            if (inlineString.length < 200) {
              return inlineString;
            }
            const multilineString = `Java.Field{
	holder: ${this.holder},
	fieldType: ${this.fieldType},
	fieldReturnType: ${this.fieldReturnType},
	value: ${this.value},
}`;
            return multilineString.split("\n").map((l) => {
              if (l.length <= 200) {
                return l;
              }
              const spaceIndex = l.indexOf(" ");
              const cut = spaceIndex === -1 ? 200 : spaceIndex + 1;
              return l.slice(0, cut) + "...,";
            }).join("\n");
          }
        }
      });
      DexFile = class _DexFile {
        static fromBuffer(buffer, factory) {
          const fileValue = createTemporaryDex(factory);
          const filePath = fileValue.getCanonicalPath().toString();
          const file = new File(filePath, "w");
          file.write(buffer.buffer);
          file.close();
          setReadOnlyDex(filePath, factory);
          return new _DexFile(filePath, fileValue, factory);
        }
        constructor(path, file, factory) {
          this.path = path;
          this.file = file;
          this._factory = factory;
        }
        load() {
          const { _factory: factory } = this;
          const { codeCacheDir } = factory;
          const DexClassLoader = factory.use("dalvik.system.DexClassLoader");
          const JFile = factory.use("java.io.File");
          let file = this.file;
          if (file === null) {
            file = factory.use("java.io.File").$new(this.path);
          }
          if (!file.exists()) {
            throw new Error("File not found");
          }
          JFile.$new(codeCacheDir).mkdirs();
          factory.loader = DexClassLoader.$new(file.getCanonicalPath(), codeCacheDir, null, factory.loader);
          vm2.preventDetachDueToClassLoader();
        }
        getClassNames() {
          const { _factory: factory } = this;
          const DexFile2 = factory.use("dalvik.system.DexFile");
          const optimizedDex = createTemporaryDex(factory);
          const dx = DexFile2.loadDex(this.path, optimizedDex.getCanonicalPath(), 0);
          const classNames = [];
          const enumeratorClassNames = dx.entries();
          while (enumeratorClassNames.hasMoreElements()) {
            classNames.push(enumeratorClassNames.nextElement().toString());
          }
          return classNames;
        }
      };
    }
  });

  // node_modules/frida-java-bridge/index.js
  function initFactoryFromApplication(factory, app) {
    const Process2 = factory.use("android.os.Process");
    factory.loader = app.getClassLoader();
    if (Process2.myUid() === Process2.SYSTEM_UID.value) {
      factory.cacheDir = "/data/system";
      factory.codeCacheDir = "/data/dalvik-cache";
    } else {
      if ("getCodeCacheDir" in app) {
        factory.cacheDir = app.getCacheDir().getCanonicalPath();
        factory.codeCacheDir = app.getCodeCacheDir().getCanonicalPath();
      } else {
        factory.cacheDir = app.getFilesDir().getCanonicalPath();
        factory.codeCacheDir = app.getCacheDir().getCanonicalPath();
      }
    }
  }
  function initFactoryFromLoadedApk(factory, apk) {
    const JFile = factory.use("java.io.File");
    factory.loader = apk.getClassLoader();
    const dataDir = JFile.$new(apk.getDataDir()).getCanonicalPath();
    factory.cacheDir = dataDir;
    factory.codeCacheDir = dataDir + "/cache";
  }
  var jsizeSize4, pointerSize8, Runtime, runtime, frida_java_bridge_default;
  var init_frida_java_bridge = __esm({
    "node_modules/frida-java-bridge/index.js"() {
      init_node_globals();
      init_api();
      init_android();
      init_class_factory();
      init_class_model();
      init_env();
      init_types();
      init_vm();
      init_result();
      jsizeSize4 = 4;
      pointerSize8 = Process.pointerSize;
      Runtime = class {
        ACC_PUBLIC = 1;
        ACC_PRIVATE = 2;
        ACC_PROTECTED = 4;
        ACC_STATIC = 8;
        ACC_FINAL = 16;
        ACC_SYNCHRONIZED = 32;
        ACC_BRIDGE = 64;
        ACC_VARARGS = 128;
        ACC_NATIVE = 256;
        ACC_ABSTRACT = 1024;
        ACC_STRICT = 2048;
        ACC_SYNTHETIC = 4096;
        constructor() {
          this.classFactory = null;
          this.ClassFactory = ClassFactory;
          this.vm = null;
          this.api = null;
          this._initialized = false;
          this._apiError = null;
          this._wakeupHandler = null;
          this._pollListener = null;
          this._pendingMainOps = [];
          this._pendingVmOps = [];
          this._cachedIsAppProcess = null;
          try {
            this._tryInitialize();
          } catch (e) {
          }
        }
        _tryInitialize() {
          if (this._initialized) {
            return true;
          }
          if (this._apiError !== null) {
            throw this._apiError;
          }
          let api2;
          try {
            api2 = api_default();
            this.api = api2;
          } catch (e) {
            this._apiError = e;
            throw e;
          }
          if (api2 === null) {
            return false;
          }
          const vm3 = new VM(api2);
          this.vm = vm3;
          initialize(vm3);
          ClassFactory._initialize(vm3, api2);
          this.classFactory = new ClassFactory();
          this._initialized = true;
          return true;
        }
        _dispose() {
          if (this.api === null) {
            return;
          }
          const { vm: vm3 } = this;
          vm3.perform((env) => {
            ClassFactory._disposeAll(env);
            Env.dispose(env);
          });
          Script.nextTick(() => {
            VM.dispose(vm3);
          });
        }
        get available() {
          return this._tryInitialize();
        }
        get androidVersion() {
          return getAndroidVersion();
        }
        synchronized(obj, fn) {
          const { $h: objHandle = obj } = obj;
          if (!(objHandle instanceof NativePointer)) {
            throw new Error("Java.synchronized: the first argument `obj` must be either a pointer or a Java instance");
          }
          const env = this.vm.getEnv();
          checkJniResult("VM::MonitorEnter", env.monitorEnter(objHandle));
          try {
            fn();
          } finally {
            env.monitorExit(objHandle);
          }
        }
        enumerateLoadedClasses(callbacks) {
          this._checkAvailable();
          const { flavor } = this.api;
          if (flavor === "jvm") {
            this._enumerateLoadedClassesJvm(callbacks);
          } else if (flavor === "art") {
            this._enumerateLoadedClassesArt(callbacks);
          } else {
            this._enumerateLoadedClassesDalvik(callbacks);
          }
        }
        enumerateLoadedClassesSync() {
          const classes = [];
          this.enumerateLoadedClasses({
            onMatch(c) {
              classes.push(c);
            },
            onComplete() {
            }
          });
          return classes;
        }
        enumerateClassLoaders(callbacks) {
          this._checkAvailable();
          const { flavor } = this.api;
          if (flavor === "jvm") {
            this._enumerateClassLoadersJvm(callbacks);
          } else if (flavor === "art") {
            this._enumerateClassLoadersArt(callbacks);
          } else {
            throw new Error("Enumerating class loaders is not supported on Dalvik");
          }
        }
        enumerateClassLoadersSync() {
          const loaders = [];
          this.enumerateClassLoaders({
            onMatch(c) {
              loaders.push(c);
            },
            onComplete() {
            }
          });
          return loaders;
        }
        _enumerateLoadedClassesJvm(callbacks) {
          const { api: api2, vm: vm3 } = this;
          const { jvmti } = api2;
          const env = vm3.getEnv();
          const countPtr = Memory.alloc(jsizeSize4);
          const classesPtr = Memory.alloc(pointerSize8);
          jvmti.getLoadedClasses(countPtr, classesPtr);
          const count = countPtr.readS32();
          const classes = classesPtr.readPointer();
          const handles = [];
          for (let i = 0; i !== count; i++) {
            handles.push(classes.add(i * pointerSize8).readPointer());
          }
          jvmti.deallocate(classes);
          try {
            for (const handle of handles) {
              const className = env.getClassName(handle);
              callbacks.onMatch(className, handle);
            }
            callbacks.onComplete();
          } finally {
            handles.forEach((handle) => {
              env.deleteLocalRef(handle);
            });
          }
        }
        _enumerateClassLoadersJvm(callbacks) {
          this.choose("java.lang.ClassLoader", callbacks);
        }
        _enumerateLoadedClassesArt(callbacks) {
          const { vm: vm3, api: api2 } = this;
          const env = vm3.getEnv();
          const addGlobalReference = api2["art::JavaVMExt::AddGlobalRef"];
          const { vm: vmHandle } = api2;
          withRunnableArtThread(vm3, env, (thread) => {
            const collectClassHandles = makeArtClassVisitor((klass) => {
              const handle = addGlobalReference(vmHandle, thread, klass);
              try {
                const className = env.getClassName(handle);
                callbacks.onMatch(className, handle);
              } finally {
                env.deleteGlobalRef(handle);
              }
              return true;
            });
            api2["art::ClassLinker::VisitClasses"](api2.artClassLinker.address, collectClassHandles);
          });
          callbacks.onComplete();
        }
        _enumerateClassLoadersArt(callbacks) {
          const { classFactory: factory, vm: vm3, api: api2 } = this;
          const env = vm3.getEnv();
          const visitClassLoaders = api2["art::ClassLinker::VisitClassLoaders"];
          if (visitClassLoaders === void 0) {
            throw new Error("This API is only available on Android >= 7.0");
          }
          const ClassLoader = factory.use("java.lang.ClassLoader");
          const loaderHandles = [];
          const addGlobalReference = api2["art::JavaVMExt::AddGlobalRef"];
          const { vm: vmHandle } = api2;
          withRunnableArtThread(vm3, env, (thread) => {
            const collectLoaderHandles = makeArtClassLoaderVisitor((loader) => {
              loaderHandles.push(addGlobalReference(vmHandle, thread, loader));
              return true;
            });
            withAllArtThreadsSuspended(() => {
              visitClassLoaders(api2.artClassLinker.address, collectLoaderHandles);
            });
          });
          try {
            loaderHandles.forEach((handle) => {
              const loader = factory.cast(handle, ClassLoader);
              callbacks.onMatch(loader);
            });
          } finally {
            loaderHandles.forEach((handle) => {
              env.deleteGlobalRef(handle);
            });
          }
          callbacks.onComplete();
        }
        _enumerateLoadedClassesDalvik(callbacks) {
          const { api: api2 } = this;
          const HASH_TOMBSTONE = ptr("0xcbcacccd");
          const loadedClassesOffset = 172;
          const hashEntrySize = 8;
          const ptrLoadedClassesHashtable = api2.gDvm.add(loadedClassesOffset);
          const hashTable = ptrLoadedClassesHashtable.readPointer();
          const tableSize = hashTable.readS32();
          const ptrpEntries = hashTable.add(12);
          const pEntries = ptrpEntries.readPointer();
          const end = tableSize * hashEntrySize;
          for (let offset = 0; offset < end; offset += hashEntrySize) {
            const pEntryPtr = pEntries.add(offset);
            const dataPtr = pEntryPtr.add(4).readPointer();
            if (dataPtr.isNull() || dataPtr.equals(HASH_TOMBSTONE)) {
              continue;
            }
            const descriptionPtr = dataPtr.add(24).readPointer();
            const description = descriptionPtr.readUtf8String();
            if (description.startsWith("L")) {
              const name = description.substring(1, description.length - 1).replace(/\//g, ".");
              callbacks.onMatch(name);
            }
          }
          callbacks.onComplete();
        }
        enumerateMethods(query) {
          const { classFactory: factory } = this;
          const env = this.vm.getEnv();
          const ClassLoader = factory.use("java.lang.ClassLoader");
          return Model.enumerateMethods(query, this.api, env).map((group) => {
            const handle = group.loader;
            group.loader = handle !== null ? factory.wrap(handle, ClassLoader, env) : null;
            return group;
          });
        }
        scheduleOnMainThread(fn) {
          this.performNow(() => {
            this._pendingMainOps.push(fn);
            let { _wakeupHandler: wakeupHandler } = this;
            if (wakeupHandler === null) {
              const { classFactory: factory } = this;
              const Handler = factory.use("android.os.Handler");
              const Looper = factory.use("android.os.Looper");
              wakeupHandler = Handler.$new(Looper.getMainLooper());
              this._wakeupHandler = wakeupHandler;
            }
            if (this._pollListener === null) {
              this._pollListener = Interceptor.attach(Process.getModuleByName("libc.so").getExportByName("epoll_wait"), this._makePollHook());
              Interceptor.flush();
            }
            wakeupHandler.sendEmptyMessage(1);
          });
        }
        _makePollHook() {
          const mainThreadId = Process.id;
          const { _pendingMainOps: pending } = this;
          return function() {
            if (this.threadId !== mainThreadId) {
              return;
            }
            let fn;
            while ((fn = pending.shift()) !== void 0) {
              try {
                fn();
              } catch (e) {
                Script.nextTick(() => {
                  throw e;
                });
              }
            }
          };
        }
        perform(fn) {
          this._checkAvailable();
          if (!this._isAppProcess() || this.classFactory.loader !== null) {
            try {
              this.vm.perform(fn);
            } catch (e) {
              Script.nextTick(() => {
                throw e;
              });
            }
          } else {
            this._pendingVmOps.push(fn);
            if (this._pendingVmOps.length === 1) {
              this._performPendingVmOpsWhenReady();
            }
          }
        }
        performNow(fn) {
          this._checkAvailable();
          return this.vm.perform(() => {
            const { classFactory: factory } = this;
            if (this._isAppProcess() && factory.loader === null) {
              const ActivityThread = factory.use("android.app.ActivityThread");
              const app = ActivityThread.currentApplication();
              if (app !== null) {
                initFactoryFromApplication(factory, app);
              }
            }
            return fn();
          });
        }
        _performPendingVmOpsWhenReady() {
          this.vm.perform(() => {
            const { classFactory: factory } = this;
            const ActivityThread = factory.use("android.app.ActivityThread");
            const app = ActivityThread.currentApplication();
            if (app !== null) {
              initFactoryFromApplication(factory, app);
              this._performPendingVmOps();
              return;
            }
            const runtime2 = this;
            let initialized = false;
            let hookpoint = "early";
            const handleBindApplication = ActivityThread.handleBindApplication;
            handleBindApplication.implementation = function(data) {
              if (data.instrumentationName.value !== null) {
                hookpoint = "late";
                const LoadedApk = factory.use("android.app.LoadedApk");
                const makeApplication = LoadedApk.makeApplication;
                makeApplication.implementation = function(forceDefaultAppClass, instrumentation) {
                  if (!initialized) {
                    initialized = true;
                    initFactoryFromLoadedApk(factory, this);
                    runtime2._performPendingVmOps();
                  }
                  return makeApplication.apply(this, arguments);
                };
              }
              handleBindApplication.apply(this, arguments);
            };
            const getPackageInfoCandidates = ActivityThread.getPackageInfo.overloads.map((m) => [m.argumentTypes.length, m]).sort(([arityA], [arityB]) => arityB - arityA).map(([_, method]) => method);
            const getPackageInfo = getPackageInfoCandidates[0];
            getPackageInfo.implementation = function(...args) {
              const apk = getPackageInfo.call(this, ...args);
              if (!initialized && hookpoint === "early") {
                initialized = true;
                initFactoryFromLoadedApk(factory, apk);
                runtime2._performPendingVmOps();
              }
              return apk;
            };
            const pollForApplication = () => {
              runtime2.vm.perform(() => {
                const app2 = ActivityThread.currentApplication();
                if (initialized) {
                  return;
                }
                if (app2 === null) {
                  setTimeout(pollForApplication, 50);
                  return;
                }
                initialized = true;
                initFactoryFromApplication(factory, app2);
                runtime2._performPendingVmOps();
              });
            };
            setTimeout(pollForApplication, 50);
          });
        }
        _performPendingVmOps() {
          const { vm: vm3, _pendingVmOps: pending } = this;
          let fn;
          while ((fn = pending.shift()) !== void 0) {
            try {
              vm3.perform(fn);
            } catch (e) {
              Script.nextTick(() => {
                throw e;
              });
            }
          }
        }
        use(className, options) {
          return this.classFactory.use(className, options);
        }
        openClassFile(filePath) {
          return this.classFactory.openClassFile(filePath);
        }
        choose(specifier, callbacks) {
          this.classFactory.choose(specifier, callbacks);
        }
        retain(obj) {
          return this.classFactory.retain(obj);
        }
        cast(obj, C) {
          return this.classFactory.cast(obj, C);
        }
        array(type, elements) {
          return this.classFactory.array(type, elements);
        }
        backtrace(options) {
          return backtrace(this.vm, options);
        }
        // Reference: http://stackoverflow.com/questions/2848575/how-to-detect-ui-thread-on-android
        isMainThread() {
          const Looper = this.classFactory.use("android.os.Looper");
          const mainLooper = Looper.getMainLooper();
          const myLooper = Looper.myLooper();
          if (myLooper === null) {
            return false;
          }
          return mainLooper.$isSameObject(myLooper);
        }
        registerClass(spec) {
          return this.classFactory.registerClass(spec);
        }
        deoptimizeEverything() {
          const { vm: vm3 } = this;
          return deoptimizeEverything(vm3, vm3.getEnv());
        }
        deoptimizeBootImage() {
          const { vm: vm3 } = this;
          return deoptimizeBootImage(vm3, vm3.getEnv());
        }
        deoptimizeMethod(method) {
          const { vm: vm3 } = this;
          return deoptimizeMethod(vm3, vm3.getEnv(), method);
        }
        isMethodDeoptimized(method) {
          const { vm: vm3 } = this;
          return isMethodDeoptimized(vm3, vm3.getEnv(), method);
        }
        _checkAvailable() {
          if (!this.available) {
            throw new Error("Java API not available");
          }
        }
        _isAppProcess() {
          let result = this._cachedIsAppProcess;
          if (result === null) {
            if (this.api.flavor === "jvm") {
              result = false;
              this._cachedIsAppProcess = result;
              return result;
            }
            const readlink = new NativeFunction(Module.getGlobalExportByName("readlink"), "pointer", ["pointer", "pointer", "pointer"], {
              exceptions: "propagate"
            });
            const pathname = Memory.allocUtf8String("/proc/self/exe");
            const bufferSize = 1024;
            const buffer = Memory.alloc(bufferSize);
            const size = readlink(pathname, buffer, ptr(bufferSize)).toInt32();
            if (size !== -1) {
              const exe = buffer.readUtf8String(size);
              result = /^\/system\/bin\/app_process/.test(exe);
            } else {
              result = true;
            }
            this._cachedIsAppProcess = result;
          }
          return result;
        }
      };
      runtime = new Runtime();
      Script.bindWeak(runtime, () => {
        runtime._dispose();
      });
      frida_java_bridge_default = runtime;
    }
  });

  // agent.js
  var require_agent = __commonJS({
    "agent.js"() {
      init_node_globals();
      init_frida_java_bridge();
      globalThis.Java = frida_java_bridge_default;
      var dexLoader = null;
      var ctxRef = null;
      var clientRef = null;
      var PRODUCTS = ["g1.play.20tb", "g1.play.ai.pro", "g1.30tb"];
      var PREFER = "";
      function L(v) {
        frida_java_bridge_default.classFactory.loader = v;
      }
      function S(o) {
        send(o);
      }
      function periodRank(p) {
        var m = { "P1Y": 12, "P12M": 12, "P6M": 6, "P3M": 3, "P1M": 1 };
        return m[String(p)] || 0;
      }
      function getActivity() {
        L(null);
        var found = null;
        try {
          frida_java_bridge_default.choose("android.app.Activity", {
            onMatch: function(a) {
              try {
                if (!found && !a.isFinishing()) found = a;
              } catch (e) {
              }
            },
            onComplete: function() {
            }
          });
        } catch (e) {
          S({ ev: "choose_err", m: String(e).slice(0, 80) });
        }
        return found;
      }
      function boot() {
        frida_java_bridge_default.perform(function() {
          try {
            L(null);
            ctxRef = frida_java_bridge_default.use("android.app.ActivityThread").currentApplication().getApplicationContext();
            var DexClassLoader = frida_java_bridge_default.use("dalvik.system.DexClassLoader");
            dexLoader = DexClassLoader.$new(
              "/data/local/tmp/module_521.apk",
              ctxRef.getCodeCacheDir().getAbsolutePath(),
              null,
              ctxRef.getClassLoader()
            );
            L(dexLoader);
            var BillingClient = frida_java_bridge_default.use("com.android.billingclient.api.BillingClient");
            var PUL = frida_java_bridge_default.use("com.android.billingclient.api.PurchasesUpdatedListener");
            var Lst = frida_java_bridge_default.registerClass({ skipInterfaceExpansion: true, name: "rc.A" + Date.now(), implements: [PUL], methods: {
              onPurchasesUpdated: function(r, p) {
                S({ ev: "purchase_cb", code: r.getResponseCode(), msg: String(r.getDebugMessage() || "") });
              }
            } });
            var b = BillingClient.newBuilder(ctxRef);
            b.setListener(Lst.$new());
            try {
              b.enablePendingPurchases();
            } catch (e) {
            }
            clientRef = b.build();
            var SLL = frida_java_bridge_default.use("com.android.billingclient.api.BillingClientStateListener");
            var SL = frida_java_bridge_default.registerClass({ skipInterfaceExpansion: true, name: "rc.B" + Date.now(), implements: [SLL], methods: {
              onBillingSetupFinished: function(r) {
                S({ ev: "setup", code: r.getResponseCode() });
                if (r.getResponseCode() === 0) query();
              },
              onBillingServiceDisconnected: function() {
                S({ ev: "disc" });
              }
            } });
            clientRef.startConnection(SL.$new());
            S({ ev: "connecting", products: PRODUCTS });
          } catch (e) {
            S({ ev: "boot_err", m: String(e).slice(0, 200) });
          }
        });
      }
      function query() {
        try {
          L(dexLoader);
          var Prod = frida_java_bridge_default.use("com.android.billingclient.api.QueryProductDetailsParams$Product");
          var Params = frida_java_bridge_default.use("com.android.billingclient.api.QueryProductDetailsParams");
          var PDL = frida_java_bridge_default.use("com.android.billingclient.api.ProductDetailsResponseListener");
          var PL = frida_java_bridge_default.registerClass({ skipInterfaceExpansion: true, name: "rc.C" + Date.now(), implements: [PDL], methods: {
            onProductDetailsResponse: function(res, list) {
              S({ ev: "pd", code: res.getResponseCode(), n: list ? list.size() : 0 });
              if (res.getResponseCode() !== 0 || !list || list.size() === 0) return;
              L(dexLoader);
              var PD = frida_java_bridge_default.use("com.android.billingclient.api.ProductDetails");
              var SOD = frida_java_bridge_default.use("com.android.billingclient.api.ProductDetails$SubscriptionOfferDetails");
              var PP = frida_java_bridge_default.use("com.android.billingclient.api.ProductDetails$PricingPhase");
              var best = null;
              for (var i = 0; i < list.size(); i++) {
                var pd = frida_java_bridge_default.cast(list.get(i), PD);
                var pid = String(pd.getProductId());
                var offs = pd.getSubscriptionOfferDetails();
                if (!offs) {
                  S({ ev: "no_offers", product: pid });
                  continue;
                }
                for (var j = 0; j < offs.size(); j++) {
                  var o = frida_java_bridge_default.cast(offs.get(j), SOD);
                  var oid = String(o.getOfferId());
                  var tok = String(o.getOfferToken());
                  var ph = o.getPricingPhases().getPricingPhaseList();
                  var first = frida_java_bridge_default.cast(ph.get(0), PP);
                  var micros = String(first.getPriceAmountMicros());
                  var period = String(first.getBillingPeriod());
                  S({ ev: "offer", product: pid, id: oid, micros, period, token: tok, title: String(pd.getTitle()), name: String(pd.getName()) });
                  if (micros !== "0") continue;
                  var rank = periodRank(period);
                  if (!best || rank > best.rank || PREFER && oid === PREFER) {
                    if (PREFER && oid !== PREFER) continue;
                    best = { pd, offer: o, product: pid, id: oid, rank, period, token: tok };
                  }
                }
              }
              if (!best) {
                S({ ev: "no_trial" });
                return;
              }
              S({ ev: "chosen", product: best.product, id: best.id, period: best.period });
              if (typeof LIST_ONLY !== "undefined" && LIST_ONLY) {
                S({ ev: "list_only", product: best.product, id: best.id, period: best.period, token: best.token });
                return;
              }
              if (typeof OLD_TOKEN !== "undefined" && OLD_TOKEN) {
                S({ ev: "stack_start", product: best.product, id: best.id, src: "provided_token" });
                launch(best.pd, best.offer, OLD_TOKEN);
              } else if (typeof STACK !== "undefined" && STACK) {
                S({ ev: "stack_start", product: best.product, id: best.id, src: "query" });
                launchWithStack(best.pd, best.offer);
              } else {
                launch(best.pd, best.offer);
              }
            }
          } });
          var arr = frida_java_bridge_default.use("java.util.ArrayList").$new();
          for (var k = 0; k < PRODUCTS.length; k++) {
            arr.add(Prod.newBuilder().setProductId(PRODUCTS[k]).setProductType("subs").build());
          }
          L(dexLoader);
          clientRef.queryProductDetailsAsync(Params.newBuilder().setProductList(arr).build(), PL.$new());
          S({ ev: "query_sent" });
        } catch (e) {
          S({ ev: "query_err", m: String(e).slice(0, 200) });
        }
      }
      function launchWithStack(pd, offer) {
        try {
          L(dexLoader);
          var QP = frida_java_bridge_default.use("com.android.billingclient.api.QueryPurchasesParams");
          var PRL = frida_java_bridge_default.use("com.android.billingclient.api.PurchasesResponseListener");
          var cls = frida_java_bridge_default.registerClass({ skipInterfaceExpansion: true, name: "rc.P" + Date.now(), implements: [PRL], methods: {
            onQueryPurchasesResponse: function(br, purchases) {
              try {
                var list = frida_java_bridge_default.cast(purchases, frida_java_bridge_default.use("java.util.List"));
                S({ ev: "purchases", n: list.size(), code: String(br.getResponseCode()) });
                if (list.size() === 0) {
                  S({ ev: "no_purchase" });
                  launch(pd, offer);
                  return;
                }
                var pu = frida_java_bridge_default.cast(list.get(0), frida_java_bridge_default.use("com.android.billingclient.api.Purchase"));
                var tok = String(pu.getPurchaseToken());
                S({ ev: "old_purchase", head: tok.slice(0, 16), products: String(pu.getProducts()) });
                launch(pd, offer, tok);
              } catch (e) {
                S({ ev: "stack_query_err", m: String(e).slice(0, 200) });
                launch(pd, offer);
              }
            }
          } });
          var qp = QP.newBuilder().setProductType("subs").build();
          clientRef.queryPurchasesAsync(qp, cls.$new());
        } catch (e) {
          S({ ev: "stack_outer_err", m: String(e).slice(0, 200) });
          launch(pd, offer);
        }
      }
      function launch(pd, offer, oldTok) {
        try {
          L(dexLoader);
          var PDP = frida_java_bridge_default.use("com.android.billingclient.api.BillingFlowParams$ProductDetailsParams");
          var BFP = frida_java_bridge_default.use("com.android.billingclient.api.BillingFlowParams");
          var pdp = PDP.newBuilder().setProductDetails(pd).setOfferToken(String(offer.getOfferToken())).build();
          var l = frida_java_bridge_default.use("java.util.ArrayList").$new();
          l.add(pdp);
          var b = BFP.newBuilder().setProductDetailsParamsList(l);
          if (oldTok) {
            try {
              var SUP = frida_java_bridge_default.use("com.android.billingclient.api.BillingFlowParams$SubscriptionUpdateParams");
              var md = typeof STACK_MODE !== "undefined" && STACK_MODE ? STACK_MODE : 5;
              var sb = SUP.newBuilder();
              var mode_set = false;
              try {
                sb = sb.setReplaceProrationMode(md);
                mode_set = true;
              } catch (e1) {
                try {
                  sb = sb.setReplaceSkusProrationMode(md);
                  mode_set = true;
                } catch (e2) {
                  S({ ev: "mode_err", m: String(e2).slice(0, 120) });
                }
              }
              S({ ev: "mode_applied", mode: md, ok: mode_set });
              var sup = sb.setOldPurchaseToken(String(oldTok)).build();
              b = b.setSubscriptionUpdateParams(sup);
              S({ ev: "stack_mode", mode: md, old: String(oldTok).slice(0, 16) });
            } catch (e) {
              S({ ev: "stack_param_err", m: String(e).slice(0, 160) });
            }
          }
          var params = b.build();
          var act = getActivity();
          S({ ev: "activity", a: act ? String(act.getClass().getName()) : "null" });
          if (!act) {
            S({ ev: "no_activity" });
            return;
          }
          L(null);
          var Handler = frida_java_bridge_default.use("android.os.Handler");
          var Looper = frida_java_bridge_default.use("android.os.Looper");
          var R = frida_java_bridge_default.registerClass({ skipInterfaceExpansion: true, name: "rc.R" + Date.now(), implements: [frida_java_bridge_default.use("java.lang.Runnable")], methods: {
            run: function() {
              try {
                L(dexLoader);
                var Activity = frida_java_bridge_default.use("android.app.Activity");
                var r2 = clientRef.launchBillingFlow(frida_java_bridge_default.cast(act, Activity), params);
                S({ ev: "launched", code: r2.getResponseCode(), msg: String(r2.getDebugMessage() || "") });
              } catch (e) {
                S({ ev: "launch_err", m: String(e).slice(0, 200) });
              }
            }
          } });
          Handler.$new(Looper.getMainLooper()).post(R.$new());
        } catch (e) {
          S({ ev: "launch_outer_err", m: String(e).slice(0, 200) });
        }
      }
      var __tries = 0;
      var iv = setInterval(function() {
        try {
          L(null);
          var a = frida_java_bridge_default.use("android.app.ActivityThread").currentApplication();
          __tries++;
          if (a || __tries > 10) {
            clearInterval(iv);
            S({ ev: "boot_start", app: !!a, tries: __tries });
            boot();
          }
        } catch (e) {
          __tries++;
          if (__tries > 10) {
            clearInterval(iv);
            S({ ev: "boot_force", m: String(e).slice(0, 120) });
            try {
              boot();
            } catch (e2) {
              S({ ev: "boot_fail", m: String(e2).slice(0, 160) });
            }
          }
        }
      }, 400);
    }
  });
  require_agent();
})();
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsiZnJpZGEtc2hpbTpub2RlX21vZHVsZXMvQGZyaWRhL2Jhc2U2NC1qcy9pbmRleC5qcyIsICJmcmlkYS1zaGltOm5vZGVfbW9kdWxlcy9AZnJpZGEvaWVlZTc1NC9pbmRleC5qcyIsICJmcmlkYS1zaGltOm5vZGVfbW9kdWxlcy9AZnJpZGEvYnVmZmVyL2luZGV4LmpzIiwgImZyaWRhLWJ1aWx0aW5zOi9ub2RlLWdsb2JhbHMuanMiLCAibm9kZV9tb2R1bGVzL2ZyaWRhLWphdmEtYnJpZGdlL2xpYi9hbGxvYy5qcyIsICJub2RlX21vZHVsZXMvZnJpZGEtamF2YS1icmlkZ2UvbGliL3Jlc3VsdC5qcyIsICJub2RlX21vZHVsZXMvZnJpZGEtamF2YS1icmlkZ2UvbGliL2p2bXRpLmpzIiwgIm5vZGVfbW9kdWxlcy9mcmlkYS1qYXZhLWJyaWRnZS9saWIvbWFjaGluZS1jb2RlLmpzIiwgIm5vZGVfbW9kdWxlcy9mcmlkYS1qYXZhLWJyaWRnZS9saWIvbWVtb2l6ZS5qcyIsICJub2RlX21vZHVsZXMvZnJpZGEtamF2YS1icmlkZ2UvbGliL2Vudi5qcyIsICJub2RlX21vZHVsZXMvZnJpZGEtamF2YS1icmlkZ2UvbGliL3ZtLmpzIiwgIm5vZGVfbW9kdWxlcy9mcmlkYS1qYXZhLWJyaWRnZS9saWIvYW5kcm9pZC5qcyIsICJub2RlX21vZHVsZXMvZnJpZGEtamF2YS1icmlkZ2UvbGliL2p2bS5qcyIsICJub2RlX21vZHVsZXMvZnJpZGEtamF2YS1icmlkZ2UvbGliL2FwaS5qcyIsICJub2RlX21vZHVsZXMvZnJpZGEtamF2YS1icmlkZ2UvbGliL2NsYXNzLW1vZGVsLmpzIiwgIm5vZGVfbW9kdWxlcy9mcmlkYS1qYXZhLWJyaWRnZS9saWIvbHJ1LmpzIiwgIm5vZGVfbW9kdWxlcy9mcmlkYS1qYXZhLWJyaWRnZS9saWIvbWtkZXguanMiLCAibm9kZV9tb2R1bGVzL2ZyaWRhLWphdmEtYnJpZGdlL2xpYi90eXBlcy5qcyIsICJub2RlX21vZHVsZXMvZnJpZGEtamF2YS1icmlkZ2UvbGliL2NsYXNzLWZhY3RvcnkuanMiLCAibm9kZV9tb2R1bGVzL2ZyaWRhLWphdmEtYnJpZGdlL2luZGV4LmpzIiwgImFnZW50LmpzIl0sCiAgIm1hcHBpbmdzIjogIjs7Ozs7Ozs7Ozs7Ozs7O0FBY0EsV0FBUyxRQUFTLEtBQUs7QUFDckIsVUFBTSxNQUFNLElBQUk7QUFFaEIsUUFBSSxNQUFNLElBQUksR0FBRztBQUNmLFlBQU0sSUFBSSxNQUFNLGdEQUFnRDtBQUFBLElBQ2xFO0FBSUEsUUFBSSxXQUFXLElBQUksUUFBUSxHQUFHO0FBQzlCLFFBQUksYUFBYSxHQUFJLFlBQVc7QUFFaEMsVUFBTSxrQkFBa0IsYUFBYSxNQUNqQyxJQUNBLElBQUssV0FBVztBQUVwQixXQUFPLENBQUMsVUFBVSxlQUFlO0FBQUEsRUFDbkM7QUFVQSxXQUFTLFlBQWEsS0FBSyxVQUFVLGlCQUFpQjtBQUNwRCxZQUFTLFdBQVcsbUJBQW1CLElBQUksSUFBSztBQUFBLEVBQ2xEO0FBRU8sV0FBUyxZQUFhLEtBQUs7QUFDaEMsVUFBTSxPQUFPLFFBQVEsR0FBRztBQUN4QixVQUFNLFdBQVcsS0FBSyxDQUFDO0FBQ3ZCLFVBQU0sa0JBQWtCLEtBQUssQ0FBQztBQUU5QixVQUFNLE1BQU0sSUFBSSxXQUFXLFlBQVksS0FBSyxVQUFVLGVBQWUsQ0FBQztBQUV0RSxRQUFJLFVBQVU7QUFHZCxVQUFNLE1BQU0sa0JBQWtCLElBQzFCLFdBQVcsSUFDWDtBQUVKLFFBQUk7QUFDSixTQUFLLElBQUksR0FBRyxJQUFJLEtBQUssS0FBSyxHQUFHO0FBQzNCLFlBQU0sTUFDSCxVQUFVLElBQUksV0FBVyxDQUFDLENBQUMsS0FBSyxLQUNoQyxVQUFVLElBQUksV0FBVyxJQUFJLENBQUMsQ0FBQyxLQUFLLEtBQ3BDLFVBQVUsSUFBSSxXQUFXLElBQUksQ0FBQyxDQUFDLEtBQUssSUFDckMsVUFBVSxJQUFJLFdBQVcsSUFBSSxDQUFDLENBQUM7QUFDakMsVUFBSSxTQUFTLElBQUssT0FBTyxLQUFNO0FBQy9C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O0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFB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QSxFQUNuQjtBQXY2Q0EsTUFHTUUsT0Fpc0NBLG9CQUVGLElBQ0EsUUFFaUI7QUF6c0NyQjtBQUFBO0FBQUE7QUFBQTtBQUNBO0FBRUEsTUFBTUEsUUFBTztBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQWlzQ2IsTUFBTSxxQkFBcUI7QUFFM0IsTUFBSSxLQUFLO0FBQ1QsTUFBSSxTQUFTO0FBRWIsTUFBcUIsUUFBckIsTUFBcUIsT0FBTTtBQUFBLFFBQ3pCLE9BQU8sTUFBTyxRQUFRLEtBQUs7QUFDekIsNEJBQWtCLEdBQUc7QUFFckIsaUJB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QUFHLGNBQWMsR0FBRSxPQUFPLENBQUMsRUFBRSxNQUFNLEdBQUUsR0FBRyxFQUFDLENBQUM7QUFBQSxjQUFHO0FBQUEsWUFDN0Q7QUFBQSxVQUFDLEVBQUMsQ0FBQztBQUNMLGtCQUFRLEtBQUssT0FBTyxjQUFjLENBQUMsRUFBRSxLQUFLLEVBQUUsS0FBSyxDQUFDO0FBQUEsUUFDbkQsU0FBTyxHQUFFO0FBQUUsWUFBRSxFQUFDLElBQUcsb0JBQW9CLEdBQUUsT0FBTyxDQUFDLEVBQUUsTUFBTSxHQUFFLEdBQUcsRUFBQyxDQUFDO0FBQUEsUUFBRztBQUFBLE1BQ2xFO0FBQ0EsVUFBSSxVQUFRO0FBQ1osVUFBSSxLQUFHLFlBQVksV0FBVTtBQUMzQixZQUFHO0FBQ0QsWUFBRSxJQUFJO0FBQ04sY0FBSSxJQUFFLDBCQUFLLElBQUksNEJBQTRCLEVBQUUsbUJBQW1CO0FBQ2hFO0FBQ0EsY0FBRyxLQUFLLFVBQVEsSUFBRztBQUFFLDBCQUFjLEVBQUU7QUFBRyxjQUFFLEVBQUMsSUFBRyxjQUFjLEtBQUksQ0FBQyxDQUFDLEdBQUcsT0FBTSxRQUFPLENBQUM7QUFBRyxpQkFBSztBQUFBLFVBQUc7QUFBQSxRQUNoRyxTQUFPLEdBQUU7QUFDUDtBQUNBLGNBQUcsVUFBUSxJQUFHO0FBQUUsMEJBQWMsRUFBRTtBQUFHLGNBQUUsRUFBQyxJQUFHLGNBQWMsR0FBRSxPQUFPLENBQUMsRUFBRSxNQUFNLEdBQUUsR0FBRyxFQUFDLENBQUM7QUFBRyxnQkFBRztBQUFFLG1CQUFLO0FBQUEsWUFBRyxTQUFPLElBQUc7QUFBRSxnQkFBRSxFQUFDLElBQUcsYUFBYSxHQUFFLE9BQU8sRUFBRSxFQUFFLE1BQU0sR0FBRSxHQUFHLEVBQUMsQ0FBQztBQUFBLFlBQUc7QUFBQSxVQUFFO0FBQUEsUUFDaEs7QUFBQSxNQUNGLEdBQUUsR0FBRztBQUFBO0FBQUE7IiwKICAibmFtZXMiOiBbIkJ1ZmZlciIsICJmaWxsIiwgImNvcHkiLCAicmVhZCIsICJpIiwgImJ5dGVMZW5ndGgiLCAiY29tcGFyZSIsICJ3cml0ZSIsICJjb2RlIiwgInNsaWNlIiwgInZtIiwgInBvaW50ZXJTaXplIiwgInZtIiwgInByb3h5IiwgInBvaW50ZXJTaXplIiwgIm5hdGl2ZUZ1bmN0aW9uT3B0aW9ucyIsICJhcGkiLCAiaW5pdGlhbGl6ZSIsICJ2dGFibGUiLCAicG9pbnRlclNpemUiLCAiaGFuZGxlIiwgInZtIiwgIm5hdGl2ZUZ1bmN0aW9uT3B0aW9ucyIsICJ2bSIsICJwb2ludGVyU2l6ZSIsICJydW50aW1lIiwgImFwaSIsICJ3cml0ZSIsICJjb2RlIiwgImNtIiwgInNpemUiLCAiZW52IiwgInJlYWQiLCAiYmVnaW4iLCAidnRhYmxlIiwgImdldEFwaSIsICJjYWNoZWRBcGkiLCAiX2dldEFwaSIsICJuYXRpdmVGdW5jdGlvbk9wdGlvbnMiLCAiYXBpIiwgInBvaW50ZXJTaXplIiwgImpzaXplU2l6ZSIsICJ2bSIsICJlbnN1cmVDbGFzc0luaXRpYWxpemVkIiwgInZ0YWJsZSIsICJtYWtlTWV0aG9kTWFuZ2xlciIsICJnZXRBcGkiLCAiYXBpIiwgInBvaW50ZXJTaXplIiwgInZtIiwgImNtIiwgImNvZGUiLCAiQnVmZmVyIiwgImtBY2NQdWJsaWMiLCAiYWNjZXNzRmxhZ3MiLCAia0FjY05hdGl2ZSIsICJzbGljZSIsICJvZmZzZXQiLCAiaW50ZXJmYWNlcyIsICJpbmRleCIsICJjb2RlIiwgInJlYWQiLCAidm0iLCAianNpemVTaXplIiwgImVuc3VyZUNsYXNzSW5pdGlhbGl6ZWQiLCAibWFrZU1ldGhvZE1hbmdsZXIiLCAia0FjY1N0YXRpYyIsICJwb2ludGVyU2l6ZSIsICJuYW1lIiwgInRhZ1B0ciIsICJjb2RlIiwgIkRWTV9KTklfRU5WX09GRlNFVF9TRUxGIiwgInNpemUiLCAiZW52IiwgInRocmVhZCIsICJ1bndyYXAiLCAidHlwZSIsICJEZXhGaWxlIiwgIlByb2Nlc3MiLCAianNpemVTaXplIiwgInBvaW50ZXJTaXplIiwgImFwaSIsICJ2bSIsICJydW50aW1lIiwgImFwcCJdCn0K
