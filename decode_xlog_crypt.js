const fs = require('fs');
const zlib = require('zlib');
const EC = require('elliptic').ec;
const { workerData, parentPort } = require('worker_threads');
const TEA = require('./util_tea');

const MAGIC_NO_COMPRESS_START = 3;
const MAGIC_NO_COMPRESS_START1 = 6;
const MAGIC_NO_COMPRESS_NO_CRYPT_START = 8;
const MAGIC_COMPRESS_START = 4;
const MAGIC_COMPRESS_START1 = 5;
const MAGIC_COMPRESS_START2 = 7;
const MAGIC_COMPRESS_NO_CRYPT_START = 9;
// const MAGIC_SYNC_ZSTD_START = 0x0A;
// const MAGIC_SYNC_NO_CRYPT_ZSTD_START = 0x0B;
// const MAGIC_ASYNC_ZSTD_START = 0x0C;
// const MAGIC_ASYNC_NO_CRYPT_ZSTD_START = 0x0D;

const MAGIC_END = 0;
let gLastSeq;

// test begin ------------------
// Generate keys
// var ec = new EC('secp256k1');
// var key1 = ec.genKeyPair();
// var key2 = ec.genKeyPair();
// console.log(`key1 privateKey: ${key1.getPrivate('hex')}`);
// console.log(`key1 publicKey: ${key1.getPublic('hex')}`);
//
// var shared1 = key1.derive(key2.getPublic());
// var shared2 = key2.derive(key1.getPublic());
// console.log('Both shared secrets are BN instances');
// console.log(shared1.toString(16));
// console.log(shared2.toString(16));
// test end ------------------

// change to parameter pass
let gPrivateKey = '';
// const PRIV_KEY = "1d1585013b876ed1261fc090920b9789a1d0f4c6d2e40647fe353f8825525f77" // demo-iOS's privateKey
// PUB_KEY = "8e4d7630ddfe81ddcc69c25d6e93f09e017c0662a06df686c486468382514ee4165275d6fc360b9a1e8ac7858c87051a0f04cd0415e688183c484f01620b4e2d"
// gPrivateKey = PRIV_KEY;

function ReadIntFromBytes(bytesBuf, startPosition) {
  return bytesBuf.readInt32LE(startPosition);
}

function ReadShortFromBytes(bytesBuf, startPosition) {
  return bytesBuf.readInt16LE(startPosition);
}

// function ReadCharFromBytes(bytesBuf, startPosition) {
//   return bytesBuf.readUint8(startPosition);
// }

function isGoodLogBuffer(_buffer, _offset, count) {
  let crypt_key_len; let headerLen; let length; let
    magic_start;

  if (_offset === _buffer.length) {
    return [true, ''];
  }

  magic_start = _buffer[_offset];

  if (MAGIC_NO_COMPRESS_START === magic_start
        || MAGIC_COMPRESS_START === magic_start
        || MAGIC_COMPRESS_START1 === magic_start) {
    crypt_key_len = 4;
  } else if (MAGIC_COMPRESS_START2 === magic_start
            || MAGIC_NO_COMPRESS_START1 === magic_start
            || MAGIC_NO_COMPRESS_NO_CRYPT_START === magic_start
            || MAGIC_COMPRESS_NO_CRYPT_START === magic_start) {
    crypt_key_len = 64;
  } else {
    return [false, '_buffer[%d]:%d != MAGIC_NUM_START' % [_offset, _buffer[_offset]]];
  }

  headerLen = 1 + 2 + 1 + 1 + 4 + crypt_key_len;

  if (_offset + headerLen + 1 + 1 > _buffer.length) {
    return [false, 'offset:%d > len(buffer):%d' % [_offset, _buffer.length]];
  }

  length = ReadIntFromBytes(_buffer, _offset + headerLen - 4 - crypt_key_len);

  if (_offset + headerLen + length + 1 > _buffer.length) {
    return [false, 'log length:%d, end pos %d > len(buffer):%d' % [length, _offset + headerLen + length + 1, _buffer.length]];
  }

  if (MAGIC_END !== _buffer[_offset + headerLen + length]) {
    return [false, 'log length:%d, buffer[%d]:%d != MAGIC_END' % [length, _offset + headerLen + length, _buffer[_offset + headerLen + length]]];
  }

  if (count <= 1) {
    return [true, ''];
  }
  return isGoodLogBuffer(_buffer, _offset + headerLen + length + 1, count - 1);
}

function getLogStartPos(_buffer, _count) {
  let offset = 0;

  while (true) {
    if (offset >= _buffer.length) {
      break;
    }

    if (MAGIC_NO_COMPRESS_START === _buffer[offset]
            || MAGIC_NO_COMPRESS_START1 === _buffer[offset]
            || MAGIC_COMPRESS_START === _buffer[offset]
            || MAGIC_COMPRESS_START1 === _buffer[offset]
            || MAGIC_COMPRESS_START2 === _buffer[offset]
            || MAGIC_COMPRESS_NO_CRYPT_START === _buffer[offset]
            || MAGIC_NO_COMPRESS_NO_CRYPT_START === _buffer[offset]) {
      if (isGoodLogBuffer(_buffer, offset, _count)[0]) {
        return offset;
      }
    }
    offset += 1;
  }

  return -1;
}

async function doDecompress(inputData) {
  return new Promise((resolve) => {
    // the decompressor
    // important: must set a large chunkSize, otherwise the output is truncated
    let decompressor = zlib.createInflateRaw({ chunkSize: 1024 * 1024 });
    decompressor.on('error', (err) => {
      if (err.code !== 'Z_BUF_ERROR') {
        // Note that Z_BUF_ERROR is not fatal
        console.log(err);
        // do not terminate, try continue
        resolve(`${err.code}, ${err.message}\n`);
        // decompressor.removeAllListeners();
        // decompressor = null;
      }
    }).on('data', (chunk) => {
      // console.log(chunk.toString());
      resolve(chunk);
      decompressor.removeAllListeners();
      decompressor = null;
    }).on('close', () => {
      decompressor.removeAllListeners();
      decompressor = null;
    });
    decompressor.write(inputData);
  }).catch((e) => {
    console.log(e);
  });
}

function decodeBuffer(buffer, offset, outStream) {
  // eslint-disable-next-line no-async-promise-executor
  return new Promise(async (resolve) => {
    if (offset >= buffer.length) {
      resolve(-1);
      return;
    }

    const ret = isGoodLogBuffer(buffer, offset, 1);
    if (!ret[0]) {
      const fixPos = getLogStartPos(buffer.slice(offset), 1);
      if (fixPos === -1) {
        resolve(-1);
        return;
      }
      outStream.write(`[F]decode decode error len=${fixPos}, result:${ret[1]} \n`);
      offset += fixPos;
    }

    const magicStart = buffer[offset];
    let cryptKeyLen;

    if (MAGIC_NO_COMPRESS_START === magicStart
      || MAGIC_COMPRESS_START === magicStart
      || MAGIC_COMPRESS_START1 === magicStart) {
      cryptKeyLen = 4;
    } else if (MAGIC_COMPRESS_START2 === magicStart
      || MAGIC_NO_COMPRESS_START1 === magicStart
      || MAGIC_NO_COMPRESS_NO_CRYPT_START === magicStart
      || MAGIC_COMPRESS_NO_CRYPT_START === magicStart) {
      cryptKeyLen = 64;
    } else {
      outStream.write(`in DecodeBuffer _buffer[${offset}]: ${magicStart} != MAGIC_NUM_START`);
      resolve(-1);
      return;
    }

    const headerLen = 1 + 2 + 1 + 1 + 4 + cryptKeyLen;
    const length = ReadIntFromBytes(buffer, offset + headerLen - 4 - cryptKeyLen);
    const seq = ReadShortFromBytes(buffer, offset + headerLen - 4 - cryptKeyLen - 2 - 2);
    // let begin_hour = ReadCharFromBytes(_buffer, _offset + headerLen - 4 - crypt_key_len - 1 - 1);
    // let end_hour = ReadCharFromBytes(_buffer, _offset + headerLen - 4 - crypt_key_len - 1);

    if (seq !== 0 && seq !== 1 && gLastSeq !== 0 && seq !== gLastSeq + 1) {
      outStream.write(`[F]decode log seq:${gLastSeq + 1}-${seq - 1} is missing\n`);
    }
    if (seq !== 0) {
      gLastSeq = seq;
    }

    let tmpBuffer = buffer.slice(offset + headerLen, offset + headerLen + length);

    try {
      if (MAGIC_NO_COMPRESS_START1 === buffer[offset]) {
        // do nothing
        // console.log('ignore MAGIC_NO_COMPRESS_START1');
      } else if (MAGIC_COMPRESS_START2 === buffer[offset]) {
        const ec = new EC('secp256k1');

        // 创建服务器和客户端的密钥对
        let svr = ec.genKeyPair();
        let client = ec.genKeyPair();

        // 从buffer中获取公钥
        // eslint-disable-next-line max-len
        const pubkeyX = buffer.slice(offset + headerLen - cryptKeyLen, offset + headerLen - cryptKeyLen / 2);
        const pubkeyY = buffer.slice(offset + headerLen - cryptKeyLen / 2, offset + headerLen);
        // 设置客户端的公钥 , 04是未压缩的公钥的标识符
        const pubKeyHex = '04' + pubkeyX.toString('hex') + pubkeyY.toString('hex');
        client = ec.keyFromPublic(pubKeyHex, 'hex');

        // 设置服务器的私钥
        svr = ec.keyFromPrivate(gPrivateKey, 'hex');
        // 获取ECDH密钥
        const teaKeyBN = svr.derive(client.getPublic());
        const teaKey = Buffer.from(teaKeyBN.toArray());

        // console.log(`teaKey = ${teaKey.toString(16)}`);
        // console.log(`buffer length = ${tmpBuffer.length}`);
        const decryptedBuf = TEA.decrypt(tmpBuffer, teaKey);
        // console.log(tmpBuffer);
        // console.log(decryptedBuf);
        // console.log(`decryptedBuf length = ${decryptedBuf.length}`);

        // give it data to inflate
        const decompressedData = await doDecompress(decryptedBuf);
        outStream.write(decompressedData);
        // console.log(decryptedBuf.toString());
      } else if (MAGIC_COMPRESS_START === buffer[offset]
        || MAGIC_COMPRESS_NO_CRYPT_START === buffer[offset]) {
        // give it data to inflate
        // console.log(tmpBuffer);
        const decompressedData = await doDecompress(tmpBuffer);
        outStream.write(decompressedData);
      } else if (MAGIC_COMPRESS_START1 === buffer[offset]) {
        console.log('goes into MAGIC_COMPRESS_START1');
        let dataToDecompress = Buffer.alloc(0);
        while (tmpBuffer.length > 0) {
          const singleLogLen = ReadShortFromBytes(tmpBuffer, 0);
          dataToDecompress = Buffer.concat([dataToDecompress, tmpBuffer.slice(2, singleLogLen + 2)]);
          tmpBuffer = tmpBuffer.slice(singleLogLen + 2, tmpBuffer.length);
        }
        // give it data to inflate
        const decompressedData = await doDecompress(dataToDecompress);
        outStream.write(decompressedData);
      } else if (MAGIC_NO_COMPRESS_NO_CRYPT_START === magicStart) {
        outStream.write(tmpBuffer);
      } else {
        console.log('unsupported format!');
        outStream.write(`unsupported magic start: ${magicStart}`);
      }
    } catch (e) {
      outStream.write(`[F]decode decompress err, ${e.toString()}\n`);
      console.error(e.toString());
    }
    resolve(offset + headerLen + length + 1);
  });
}

async function handleRawBuffer(data, outputPath) {
  // eslint-disable-next-line no-async-promise-executor
  return new Promise(async (resolve) => {
    gLastSeq = 0;
    let startPos = getLogStartPos(data, 2);
    if (startPos === -1) {
      console.error(`invalid xlog file: ${outputPath}!`);
      resolve(false);
    }
    // console.log(`start position is ${startPos}`);
    // The stream to write
    const writeStream = fs.createWriteStream(outputPath);

    do {
      // eslint-disable-next-line no-await-in-loop
      startPos = await decodeBuffer(data, startPos, writeStream);
    } while (startPos !== -1);

    // close stream
    writeStream.end();
    writeStream.close();

    resolve(true);
  });
}

async function parseFileAsync(filePath, outputPath) {
  // first, read file
  return new Promise((resolve) => {
    fs.readFile(filePath, async (err, data) => {
      if (err) {
        console.log(err);
      } else {
        await handleRawBuffer(data, outputPath);
        fs.unlinkSync(filePath); // remove original file
      }
      resolve();
    });
  });
}

// async function decodeEncryptedFileOrDir(inputPath, privateKey) {
//   console.log(`start decoding inputPath: ${inputPath}`);
//   console.log(`private key = ${privateKey}`);
//   gPrivateKey = privateKey;
//   if (fs.lstatSync(inputPath).isDirectory()) {
//     for (const path of fs.readdirSync(inputPath).sort()) {
//       const fileFullPath = `${inputPath}/${path}`;
//       if (path.endsWith('.xlog')) {
//         console.log(`handling file: ${fileFullPath}`);
//         await parseFileAsync(fileFullPath, `${fileFullPath}.log`);
//       } else if (fs.lstatSync(fileFullPath).isDirectory()) {
//         await decodeEncryptedFileOrDir(fileFullPath);
//       } else {
//         console.log(`ignore unsupported file : ${path}`);
//       }
//     }
//   } else {
//     // single file
//     await parseFileAsync(inputPath, `${inputPath}.log`);
//   }
// }

// const args = process.argv.slice(2);
// if (args.length < 1) {
//   console.error('Error: path param not found!');
//   process.exit(-1);
// }
// console.log('Path list is:', args);
// decodeEncryptedFileOrDir(args[0], args[1]).then(() => console.log('process end!!!!'));

// module.exports = decodeEncryptedFileOrDir;

gPrivateKey = workerData.privateKey;
parseFileAsync(workerData.inputPath, `${workerData.inputPath}.log`).then(() => {
  console.log(`decode ${workerData.inputPath} finish.`);
  // use worker threads
  parentPort.postMessage(1);
});

module.exports = parseFileAsync;
