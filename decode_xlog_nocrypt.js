const fs = require('fs');
const zlib = require('zlib');
const { parentPort, workerData } = require('worker_threads');

const MAGIC_NO_COMPRESS_START = 3;
const MAGIC_NO_COMPRESS_START1 = 6;
const MAGIC_NO_COMPRESS_NO_CRYPT_START = 8;
const MAGIC_COMPRESS_START = 4;
const MAGIC_COMPRESS_START1 = 5;
const MAGIC_COMPRESS_START2 = 7;
const MAGIC_COMPRESS_NO_CRYPT_START = 9;
const MAGIC_END = 0;
let gLastSeq;

function ReadIntFromBytes(bytesBuf, startPosition) {
  return bytesBuf.readInt32LE(startPosition);
}

function ReadShortFromBytes(bytesBuf, startPosition) {
  return bytesBuf.readInt16LE(startPosition);
}

// function ReadCharFromBytes(bytesBuf, startPosition) {
//   return bytesBuf.readUint8(startPosition);
// }

function isGoodLogBuffer(rawBuffer, offset, count) {
  if (offset === rawBuffer.length) {
    return [true, ''];
  }

  const magicStart = rawBuffer[offset];
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
    return [false, '_buffer[%d]:%d != MAGIC_NUM_START' % [offset, rawBuffer[offset]]];
  }

  const headerLen = 1 + 2 + 1 + 1 + 4 + cryptKeyLen;

  if (offset + headerLen + 1 + 1 > rawBuffer.length) {
    return [false, 'offset:%d > len(buffer):%d' % [offset, rawBuffer.length]];
  }

  const length = ReadIntFromBytes(rawBuffer, offset + headerLen - 4 - cryptKeyLen);

  if (offset + headerLen + length + 1 > rawBuffer.length) {
    return [false, 'log length:%d, end pos %d > len(buffer):%d' % [length, offset + headerLen + length + 1, rawBuffer.length]];
  }

  if (MAGIC_END !== rawBuffer[offset + headerLen + length]) {
    return [false, 'log length:%d, buffer[%d]:%d != MAGIC_END' % [length, offset + headerLen + length, rawBuffer[offset + headerLen + length]]];
  }

  if (count <= 1) {
    return [true, ''];
  }
  return isGoodLogBuffer(rawBuffer, offset + headerLen + length + 1, count - 1);
}

function getLogStartPos(buffer, count) {
  let offset = 0;

  while (true) {
    if (offset >= buffer.length) {
      break;
    }

    const magicStart = buffer[offset];
    if (MAGIC_NO_COMPRESS_START === magicStart
      || MAGIC_NO_COMPRESS_START1 === magicStart
      || MAGIC_COMPRESS_START === magicStart
      || MAGIC_COMPRESS_START1 === magicStart
      || MAGIC_COMPRESS_START2 === magicStart
      || MAGIC_COMPRESS_NO_CRYPT_START === magicStart
      || MAGIC_NO_COMPRESS_NO_CRYPT_START === magicStart) {
      if (isGoodLogBuffer(buffer, offset, count)[0]) {
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
        decompressor.removeAllListeners();
        decompressor = null;
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

async function decodeBuffer(rawBuffer, offset, outStream) {
  return new Promise(async (resolve) => {
    if (offset >= rawBuffer.length) {
      resolve(-1);
      return;
    }

    const ret = isGoodLogBuffer(rawBuffer, offset, 1);
    if (!ret[0]) {
      const fixPos = getLogStartPos(rawBuffer.slice(offset), 1);
      if (fixPos === -1) {
        resolve(-1);
        return;
      }
      outStream.write(`[F]decode_xlog_nocrypt.js decode error len=${fixPos}, result:${ret[1]} \n`);
      offset += fixPos;
    }

    const magicStart = rawBuffer[offset];
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
    const length = ReadIntFromBytes(rawBuffer, offset + headerLen - 4 - cryptKeyLen);
    const seq = ReadShortFromBytes(rawBuffer, offset + headerLen - 4 - cryptKeyLen - 2 - 2);
    // const beginHour = ReadCharFromBytes(rawBuffer, offset + headerLen - 4 - cryptKeyLen - 1 - 1);
    // const endHour = ReadCharFromBytes(rawBuffer, offset + headerLen - 4 - cryptKeyLen - 1);

    if (seq !== 0 && seq !== 1 && gLastSeq !== 0 && seq !== (gLastSeq + 1)) {
      outStream.write(`[F]decode_xlog_nocrypt.js log seq:${gLastSeq + 1}-${seq - 1} is missing\n`);
    }
    if (seq !== 0) {
      gLastSeq = seq;
    }

    let tmpBuffer = rawBuffer.slice(offset + headerLen, offset + headerLen + length);

    if (MAGIC_NO_COMPRESS_START1 === magicStart
        || MAGIC_COMPRESS_START2 === magicStart) {
      // console.log('use wrong decode script');
      outStream.write('use wrong decode script\n');
    } else if (MAGIC_COMPRESS_START === magicStart
        || MAGIC_COMPRESS_NO_CRYPT_START === magicStart) {
      // give it data to inflate
      const decompressedData = await doDecompress(tmpBuffer);
      outStream.write(decompressedData);
    } else if (MAGIC_COMPRESS_START1 === magicStart) {
      let dataToDecompress = Buffer.alloc(0);
      while (tmpBuffer.length > 0) {
        const singleLogLen = ReadShortFromBytes(tmpBuffer, 0);
        if (singleLogLen <= 0) break;
        dataToDecompress = Buffer.concat([dataToDecompress, tmpBuffer.slice(2, singleLogLen + 2)]);
        tmpBuffer = tmpBuffer.slice(singleLogLen + 2, tmpBuffer.length);
      }
      // give it data to inflate
      const decompressedData = await doDecompress(dataToDecompress);
      outStream.write(decompressedData);
    } else if (MAGIC_NO_COMPRESS_NO_CRYPT_START === magicStart) {
      outStream.write(tmpBuffer);
    } else {
      // nothing
      console.log(`unsupported magic start: ${magicStart}`);
      outStream.write(`unsupported magic start: ${magicStart}`);
    }

    resolve(offset + headerLen + length + 1);
  });
}

async function handleRawBuffer(data, outputPath) {
  return new Promise(async (resolve) => {
    // The stream to write
    const writeStream = fs.createWriteStream(outputPath);

    let startPos = getLogStartPos(data, 2);
    if (startPos === -1) {
      console.error(`invalid xlog file: ${outputPath}!`);
      writeStream.write('invalid xlog file!');
      resolve(false);
    }

    do {
      // eslint-disable-next-line no-await-in-loop
      startPos = await decodeBuffer(data, startPos, writeStream);
    } while (startPos !== -1);

    // close stream
    writeStream.end();
    writeStream.close();
    // console.log('write stream has closed!');

    resolve(true);
  });
}

async function parseFileAsync(filePath, outputPath) {
  // console.log(`start parse: ${filePath}, out: ${outputPath}`);
  // first, read file
  return new Promise((resolve) => {
    fs.readFile(filePath, async (err, data) => {
      if (err) {
        console.log(err);
      } else {
        gLastSeq = 0;
        const result = await handleRawBuffer(data, outputPath);
        // console.log(`parse result = ${result}`);
        if (result) {
          fs.unlinkSync(filePath); // remove original file
        }
      }
      resolve();
    });
  });
}

// test code
// const args = process.argv.slice(2);
// if (args.length < 1) {
//   console.error('Error: path param not found!');
//   process.exit(-1);
// }
//
// console.log('Path list is:', args);
// decodeFileOrDir(args[0]).then(() => console.log('process end!!!!')).
// catch((e) => { console.log(e); });

parseFileAsync(workerData, `${workerData}.log`).then(() => {
  console.log(`decode ${workerData} finish.`);
  // use worker threads
  parentPort.postMessage(1);
});

module.exports = parseFileAsync;
