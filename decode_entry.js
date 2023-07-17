const { Worker } = require('worker_threads');
const fs = require('fs');
const util = require('util');

const readdir = util.promisify(fs.readdir);
const lstat = util.promisify(fs.lstat);

function runWorkerWithTimeout(workerPath, workerData, timeoutDuration) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(workerPath, { workerData });

    // Handle worker messages
    worker.on('message', resolve);

    // Handle worker errors
    worker.on('error', reject);

    // Handle worker exit
    worker.on('exit', (code) => {
      if (code !== 0) {
        reject(new Error(`Worker stopped with exit code ${code}`));
      }
    });

    // Set up timeout
    const timeoutId = setTimeout(() => {
      console.log('Worker timed out, terminating...');
      worker.terminate();
      reject(new Error('Worker operation timed out'));
    }, timeoutDuration);

    // Clear timeout if worker finishes in time
    worker.on('exit', () => {
      clearTimeout(timeoutId);
    });
  });
}

async function decodeFileOrDir(inputPath) {
  console.log(`start decoding inputPath: ${inputPath}`);
  const stats = await lstat(inputPath);
  if (stats.isDirectory()) {
    const paths = await readdir(inputPath);
    const promises = paths.sort().map(async (path) => {
      const fileFullPath = `${inputPath}/${path}`;
      const fileStats = await lstat(fileFullPath);
      if (path.endsWith('.xlog')) {
        console.log(`handling file: ${fileFullPath}`);
        return Promise.race([
          runWorkerWithTimeout('./lib/decode_xlog_nocrypt.js', fileFullPath, 10000),
        ]);
      } else if (fileStats.isDirectory()) {
        return decodeFileOrDir(fileFullPath);
      } else {
        console.log(`ignore unsupported file : ${path}`);
      }
    });
    await Promise.all(promises);
  } else {
    // single file
    await Promise.race([
      runWorkerWithTimeout('./lib/decode_xlog_nocrypt.js', inputPath, 10000),
    ]);
  }
}

async function decodeEncryptedFileOrDir(inputPath, privateKey) {
  console.log(`start decoding inputPath: ${inputPath}`);
  console.log(`private key = ${privateKey}`);
  const stats = await lstat(inputPath);
  if (stats.isDirectory()) {
    const paths = await readdir(inputPath);
    const promises = paths.sort().map(async (path) => {
      const fileFullPath = `${inputPath}/${path}`;
      const fileStats = await lstat(fileFullPath);
      if (path.endsWith('.xlog')) {
        console.log(`handling file: ${fileFullPath}`);
        return Promise.race([
          runWorkerWithTimeout('./lib/decode_xlog_crypt.js', { inputPath: fileFullPath, privateKey }, 30000),
        ]);
      } else if (fileStats.isDirectory()) {
        return decodeEncryptedFileOrDir(fileFullPath, privateKey);
      } else {
        console.log(`ignore unsupported file : ${path}`);
      }
    });
    await Promise.all(promises);
  } else {
    // single file
    await Promise.race([
      runWorkerWithTimeout('./lib/decode_xlog_crypt.js', { inputPath, privateKey }, 30000),
    ]);
  }
}

module.exports = { decodeFileOrDir, decodeEncryptedFileOrDir };

// // test code
// const { Signals } = require('node:process');
//
// const args = process.argv.slice(2);
// if (args.length < 1) {
//   console.error('Error: path param not found!');
//   process.exit(-1);
// }
// process.addListener(Signals, (signal) => {
//   console.log(`signal - ${signal}`);
// });
// process.addListener('uncaughtException', (e) => {
//   console.log(`uncaughtException - ${e.message}`);
// });
// process.addListener('beforeExit', (code) => {
//   console.log(`beforeExit - ${code}`);
// });
//
// console.log('Path list is:', args);
// // decodeFileOrDir(args[0]).then(() => console.log('process end!!!!')).catch((e) => {
// //   console.log(e);
// // });
// decodeEncryptedFileOrDir(args[0], args[1]).then(() => console.log('process end!!!!')).catch((e) => {
//   console.log(e);
// });
