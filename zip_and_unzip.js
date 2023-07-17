const fs = require('fs');
const StreamZip = require('node-stream-zip');
const path = require('path');
const archiver = require('archiver');

const unzip = async (filePath, storePath) => {
  if (!storePath) {
    storePath = './temp';
  }
  return new Promise((resolve) => {
    const zip = new StreamZip({
      file: filePath,
      storeEntries: true,
      skipEntryNameValidation: true,
    });
    let streamCounter = 0;

    zip.on('error', (err) => { console.error('[ERROR]', err); });
    zip.on('ready', () => {
      console.log(`All entries read: ${zip.entriesCount}`);
    });
    zip.on('entry', (entry) => {
      let adjustedName = entry.name;
      if (adjustedName.startsWith('/')) {
        adjustedName = adjustedName.slice(1); // 去除开头的斜杠字符
      }

      const pathname = path.resolve(storePath, adjustedName);
      if (/\.\./.test(path.relative(storePath, pathname))) {
        console.warn('[zip warn]: ignoring maliciously crafted paths in zip file:', entry.name);
        return;
      }

      if (entry.name[entry.name.length - 1] === '/') {
        console.log('[DIR]', entry.name);
        return;
      }

      // In case of some error
      const timeoutID = setTimeout(() => {
        resolve();
      }, 5000);
      console.log('[FILE]', entry.name);
      zip.stream(entry.name, (err, stream) => {
        if (err) { console.error('Error:', err.toString()); return; }
        stream.on('error', (error) => { console.log('[ERROR]', error); });

        // example: print contents to screen
        // stream.pipe(process.stdout);

        // example: save contents to file
        fs.mkdir(
          path.dirname(pathname),
          { recursive: true },
          () => {
            stream.pipe(fs.createWriteStream(pathname))
              .on('close', () => {
                console.log(`unzip ${pathname} done`);
                streamCounter += 1;
                if (zip.entriesCount === streamCounter) {
                  clearTimeout(timeoutID);
                  resolve();
                }
              });
          },
        );
      });
    });
  });
};

/**
 * @param {String} sourceDir: /some/folder/to/compress
 * @param {String} outPath: /path/to/created.zip
 * @returns {Promise}
 */
function zipDirectory(sourceDir, outPath) {
  const archive = archiver('zip', { zlib: { level: 9 } });
  const stream = fs.createWriteStream(outPath);

  return new Promise((resolve, reject) => {
    archive.directory(sourceDir, false)
      .on('error', (err) => reject(err))
      .pipe(stream);
    stream.on('close', () => resolve());
    archive.finalize();
  });
}

module.exports = { zipDirectory, unzip };

// test code
// const args = process.argv.slice(2);
// console.log('Path list is:', args);
// unzip(args[0], args[1]).then(() => console.log('process end!!!!'));
