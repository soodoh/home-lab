"use strict";
const fs = require("node:fs");
const path = require("node:path");

function readRegular(file, limit = 2 * 1024 * 1024, privateFile = false) {
  const absolute = path.resolve(file);
  let ancestor = path.dirname(absolute);
  while (ancestor !== path.dirname(ancestor)) {
    if (!fs.lstatSync(ancestor).isDirectory()) throw new Error("non-directory input ancestor");
    ancestor = path.dirname(ancestor);
  }
  const fd = fs.openSync(absolute, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size > BigInt(limit) ||
        (privateFile && (before.uid !== BigInt(process.getuid()) || (before.mode & 0o777n) !== 0o600n))) throw new Error("unsafe evidence input");
    const raw = fs.readFileSync(fd);
    const after = fs.fstatSync(fd, { bigint: true });
    const named = fs.lstatSync(absolute, { bigint: true });
    for (const key of ["dev", "ino", "size", "mode", "uid", "gid", "nlink", "mtimeNs", "ctimeNs"]) {
      if (before[key] !== after[key] || before[key] !== named[key]) throw new Error("evidence changed while reading");
    }
    if (raw.length !== Number(before.size)) throw new Error("short evidence input");
    return raw;
  } finally { fs.closeSync(fd); }
}
module.exports = { readRegular };
