import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

const source = process.argv[2];
if (!source) {
  throw new Error(
    "Usage: node scripts/generate-brand-assets.mjs <PNG export directory>",
  );
}

const sizes = [16, 32, 48, 96, 180, 192, 512];
const pngSignature = Buffer.from("89504e470d0a1a0a", "hex");
const images = new Map(
  await Promise.all(
    sizes.map(async (size) => {
      const file = join(source, `favicon_new_ctf_${size}.png`);
      const png = await readFile(file);
      if (
        !png.subarray(0, 8).equals(pngSignature) ||
        png.length < 24 ||
        png.readUInt32BE(16) !== size ||
        png.readUInt32BE(20) !== size
      ) {
        throw new Error(`Expected a ${size} × ${size} PNG at ${file}`);
      }
      return [size, png];
    }),
  ),
);

function ico(images) {
  // ICO supports embedding the PNG for each size directly in its image table.
  const directory = Buffer.alloc(6 + images.length * 16);
  directory.writeUInt16LE(1, 2);
  directory.writeUInt16LE(images.length, 4);
  let offset = directory.length;
  for (const [index, { size, png }] of images.entries()) {
    const entry = 6 + index * 16;
    directory[entry] = directory[entry + 1] = size;
    directory.writeUInt16LE(1, entry + 4);
    directory.writeUInt16LE(32, entry + 6);
    directory.writeUInt32LE(png.length, entry + 8);
    directory.writeUInt32LE(offset, entry + 12);
    offset += png.length;
  }
  return Buffer.concat([directory, ...images.map(({ png }) => png)]);
}

const destinations = [
  ["favicon-96.png", 96],
  ["favicon-512.png", 512],
  ["icon-180.png", 180],
  ["icon-192.png", 192],
  ["icon-512.png", 512],
];
const save = (file, bytes) =>
  writeFile(new URL(`../public/${file}`, import.meta.url), bytes);
await Promise.all([
  ...destinations.map(([file, size]) => save(file, images.get(size))),
  save(
    "favicon.ico",
    ico([16, 32, 48].map((size) => ({ size, png: images.get(size) }))),
  ),
]);
