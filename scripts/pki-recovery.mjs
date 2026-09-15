import { resolve } from "node:path";
import { environment, repositoryRoot } from "./lib/foundation-context.mjs";
import {
  createEncryptedStepCaBackup,
  restoreEncryptedStepCaBackup,
} from "./lib/step-ca-recovery.mjs";

function parseOptions(args) {
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (!name?.startsWith("--") || !value) throw new Error(`Invalid option near ${name || "end of command"}.`);
    options[name.slice(2)] = value;
  }
  return options;
}

const [operation, ...rawOptions] = process.argv.slice(2);
if (!new Set(["backup", "restore"]).has(operation)) {
  throw new Error("Usage: node scripts/pki-recovery.mjs <backup|restore> --volume NAME --backup ABSOLUTE_PATH --passphrase-file ABSOLUTE_PATH");
}
const options = parseOptions(rawOptions);
for (const required of ["volume", "backup", "passphrase-file"]) {
  if (!options[required]) throw new Error(`Missing required --${required} option.`);
}
const image = options.image || environment.STEP_CA_IMAGE;
const parameters = {
  volumeName: options.volume,
  passphraseFile: resolve(options["passphrase-file"]),
  image,
  repositoryRoot,
};

if (operation === "backup") {
  const metadata = await createEncryptedStepCaBackup({ ...parameters, outputPath: resolve(options.backup) });
  console.log(`Created authenticated encrypted step-ca backup ${metadata.archiveSha256}.`);
} else {
  const metadata = await restoreEncryptedStepCaBackup({ ...parameters, inputPath: resolve(options.backup) });
  console.log(`Restored authenticated step-ca backup ${metadata.archiveSha256} into new volume ${options.volume}.`);
}

