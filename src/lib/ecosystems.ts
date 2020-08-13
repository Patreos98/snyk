import * as cppPlugin from 'snyk-cpp-plugin';
import { TestOptions, Options } from './types';
import { TestCommandResult } from '../cli/commands/types';
import { MethodArgs } from '../cli/args';
import { Fingerprint } from 'snyk-cpp-plugin';

interface ScannedArtifact {
  type:
    | 'depTree'
    | 'depGraph'
    | 'callGraph'
    | 'manifestFile'
    | 'binaries'
    | 'hashes'
    | 'dockerLayers'
    | 'cpp-fingerprints';
  data: any;
  meta?: { [key: string]: any };
}

interface ScannedProject {
  artifacts: ScannedArtifact[];
}

export interface EcosystemPlugin {
  scan: (options: Options & TestOptions) => Promise<ScannedProject>;
}

export type Ecosystem = 'cpp';

const EcosystemPlugins: {
  readonly [ecosystem in Ecosystem]: EcosystemPlugin;
} = {
  cpp: cppPlugin,
};

export function getPlugin(ecosystem: Ecosystem): EcosystemPlugin {
  return EcosystemPlugins[ecosystem];
}

export function getEcosystem(options: Options & TestOptions): Ecosystem | null {
  if (options.source) {
    return 'cpp';
  }
  return null;
}

export async function testEcosystem(
  ecosystem: Ecosystem,
  args: string[],
  options: Options & TestOptions,
): Promise<TestCommandResult> {
  const plugin = getPlugin(ecosystem);

  let responseReadable = 'C++ Files: \n';
  const responseJSON: ScannedProject[] = [];

  for (const path of args as string[]) {
    options.path = path;
    const scan = await plugin.scan(options);
    responseJSON.push(scan);
  }

  for (const scannedProject of responseJSON) {
    for (const artifact of scannedProject.artifacts) {
      // Do we have an array of fingerPrints? yes? Cool! otherwise continue!
      if (!artifact.data.length) {
        continue;
      }
      for (const fingerPrint of artifact.data) {
        responseReadable += `\n filePath = ${fingerPrint.filePath} \n hash = ${fingerPrint.hash}`;
      }
    }
  }

  const stringifiedData = JSON.stringify(responseReadable, null, 2);

  if (options.json) {
    return TestCommandResult.createJsonTestCommandResult(stringifiedData);
  }

  return TestCommandResult.createHumanReadableTestCommandResult(
    responseReadable,
    stringifiedData,
  );
}
