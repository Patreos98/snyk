import * as debugModule from 'debug';
import { legacyPlugin as pluginApi } from '@snyk/cli-interface';
import { find } from '../find-files';
import { Options, TestOptions, MonitorOptions } from '../types';
import { NoSupportedManifestsFoundError } from '../errors';
import {
  getMultiPluginResult,
  MultiProjectResultCustom,
} from './get-multi-plugin-result';
import { getSinglePluginResult } from './get-single-plugin-result';
import {
  detectPackageFile,
  AUTO_DETECTABLE_FILES,
  detectPackageManagerFromFile,
} from '../detect';
import analytics = require('../analytics');
import { convertSingleResultToMultiCustom } from './convert-single-splugin-res-to-multi-custom';
import { convertMultiResultToMultiCustom } from './convert-multi-plugin-res-to-multi-custom';
import { processYarnWorkspaces } from './nodejs-plugin/yarn-workspaces-parser';
import { ScannedProject } from '@snyk/cli-interface/legacy/common';

const debug = debugModule('snyk-test');

const multiProjectProcessors = {
  yarnWorkspaces: {
    handler: processYarnWorkspaces,
    files: ['package.json'],
  },
  allProjects: {
    handler: getMultiPluginResult,
    files: AUTO_DETECTABLE_FILES,
  },
};

// Force getDepsFromPlugin to return scannedProjects for processing
export async function getDepsFromPlugin(
  root: string,
  options: Options & (TestOptions | MonitorOptions),
): Promise<pluginApi.MultiProjectResult | MultiProjectResultCustom> {
  let inspectRes: pluginApi.InspectResult;

  if (Object.keys(multiProjectProcessors).some((key) => options[key])) {
    const scanType = options.yarnWorkspaces ? 'yarnWorkspaces' : 'allProjects';
    const levelsDeep = options.detectionDepth;
    const ignore = options.exclude ? options.exclude.split(',') : [];
    const { files: targetFiles, allFilesFound } = await find(
      root,
      ignore,
      multiProjectProcessors[scanType].files,
      levelsDeep,
    );
    debug(
      `auto detect manifest files, found ${targetFiles.length}`,
      targetFiles,
    );
    if (targetFiles.length === 0) {
      throw NoSupportedManifestsFoundError([root]);
    }
    // enable full sub-project scan for gradle
    options.allSubProjects = true;
    inspectRes = await multiProjectProcessors[scanType].handler(
      root,
      options,
      targetFiles,
    );
    const scannedProjects = inspectRes.scannedProjects;
    const analyticData = {
      scannedProjects: scannedProjects.length,
      targetFiles,
      packageManagers: targetFiles.map((file) =>
        detectPackageManagerFromFile(file),
      ),
      levelsDeep,
      ignore,
    };
    analytics.add(scanType, analyticData);
    debug(
      `Found ${scannedProjects.length} projects from ${allFilesFound.length} detected manifests`,
    );
    warnIfAnyManifestsAreNotResolved(scannedProjects, allFilesFound);
    return inspectRes;
  }

  // TODO: is this needed for the auto detect handling above?
  // don't override options.file if scanning multiple files at once
  if (!options.scanAllUnmanaged) {
    options.file = options.file || detectPackageFile(root);
  }
  if (!options.docker && !(options.file || options.packageManager)) {
    throw NoSupportedManifestsFoundError([...root]);
  }
  inspectRes = await getSinglePluginResult(root, options);

  if (!pluginApi.isMultiResult(inspectRes)) {
    if (!inspectRes.package && !inspectRes.dependencyGraph) {
      // something went wrong if both are not present...
      throw Error(
        `error getting dependencies from ${
          options.docker ? 'docker' : options.packageManager
        } ` + "plugin: neither 'package' nor 'scannedProjects' were found",
      );
    }

    return convertSingleResultToMultiCustom(inspectRes, options.packageManager);
  }
  // We are using "options" to store some information returned from plugin that we need to use later,
  // but don't want to send to Registry in the Payload.
  // TODO(kyegupov): decouple inspect and payload so that we don't need this hack
  (options as any).projectNames = inspectRes.scannedProjects.map(
    (scannedProject) => scannedProject?.depTree?.name,
  );
  return convertMultiResultToMultiCustom(inspectRes, options.packageManager);
}

function warnIfAnyManifestsAreNotResolved(
  scannedProjects: ScannedProject[],
  allFilesFound: string[],
): void {
  const scannedGradleFiles = scannedProjects
    .map((p) => p.targetFile)
    .filter(
      (targetFile) =>
        targetFile &&
        (targetFile.endsWith('build.gradle') ||
          targetFile.endsWith('build.gradle.kts')),
    );
  const detectedGradleFiles = allFilesFound.filter(
    (targetFile) =>
      targetFile.endsWith('build.gradle') ||
      targetFile.endsWith('build.gradle.kts'),
  );
  const diff = detectedGradleFiles.filter((file) =>
    scannedGradleFiles.includes(file),
  );
  debug('**** scannedGradleFiles ', scannedProjects);
  debug('**** detectedGradleFiles ', detectedGradleFiles);

  debug('**** diff ', diff);
}
