/* jshint esversion: 6 */
/* jshint node: true */
'use strict';

const fs = require('fs');
const convert = require('xml-js');
const http = require('http');
const https = require('https');
const url = require('url');
const path = require('path');
const EventEmitter = require('events');

const pollDelay = 2000;
const AVAILABLE = 'AVAILABLE';
const INACTIVE = 'INACTIVE';
const REQUESTED = 'REQUESTED';
const QUERYING = 'QUERYING';
const REMOVING = 'REMOVING';
const EXPORTING = 'EXPORTING';
const UPLOADING = 'UPLOADING';
const IMPORTING = 'IMPORTING';
const APPLYING = 'APPLYING';
const FINISHED = 'COMPLETED';
const FAILURE = 'FAILURE';
const ERROR = 'ERROR';
const UNDISCOVERED = 'UNDISCOVERED';
const UNKNOWN = 'UNKNOWN';
const DEVICEGROUP_PREFIX = 'TrustProxy_';

const TASKTIMEOUT = 120000;

const POLICYFILEPREFIX = 'exportedPolicy';
const POLICYCACHETIME = 3600e3; // 1 hour

const downloadDirectory = '/var/tmp';
const VALIDDOWNLOADPROTOCOLS = ['file:', 'http:', 'https:'];
const deviceGroupsUrl = 'http://localhost:8100/mgmt/shared/resolver/device-groups';
const localauth = 'Basic ' + new Buffer('admin:').toString('base64');

const LOGGINGPREFIX = '[TrustedASMPolicies], ';

// Async Request state object
let requestedTasks = {};

// Concurrency Semaphores 
let inFlightExports = {}; // export from source ASM devices
let inFlightDownloads = {}; // downloading policy from source device
let inFlightUploads = {}; // uploading policy to target device
let inFlightImports = {}; // import to target ASM devices

// polyfill old node to include [].includes
if (!Array.prototype.includes) {
    Object.defineProperty(Array.prototype, 'includes', {
        value: function (searchElement, fromIndex) {
            if (this === null) {
                throw new TypeError('"this" is null or not defined');
            }
            var o = Object(this);
            var len = o.length >>> 0;
            if (len === 0) {
                return false;
            }
            var n = fromIndex | 0;
            var k = Math.max(n >= 0 ? n : len - Math.abs(n), 0);

            function sameValueZero(x, y) {
                return x === y || (typeof x === 'number' && typeof y === 'number' && isNaN(x) && isNaN(y));
            }
            while (k < len) {
                if (sameValueZero(o[k], searchElement)) {
                    return true;
                }
                k++;
            }
            return false;
        }
    });
}

const wait = (ms) => new Promise((resolve) => {
    setTimeout(resolve, ms);
});

const copyFile = (filePath, symlink) => {
    const filename = path.basename(filePath);
    const dest = downloadDirectory + '/' + filename;
    if (fs.existsSync(filePath)) {
        try {
            if (!fs.existsSync(dest)) {
                if (symlink) {
                    fs.symlinkSync(filePath, dest);
                } else {
                    fs.createReadStream(filePath).pipe(fs.createWriteStream(dest));
                }
            }
            return filename;
        } catch (err) {
            throw err;
        }
    } else {
        const err = 'file does not exist ' + filePath;
        console.error(err);
        throw Error(err);
    }
};

/**
 * Upload Worker
 *
 * Uploads specified files to a specified server.
 */
class TrustedASMPoliciesWorker {
    constructor() {
        this.WORKER_URI_PATH = "shared/TrustedASMPolicies";
        this.isPassThrough = true;
        this.isPublic = true;
    }

    onStart(success) {
        this.clearPolicyFileCache();
        setInterval(() => { this.clearPolicyFileCache(); }, POLICYCACHETIME);
        success();
    }

    /**
     * Get can take 3 query params (targetHost, targetPort, name)
     * example: /shared/TrustedASMPolicies?targetHost=10.144.72.186&targetPort=443&name=linux-high
     * @param {RestOperation} restOperation
     */
    onGet(restOperation) {
        const paths = restOperation.uri.pathname.split('/');
        const query = restOperation.getUri().query;

        let targetDevice = null;
        let sourceDevice = null;
        let policyId = null;
        let policyName = null;

        if (query.targetHost) {
            targetDevice = query.targetHost;
        } else if (query.targetUUID) {
            targetDevice = query.targetUUID;
        } else if (paths.length > 3) {
            targetDevice = paths[3];
        }

        if (query.sourceHost) {
            sourceDevice = query.sourceHost;
        } else if (query.sourceUUID) {
            sourceDevice = query.sourceUUID;
        }

        if (query.policyName) {
            policyName = query.policyName;
        }

        if (query.policyId) {
            policyId = query.policyId;
        } else if (paths.length > 4) {
            policyId = paths[4];
        }

        if (sourceDevice) {
            // Download Policy XML file from BIG-IP
            if (targetDevice) {
                const err = new Error(`target device should not be defined when defining source device for policy XML file download`);
                err.httpStatusCode = 400;
                restOperation.fail(err);
            } else if (policyId || policyName) {
                this.validateTarget(sourceDevice)
                    .then((source) => {
                        let policyLastChanged = null;
                        return this.getPoliciesOnBigIP(source.targetHost, source.targetPort)
                            .then((policies) => {
                                let policyFound = false;
                                policies.forEach((policy) => {
                                    if (!policyFound) {
                                        if (policy.id == policyId || policy.name == policyName) {
                                            policyFound = true;
                                            policyName = policy.name;
                                            policyId = policy.id;
                                            policyLastChanged = new Date(policy.lastChanged).getTime();
                                        }
                                    }
                                });
                                if (policyFound) {
                                    return this.exportPolicyFromBigIP(source.targetHost, source.targetPort, policyId, policyLastChanged);
                                } else {
                                    const throwError = new Error('could not find policy');
                                    throwError.httpStatusCode = 404;
                                    throw throwError;
                                }
                            })
                            .then(() => {
                                return this.getPolicyFileContent(policyId, policyLastChanged);
                            })
                            .then((policyContent) => {
                                restOperation.statusCode = 200;
                                restOperation.setHeaders({
                                    'Content-Type': 'text/xml',
                                    'Content-Disposition': 'attachment; filename="' + policyName + '.xml"'
                                });
                                restOperation.body = policyContent;
                                this.completeRestOperation(restOperation);
                            })
                            .catch((err) => {
                                restOperation.fail(err);
                            });
                    });
            } else {
                const err = new Error(`you must supply either a policyName or policyId to retrieve a policy XML file`);
                err.httpStatusCode = 400;
                restOperation.fail(err);
            }
        } else {
            // Get a policy list from a target device
            this.validateTarget(targetDevice)
                .then((target) => {
                    this.getPoliciesOnBigIP(target.targetHost, target.targetPort)
                        .then((policies) => {
                            if (policyName || policyId) {
                                let returnPolicies = [];
                                policies.forEach((policy) => {
                                    if (policyName && policy.name.startsWith(policyName)) {
                                        returnPolicies.push(policy);
                                    }
                                    if (policyId && policy.id == policyId) {
                                        returnPolicies.push(policy);
                                    }
                                });
                                if (returnPolicies.length === 0) {
                                    const err = new Error(`no policy with matching policyName or policyId found.`);
                                    err.httpStatusCode = 404;
                                    restOperation.fail(err);
                                } else {
                                    restOperation.statusCode = 200;
                                    restOperation.setContentType('application/json');
                                    restOperation.body = returnPolicies;
                                    this.completeRestOperation(restOperation);
                                }
                            } else {
                                restOperation.statusCode = 200;
                                restOperation.setContentType('application/json');
                                restOperation.body = policies;
                                this.completeRestOperation(restOperation);
                            }
                        })
                        .catch((err) => {
                            err.httpStatusCode = 400;
                            restOperation.fail(err);
                        });
                })
                .catch((err) => {
                    err.httpStatusCode = 404;
                    restOperation.fail(err);
                });
        }

    }
    /**
     * Post can take 5 query params (sourceHost, url, targetHost, policyId, policeName, targetPolicyName)
     * exemple: /shared/TrustedASMPolicies?sourceHost=10.144.72.135&sourcePort=443&targetHost=10.144.72.186&targetPort=443&policyName=linux-high&targetPolicyName=imported-linux-high
     * @param {RestOperation} restOperation
     */
    onPost(restOperation) {
        const query = restOperation.getUri().query;

        let sourceDevice = null;
        let sourceUrl = null;
        let targetDevice = null;
        let policyId = null;
        let policyName = null;
        let targetPolicyName = null;

        if (query.sourceHost) {
            sourceDevice = query.sourceHost;
        } else if (query.sourceUUID) {
            sourceDevice = query.sourceUUID;
        }

        if (query.url) {
            sourceUrl = query.url;
        }

        if (query.targetHost) {
            targetDevice = query.targetHost;
        } else if (query.targetUUID) {
            targetDevice = query.targetUUID;
        }

        if (query.policyId) {
            policyId = query.policyId;
        }

        if (query.policyName) {
            policyName = query.policyName;
        }

        if (query.targetPolicyName) {
            targetPolicyName = query.targetPolicyName;
        }

        const createBody = restOperation.getBody();
        if (createBody.hasOwnProperty('sourceHost')) {
            sourceDevice = createBody.sourceHost;
        }
        if (createBody.hasOwnProperty('sourceUUID')) {
            sourceDevice = createBody.sourceUUID;
        }
        if (createBody.hasOwnProperty('url')) {
            sourceUrl = createBody.url;
        }
        if (createBody.hasOwnProperty('targetHost')) {
            targetDevice = createBody.targetHost;
        }
        if (createBody.hasOwnProperty('targetUUID')) {
            targetDevice = createBody.targetUUID;
        }
        if (createBody.hasOwnProperty('policyId')) {
            policyId = createBody.policyId;
        }
        if (createBody.hasOwnProperty('policyName')) {
            policyName = createBody.policyName;
        }
        if (createBody.hasOwnProperty('targetPolicyName')) {
            targetPolicyName = createBody.targetPolicyName;
        }

        if (sourceUrl) {
            // Download policy XML from a source URL and import and apply on target device
            if (!targetPolicyName) {
                const policyResolveError = new Error('must supply targetPolicyName if using URL as the source of the policy');
                this.logger.severe(LOGGINGPREFIX + policyResolveError.message);
                policyResolveError.httpStatusCode = 404;
                restOperation.fail(policyResolveError);
            } else {
                if (!targetDevice) {
                    const targetError = new Error('must supply a targetHost or targetUUID to import policy from url');
                    this.logger.severe(LOGGINGPREFIX + targetError.message);
                    targetError.httpStatusCode = 404;
                    restOperation.fail(targetError);
                }
                const sourcePolicyId = targetPolicyName;
                const sourcePolicyTimestamp = new Date().getTime();
                this.validateTarget(targetDevice)
                    .then((target) => {
                        this.logger.info(LOGGINGPREFIX + 'request made to import policy ' + targetPolicyName + ' from url ' + sourceUrl + ' on device ' + target.targetUUID + ' ' + target.targetHost + ':' + target.targetPort);
                        let requestIndex = `${target.targetHost}:${target.targetPort}:${sourcePolicyId}`;
                        let returnPolicy = {
                            id: sourceUrl,
                            name: targetPolicyName,
                            enforcementMode: UNKNOWN,
                            lastChanged: UNKNOWN,
                            lastChange: UNKNOWN,
                            state: REQUESTED,
                            path: UNKNOWN
                        };
                        requestedTasks[requestIndex] = returnPolicy;
                        this.updateInflightState(target.targetHost, target.targetPort, sourcePolicyId, EXPORTING);
                        this.downloadPolicyFile(sourceUrl, sourcePolicyId, sourcePolicyTimestamp)
                            .then((policyFile) => {
                                return this.validateFileIsValidASMPolicy(policyFile, target.targetVersion);
                            })
                            .then(() => {
                                delete requestedTasks[requestIndex];
                                return this.getPoliciesOnBigIP(target.targetHost, target.targetPort);
                            })
                            .then((targetPolicies) => {
                                let needToRemove = false;
                                let targetPolicyId = null;
                                targetPolicies.forEach((targetPolicy) => {
                                    if (targetPolicyName == targetPolicy.name) {
                                        // the policy WAS found on the target device, but it was another version, flag the policy for removal
                                        this.logger.info(LOGGINGPREFIX + 'requested policy name:' + targetPolicyName + ' was found on the target device. removing policy from target device.');
                                        needToRemove = true;
                                        targetPolicyId = targetPolicy.id;
                                    }
                                });
                                if (needToRemove) {
                                    // the policy on the target device was not the right version, delete it and continue processing
                                    this.updateInflightState(target.targetHost, target.targetPort, sourcePolicyId, REMOVING);
                                    return this.deletePolicyOnBigIP(target.targetHost, target.targetPort, targetPolicyId);
                                }
                            })
                            .then(() => {
                                return this.importPolicyToBigIP(target.targetHost, target.targetPort, sourcePolicyId, targetPolicyName, sourcePolicyTimestamp);
                            })
                            .then((newPolicyId) => {
                                this.logger.info(LOGGINGPREFIX + 'policy ' + sourcePolicyId + ' with policyId: ' + newPolicyId + ' was imported and applied on ' + target.targetUUID + ' ' + target.targetHost + ':' + target.targetPort);
                            })
                            .catch((err) => {
                                if (requestedTasks.hasOwnProperty(requestIndex)) {
                                    this.logger.severe(LOGGINGPREFIX + 'error processing ASM policy in state:' + requestedTasks[requestIndex].state + ' - ' + err.message);
                                    this.updateInflightState(target.targetHost, target.targetPort, sourcePolicyId, ERROR, err.message);
                                } else {
                                    this.logger.severe(LOGGINGPREFIX + 'error after applying ASM policy - ' + err.message);
                                    this.updateInflightState(target.targetHost, target.targetPort, sourcePolicyId, ERROR, err.message);
                                }
                            });
                        restOperation.statusCode = 202;
                        restOperation.setContentType('application/json');
                        restOperation.body = requestedTasks[requestIndex];
                        this.completeRestOperation(restOperation);
                    })
                    .catch((err) => {
                        this.logger.severe(LOGGINGPREFIX + err.message);
                        err.httpStatusCode = 400;
                        restOperation.fail(err);
                    });
            }
        } else {
            // Pull source policy from sourceDevice and push to targetDevice
            this.validateTarget(sourceDevice)
                .then((source) => {
                    // clean up input variable
                    if (!targetPolicyName) {
                        targetPolicyName = policyName;
                    }
                    let sourcePolicyId = targetPolicyName;
                    let sourcePolicyName = false;
                    let sourcePolicyLastChanged = null;
                    let sourcePolicyTimestamp = null;
                    if (policyId) {
                        sourcePolicyId = policyId;
                    }

                    let requestIndex = null;

                    this.validateTarget(targetDevice)
                        .then((target) => {
                            if (this.validateTMOSCompatibility(source.targetVersion, target.targetVersion)) {
                                this.getPoliciesOnBigIP(source.targetHost, source.targetPort)
                                    .then((sourcePolicies) => {
                                        sourcePolicies.forEach((sourcePolicy) => {
                                            if ((policyId && sourcePolicy.id == policyId) || (policyName && policyName == sourcePolicy.name)) {
                                                sourcePolicyId = sourcePolicy.id;
                                                sourcePolicyName = sourcePolicy.name;
                                                sourcePolicyLastChanged = sourcePolicy.lastChanged;
                                                sourcePolicyTimestamp = new Date(sourcePolicy.lastChanged).getTime();
                                                // initialize inflight state for this request
                                                requestIndex = `${target.targetHost}:${target.targetPort}:${sourcePolicyId}`;
                                                let returnPolicy = {
                                                    id: sourcePolicy.id,
                                                    name: targetPolicyName,
                                                    enforcementMode: sourcePolicy.enforcementMode,
                                                    lastChanged: sourcePolicy.lastChanged,
                                                    lastChange: sourcePolicy.lastChange,
                                                    state: REQUESTED,
                                                    path: sourcePolicy.path
                                                };
                                                requestedTasks[requestIndex] = returnPolicy;
                                            }
                                        });
                                        if (!sourcePolicyName) {
                                            const throwErr = new Error(`source policy ${policyName} could not be found on ${source.targetHost}:${source.targetPort}`);
                                            this.updateInflightState(target.targetHost, target.targetPort, sourcePolicyId, ERROR, throwErr.message);
                                            throw throwErr;
                                        } else {
                                            this.logger.info(LOGGINGPREFIX + 'request made to transfer and import source policy ' + sourcePolicyName + ' as ' + targetPolicyName + ' from source device ' + source.targetUUID + ' ' + source.targetHost + ":" + source.targetPort + ' to target device ' + target.targetUUID + ' ' + target.targetHost + ':' + target.targetPort);
                                            this.logger.info(LOGGINGPREFIX + 'source policy ' + sourcePolicyName + ' was found on source device as policy id: ' + sourcePolicyId + ' last changed: ' + sourcePolicyLastChanged);
                                            this.updateInflightState(target.targetHost, target.targetPort, sourcePolicyId, QUERYING);
                                            return this.getPoliciesOnBigIP(target.targetHost, target.targetPort, true);
                                        }
                                    })
                                    .then((targetPolicies) => {
                                        let needToRemove = false;
                                        let targetPolicyId = null;
                                        targetPolicies.forEach((targetPolicy) => {
                                            if (targetPolicyName == targetPolicy.name && sourcePolicyLastChanged == targetPolicy.lastChanged) {
                                                // the policy WAS found on the target device and it is the same exact policy version.. no further processing needed
                                                this.logger.info(LOGGINGPREFIX + 'requested policy name:' + targetPolicyName + ' lastChanged:' + targetPolicy.lastChanged + ' already exists on target device:' + target.targetUUID + ' ' + target.targetHost + ':' + target.targetPort);
                                                this.updateInflightState(target.targetHost, target.targetPort, sourcePolicyId, FINISHED);
                                            } else if (targetPolicyName == targetPolicy.name) {
                                                // the policy WAS found on the target device, but it was another version, flag the policy for removal
                                                this.logger.info(LOGGINGPREFIX + 'requested policy name:' + targetPolicyName + ' was found on the target device but the lastChanged timestamps (source: ' + sourcePolicyLastChanged + ' target: ' + targetPolicy.lastChanged + ') were not the same. removing policy from target device.');
                                                needToRemove = true;
                                                targetPolicyId = targetPolicy.id;
                                            }
                                        });
                                        if (needToRemove) {
                                            // the policy on the target device was not the right version, delete it and continue processing
                                            this.updateInflightState(target.targetHost, target.targetPort, sourcePolicyId, REMOVING);
                                            return this.deletePolicyOnBigIP(target.targetHost, target.targetPort, targetPolicyId);
                                        }
                                    })
                                    .then(() => {
                                        // if I have not submitted the FINISHED state, export the policy from the source device and download
                                        if (requestedTasks.hasOwnProperty(requestIndex)) {
                                            this.updateInflightState(target.targetHost, target.targetPort, sourcePolicyId, EXPORTING);
                                            return this.exportPolicyFromBigIP(source.targetHost, source.targetPort, sourcePolicyId, sourcePolicyTimestamp);
                                        }
                                    })
                                    .then(() => {
                                        if (requestedTasks.hasOwnProperty(requestIndex)) {
                                            return this.importPolicyToBigIP(target.targetHost, target.targetPort, sourcePolicyId, targetPolicyName, sourcePolicyTimestamp);
                                        }
                                    })
                                    .then(() => {
                                        this.logger.info(LOGGINGPREFIX + 'policy ' + sourcePolicyId + ' imported and applied on ' + target.targetUUID + ' ' + target.targetHost + ':' + target.targetPort);
                                    })
                                    .catch((err) => {
                                        this.logger.severe(LOGGINGPREFIX + 'error processing ASM policy - ' + err.message);
                                    });
                                restOperation.statusCode = 202;
                                restOperation.setContentType('application/json');
                                restOperation.body = {
                                    id: targetPolicyName,
                                    name: targetPolicyName,
                                    enforcementMode: UNKNOWN,
                                    lastChanged: UNKNOWN,
                                    lastChange: UNKNOWN,
                                    state: REQUESTED,
                                    path: UNKNOWN
                                };
                                this.completeRestOperation(restOperation);
                            } else {
                                const err = new Error('Policy TMOS version:' + source.targetVersion + ' is not compatible with ASM on ' + target.targetVersion);
                                err.httpStatusCode = 400;
                                restOperation.fail(err);
                            }
                        })
                        .catch((err) => {
                            err.httpStatusCode = 400;
                            restOperation.fail(err);
                        });
                })
                .catch((err) => {
                    err.httpStatusCode = 400;
                    restOperation.fail(err);
                });
        }
    }
    /**
     * Delete can take 4 query params (targetHost, targetPort, policyId, policyName)
     * example: /shared/TrustedASMPolicies?targetHost=10.144.72.186&targetPort=443&policyName=linux-high
     * @param {RestOperation} restOperation
     */
    onDelete(restOperation) {
        const paths = restOperation.uri.pathname.split('/');
        const query = restOperation.getUri().query;

        let targetDevice = null;
        let policyId = null;
        let policyName = null;

        if (query.targetHost) {
            targetDevice = query.targetHost;
        } else if (query.targetUUID) {
            targetDevice = query.targetUUID;
        } else if (paths.length > 3) {
            targetDevice = paths[3];
        }

        if (query.policyId) {
            policyId = query.policyId;
        } else if (paths.length > 4) {
            policyId = paths[4];
        }

        if (query.policyName) {
            policyName = query.policyName;
        }

        this.validateTarget(targetDevice)
            .then((target) => {
                this.getPoliciesOnBigIP(target.targetHost, target.targetPort)
                    .then((policies) => {
                        let targetPolicyId = null;
                        let targetPolicyState = null;
                        policies.forEach((policy) => {
                            if (policyId && policy.id == policyId) {
                                targetPolicyId = policy.id;
                                targetPolicyState = policy.state;
                            } else if (policyName && policy.name == policyName) {
                                targetPolicyId = policy.id;
                                targetPolicyState = policy.state;
                            }
                        });
                        if (!targetPolicyId) {
                            const throwError = new Error(`policy could not be found on ${target.targetHost}:${target.targetPort}`);
                            throwError.httpStatusCode = 404;
                        } else {
                            const inFlightIndex = `${target.targetHost}:${target.targetPort}:${targetPolicyId}`;
                            if (Object.keys(requestedTasks).includes(inFlightIndex)) {
                                if (requestedTasks[inFlightIndex].state == ERROR) {
                                    delete requestedTasks[inFlightIndex];
                                    restOperation.statusCode = 200;
                                    restOperation.body = {
                                        msg: `policy processing removed for policy: ${targetPolicyId} in error state`
                                    };
                                    this.completeRestOperation(restOperation);
                                } else {
                                    const throwErr = new Error('can not delete policy while processing. Current policy processing state is:' + requestedTasks[inFlightIndex].state);
                                    throwErr.httpStatusCode = 409;
                                    throw throwErr;
                                }
                            } else {
                                if (targetPolicyState == AVAILABLE || targetPolicyState == INACTIVE) {
                                    return this.deletePolicyOnBigIP(target.targetHost, target.targetPort, targetPolicyId);
                                } else {
                                    const throwErr = new Error('can not delete policy on target: ' + target.targetHost + ":" + target.targetPort + ' - policy state is:' + targetPolicyState);
                                    throwErr.httpStatusCode = 409;
                                    throw throwErr;
                                }
                            }
                        }
                    })
                    .then(() => {
                        restOperation.statusCode = 200;
                        restOperation.body = {
                            msg: `policy ${policyName} removed on target ${target.targetHost}:${target.targetPort}`
                        };
                        this.completeRestOperation(restOperation);
                    })
                    .catch((err) => {
                        restOperation.fail(err);
                    });
            })
            .catch((err) => {
                err.httpStatusCode = 400;
                restOperation.fail(err);
            });
    }

    getPoliciesOnBigIP(targetHost, targetPort, excludeInFlight) {
        return new Promise((resolve, reject) => {
            // assume targetHost + targetPort have ASM provisioned
            // assume localhost should be returning only all inflight requests
            let returnPolicies = [];
            let inFlightPolicyIds = [];
            if (!excludeInFlight) {
                Object.keys(requestedTasks).forEach((inFlightIndex) => {
                    if (targetHost != 'localhost') {
                        if (inFlightIndex.startsWith(targetHost + ':' + targetPort)) {
                            inFlightPolicyIds.push(requestedTasks[inFlightIndex].id);
                            returnPolicies.push(requestedTasks[inFlightIndex]);
                        }
                    } else {
                        inFlightPolicyIds.push(requestedTasks[inFlightIndex].id);
                        returnPolicies.push(requestedTasks[inFlightIndex]);
                    }
                });
            }
            if (targetHost != 'localhost') {
                // augment inFlight requests for targetHost:targetPort with ASM policies on device
                this.restRequestSender.sendGet(this.getQueryPoliciesRestOp(targetHost, targetPort))
                    .then((response) => {
                        let policies = response.getBody();
                        if (policies.hasOwnProperty('items')) {
                            policies.items.forEach((policy) => {
                                let returnPolicy = {
                                    id: policy.id,
                                    name: policy.name,
                                    enforcementMode: policy.enforcementMode,
                                    lastChanged: policy.versionDatetime,
                                    lastChange: policy.versionLastChange,
                                    state: AVAILABLE,
                                    path: policy.fullPath
                                };
                                if (!policy.active) {
                                    returnPolicy.state = 'INACTIVE';
                                }
                                if (!inFlightPolicyIds.includes(policy.id)) {
                                    returnPolicies.push(returnPolicy);
                                }
                            });
                        } else {
                            reject(new Error('policies request did not return a list of policies: ' + JSON.stringify(policies)));
                        }
                        resolve(returnPolicies);
                    })
                    .catch((err) => {
                        if (err.message.includes('java.net.ConnectException: Connection refused')) {
                            reject(new Error('ASM is not provisioned on ' + targetHost + ':' + targetPort));
                        } else {
                            reject(err);
                        }
                    });
            } else {
                resolve(returnPolicies);
            }
        });
    }

    /* jshint ignore:start */
    updateInflightState(targetHost, targetPort, policyId, state, errMessage) {
        const inFlightIndex = `${targetHost}:${targetPort}:${policyId}`;
        if (state == FINISHED) {
            if (requestedTasks.hasOwnProperty(inFlightIndex)) {
                this.logger.info(LOGGINGPREFIX + 'policy processing complete for policy: ' + policyId + ' removing state');
                delete requestedTasks[inFlightIndex];
            }
        } else {
            if (!requestedTasks.hasOwnProperty(inFlightIndex)) {
                this.logger.info(LOGGINGPREFIX + 'initializing policy: ' + policyId + ' processing state to:' + state);
                requestedTasks[inFlightIndex] = {
                    id: policyId,
                    name: policyId,
                    enforcementMode: 'UNKNOWN',
                    state: state,
                    path: 'UNKNOWN'
                }
            } else {
                this.logger.info(LOGGINGPREFIX + 'transitioning policy: ' + policyId + ' processing from state:' + requestedTasks[inFlightIndex].state + ' to state: ' + state);
                requestedTasks[inFlightIndex].state = state;
            }
            if(state == ERROR) {
                requestedTasks[inFlightIndex].errMessage = errMessage;
            }
        }
    }
    /* jshint ignore:end */


    resolvePolicyFileName(policyId, timestamp) {
        if (!timestamp) {
            timestamp = new Date().getTime();
        }
        return POLICYFILEPREFIX + '_' + policyId + '_' + timestamp + '.xml';
    }

    getPolicyVersionFromFile(policyFile) {
        const filePath = `${downloadDirectory}/${policyFile}`;
        try {
            const policyXML = fs.readFileSync(filePath, 'utf8');
            const policyObj = convert.xml2js(policyXML, {
                compact: true
            });
            return policyObj.policy._attributes.bigip_version;
        } catch (err) {
            this.logger.severe(LOGGINGPREFIX + 'file ' + policyFile + ' is not a valid ASM policy... deleting.');
            try {
                fs.unlinkSync(filePath);
            } catch (err) {
                this.logger.severe(LOGGINGPREFIX + ' could not delete file ' + policyFile + ' - ' + err.message);
            }
            return "0.0";
        }
    }

    validateTMOSCompatibility(sourceVersion, targetVersion) {
        if (sourceVersion && targetVersion) {
            if (sourceVersion.split('.')[0] == targetVersion.split('.')[0]) {
                return true;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

    validateFileIsValidASMPolicy(policyFile, targetVersion) {
        return new Promise((resolve, reject) => {
            try {
                const policyVersion = this.getPolicyVersionFromFile(policyFile);
                if (this.validateTMOSCompatibility(policyVersion, targetVersion)) {
                    resolve(true);
                } else {
                    const err = new Error('policy XML file TMOS version:' + policyVersion + ' is not compatible with ASM on ' + targetVersion);
                    reject(err);
                }
            } catch (err) {
                reject(err);
            }
        });
    }

    /* jshint ignore:start */
    exportPolicyFromBigIP(sourceHost, sourcePort, policyId, timestamp) {
        return new Promise((resolve, reject) => {
            const inFlightExportIndex = `${sourceHost}:${sourcePort}:${policyId}`;
            if (inFlightExports.hasOwnProperty(inFlightExportIndex)) {
                inFlightExports[inFlightExportIndex].notify.on('downloaded', (policyFile) => {
                    resolve(policyFile)
                });
                inFlightExports[inFlightExportIndex].notify.on('exportError', (err) => {
                    reject(err)
                });
            } else {
                // there is no existing semaphore... add one..
                inFlightExports[inFlightExportIndex] = {
                    notify: new EventEmitter()
                };
                const policyFile = this.resolvePolicyFileName(policyId, timestamp);
                const filePath = `${downloadDirectory}/${policyFile}`;
                if (fs.existsSync(filePath)) {
                    this.logger.info(LOGGINGPREFIX + 'policy to export: ' + policyId + ' last changed on ' + timestamp + ' is already downloaded. skipping export.')
                    inFlightExports[inFlightExportIndex].notify.emit('downloaded', policyFile);
                    delete inFlightExports[inFlightExportIndex];
                    resolve(true);
                } else {
                    this.exportTaskOnBigIP(sourceHost, sourcePort, policyId, timestamp)
                        .then(() => {
                            return this.downloadPolicyFileFromBigIP(sourceHost, sourcePort, policyId, timestamp);
                        })
                        .then((policyFile) => {
                            inFlightExports[inFlightExportIndex].notify.emit('downloaded', policyFile);
                            delete inFlightExports[inFlightExportIndex];
                            resolve(true);
                        })
                        .catch((err) => {
                            inFlightExports[inFlightExportIndex].notify.emit('exportError', err);
                            delete inFlightExports[inFlightExportIndex];
                            reject(err);
                        })
                        .catch((err) => {
                            reject(err);
                        })
                }
            }
        });
    }
    /* jshint ignore:end */

    /* jshint ignore:start */
    importPolicyToBigIP(targetHost, targetPort, policyId, policyName, timestamp) {
        return new Promise((resolve, reject) => {
            const inFlightImportIndex = `${targetHost}:${targetPort}:${policyId}`;
            if (inFlightImports.hasOwnProperty(inFlightImportIndex)) {
                inFlightImports[inFlightImportIndex].notify.on('applied', (targetPolicyId) => {
                    resolve(targetPolicyId);
                });
                inFlightImports[inFlightImportIndex].notify.on('importError', (err) => {
                    reject(err);
                });
            } else {
                inFlightImports[inFlightImportIndex] = {
                    notify: new EventEmitter()
                };
                this.updateInflightState(targetHost, targetPort, policyId, UPLOADING);
                this.uploadPolicyFileToBigIP(targetHost, targetPort, policyId, timestamp)
                    .then(() => {
                        this.updateInflightState(targetHost, targetPort, policyId, IMPORTING);
                        return this.importTaskOnBigIP(targetHost, targetPort, policyId, policyName, timestamp);
                    })
                    .then((targetPolicyId) => {
                        if (targetPolicyId != policyId) {
                            // move URL downloaded policies to ASM assigned Policy ID
                            const returnPolicy = requestedTasks[`${targetHost}:${targetPort}:${policyId}`];
                            returnPolicy.id = targetPolicyId;
                            requestedTasks[`${targetHost}:${targetPort}:${targetPolicyId}`] = returnPolicy;
                            delete requestedTasks[`${targetHost}:${targetPort}:${policyId}`];
                            policyId = targetPolicyId;
                        }
                        this.updateInflightState(targetHost, targetPort, policyId, APPLYING);
                        return this.applyTaskOnBigIP(targetHost, targetPort, targetPolicyId);
                    })
                    .then((targetPolicyId) => {
                        this.updateInflightState(targetHost, targetPort, policyId, FINISHED);
                        inFlightImports[inFlightImportIndex].notify.emit('applied', targetPolicyId);
                        delete inFlightImports[inFlightImportIndex];
                        resolve(targetPolicyId);
                    })
                    .catch((err) => {
                        inFlightImports[inFlightImportIndex].notify.emit('importError', err);
                        delete inFlightImports[inFlightImportIndex];
                        reject(err);
                    })
            }
        });
    }

    /* jshint ignore:end */
    exportTaskOnBigIP(sourceHost, sourcePort, policyId, timestamp) {
        return new Promise((resolve, reject) => {
            this.logger.info(LOGGINGPREFIX + 'exporting policy ' + policyId + ' from ' + sourceHost + ':' + sourcePort);
            this.restRequestSender.sendPost(this.getExportRestOp(sourceHost, sourcePort, policyId, timestamp))
                .then((response) => {
                    let task = response.getBody();
                    if (task.hasOwnProperty('id')) {
                        this.pollTaskUntilFinished(sourceHost, sourcePort, task.id, 'export')
                            .then(() => {
                                resolve();
                            })
                            .catch((err) => {
                                reject(err);
                            });
                    } else {
                        reject(new Error('policy export request did not return a task ID: ' + JSON.stringify(task)));
                    }
                })
                .catch((err) => {
                    reject(err);
                });
        });
    }


    /* jshint ignore:end */
    importTaskOnBigIP(targetHost, targetPort, policyId, policyName, timestamp) {
        return new Promise((resolve, reject) => {
            this.restRequestSender.sendPost(this.getImportRestOp(targetHost, targetPort, policyId, policyName, timestamp))
                .then((response) => {
                    let task = response.getBody();
                    if (task.hasOwnProperty('id')) {
                        this.logger.info(LOGGINGPREFIX + 'importing policy ' + policyId + ' to ' + targetHost + ':' + targetPort + ' task ID:' + task.id);
                        this.pollTaskUntilFinished(targetHost, targetPort, task.id, 'import')
                            .then((targetPolicyId) => {
                                resolve(targetPolicyId);
                            })
                            .catch((err) => {
                                reject(err);
                            });
                    } else {
                        reject(new Error('policy import request did not return a task ID: ' + JSON.stringify(task)));
                    }
                })
                .catch((err) => {
                    reject(err);
                });
        });
    }

    /* jshint ignore:start */
    applyTaskOnBigIP(targetHost, targetPort, policyId) {
        return new Promise((resolve, reject) => {
            this.restRequestSender.sendPost(this.getApplyPolicyRestOp(targetHost, targetPort, policyId))
                .then((response) => {
                    let task = response.getBody();
                    if (task.hasOwnProperty('id')) {
                        this.pollTaskUntilFinished(targetHost, targetPort, task.id, 'apply')
                            .then(() => {
                                resolve(policyId);
                            })
                            .catch((err) => {
                                reject(err);
                            })
                    } else {
                        reject(new Error('policy apply request did not return a task ID: ' + JSON.stringify(task)));
                    }
                })
                .catch((err) => {
                    reject(err);
                })
        });
    }
    /* jshint ignore:end */

    /* jshint ignore:start */
    deletePolicyOnBigIP(targetHost, targetPort, policyId) {
        return new Promise((resolve, reject) => {
            this.restRequestSender.sendDelete(this.getDeletePolicyRestOp(targetHost, targetPort, policyId))
                .then(() => {
                    resolve(true);
                })
                .catch((err) => {
                    reject(err);
                })
        });
    }
    /* jshint ignore:end */

    getQueryPoliciesRestOp(targetHost, targetPort) {
        let protocol = 'https';
        if (targetHost == 'localhost') {
            protocol = 'http';
        }
        const destUri = `${protocol}://${targetHost}:${targetPort}/mgmt/tm/asm/policies?$select=id,name,fullPath,enforcementMode,active,versionDatetime,versionLastChange`;
        const op = this.restOperationFactory.createRestOperationInstance()
            .setUri(url.parse(destUri))
            .setContentType("application/json");
        if (targetHost == 'localhost') {
            op.setBasicAuthorization(localauth);
            op.setIsSetBasicAuthHeader(true);
        } else {
            op.setIdentifiedDeviceRequest(true);
        }
        return op;
    }

    getExportRestOp(sourceHost, sourcePort, policyId, timestamp) {
        let protocol = 'https';
        if (sourceHost == 'localhost') {
            protocol = 'http';
        }
        const destUri = `${protocol}://${sourceHost}:${sourcePort}/mgmt/tm/asm/tasks/export-policy`;
        const destBody = {
            filename: this.resolvePolicyFileName(policyId, timestamp),
            minimal: true,
            policyReference: {
                link: "http://localhost/mgmt/tm/asm/policies/" + policyId
            }
        };
        const op = this.restOperationFactory.createRestOperationInstance()
            .setUri(url.parse(destUri))
            .setContentType("application/json")
            .setMethod('Post')
            .setBody(destBody);
        if (sourceHost == 'localhost') {
            op.setBasicAuthorization(localauth);
            op.setIsSetBasicAuthHeader(true);
        } else {
            op.setIdentifiedDeviceRequest(true);
        }
        return op;
    }

    getImportRestOp(targetHost, targetPort, policyId, policyName, timestamp) {
        let protocol = 'https';
        if (targetHost == 'localhost') {
            protocol = 'http';
        }
        const destUri = `${protocol}://${targetHost}:${targetPort}/mgmt/tm/asm/tasks/import-policy`;
        const destBody = {
            filename: this.resolvePolicyFileName(policyId, timestamp),
            name: policyName
        };
        const op = this.restOperationFactory.createRestOperationInstance()
            .setUri(url.parse(destUri))
            .setContentType("application/json")
            .setMethod('Post')
            .setBody(destBody);
        if (targetHost == 'localhost') {
            op.setBasicAuthorization(localauth);
            op.setIsSetBasicAuthHeader(true);
        } else {
            op.setIdentifiedDeviceRequest(true);
        }
        return op;
    }

    getApplyPolicyRestOp(sourceHost, sourcePort, policyId) {
        let protocol = 'https';
        if (sourceHost == 'localhost') {
            protocol = 'http';
        }
        const destUri = `${protocol}://${sourceHost}:${sourcePort}/mgmt/tm/asm/tasks/apply-policy`;
        const destBody = {
            policyReference: {
                link: "http://localhost/mgmt/tm/asm/policies/" + policyId
            }
        };
        const op = this.restOperationFactory.createRestOperationInstance()
            .setUri(url.parse(destUri))
            .setContentType("application/json")
            .setMethod('Post')
            .setBody(destBody);
        if (sourceHost == 'localhost') {
            op.setBasicAuthorization(localauth);
            op.setIsSetBasicAuthHeader(true);
        } else {
            op.setIdentifiedDeviceRequest(true);
        }
        return op;
    }

    getDeletePolicyRestOp(targetHost, targetPort, policyId) {
        let protocol = 'https';
        if (targetHost == 'localhost') {
            protocol = 'http';
        }
        const destUri = `${protocol}://${targetHost}:${targetPort}/mgmt/tm/asm/policies/${policyId}`;
        const op = this.restOperationFactory.createRestOperationInstance()
            .setUri(url.parse(destUri))
            .setContentType("application/json")
            .setMethod('Delete');
        if (targetHost == 'localhost') {
            op.setBasicAuthorization(localauth);
            op.setIsSetBasicAuthHeader(true);
        } else {
            op.setIdentifiedDeviceRequest(true);
        }
        return op;
    }

    getTaskStatus(targetHost, targetPort, taskId, type) {
        return new Promise((resolve, reject) => {
            let options = {
                host: targetHost,
                port: targetPort,
                path: `/mgmt/tm/asm/tasks/${type}-policy/${taskId}`,
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json'
                }
            };
            this.logger.info(LOGGINGPREFIX + 'retrieving task status for ' + targetHost + ":" + targetPort + ' path ' + options.path);
            if (targetHost == 'localhost') {
                options.port = 8100;
                options.headers = {
                    'Content-Type': 'application/json',
                    'Authorization': localauth
                };
                let request = http.request(options, (response) => {
                        let body = '';
                        response.on('data', (data) => {
                                body += data;
                            })
                            .on('end', () => {
                                if (response.statusCode >= 400) {
                                    const err = new Error(response.body);
                                    err.httpStatusCode = response.statusCode;
                                    reject(err);
                                } else {
                                    resolve(JSON.parse(body));
                                }
                            });
                    })
                    .on('error', (err) => {
                        reject(err);
                    });
                request.end();
            } else {
                this.getToken(targetHost)
                    .then((JSONToken) => {
                        const token = JSON.parse(JSONToken);
                        options.path = `${options.path}?${token.queryParam}`;
                        process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0; // jshint ignore:line
                        let request = https.request(options, (response) => {
                                let body = '';
                                response.on('data', (data) => {
                                        body += data;
                                    })
                                    .on('end', () => {
                                        if (response.statusCode >= 400) {
                                            const err = new Error(response.body);
                                            err.httpStatusCode = response.statusCode;
                                            reject(err);
                                        } else {
                                            resolve(JSON.parse(body));
                                        }
                                    });
                            })
                            .on('error', (err) => {
                                reject(err);
                            });
                        request.end();
                    });
            }
        });
    }

    getDeleteTaskRestOp(targetHost, targetPort, taskId, type) {
        let protocol = 'https';
        if (targetHost == 'localhost') {
            protocol = 'http';
        }
        const destUri = `${protocol}://${targetHost}:${targetPort}/mgmt/tm/asm/tasks/${type}-policy/${taskId}`;
        const op = this.restOperationFactory.createRestOperationInstance()
            .setUri(url.parse(destUri))
            .setContentType("application/json")
            .setMethod("Delete");
        if (targetHost == 'localhost') {
            op.setBasicAuthorization(localauth);
            op.setIsSetBasicAuthHeader(true);
        } else {
            op.setIdentifiedDeviceRequest(true);
        }
        return op;
    }

    validateTarget(targetDevice) {
        return new Promise((resolve, reject) => {
            if (!targetDevice) {
                resolve({
                    targetHost: 'localhost',
                    targetPort: 8100
                });
            }
            if (targetDevice == 'localhost') {
                resolve({
                    targetHost: 'localhost',
                    targetPort: 8100
                });
            }
            this.getDevices()
                .then((devices) => {
                    devices.forEach((device) => {
                        if (device.targetHost == targetDevice || device.targetUUID == targetDevice) {
                            resolve(device);
                        }
                    });
                    reject(new Error('target ' + targetDevice + ' is not a trusted device.'));
                });
        });
    }

    /**
     * Request to get all trusted device groups
     * @returns Promise when request completes
     */
    getDeviceGroups() {
        return new Promise((resolve, reject) => {
            const deviceGroupsGetRequest = this.restOperationFactory.createRestOperationInstance()
                .setUri(this.url.parse(deviceGroupsUrl))
                .setBasicAuthorization(localauth)
                .setIsSetBasicAuthHeader(true);
            this.restRequestSender.sendGet(deviceGroupsGetRequest)
                .then((response) => {
                    let respBody = response.getBody();
                    if (!respBody.hasOwnProperty('items')) {
                        // we need to create a device group for our desired devices
                        Promise.all([this.resolveDeviceGroup()])
                            .then((deviceGroupName) => {
                                resolve(deviceGroupName);
                            })
                            .catch(err => {
                                this.logger.severe(LOGGINGPREFIX + 'could not create device group');
                                reject(err);
                            });
                    }
                    const returnDeviceGroups = [];
                    respBody.items.forEach((deviceGroup) => {
                        if (deviceGroup.groupName.startsWith(DEVICEGROUP_PREFIX)) {
                            returnDeviceGroups.push(deviceGroup);
                        }
                    });
                    if (!returnDeviceGroups) {
                        this.createDeviceGroup(DEVICEGROUP_PREFIX + '0')
                            .then((response) => {
                                resolve([response.groupName]);
                            })
                            .catch((err) => {
                                reject(err);
                            });
                    } else {
                        resolve(returnDeviceGroups);
                    }
                })
                .catch(err => {
                    this.logger.severe(LOGGINGPREFIX + 'could not get a list of device groups:' + err.message);
                    reject(err);
                });
        });
    }

    getDevices() {
        return new Promise((resolve, reject) => {
            const devices = [];
            this.getDeviceGroups()
                .then((deviceGroups) => {
                    const devicesPromises = [];
                    deviceGroups.forEach((devicegroup, indx) => {
                        const devicesGroupUrl = deviceGroupsUrl + '/' + devicegroup.groupName + '/devices';
                        const devicesGetRequest = this.restOperationFactory.createRestOperationInstance()
                            .setUri(this.url.parse(devicesGroupUrl))
                            .setBasicAuthorization(localauth)
                            .setIsSetBasicAuthHeader(true);
                        const devicesGetPromise = this.restRequestSender.sendGet(devicesGetRequest)
                            .then((response) => {
                                const devicesBody = response.getBody();
                                devicesBody.items.forEach((device) => {
                                    if (device.hasOwnProperty('mcpDeviceName') ||
                                        device.state == UNDISCOVERED) {
                                        const returnDevice = {
                                            targetHost: device.address,
                                            targetPort: device.httpsPort,
                                            targetUUID: device.machineId,
                                            targetHostname: device.hostname,
                                            targetVersion: device.version,
                                            state: device.state
                                        };
                                        devices.push(returnDevice);
                                    }
                                });
                            })
                            .catch((err) => {
                                this.logger.severe(LOGGINGPREFIX + 'error getting devices from device group:' + err.message);
                                reject(err);
                            });
                        devicesPromises.push(devicesGetPromise);
                    });
                    Promise.all(devicesPromises)
                        .then(() => {
                            resolve(devices);
                        })
                        .catch((err) => {
                            reject(err);
                        });
                })
                .catch((err) => {
                    this.logger.severe(LOGGINGPREFIX + 'error getting device groups:' + err.message);
                    throw err;
                });
        });
    }

    pollTaskUntilFinished(targetHost, targetPort, taskId, type, timeout) {
        return new Promise((resolve, reject) => {
            if (!timeout) {
                timeout = TASKTIMEOUT;
            }
            const start = new Date().getTime();
            let stop = start + timeout;
            let returnData = {};

            const poll = () => {
                this.getTaskStatus(targetHost, targetPort, taskId, type)
                    .then((responseBody) => {
                        if (responseBody.hasOwnProperty('status')) {
                            if (responseBody.status === FINISHED) {
                                if (responseBody.hasOwnProperty('result') && responseBody.result.hasOwnProperty('policyReference')) {
                                    returnData = path.basename(responseBody.result.policyReference.link).split('?')[0];
                                } else {
                                    returnData = responseBody;
                                }
                                resolve(returnData);
                            } else if (responseBody.status === FAILURE) {
                                reject(new Error('Task failed returning ' + JSON.stringify(responseBody)));
                            } else {
                                wait(pollDelay)
                                    .then(() => {
                                        if (new Date().getTime() < stop) {
                                            poll();
                                        } else {
                                            reject(new Error('policy task did not reach ' + FINISHED + ' status within timeout. Instead returned: ' + JSON.stringify(responseBody)));
                                        }
                                    });
                            }
                        }
                    })
                    .catch((err) => {
                        reject(err);
                    });
            };

            setImmediate(poll);
        });
    }

    downloadPolicyFile(sourceUrl, policyId, timestamp) {
        return new Promise((resolve, reject) => {
            const inFlightDownloadIndex = `${sourceUrl}:${policyId}:${timestamp}`;
            try {
                if (inFlightDownloads.hasOwnProperty(inFlightDownloadIndex)) {
                    inFlightDownloads[inFlightDownloadIndex].notify.on('downloaded', (policyFile) => {
                        resolve(policyFile);
                    });
                    inFlightDownloads[inFlightDownloadIndex].notify.on('downloadError', (err) => {
                        reject(err);
                    });
                } else {
                    inFlightDownloads[inFlightDownloadIndex] = {
                        notify: new EventEmitter()
                    };
                    const policyFile = this.resolvePolicyFileName(policyId, timestamp);
                    this.logger.info(LOGGINGPREFIX + 'downloading policy file:' + policyFile + ' from url:' + sourceUrl);
                    if (!sourceUrl) {
                        const err = new Error('soure URL was not defined');
                        reject(err);
                    }
                    const filePath = `${downloadDirectory}/${policyFile}`;
                    if (fs.existsSync(filePath)) {
                        const fstats = fs.statSync(filePath);
                        this.logger.info(LOGGINGPREFIX + 'file ' + policyFile + '(' + fstats.size + ' bytes) is being replaced by file from: ' + sourceUrl);
                        fs.unlinkSync(filePath);
                    }
                    const parsedUrl = url.parse(sourceUrl);
                    if (VALIDDOWNLOADPROTOCOLS.includes(parsedUrl.protocol)) {
                        if (parsedUrl.protocol == 'file:') {
                            try {
                                copyFile(parsedUrl.pathname, true);
                                inFlightDownloads[inFlightDownloadIndex].notify.emit('downloaded', policyFile);
                                delete inFlightDownloads[inFlightDownloadIndex];
                                resolve(policyFile);
                            } catch (err) {
                                inFlightDownloads[inFlightDownloadIndex].notify.emit('downloadError', err);
                                delete inFlightDownloads[inFlightDownloadIndex];
                                reject(err);
                            }
                        } else if (parsedUrl.protocol == 'http:') {
                            this.logger.info(LOGGINGPREFIX + 'downloading ' + sourceUrl);
                            let fws = fs.createWriteStream(filePath);
                            let request = http.get(sourceUrl, (response) => {
                                    if (response.statusCode > 300 && response.statusCode < 400 && response.headers.location) {
                                        fs.unlinkSync(filePath);
                                        const redirectUrlParsed = url.parse(response.headers.location);
                                        let redirectUrl = parsedUrl.host + response.headers.location;
                                        if (redirectUrlParsed.hostname) {
                                            redirectUrl = response.headers.location;
                                        }
                                        this.logger.info(LOGGINGPREFIX + 'following download redirect to:' + redirectUrl);
                                        fws = fs.createWriteStream(filePath);
                                        request = https.get(redirectUrl, (response) => {
                                                this.logger.info(LOGGINGPREFIX + 'redirect has status: ' + response.statusCode + ' body:' + JSON.stringify(response.headers));
                                                response.pipe(fws);
                                                fws.on('finish', () => {
                                                    fws.close();
                                                    inFlightDownloads[inFlightDownloadIndex].notify.emit('downloaded', policyFile);
                                                    delete inFlightDownloads[inFlightDownloadIndex];
                                                    resolve(policyFile);
                                                });
                                            })
                                            .on('error', (err) => {
                                                this.logger.severe(LOGGINGPREFIX + 'error downloading url ' + redirectUrl + ' - ' + err.message);
                                                fws.close();
                                                fs.unlinkSync(filePath);
                                                inFlightDownloads[inFlightDownloadIndex].notify.emit('downloadError', err);
                                                delete inFlightDownloads[inFlightDownloadIndex];
                                                reject(err);
                                            });
                                    } else {
                                        response.pipe(fws);
                                        fws.on('finish', () => {
                                            fws.close();
                                            if (response.statusCode < 300) {
                                                inFlightDownloads[inFlightDownloadIndex].notify.emit('downloaded', policyFile);
                                                delete inFlightDownloads[inFlightDownloadIndex];
                                                resolve(policyFile);
                                            } else {
                                                const downloadError = new Error(LOGGINGPREFIX + 'error downloading url ' + sourceUrl + ' - ' + response.statusCode);
                                                this.logger.severe(downloadError.message);
                                                if(fs.existsSync(filePath)) {
                                                    fs.unlinkSync(filePath);
                                                }
                                                inFlightDownloads[inFlightDownloadIndex].notify.emit('downloadError', downloadError);
                                                delete inFlightDownloads[inFlightDownloadIndex];
                                                reject(downloadError);
                                            }
                                        });
                                    }
                                })
                                .on('error', (err) => {
                                    this.logger.severe(LOGGINGPREFIX + 'error downloading url ' + sourceUrl + ' - ' + err.message);
                                    fws.close();
                                    fs.unlinkSync(filePath);
                                    inFlightDownloads[inFlightDownloadIndex].notify.emit('downloadError', err);
                                    delete inFlightDownloads[inFlightDownloadIndex];
                                    reject(err);
                                });
                            request.end();
                        } else {
                            this.logger.info(LOGGINGPREFIX + 'downloading ' + sourceUrl);
                            process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0; // jshint ignore:line
                            let fws = fs.createWriteStream(filePath);
                            let request = https.get(sourceUrl, (response) => {
                                    if (response.statusCode > 300 && response.statusCode < 400 && response.headers.location) {
                                        fs.unlinkSync(filePath);
                                        const redirectUrlParsed = url.parse(response.headers.location);
                                        let redirectUrl = parsedUrl.host + response.headers.location;
                                        if (redirectUrlParsed.hostname) {
                                            redirectUrl = response.headers.location;
                                        }
                                        this.logger.info(LOGGINGPREFIX + 'following download redirect to:' + redirectUrl);
                                        fws = fs.createWriteStream(filePath);
                                        request = https.get(redirectUrl, (response) => {
                                                this.logger.info(LOGGINGPREFIX + 'redirect has status: ' + response.statusCode + ' body:' + JSON.stringify(response.headers));
                                                response.pipe(fws);
                                                fws.on('finish', () => {
                                                    fws.close();
                                                    inFlightDownloads[inFlightDownloadIndex].notify.emit('downloaded', policyFile);
                                                    delete inFlightDownloads[inFlightDownloadIndex];
                                                    resolve(policyFile);
                                                });
                                            })
                                            .on('error', (err) => {
                                                this.logger.severe(LOGGINGPREFIX + 'error downloading url ' + redirectUrl + ' - ' + err.message);
                                                fws.close();
                                                if(fs.existsSync(filePath)) {
                                                    fs.unlinkSync(filePath);
                                                }
                                                inFlightDownloads[inFlightDownloadIndex].notify.emit('downloadError', policyFile);
                                                delete inFlightDownloads[inFlightDownloadIndex];
                                                reject(err);
                                            });
                                    } else {
                                        response.pipe(fws);
                                        fws.on('finish', () => {
                                            fws.close();
                                            if (response.statusCode < 300) {
                                                inFlightDownloads[inFlightDownloadIndex].notify.emit('downloaded', policyFile);
                                                delete inFlightDownloads[inFlightDownloadIndex];
                                                resolve(policyFile);
                                            } else {
                                                const downloadError = new Error(LOGGINGPREFIX + 'error downloading url ' + sourceUrl + ' - ' + response.statusCode);
                                                this.logger.severe(downloadError.message);
                                                if(fs.existsSync(filePath)) {
                                                    fs.unlinkSync(filePath);
                                                }
                                                inFlightDownloads[inFlightDownloadIndex].notify.emit('downloadError', downloadError);
                                                delete inFlightDownloads[inFlightDownloadIndex];
                                                reject(downloadError);
                                            }
                                        });
                                    }
                                })
                                .on('error', (err) => {
                                    this.logger.severe(LOGGINGPREFIX + 'error downloading url ' + sourceUrl + ' - ' + err.message);
                                    fws.close();
                                    fs.unlinkSync(filePath);
                                    inFlightDownloads[inFlightDownloadIndex].notify.emit('downloadError', err);
                                    delete inFlightDownloads[inFlightDownloadIndex];
                                    resolve(false);
                                });
                            request.end();
                        }
                    } else {
                        const err = 'extension url must use the following protocols:' + JSON.stringify(VALIDDOWNLOADPROTOCOLS);
                        inFlightDownloads[inFlightDownloadIndex].notify.emit('downloadError', err);
                        delete inFlightDownloads[inFlightDownloadIndex];
                        reject(new Error(err));
                    }
                }
            } catch (err) {
                inFlightDownloads[inFlightDownloadIndex].notify.emit('downloadError', err);
                delete inFlightDownloads[inFlightDownloadIndex];
                reject(err);
            }
        });
    }

    downloadPolicyFileFromBigIP(sourceHost, sourcePort, policyId, timestamp) {
        return new Promise((resolve, reject) => {
            const inFlightDownloadIndex = `${sourceHost}:${sourcePort}:${policyId}:${timestamp}`;
            try {
                if (inFlightDownloads.hasOwnProperty(inFlightDownloadIndex)) {
                    inFlightDownloads[inFlightDownloadIndex].on('downloaded', (policyFile) => {
                        resolve(policyFile);
                    });
                    inFlightDownloads[inFlightDownloadIndex].on('downloadError', (err) => {
                        reject(err);
                    });
                } else {
                    inFlightDownloads[inFlightDownloadIndex] = {
                        'notify': new EventEmitter()
                    };
                    if (!policyId) {
                        resolve(false);
                    }
                    const policyFile = this.resolvePolicyFileName(policyId, timestamp);
                    this.logger.info(LOGGINGPREFIX + 'downloading policy file ' + policyFile + ' from ' + sourceHost + ':' + sourcePort);
                    const filePath = `${downloadDirectory}/${policyFile}`;
                    if (fs.existsSync(filePath)) {
                        this.logger.info(LOGGINGPREFIX + 'policy to download: ' + policyId + ' last changed on ' + timestamp + ' was already downloaded.');
                        resolve(policyFile);
                    } else {
                        let options = {
                            host: sourceHost,
                            port: sourcePort,
                            path: `/mgmt/tm/asm/file-transfer/downloads/${policyFile}`,
                            method: 'GET'
                        };
                        this.logger.info(LOGGINGPREFIX + 'download file request options:' + JSON.stringify(options));
                        let fws = fs.createWriteStream(filePath);
                        if (sourceHost == 'localhost') {
                            options.port = 8100;
                            options.headers = {
                                Authorization: localauth
                            };
                            let request = http.request(options, (response) => {
                                if (response.statusCode > 399) {
                                    const downloadError = new Error(LOGGINGPREFIX + 'error downloading policy ' + policyFile + ' from ' + sourceHost + ':' + sourcePort + ' - ' + JSON.stringify(response));
                                    this.logger.severe(downloadError.message);
                                    fws.close();
                                    fs.unlinkSync(filePath);
                                    inFlightDownloads[inFlightDownloadIndex].notify.emit('downloadError', downloadError);
                                    delete inFlightDownloads[inFlightDownloadIndex];
                                    reject(downloadError);
                                } else {
                                    response.pipe(fws);
                                    fws.on('finish', () => {
                                        fws.close();
                                        inFlightDownloads[inFlightDownloadIndex].notify.emit('downloaded', policyFile);
                                        delete inFlightDownloads[inFlightDownloadIndex];
                                        resolve(policyFile);
                                    });
                                }
                            }).on('error', (err) => {
                                this.logger.severe(LOGGINGPREFIX + 'error downloading policy ' + policyFile + ' from ' + sourceHost + ':' + sourcePort + ' - ' + err.message);
                                fws.close();
                                fs.unlinkSync(filePath);
                                inFlightDownloads[inFlightDownloadIndex].notify.emit('downloadError', err);
                                delete inFlightDownloads[inFlightDownloadIndex];
                                reject(err);
                            });
                            request.end();
                        } else {
                            this.getToken(sourceHost)
                                .then((JSONToken) => {
                                    const token = JSON.parse(JSONToken);
                                    options.path = `${options.path}?${token.queryParam}`;
                                    process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0; // jshint ignore:line
                                    let request = https.request(options, (response) => {
                                        response.pipe(fws);
                                        fws.on('finish', () => {
                                            fws.close();
                                            inFlightDownloads[inFlightDownloadIndex].notify.emit('downloaded', policyFile);
                                            delete inFlightDownloads[inFlightDownloadIndex];
                                            resolve(policyFile);
                                        });
                                    }).on('error', (err) => {
                                        this.logger.severe(LOGGINGPREFIX + 'error downloading policy ' + policyFile + ' from ' + sourceHost + ':' + sourcePort + ' - ' + err.message);
                                        fws.close();
                                        fs.unlinkSync(filePath);
                                        inFlightDownloads[inFlightDownloadIndex].notify.emit('downloadError', err);
                                        delete inFlightDownloads[inFlightDownloadIndex];
                                        reject(err);
                                    });
                                    request.end();
                                });
                        }
                    }
                }
            } catch (err) {
                inFlightDownloads[inFlightDownloadIndex].notify.emit('downloadError', err);
                delete inFlightDownloads[inFlightDownloadIndex];
                reject(err);
            }
        });
    }

    getPolicyFileContent(policyId, timestamp) {
        return new Promise((resolve, reject) => {
            const policyFile = this.resolvePolicyFileName(policyId, timestamp);
            const filePath = `${downloadDirectory}/${policyFile}`;
            if (fs.existsSync(filePath)) {
                resolve(fs.readFileSync(filePath, 'utf8'));
            } else {
                reject(new Error('file ' + filePath + ' was not found'));
            }
        });
    }

    uploadPolicyFileToBigIP(targetHost, targetPort, policyId, timestamp) {
        const policyFile = this.resolvePolicyFileName(policyId, timestamp);
        const filePath = `${downloadDirectory}/${policyFile}`;
        const errorFile = filePath + '.upload.error.' + targetHost + targetPort;
        this.logger.info(LOGGINGPREFIX + 'uploading file ' + policyFile + ' to ' + targetHost + ':' + targetPort);
        return new Promise((resolve, reject) => {
            const inFlightUploadIndex = `${targetHost}:${targetPort}:${policyId}:${timestamp}`;
            if (inFlightUploads.hasOwnProperty(inFlightUploadIndex)) {
                const pollExistingTask = () => {
                    this.logger.info(LOGGINGPREFIX + 'waiting for previous upload request for ' + policyFile + ' to ' + targetHost + ':' + targetPort);
                    if (!inFlightUploads.hasOwnProperty(inFlightUploadIndex)) {
                        if (fs.existsSync(errorFile)) {
                            const err = new Error('upload of policy: ' + filePath + ' to ' + targetHost + ':' + targetPort + ' failed');
                            reject(err);
                        } else {
                            resolve(true);
                        }
                    } else {
                        wait(pollDelay)
                            .then(() => {
                                return pollExistingTask();
                            });
                    }
                };
                setImmediate(pollExistingTask);
            } else {
                inFlightUploads[inFlightUploadIndex] = {
                    'status': REQUESTED
                };
                if (fs.existsSync(errorFile)) {
                    this.logger.info(LOGGINGPREFIX + 'clearing previous failed upload attempt for ' + policyFile + ' to ' + targetHost + ':' + targetPort);
                    fs.unlinkSync(errorFile);
                }
                const fstats = fs.statSync(filePath);
                const CHUNK_SIZE = 512000;
                const postOptions = {
                    hostname: targetHost,
                    port: targetPort,
                    path: `/mgmt/tm/asm/file-transfer/uploads/${policyFile}`,
                    method: 'POST'
                };
                process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0; // jshint ignore:line
                let httplib = https;
                if (targetHost == 'localhost') {
                    targetPort = 8100;
                    httplib = http;
                }
                const uploadPart = (start, end) => {
                    const headers = {
                        'Content-Type': 'application/octet-stream',
                        'Content-Range': start + '-' + end + '/' + fstats.size,
                        'Content-Length': (end - start) + 1,
                        'Connection': 'keep-alive'
                    };
                    this.getToken(targetHost)
                        .then((JSONToken) => {
                            const token = JSON.parse(JSONToken);
                            if (targetHost == 'localhost') {
                                headers.Authorization = localauth;
                            } else {
                                postOptions.path = `/mgmt/tm/asm/file-transfer/uploads/${policyFile}?${token.queryParam}`;
                            }
                            postOptions.headers = headers;
                            this.logger.info(LOGGINGPREFIX + 'uploading ' + policyFile + ' to ' + targetHost + ':' + targetPort + ' ' + start + '-' + end + '/' + fstats.size);
                            const req = httplib.request(postOptions, (res) => {
                                if (res.statusCode > 399) {
                                    const err = new Error('upload part start: ' + start + ' end:' + end + ' return status: ' + res.statusCode);
                                    delete inFlightUploads[inFlightUploadIndex];
                                    fs.closeSync(fs.openSync(errorFile, 'w'));
                                    reject(err);
                                }
                                if (end === fstats.size - 1) {
                                    delete inFlightUploads[inFlightUploadIndex];
                                    resolve(true);
                                } else {
                                    const nextStart = start + CHUNK_SIZE;
                                    const nextEnd = (() => {
                                        if (end + CHUNK_SIZE > fstats.size - 1)
                                            return fstats.size - 1;
                                        return end + CHUNK_SIZE;
                                    })();
                                    uploadPart(nextStart, nextEnd);
                                }
                            });
                            req.on('error', (err) => {
                                delete inFlightUploads[inFlightUploadIndex];
                                fs.closeSync(fs.openSync(errorFile, 'w'));
                                reject(err);
                            });
                            const fstream = fs.createReadStream(filePath, {
                                start: start,
                                end: end
                            });
                            fstream.on('end', () => {
                                req.end();
                            });
                            fstream.pipe(req);
                        })
                        .catch((err) => {
                            delete inFlightUploads[inFlightUploadIndex];
                            fs.closeSync(fs.openSync(errorFile, 'w'));
                            reject(err);
                        });
                };
                setImmediate(() => {
                    this.logger.info(LOGGINGPREFIX + 'uploading policy file ' + policyFile + ' to ' + targetHost + ':' + targetPort);
                    if (CHUNK_SIZE < fstats.size)
                        uploadPart(0, CHUNK_SIZE - 1);
                    else
                        uploadPart(0, fstats.size - 1);
                });
            }
        });
    }

    clearPolicyFileCache() {
        fs.readdirSync(downloadDirectory).forEach((file) => {
            if (file.startsWith(POLICYFILEPREFIX)) {
                fs.stat(path.join(downloadDirectory, file), (err, stat) => {
                    if(err) {
                        this.logger.info(`TrustedASMPolicies: clearPolicyFileCache: ERROR: ${err}`);
                        return;
                    }
                    const curTime = new Date().getTime();
                    const expireTime = new Date(stat.ctime).getTime() + (POLICYCACHETIME - 100);
                    if(curTime > expireTime) {
                        fs.unlinkSync(`${downloadDirectory}/${file}`);
                        this.logger.info(`TrustedASMPolcies: clearPolicyFileCache: cleaned up ${file}`);
                    }
                });
            }
        });
    }

    getToken(targetHost) {
        return new Promise((resolve) => {
            if (targetHost == 'localhost') {
                resolve(null);
            } else {
                const tokenBody = JSON.stringify({
                    address: targetHost
                });
                let body = '';
                const postOptions = {
                    host: 'localhost',
                    port: 8100,
                    path: '/shared/token',
                    headers: {
                        'Authorization': localauth,
                        'Content-Type': 'application/json',
                        'Content-Legth': tokenBody.length
                    },
                    method: 'POST'
                };
                const request = http.request(postOptions, (res) => {
                    res.on('data', (seg) => {
                        body += seg;
                    });
                    res.on('end', () => {
                        resolve(body);
                    });
                    res.on('error', (err) => {
                        this.logger.severe('error: ' + err);
                        resolve(null);
                    });
                });
                request.write(tokenBody);
                request.end();
            }
        });
    }
}

module.exports = TrustedASMPoliciesWorker;