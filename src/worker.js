// Worker thread: runs the search loop and reports back to the main thread.
import { parentPort, workerData } from 'node:worker_threads';
import { search } from './generator.js';

let stop = false;
parentPort.on('message', (msg) => {
  if (msg === 'stop') stop = true;
});

const result = search({
  prefix: workerData.prefix,
  ignoreCase: workerData.ignoreCase,
  reportEvery: workerData.reportEvery,
  shouldStop: () => stop,
  onProgress: (count) => {
    if (count > 0) parentPort.postMessage({ type: 'progress', count });
  },
});

if (result) {
  parentPort.postMessage({ type: 'found', ...result });
} else {
  parentPort.postMessage({ type: 'stopped' });
}
