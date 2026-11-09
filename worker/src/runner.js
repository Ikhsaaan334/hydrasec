import Docker from 'dockerode';
import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import { Writable } from 'node:stream';
import { config } from './config.js';
import { logger } from './logger.js';
import { appendLog } from './events.js';
import { CONTROL_CHANNEL } from './keys.js';
import { buildToolInvocation } from './jobs.js';

const docker = new Docker({ socketPath: '/var/run/docker.sock' });

// Siapkan root volume bersama: kontainer tool (uid acak, non-root) hanya boleh
// men-traverse (/data), tidak boleh melihat isi direktori scan milik scan lain.
export async function ensureVolumeRoot() {
  try {
    await fsp.mkdir(config.toolDataRoot + '/scans', { recursive: true });
    await fsp.chmod(config.toolDataRoot, 0o711);
    await fsp.chmod(config.toolDataRoot + '/scans', 0o711);
  } catch (err) {
    logger.warn('prepare volume root failed', { err: err.message });
  }
}

// Bersihkan kontainer tool yatim (sisa worker crash/restart)
export async function sweepOrphanToolContainers() {
  let list = [];
  try {
    list = await docker.listContainers({
      all: true,
      filters: JSON.stringify({ label: ['hydrasec.role=tool'] }),
    });
  } catch (err) {
    logger.warn('container list failed (docker.sock not ready?)', { err: err.message });
    return 0;
  }
  for (const info of list) {
    await docker.getContainer(info.Id).remove({ force: true }).catch(() => {});
  }
  if (list.length) logger.info('orphan tool containers cleaned', { count: list.length });
  return list.length;
}

// Jalankan satu kontainer tool ephemeral, streaming stdout/stderr ke buffer log,
// terapkan batas waktu, dukung pembatalan, lalu hapus kontainer (--rm ekuivalen).
export async function runScanContainer({ scanId, eventsChannel, tool, target, options, controlSubscribe, onCreated }) {
  const uid = 10000 + crypto.randomInt(0, 50000);
  const outDir = config.toolDataRoot + '/scans/' + scanId;
  await fsp.mkdir(outDir, { recursive: true });
  await fsp.chown(outDir, uid, uid).catch(() => {});
  await fsp.chmod(outDir, 0o700).catch(() => {});

  const inv = buildToolInvocation(tool, { target, options, outDir });
  const image = config.toolImagePrefix + tool + ':latest';

  const binds = [config.dataVolume + ':/data:rw'];
  if (tool === 'nuclei' && config.nucleiTemplatesVolume) {
    // Volume template persisten: copy-on-first-mount mengisi dari image (baked),
    // dan pembaruan nuclei -ut di dalam volume bertahan antar-container.
    binds.push(config.nucleiTemplatesVolume + ':/home/scanner/nuclei-templates:rw');
  }
  if (tool === 'xray' && fs.existsSync('/xray-license/license')) {
    binds.push('/xray-license/license:/opt/xray/license:ro');
  }

  const env = ['HOME=/tmp', 'TMPDIR=/tmp'];

  let container;
  try {
    container = await docker.createContainer({
      Image: image,
      name: 'hydrasec-scan-' + scanId,
      Labels: { 'hydrasec.role': 'tool', 'hydrasec.scan': scanId },
      User: String(uid) + ':' + String(uid),
      WorkingDir: '/tmp',
      Env: env,
      Cmd: inv.cmd.length ? inv.cmd : undefined,
      NetworkingConfig: { EndpointsConfig: { [config.dockerNetwork]: {} } },
      HostConfig: {
        Binds: binds,
        NetworkMode: config.dockerNetwork,
        CapDrop: ['ALL'],
        SecurityOpt: ['no-new-privileges'],
        PidsLimit: 512,
        Memory: inv.memoryMb * 1024 * 1024,
        AutoRemove: false,
      },
      OpenStdin: false,
      Tty: false,
    });
  } catch (err) {
    if (String(err.message || '').includes('image')) {
      throw new Error(
        'Image ' + image + ' not found — run tools/build-all.sh first (' + err.message + ')'
      );
    }
    throw err;
  }

  let consoleBuf = '';
  let cancelled = false;

  const stream = await container.attach({ stream: true, stdout: true, stderr: true });
  const sink = new Writable({
    write(chunk, _enc, cb) {
      const text = chunk.toString('utf8');
      if (consoleBuf.length < 2_000_000) consoleBuf += text;
      appendLog(eventsChannel, text).catch(() => {});
      cb();
    },
  });
  docker.modem.demuxStream(stream, sink, sink);

  // Langganan kanal kontrol untuk pembatalan
  let unsubscribe;
  if (typeof controlSubscribe === 'function') {
    unsubscribe = controlSubscribe(CONTROL_CHANNEL(eventsChannel), async () => {
      cancelled = true;
      await container.kill().catch(() => {});
    });
  }

  await container.start();
  if (typeof onCreated === 'function') {
    await onCreated(container.id).catch(() => {});
  }

  let exitCode = null;
  let timedOut = false;
  try {
    const waitPromise = container.wait();
    const timeoutPromise = new Promise((resolve) =>
      setTimeout(() => resolve({ __timeout: true }), inv.timeoutMs)
    );
    const outcome = await Promise.race([waitPromise, timeoutPromise]);
    if (outcome && outcome.__timeout) {
      timedOut = true;
      await container.kill().catch(() => {});
      const final = await waitPromise.catch(() => ({ StatusCode: null }));
      exitCode = final.StatusCode ?? null;
    } else {
      exitCode = outcome?.StatusCode ?? null;
    }
  } finally {
    if (unsubscribe) unsubscribe();
    await container.remove({ force: true }).catch(() => {});
  }

  return { exitCode, timedOut, cancelled, consoleText: consoleBuf, outDir, containerId: container.id };
}
