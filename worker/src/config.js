const num = (v, d) => {
  const n = parseInt(v ?? '', 10);
  return Number.isFinite(n) && n > 0 ? n : d;
};

export const config = {
  databaseUrl: process.env.DATABASE_URL || '',
  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
  scanQueue: process.env.SCAN_QUEUE || 'scans',
  concurrency: num(process.env.WORKER_CONCURRENCY, 2),
  dockerNetwork: process.env.DOCKER_NETWORK || 'hydrasec_sandbox',
  toolImagePrefix: process.env.DOCKER_TOOL_PREFIX || 'hydrasec/tool-',
  dataVolume: process.env.DOCKER_DATA_VOLUME || 'hydrasec_tooldata',
  nucleiTemplatesVolume: process.env.DOCKER_NUCLEI_VOLUME || '',
  toolDataRoot: process.env.TOOL_DATA_ROOT || '/data',
  metricsPort: num(process.env.METRICS_PORT, 9591),
  version: '1.0.0',
};
