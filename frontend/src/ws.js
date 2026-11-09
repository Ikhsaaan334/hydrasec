import { getToken } from './api.js';

// WebSocket terminal: subscribe ke kanal event scan lewat gateway /ws.
// Server mengirim {type:'log'|'status'|'subscribed'|'error', ...}.
export function connectScanSocket(scanId, handlers = {}) {
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(
    proto + '://' + window.location.host + '/ws?token=' + encodeURIComponent(getToken() ?? '')
  );

  ws.onopen = () => {
    handlers.onOpen?.();
    ws.send(JSON.stringify({ type: 'subscribe', scanId }));
  };

  ws.onmessage = (ev) => {
    let msg = null;
    try { msg = JSON.parse(ev.data); } catch { return; }
    if (msg.type === 'log') handlers.onLog?.(msg.data);
    else if (msg.type === 'status') handlers.onStatus?.(msg);
    else if (msg.type === 'subscribed') handlers.onSubscribed?.(msg);
    else if (msg.type === 'error') handlers.onError?.(msg);
  };

  ws.onclose = (ev) => {
    if (ev.code === 4001 && handlers.onUnauthorized) handlers.onUnauthorized();
    else handlers.onClose?.();
  };

  return {
    close: () => {
      try { ws.close(); } catch { /* noop */ }
    },
  };
}
