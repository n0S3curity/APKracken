import { useEffect, useRef, useState } from 'react';

// Real-time H.264 mirror: connect to the engine's WebSocket, depacketize the Annex-B stream
// (screenrecord output), decode with WebCodecs, and paint a <canvas>. Calls onFallback() when
// WebCodecs is unavailable or the stream fails, so the caller can drop back to screenshots.
export default function DeviceStreamMirror({ serial, streamPort, onFallback }) {
  const canvasRef = useRef(null);
  const [status, setStatus] = useState('connecting'); // connecting | live | error

  useEffect(() => {
    if (!serial || !streamPort) return undefined;
    if (typeof window.VideoDecoder === 'undefined') {
      onFallback?.('WebCodecs not supported in this browser');
      return undefined;
    }

    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    let closed = false;
    let ws = null;
    let decoder = null;
    let leftover = new Uint8Array(0);
    let sps = null;
    let pps = null;
    let configured = false;
    let haveKey = false;
    let ts = 0;
    let framesDrawn = 0;
    let watchdog = null;

    const fail = (msg) => {
      if (closed) return;
      closed = true;
      cleanup();
      onFallback?.(msg);
    };

    const draw = (frame) => {
      if (closed) {
        frame.close();
        return;
      }
      if (canvas.width !== frame.displayWidth || canvas.height !== frame.displayHeight) {
        canvas.width = frame.displayWidth;
        canvas.height = frame.displayHeight;
      }
      ctx.drawImage(frame, 0, 0);
      frame.close();
      framesDrawn += 1;
      if (status !== 'live') setStatus('live');
    };

    const resetDecoder = () => {
      configured = false;
      haveKey = false;
      try {
        if (decoder && decoder.state !== 'closed') decoder.close();
      } catch {
        /* ignore */
      }
      decoder = new VideoDecoder({ output: draw, error: () => resetDecoder() });
    };
    resetDecoder();

    const hex2 = (n) => n.toString(16).padStart(2, '0');
    const configure = () => {
      if (configured || !sps || !pps) return;
      const codec = `avc1.${hex2(sps[1])}${hex2(sps[2])}${hex2(sps[3])}`;
      try {
        decoder.configure({ codec, optimizeForLatency: true, hardwareAcceleration: 'prefer-hardware' });
        configured = true;
      } catch {
        try {
          decoder.configure({ codec, optimizeForLatency: true });
          configured = true;
        } catch {
          /* wait for a valid SPS */
        }
      }
    };

    const annexb = (nals) => {
      let len = 0;
      for (const n of nals) len += 4 + n.length;
      const out = new Uint8Array(len);
      let o = 0;
      for (const n of nals) {
        out[o + 3] = 1; // 00 00 00 01
        o += 4;
        out.set(n, o);
        o += n.length;
      }
      return out;
    };

    const decode = (type, nals) => {
      if (!configured) return;
      try {
        decoder.decode(new EncodedVideoChunk({ type, timestamp: ts, data: annexb(nals) }));
        ts += 33333;
      } catch {
        resetDecoder();
      }
    };

    const onNal = (nal) => {
      const t = nal[0] & 0x1f;
      if (t === 7) {
        sps = nal;
        configure();
        return;
      }
      if (t === 8) {
        pps = nal;
        configure();
        return;
      }
      if (t === 5) {
        // IDR keyframe — carries SPS+PPS so the decoder can (re)sync.
        configure();
        haveKey = true;
        decode('key', [sps, pps, nal].filter(Boolean));
      } else if (t === 1) {
        if (haveKey) decode('delta', [nal]);
      }
      // types 6 (SEI) / 9 (AUD) etc. are not needed for decoding.
    };

    // Split an Annex-B byte buffer into NAL units; keep an incomplete tail as leftover.
    const parse = (buf) => {
      const n = buf.length;
      const starts = [];
      let i = 0;
      while (i + 3 <= n) {
        if (buf[i] === 0 && buf[i + 1] === 0 && buf[i + 2] === 1) {
          starts.push([i, 3]);
          i += 3;
        } else if (i + 4 <= n && buf[i] === 0 && buf[i + 1] === 0 && buf[i + 2] === 0 && buf[i + 3] === 1) {
          starts.push([i, 4]);
          i += 4;
        } else {
          i += 1;
        }
      }
      if (starts.length === 0) {
        leftover = buf; // whole buffer is mid-NAL — carry it forward
        return;
      }
      for (let s = 0; s < starts.length; s += 1) {
        const [pos, scLen] = starts[s];
        if (s + 1 >= starts.length) {
          leftover = buf.subarray(pos); // last (incomplete) NAL incl. its start code
          break;
        }
        const nal = buf.subarray(pos + scLen, starts[s + 1][0]);
        if (nal.length > 0) onNal(nal.slice());
      }
    };

    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const url = `${proto}://${window.location.hostname}:${streamPort}/?serial=${encodeURIComponent(serial)}`;
    try {
      ws = new WebSocket(url);
    } catch {
      fail('Could not open the stream socket');
      return undefined;
    }
    ws.binaryType = 'arraybuffer';
    ws.onmessage = (ev) => {
      if (closed) return;
      const chunk = new Uint8Array(ev.data);
      if (leftover.length) {
        const merged = new Uint8Array(leftover.length + chunk.length);
        merged.set(leftover, 0);
        merged.set(chunk, leftover.length);
        leftover = new Uint8Array(0);
        parse(merged);
      } else {
        parse(chunk);
      }
    };
    ws.onerror = () => fail('Stream connection failed');
    ws.onclose = () => {
      if (!closed && framesDrawn === 0) fail('Stream closed before any video');
    };

    // If no frame paints within a few seconds, fall back to screenshots.
    watchdog = setTimeout(() => {
      if (!closed && framesDrawn === 0) fail('No video within timeout');
    }, 6000);

    function cleanup() {
      clearTimeout(watchdog);
      try {
        if (ws) {
          ws.onmessage = null;
          ws.onerror = null;
          ws.onclose = null;
          ws.close();
        }
      } catch {
        /* ignore */
      }
      try {
        if (decoder && decoder.state !== 'closed') decoder.close();
      } catch {
        /* ignore */
      }
    }

    return () => {
      closed = true;
      cleanup();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [serial, streamPort]);

  return (
    <div style={{ position: 'relative', background: '#000', borderRadius: 10, overflow: 'hidden', minHeight: 200, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <canvas ref={canvasRef} style={{ width: '100%', display: 'block' }} />
      {status !== 'live' && (
        <div style={{ position: 'absolute', color: 'var(--text-3)', fontSize: 12.5 }}>connecting to live stream…</div>
      )}
      {status === 'live' && (
        <span
          title="live H.264"
          style={{ position: 'absolute', top: 8, right: 8, display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 10, fontWeight: 700, color: '#fff', background: 'rgba(0,0,0,.45)', padding: '2px 7px', borderRadius: 12 }}
        >
          <span style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--ok)', animation: 'okpulse 1.4s ease-in-out infinite' }} />
          LIVE
        </span>
      )}
    </div>
  );
}
