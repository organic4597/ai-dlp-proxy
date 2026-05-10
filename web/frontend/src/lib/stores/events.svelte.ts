/**
 * SSE EventSource 전역 스토어 (Svelte 5 rune class)
 * +layout.svelte에서 connect() 호출 후 전역 사용.
 */

type Handler = (data: unknown) => void;

class EventStore {
  connected = $state(false);
  private source: EventSource | null = null;
  private handlers = new Map<string, Handler[]>();

  connect() {
    if (typeof window === 'undefined') return;
    if (this.source) return; // 이미 연결됨

    const es = new EventSource('/api/events');
    this.source = es;

    es.onopen = () => { this.connected = true; };
    es.onerror = () => {
      this.connected = false;
      // 3초 후 재연결
      setTimeout(() => {
        this.source?.close();
        this.source = null;
        this.connect();
      }, 3000);
    };
    es.onmessage = (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data) as { type: string };
        (this.handlers.get(data.type) ?? []).forEach(h => h(data));
        (this.handlers.get('*') ?? []).forEach(h => h(data));
      } catch { /* ignore */ }
    };
  }

  /** 이벤트 타입별 핸들러 등록. 반환값은 해제 함수. */
  on(type: string, handler: Handler): () => void {
    if (!this.handlers.has(type)) this.handlers.set(type, []);
    this.handlers.get(type)!.push(handler);
    return () => {
      const arr = this.handlers.get(type) ?? [];
      const i = arr.indexOf(handler);
      if (i >= 0) arr.splice(i, 1);
    };
  }
}

export const sse = new EventStore();
