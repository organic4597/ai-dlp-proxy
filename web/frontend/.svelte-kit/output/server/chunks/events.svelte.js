import "clsx";
class EventStore {
  connected = false;
  source = null;
  handlers = /* @__PURE__ */ new Map();
  connect() {
    if (typeof window === "undefined") return;
    if (this.source) return;
    const es = new EventSource("/api/events");
    this.source = es;
    es.onopen = () => {
      this.connected = true;
    };
    es.onerror = () => {
      this.connected = false;
      setTimeout(
        () => {
          this.source?.close();
          this.source = null;
          this.connect();
        },
        3e3
      );
    };
    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        (this.handlers.get(data.type) ?? []).forEach((h) => h(data));
        (this.handlers.get("*") ?? []).forEach((h) => h(data));
      } catch {
      }
    };
  }
  /** 이벤트 타입별 핸들러 등록. 반환값은 해제 함수. */
  on(type, handler) {
    if (!this.handlers.has(type)) this.handlers.set(type, []);
    this.handlers.get(type).push(handler);
    return () => {
      const arr = this.handlers.get(type) ?? [];
      const i = arr.indexOf(handler);
      if (i >= 0) arr.splice(i, 1);
    };
  }
}
const sse = new EventStore();
export {
  sse as s
};
