import QuickLRU from 'quick-lru';

let storage = new QuickLRU({ maxSize: 1000 });

class MemoryAdapter {
    async getFidoObjectById(id) {
        return storage.get(id);
    }

    async saveFidoObject(id, value) {
        storage.set(id, value);
    }
}

export default MemoryAdapter;
