import QuickLRU from 'quick-lru';

let storage = new QuickLRU({ maxSize: 1000 });

class MemoryAdapter {
    async get(id) {
        return storage.get(id);
    }

    async save(id, value) {
        storage.set(id, value);
    }
}

export default MemoryAdapter;
