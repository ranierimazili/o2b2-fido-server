import QuickLRU from 'quick-lru';

let storage = new QuickLRU({ maxSize: 1000 });

class MemoryAdapter {
    save(id, value) {
        storage.set(id, value);
    }

    get(id) {
        return storage.get(id);
    }
}

export default MemoryAdapter;
