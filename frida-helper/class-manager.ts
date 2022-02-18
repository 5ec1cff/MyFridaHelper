type ClassSet = { [key: string]: Java.Wrapper };

const keyClassName = Symbol('className');
const keyStage = Symbol('stage');

enum Stage {
    perform,
    performNow
}

function Stub(name: string, stage: Stage=Stage.performNow): Java.Wrapper {
    return new Proxy({}, {
        get(t, p, r) {
            if (p == keyClassName) {
                return name;
            } else if (p == keyStage) {
                return stage;
            }
            throw new Error('not initialized!')
        }
    }) as Java.Wrapper
}

function load(t: ClassSet, s: Stage) {
    for (const k in t) {
        let stage = (t[k] as any)[keyStage];
        if (stage != s) continue;
        let className = (t[k] as any)[keyClassName];
        if (className != null) {
            t[k] = Java.use(className);
        }
    }
}

function register(api: ClassSet) {    
    Java.performNow(() => load(api, Stage.performNow));
    Java.perform(() => load(api, Stage.perform));
}

export {
    Stub,
    ClassSet,
    Stage,
    register
}
