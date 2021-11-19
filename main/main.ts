import * as util from '../frida-helper/util';
import {LibView, ViewWrapper} from '../frida-helper/view';

Java.perform(() => {
    console.log('loaded')
    util.init();
    let global = new Function('return this')()
    global.LibView = LibView;
    global.util = util;
    /*
    Java.use('android.app.Activity').onResume.implementation = function (...args: any[]) {
        this.onResume(...args);
        console.warn('print stack trace for activity resume:', this);
        util.printStackTrace();
        console.warn('=======================================')
    }*/
    const cs = util.castSelf;
    // let v = cs(LibView.getCurrentActivityRootView());
    const Bitmap = Java.use('android.graphics.Bitmap');
    const Bitmap$Config = Java.use('android.graphics.Bitmap$Config');
    const Canvas = Java.use('android.graphics.Canvas');
    const FileOutputStream = Java.use('java.io.FileOutputStream');
    const CompressFormat = Java.use('android.graphics.Bitmap$CompressFormat');
    function capture(v: any, path: string) {
        let bitmap = Bitmap.createBitmap(v.getWidth(), v.getHeight(), Bitmap$Config.ARGB_8888.value);
        let canvas = Canvas.$new();
        canvas.setBitmap(bitmap);
        v.draw(canvas);
        let fout = FileOutputStream.$new(path);
        bitmap.compress(CompressFormat.PNG.value, 100, fout);
        fout.flush();
        fout.close();
    }
    global.capture = capture;
    global.$ = LibView;
    global.ViewWrapper = ViewWrapper;
    global.cs = global._ = cs;
})

