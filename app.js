var app = new Vue({
    el: '#app',
    data: {
        files: undefined,
        password: '',
        showPassword: false,
        processing: false,
        worker: undefined,
        log: '',
    },
    methods: {
        changeFile: function(event) {
            if (event.target.length == 0) {
                this.files = undefined;
            } else {
                this.files = event.target.files;
            }
        },
        submit: function(event) {
            this.log = '';
            var blob = new Blob(['worker();'+window.worker], {type: 'text/javascrit'});
            this.worker = new Worker(URL.createObjectURL(blob));
            var files = [];
            var read = index => {
                if (index < this.files.length) {
                    var reader = new FileReader();
                    reader.readAsArrayBuffer(this.files[index]);
                    reader.onload = event => {
                        files.push({
                            name: this.files[index].name,
                            data: event.target.result,
                        });
                        read(index+1);
                    }
                } else {
                    this.worker.postMessage(files);
                }
            };
            read(0);
            this.worker.onmessage = event => {
                if (event.data.type == 'log') {
                    this.log += event.data.data;
                } else if (event.data.type == 'encrypted') {
                    this.worker.terminate();
                    this.worker = undefined;

                    var blob = new Blob([event.data.data], {type: 'application/zip'});
                    var a = document.createElement('a');
                    a.href = URL.createObjectURL(blob);
                    a.target = '_blank';
                    a.download = 'encrypted.zip';
                    a.click();
                }
            };
        },
    }
});

function worker() {
    onmessage = function(event) {
        var zip = encrypt(event.data);
        postMessage({
            type: 'encrypted',
            data: zip,
        });
    };
    function encrypt(files) {
        log('start');
        log('end');
        return new Uint8Array([
            0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ]);
    }
    function log(message) {
        postMessage({
            type: 'log',
            data: message + '\n',
        });
    }
}
