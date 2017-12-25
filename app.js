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
                            data: new Uint8Array(event.target.result),
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

    function log(message) {
        postMessage({
            type: 'log',
            data: message + '\n',
        });
    }

    function encrypt(files) {
        log('start');
        var arr = [];

        var header = [];
        for (var i=0; i<files.length; i++) {
            var compressed = compress(files[i].data);

            header.push({
                signature: 0x04034b50,
                versionNeeded: 20,
                versionMade: 20,
                flag: 1<<11,    //  UTF-8
                compression: 8, //  Deflate
                modifiedTime: 0,
                modifiedDate: 0,
                crc: crc(files[i].data),
                compressedSize: compressed.length,
                uncompressedSize: files[i].data.length,
                fileName: utf8(files[i].name),
                extraField: new Uint8Array(0),
                comment: new Uint8Array(0),
                disk: 0,
                internalAttr: 0,
                externalAttr: 0,
                offset: arr.length,
            });

            writeLocalFileHeader(arr, header[i]);
            for (var c of compressed) {
                arr.push(c);
            }
        }

        var central = {
            signature: 0x06054b50,
            disk: 0,
            centralDirDisk: 0,
            entryNumber: header.length,
            totalEntryNumber: header.length,
            centralDirOffset: arr.length,
            comment: new Uint8Array(0),
        };
        for (var i=0; i<header.length; i++) {
            header[i].signature = 0x02014b50;
            writeCentralDirectoryHeader(arr, header[i]);
        }
        central.centralDirSize = arr.length - central.centralDirOffset;
        writeEndOfCentralDirectoryRecord(arr, central);

        log('end');
        return new Uint8Array(arr);
    }

    function writeLocalFileHeader(arr, header) {
        dword(arr, header.signature);
        word(arr, header.versionNeeded);
        word(arr, header.flag);
        word(arr, header.compression);
        word(arr, header.modifiedTime);
        word(arr, header.modifiedDate);
        dword(arr, header.crc);
        dword(arr, header.compressedSize);
        dword(arr, header.uncompressedSize);
        word(arr, header.fileName.length);
        word(arr, header.extraField.length);
        for (var n of header.fileName) {
            arr.push(n);
        }
        for (var e of header.extraField) {
            arr.push(e);
        }
    }
    function writeCentralDirectoryHeader(arr, header) {
        dword(arr, header.signature);
        word(arr, header.versionNeeded);
        word(arr, header.versionMade);
        word(arr, header.flag);
        word(arr, header.compression);
        word(arr, header.modifiedTime);
        word(arr, header.modifiedDate);
        dword(arr, header.crc);
        dword(arr, header.compressedSize);
        dword(arr, header.uncompressedSize);
        word(arr, header.fileName.length);
        word(arr, header.extraField.length);
        word(arr, header.comment.length);
        word(arr, header.disk);
        word(arr, header.internalAttr);
        dword(arr, header.externalAttr);
        dword(arr, header.offset);
        for (var n of header.fileName) {
            arr.push(n);
        }
        for (var e of header.extraField) {
            arr.push(e);
        }
        for (var c of header.comment) {
            arr.push(c);
        }
    }
    function writeEndOfCentralDirectoryRecord(arr, record) {
        dword(arr, record.signature);
        word(arr, record.disk);
        word(arr, record.centralDirDisk);
        word(arr, record.entryNumber);
        word(arr, record.totalEntryNumber);
        dword(arr, record.centralDirSize);
        dword(arr, record.centralDirOffset);
        word(arr, record.comment.length);
        for (var c of record.comment) {
            arr.push(c);
        }
    }

    var crcTable = [
        0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
        0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
        0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
        0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
        0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
        0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
        0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
        0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
        0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
        0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
        0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
        0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
        0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
        0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
        0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
        0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
        0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
        0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
        0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
        0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
        0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
        0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
        0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
        0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
        0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
        0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
        0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
        0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
        0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
        0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
        0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
        0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
        0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
        0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
        0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
        0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
        0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
        0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
        0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
        0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
        0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
        0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
        0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
        0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
        0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
        0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
        0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
        0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
        0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
        0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
        0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
        0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
        0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
        0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
        0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
        0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
        0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
        0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
        0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
        0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
        0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
        0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
        0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
        0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
    ];
    function crc(data) {
        var c = 0xffffffff;
        for (var d of data) {
            c = c>>8&0xffffff ^ crcTable[c&0xff^d];
        }
        return ~c;
    }

    function BitStream() {
        this.data = [];
        this.c = 0;
    }
    BitStream.prototype = {
        write: function(bit) {
            if (this.c%8 == 0) {
                this.data.push(0);
            }
            this.data[this.data.length-1] |= bit<<(this.c%8);
            this.c++;
        },
        writeBits: function(bits, len) {
            for (var i=0; i<len; i++) {
                this.write(bits>>i&1);
            }
        },
    };

    function Huffman(lengths) {
        this.lengths = lengths;
        this.codes = Array(lengths.length);
        var n = 0;
        for (var l of lengths) {
            if (l==0) {
                n++;
            }
        }
        var c = 0;
        for (var l=1; n<this.codes.length; l++, c<<=1) {
            for (var i=0; i<this.lengths.length; i++) {
                if (this.lengths[i]==l) {
                    this.codes[i] = c++;
                    n++;
                }
            }
        }
    }
    Huffman.prototype = {
        write: function(stream, symbol) {
            for (var i=this.lengths[symbol]-1; i>=0; i--) {
                stream.write(this.codes[symbol]>>i&1);
            }
        }
    };

    function compress(data) {
        var literalExtTable = [
            0, 0, 0, 0, 0, 0, 0, 0,  1, 1, 1, 1, 2, 2, 2, 2,
            3, 3, 3, 3, 4, 4, 4, 4,  5, 5, 5, 5, 0,
        ];
        var distExtTable = [
            0, 0, 0, 0, 1, 1, 2, 2,  3, 3, 4, 4, 5, 5, 6, 6,
            7, 7, 8, 8, 9, 9,10,10, 11,11,12,12,13,13,
        ];
        function calcCodeExt(value, table, offset) {
            for (var i=0; i<table.length; i++) {
                if (value < 1<<table[i]) {
                    return {code: i+offset, ext: value, extLen: table[i]};
                }
                value -= 1<<table[i];
            }
            throw 'calcCodeExt';
        }

        var literal = [];
        var dist = [];
        for (var i=0; i<data.length;) {
            var cand = [[
                {code: data[i], ext: 0, extLen: 0},
                {code: -1},
                1,
            ]];
            for (var d=1; d<=16; d++)
            if (0<=i-d) {
                for (var l=1; l<=16 && i+l-1<data.length && data[i+l-1]==data[i-d+l-1]; l++) {
                    if (3<=l) {
                        cand.push([
                            calcCodeExt(l-3, literalExtTable, 257),
                            calcCodeExt(d-1, distExtTable, 0),
                            l,
                        ]);
                    }
                }
            }
            var r = rand()%cand.length;
            literal.push(cand[r][0]);
            dist.push(cand[r][1]);
            i += cand[r][2];
        }
        literal.push({code: 256, ext: 0, extLen: 0});
        dist.push({code: -1});

        //  仕様上許される最大値は29
        var HLIT = rand()%16 + 14;
        //  HDISTの定義では31まで許されそうだが、30と31は使われないので、念のため最大29
        var HDIST = rand()%16 + 14;
        //  ビット長は3-14
        var HCLEN = rand()%3 + 13;

        function makeLengths(num, min) {
            var block = 1<<(min-1);
            var max = (min + (num+block-1)/block - 1)|0;
            if (max - min < 2) {
                throw 'makeLengths';
            }
            var lengths = [];
            for (var l=min; l<max-2; l++) {
                for (var i=0; i<block; i++) {
                    lengths.push(l);
                }
            }
            var rem = (max-min+1)*block - num;
            for (var i=0; i<block+rem; i++) {
                lengths.push(max-2);
            }
            for (var i=0; i<block*2-rem*2; i++) {
                lengths.push(max-1);
            }

            for (var i=num-1; i>=0; i--) {
                var r = rand()%(i+1);
                var t = lengths[i];
                lengths[i] = lengths[r];
                lengths[r] = t;
            }
            return lengths;
        }

        var codeLenLen = makeLengths(HCLEN+4, 3);
        var literalLen = makeLengths(HLIT+257, 6);
        var distLen = makeLengths(HDIST+1, 3);

        stream = new BitStream();
        stream.write(1);
        stream.writeBits(2, 2);

        stream.writeBits(HLIT, 5);
        stream.writeBits(HDIST, 5);
        stream.writeBits(HCLEN, 4);

        for (var i=0; i<HCLEN+4; i++) {
            stream.writeBits(codeLenLen[i], 3);
        }
        var trans = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
        var codeLenLenTrans = [];
        for (var i=0; i<19; i++) {
            var idx = trans.indexOf(i);
            codeLenLenTrans.push(idx < HCLEN+4 ? codeLenLen[idx] : 0);
        }
        huffLen = new Huffman(codeLenLenTrans);
        for (var i=0; i<HLIT+257; i++) {
            huffLen.write(stream, literalLen[i]);
        }
        for (var i=0; i<HDIST+1; i++) {
            huffLen.write(stream, distLen[i]);
        }

        huffLiteral = new Huffman(literalLen);
        huffDist = new Huffman(distLen);
        for (var i=0; i<literal.length; i++) {
            huffLiteral.write(stream, literal[i].code);
            stream.writeBits(literal[i].ext, literal[i].extLen);
            if (dist[i].code >= 0) {
                huffDist.write(stream, dist[i].code);
                stream.writeBits(dist[i].ext, dist[i].extLen);
            }
        }

        return stream.data;
    }

    function byte(arr, num) {
        arr.push(num&0xff);
    }
    function word(arr, num) {
        arr.push(num&0xff);
        arr.push(num>>8&0xff);
    }
    function dword(arr, num) {
        arr.push(num&0xff);
        arr.push(num>>8&0xff);
        arr.push(num>>16&0xff);
        arr.push(num>>24&0xff);
    }

    randBuffer = new Uint32Array(1024);
    randCount = 1024;
    function rand() {
        if (randCount >= 1024) {
            randCount = 0;
            crypto.getRandomValues(randBuffer);
        }
        return randBuffer[randCount++];
    }

    function utf8(str) {
        var result = [];
        for (var i=0; i<str.length; i++) {
            var code = str.codePointAt(i);
            if (code >= 0x10000) {
                i++;
            }
            if (code < 0x80) {
                result.push(code);
            } else if (code < 0x800) {
                result.push(0xc0 | code>>6);
                result.push(0x80 | code&0x3f);
            } else if (code < 0x10000) {
                result.push(0xe0 | code>>12);
                result.push(0x80 | code>>6&0x3f);
                result.push(0x80 | code&0x3f);
            } else {
                result.push(0xf0 | code>>18);
                result.push(0x80 | code>>12&0x3f);
                result.push(0x80 | code>>6&0x3f);
                result.push(0x80 | code&0x3f);
            }
        }
        return new Uint8Array(result);
    }
}
