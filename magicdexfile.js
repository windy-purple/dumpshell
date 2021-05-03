var addrLoadMethod = null;
var ishook = false
var savepath = "/storage/emulated/0"
var filenamelist = new Array();
var featurestring = "com/zxjw/mtkediter";

function getString(strarray)
{
    var str = "";
    var i = 0;
    for(i=0;i<strarray.length;i++){
        str += String.fromCharCode(strarray[i])
    }
    return str;
}

function identifyDex(dexarray)
{
    var i = 0;
    var count = 0;
    var stringIdsSize = (((dexarray[0x3B] << 24) | (dexarray[0x3A] << 16)) | (dexarray[0x39] << 8)) | dexarray[0x38];
    console.log("stringIdSize==>" + stringIdsSize);
    var stringIdsOff = (((dexarray[0x3F] << 24) | (dexarray[0x3E] << 16)) | (dexarray[0x3D] << 8)) | dexarray[0x3C];
    console.log("stringIdOff==>" + stringIdsOff);
    var index = stringIdsOff;
    for(i=0;i<stringIdsSize;i++){
        var stroffest = (((dexarray[index + 3] << 24) | (dexarray[index + 2] << 16)) | (dexarray[index + 1] << 8)) | dexarray[index];
        index += 4;
        var flag = 1;
        var string = new Array();
        var stroff = stroffest + 1;
        while(flag != 0){
            flag = dexarray[stroff];
            stroff += 1;
            if(flag != 0){
                string.push(flag);
            }
        }
        var str = getString(string);
        if(str.indexOf(featurestring) != -1){
            count += 1;
        }
    }
    console.log("[" + featurestring + "]: Count " + count);
}

function hookart()
{
    var symbols = Module.enumerateSymbolsSync("libart.so");
    console.log("[*] load libart.so finish");
	for(var i = 0;i < symbols.length;i++)
	{
		var symbol = symbols[i];
		if(symbol.name == "_ZN3art11ClassLinker13ResolveMethodERKNS_7DexFileEjNS_6HandleINS_6mirror8DexCacheEEENS4_INS5_11ClassLoaderEEEPNS_9ArtMethodENS_10InvokeTypeE")
		{
            console.log("[*] find function, Method sign ==>",symbol.name);
            addrLoadMethod = symbol.address;
            console.log("[*] init var addLoadMethod");
            break;
		}
    }

    if(addrLoadMethod != null)
    {
        Interceptor.attach(addrLoadMethod,{
            onEnter:function(args)
            {
                if(!ishook)
                {
                    //console.log("\n[*] jump RegisterDexFile onEnter");
                    this.dexfileptr = args[1];
                }
            },
            onLeave:function(retval)
            {
                //console.log("[*] jump RegisterDexFile onLeave");
                var dexfilebegin = null;
                var dexfilesize = null;
                if(this.dexfileptr != null)
                {
                    dexfilebegin = Memory.readPointer(ptr(this.dexfileptr).add(Process.pointerSize * 1));
                    dexfilesize = Memory.readU32(ptr(this.dexfileptr).add(Process.pointerSize * 2));
                    var dexfile_path = savepath + "/" + dexfilesize + "_ResolveMethod.dex";
                    if(filenamelist.length == 0 || filenamelist.indexOf(dexfile_path) < 0)
                    {
                        filenamelist.push(dexfile_path);
                        var dexfile_handle = 1;
                        //try
                        //{
                            //var fso = new ActiveXObject("Scripting.FileSystemObject");
                            //var isexist = fso.FileExists(dexfile_path)
                            dexfile_handle = new File(dexfile_path,"w+");
                            if(dexfile_handle && dexfile_handle != null)
                            {
                                var dex_buffer = ptr(dexfilebegin).readByteArray(dexfilesize);
                                console.log("\n[dumpdex]: dump success " + dexfile_path);
                                var dex = new Uint8Array(dex_buffer);
                                identifyDex(dex);
                                dexfile_handle.write(dex_buffer[0]);
                                //console.log("[dumpdex]: write success");
                                dexfile_handle.flush();
                                dexfile_handle.close();
                                //console.log("[dumpdex]: ",dexfile_path);
                            }
                        //}catch(e){
                        //    console.log("[dumpdex]: error!");
                        //}
                    }
                }
            }
        })
    }
}

setImmediate(hookart);