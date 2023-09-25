# Nginx G Streaming

It's a streaming server fork from ngx-rtmp-module.

Tested nginx version: `1.15.8`   

## features
* Orignal ngx-rtmp-module features
* Http-flv live streaming output support
  * standard http output, any http function that nginx already has can be used(such as http2)
  * same ref-count shared memory management, low memory usage
  * http-flv play will trigger other rtmp module(such as relay), except live module
  * gop cache for quick play start

## Build

go (https://github.com/arut/nginx-rtmp-module) to find how to build.    
    
cd to NGINX source directory & run this:    
```
./configure --add-module=/path/to/nginx-rtmp-module
make
make install
```

## Config

### http/flv output

The code implements this feature is contained in `ngx_rtmp_http_live_module.h` and
`ngx_rtmp_http_live_module.c`.     
The original nginx rtmp code is not changed except a small modification for `ngx_rtmp_codec_module`: add a field `raw_meta`. We need it to build flv metadata.

The example config for using these module is like this
```
rtmp {
    server {
        listen 19350;

        http_live_src mylive;

        application myapp {
            live on; 
            http_live on; 
        }   
    }   
}

http {
    server {
        listen       8080;

        location /myapp {
            http_rtmp_live_dst mylive;
            http_rtmp_live on;
        }
    }
}
```

`http_rtmp_live_dst` and `http_live_src` are paired, for example:    
When we visit a http/flv stream `http://127.0.0.1:8080/myapp/test.flv`, it will find rtmp server block contains the `http_live_src` as `mylive`, and find app `myapp` and stream name `test`.
So if we using ffmpeg to push rtmp stream to `rtmp://127.0.0.1:19350/myapp/test`,  the stream data will send to the http/flv client.

## Directive

#### http_live_src
Syntax: `http_live_src name`    
Context: server    
    
Name a rtmp server block, when play using http/flv, `http_rtmp_live_dst` will try    
to find this server block

#### http_live
Syntax: `http_live on|off`    
Context: rtmp, server, app    
    
Whether enable http/flv live function

#### http_wait_key
Syntax: `http_wait_key on|off`    
Context: rtmp, server, app    
    
Wait for key-frame when output    

#### http_wait_video
Syntax: `http_wait_video on|off`    
Context: rtmp, server, app    
    
When audio packet arrive first, drop it and wait for video    

#### http_live_cache
Syntax: `http_live_cache on|off`    
Context: rtmp, server, app    
    
Cache frame, so when a new player start to play, the cached frame will be sent first.    
This will make player start to play quickly.    

#### http_rtmp_live_dst
Syntax: `http_rtmp_live_dst name`    
Context: http, server, location    
        
Find `http_live_src` server of the 'name', so we will get rtmp packet from that server block

#### http_rtmp_live
Syntax: `http_rtmp_live on|off`    
Context: http, server, location    
    
Enable http/flv by convert from live rtmp stream publish.    

### Try

pushing using ffmpeg

```
ffmpeg -re -i $input_video_file_path -acodec copy -vcodec copy -flags global_header -f flv rtmp://127.0.0.1:19350/myapp/test
```

download(or play by any player, such as vlc)

```
➜  ~ curl http://127.0.0.1:8080/myapp/test.flv > /dev/null
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 1594k    0 1594k    0     0   114k      0 --:--:--  0:00:13 --:--:--  117k
```
