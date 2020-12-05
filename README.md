# caddy-oss-object

caddy HTTP handler for aliyun oss

## How To Use

This is an example Caddyfile:

```Caddyfile
{
  order oss_object last
}

:1080 {
    oss_object {
        endpoint oss-cn-shanghai.aliyuncs.com
        access_key_id LTAI4**********CwTBwk
        access_key_secret 9Fwra2d************AbBbJPu16
        bucket static-source
        object_key 404/index.html
    }
}
```

All of the five arguments support [Placeholder Conventions](https://caddyserver.com/docs/conventions#placeholders).
