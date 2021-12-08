# Use Samples
The sample auth server & sample client are derived from https://github.com/go-oauth2/oauth2/blob/master/example/.

## Run ras server
```bash
$ cd ../cmd/ras
$ go build main.go
$ ./main

```

## Run Sample Auth Server

``` bash
$ cd sampleauthserver
$ go build server.go
$ ./server
```

## Run Sample Client

```
$ cd sampleclient
$ go build client.go
$ ./client
```

## Authorization Code Grant

### Open the browser

[http://localhost:5094](http://localhost:5094)

```
{
  "access_token": "GIGXO8XWPQSAUGOYQGTV8Q",
  "token_type": "Bearer",
  "refresh_token": "5FBLXQ47XJ2MGTY8YRZQ8W",
  "expiry": "2019-01-08T01:53:45.868194+08:00"
}
```


### Try access token

Open the browser [http://localhost:5094/try](http://localhost:5094/try)

```
got it!
```

## Refresh token

Open the browser [http://localhost:5094/refresh](http://localhost:5094/refresh)

```
{
  "access_token": "0IIL4_AJN2-SR0JEYZVQWG",
  "token_type": "Bearer",
  "refresh_token": "AG6-63MLXUEFUV2Q_BLYIW",
  "expiry": "2019-01-09T23:03:16.374062+08:00"
}
```

## Password Credentials Grant

Open the browser [http://localhost:5094/pwd](http://localhost:5094/pwd)

```
{
  "access_token": "87JT3N6WOWANXVDNZFHY7Q",
  "token_type": "Bearer",
  "refresh_token": "LDIS6PXAVY-BXHPEDESWNG",
  "expiry": "2019-02-12T10:58:43.734902+08:00"
}
```

## Client Credentials Grant

Open the browser [http://localhost:5094/client](http://localhost:5094/client)

```
{
  "access_token": "OA6ITALNMDOGD58C0SN-MG",
  "token_type": "Bearer",
  "expiry": "2019-02-12T11:10:35.864838+08:00"
}
```