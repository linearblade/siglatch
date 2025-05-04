FAFO the annoying way.

if you are building on an ancient system ... like centos 7 or below, you'll prolly need to install openssl 3, b/c its so danng old nothing works.
if curl -O doesnt work, use wget, then tar zxvf.

```
curl -O https://www.openssl.org/source/openssl-3.0.13.tar.gz
tar xzf openssl-3.0.13.tar.gz
cd openssl-3.0.13
./config --prefix=/opt/openssl-3.0 --openssldir=/opt/openssl-3.0 shared
make -j$(nproc)
make install
```
then set this 
```
export CPPFLAGS="-I/opt/openssl-3.0/include"
export LDFLAGS="-L/opt/openssl-3.0/lib"
export LD_LIBRARY_PATH="/opt/openssl-3.0/lib"

export LD_LIBRARY_PATH=/usr/local/lib64:$LD_LIBRARY_PATH
```