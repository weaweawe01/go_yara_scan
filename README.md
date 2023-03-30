# yara_scan 


## Environment
### Ubuntu 20.04

```bash
apt install ld
apt install zip 
apt update && apt install automake bison help2man m4 texinfo \
apt update && apt install automake bison help2man m4 texinfo texlive
sudo apt install automake libtool make gcc flex bison libssl-dev libjansson-dev libmagic-dev
sudo apt-get install libssl-dev
sudo apt-get install libssl-dev libgcrypt-dev
apt install openssl -y 
apt install openssl-dev

```
### install  yara-4.3.0
```bash
mkdir ~/softs/
cd ~/softs/
wget https://github.com/VirusTotal/yara/archive/v4.3.0.tar.gz
tar -zxvf v4.3.0.tar.gz
cd yara-4.3.0
export YARA_SRC=~/softs/yara-4.3.0
./bootstrap.sh
./configure --disable-shared --enable-static --without-crypto
make && make install
cp ./libyara/yara.pc /usr/local/lib/pkgconfig/yara.pc

```


### Static build
```bash
$ git clone github.com/weaweawe01/go_yara_scan.git 
$ cd go_yara_scan
$ SRCDIR=$(pwd)
$ SRCDIR=/root/softs/yara-4.3.0/
$ export CGO_CFLAGS="-g -Wall -I${SRCDIR}/libyara/include"
$ export CGO_LDFLAGS="-L${YARA_SRC}/libyara/.libs -lyara -lm"
$ CGO_ENABLED=1 go build -ldflags '-linkmode external -extldflags "-static"' -o go_yara_scan main.go config.go 
```


###  Usage
```bash
$ ./go_yara_scan --hlep
flag provided but not defined: -hlep
Usage of ./go_yara_scan:
  -cpu int
    	the maximum number of CPUs to use 10-100 (default 10)
  -dir string
    	the directory to scan
  -file string
    	the file to scan
  -scan_recu uint
    	the maximum recursion depth for directory scanning default 5 max 20 (default 5)


$ Scan File 
$ ./go_yara_scan --file=/etc/passwd
db load succeed: 9912
chan string count 1
Scan completed.
costTime 1.516261496s

$ ./go_yara_scan --dir=/www
db load succeed: 9912
chan string count 2
209 YARA.Unix_Packer_UpxDetail.UNOFFICIAL Virus(es) detected ../test_file/dd/nmap
209 YARA.Unix_Packer_UpxDetail.UNOFFICIAL Virus(es) detected ../test_file/nmap
Scan completed.
costTime 14.905588934s


The default limit is 10% of the overall CPU if you want to open the CPU. Use the following:
$ ./go_yara_scan --dir=../test_file --cpu=80
db load succeed: 9912
chan string count 2
209 YARA.Unix_Packer_UpxDetail.UNOFFICIAL Virus(es) detected ../test_file/dd/nmap
209 YARA.Unix_Packer_UpxDetail.UNOFFICIAL Virus(es) detected ../test_file/nmap
Scan completed.
costTime 6.38549549s

The default scan directory level is 5 times. If you want to scan multiple layers. As follows:
$ ./go_yara_scan --dir=../test_file --cpu=80  --scan_recu=10
db load succeed: 9912
chan string count 2
209 YARA.Unix_Packer_UpxDetail.UNOFFICIAL Virus(es) detected ../test_file/dd/nmap
209 YARA.Unix_Packer_UpxDetail.UNOFFICIAL Virus(es) detected ../test_file/nmap
Scan completed.
costTime 6.38549549s
```





## Reference
[hillu/go-yara](https://github.com/hillu/go-yara)

