<h2>netfilter install</h2>

http://netfilter.org

<h2>install list</h2>

tar -xvf libmnl.tar.bz2

tar -xvf libnfnetlink.tar.bz2

tar -xvf libnetfilter_queue.tar.bz2

<h2>setting</h2>

cd <directory>

./configure

make

make install

<h2>TEST</h2>

export LD_LIBRARY_PATH=/usr/local/lib ./file

iptables -A OUTPUT -p icmp -j NFQUEUE --queue-num 0


