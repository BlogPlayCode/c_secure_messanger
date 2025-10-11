rm -rf kyber
rm -rf mbedtls

git clone https://github.com/pq-crystals/kyber.git
git clone https://github.com/Mbed-TLS/mbedtls.git

cd mbedtls
git checkout v3.6.1
git submodule update --init --recursive

mkdir build
cd build
sudo apt install cmake -y
cmake ..
cmake --build .
