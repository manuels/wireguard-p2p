export HOME=/home/travis
cd $HOME
pwd
sudo apt-get install -y ruby-dev build-essential rpm python3-setuptools

wget 'https://bootstrap.pypa.io/get-pip.py'
python3 get-pip.py

git clone https://github.com/rbenv/rbenv.git $HOME/.rbenv
cd $HOME/.rbenv && src/configure && make -C src
export PATH="$HOME/.rbenv/bin:/home/travis/.rvm/gems/ruby-2.2.6/bin/:/home/travis/.rvm/rubies/ruby-2.2.6/bin:$PATH"
eval "$(rbenv init -)"
$HOME/.rbenv/bin/rbenv rehash
gem install --no-ri --no-rdoc ffi
gem install --no-ri --no-rdoc fpm
cd $TRAVIS_BUILD_DIR
ls -l
echo $PACKAGE_NAME $TRAVIS_TAG
which fpm
pip3 install setuptools
fpm -s python -t deb -n $PACKAGE_NAME -v `echo $TRAVIS_TAG | tr -d v` \
        --python-bin /usr/bin/python3 \
        --depends python3-nacl \
        --python-package-name-prefix python3 \
        --python-disable-dependency PyNaCl \
        --config-files etc/wireguard-p2p.conf \
        --deb-init etc/init.d/wireguard-p2p \
        --after-install after-install.sh \
        --after-upgrade after-update.sh ./setup.py
