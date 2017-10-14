# Contributor: Sergei Lukin <sergej.lukin@gmail.com>
# Contributor: Valery Kartel <valery.kartel@gmail.com>
# Contributor: Jakub Jirutka <jakub@jirutka.cz>
# Maintainer: Natanael Copa <ncopa@alpinelinux.org>
pkgname=qemu
pkgver=2.10.1
pkgrel=3
pkgdesc="QEMU is a generic machine emulator and virtualizer"
url="http://qemu.org/"
arch="x86_64"
license="GPL2 LGPL-2"
makedepends="
	alsa-lib-dev
	bison
	curl-dev
	flex
	glib-dev
	glib-static
	gnutls-dev
	gtk+3.0-dev
	libaio-dev
	libcap-dev
	libcap-ng-dev
	libjpeg-turbo-dev
	libnfs-dev
	libpng-dev
	libssh2-dev
	libusb-dev
	linux-headers
	lzo-dev
	ncurses-dev
	paxmark
	snappy-dev
	spice-dev
	texinfo
	usbredir-dev
	util-linux-dev
	vde2-dev
	xfsprogs-dev
	zlib-dev
	"
depends=""
pkggroups="qemu"
install="qemu.pre-install qemu.post-install"
options="suid !strip"  # needed for qemu-bridge-helper
subpackages="qemu-doc qemu-guest-agent:guest"

_subsystems="
	system-x86_64
	x86_64
	"

for _sub in $_subsystems; do
	subpackages="$subpackages $pkgname-$_sub:_subsys"
done

_arch=x86_64 
#if [ -n "$_arch" ]; then
#	subpackages="$subpackages $pkgname-gtk"
#	gtk() { _subsys system-$_arch-gtk; }
#fi:

subpackages="$subpackages $pkgname-img"  # -img must be declared the last

source="http://wiki.qemu-project.org/download/qemu-$pkgver.tar.bz2
	0001-elfload-load-PIE-executables-to-right-address.patch
	0006-linux-user-signal.c-define-__SIGRTMIN-MAX-for-non-GN.patch
	musl-F_SHLCK-and-F_EXLCK.patch
	fix-sigevent-and-sigval_t.patch
	xattr_size_max.patch
	ncurses.patch
	ignore-signals-33-and-64-to-allow-golang-emulation.patch
	fix-sockios-header.patch
	0007-fadt.patch
	qemu-guest-agent.confd
	qemu-guest-agent.initd
	80-kvm.rules
	bridge.conf
	"
builddir="$srcdir/$pkgname-$pkgver"

# secfixes:
#   2.8.1-r1:
#   - CVE-2016-7994
#   - CVE-2016-7995
#   - CVE-2016-8576
#   - CVE-2016-8577
#   - CVE-2016-8578
#   - CVE-2016-8668
#   - CVE-2016-8909
#   - CVE-2016-8910
#   - CVE-2016-9101
#   - CVE-2016-9102
#   - CVE-2016-9103
#   - CVE-2016-9104
#   - CVE-2016-9105
#   - CVE-2016-9106
#   - CVE-2017-2615
#   - CVE-2017-2620
#   - CVE-2017-5525
#   - CVE-2017-5552
#   - CVE-2017-5578
#   - CVE-2017-5579
#   - CVE-2017-5667
#   - CVE-2017-5856
#   - CVE-2017-5857
#   - CVE-2017-5898
#   - CVE-2017-5931


prepare() {
	default_prepare  # apply patches

	sed -i 's/^VL_LDFLAGS=$/VL_LDFLAGS=-Wl,-z,execheap/' \
		Makefile.target
}

_compile_common() {
	"$builddir"/configure \
		--prefix=/usr \
		--localstatedir=/var \
		--sysconfdir=/etc \
		--libexecdir=/usr/lib/qemu \
		--disable-glusterfs \
		--disable-debug-info \
		--disable-bsd-user \
		--disable-werror \
		--disable-sdl \
		--disable-xen \
		--cc="${CC:-gcc}" \
		"$@"
	make ARFLAGS="rc"
}

_compile_system() {
	_compile_common \
		--audio-drv-list=oss,alsa \
		--enable-kvm \
		--enable-vde \
		--enable-virtfs \
		--enable-curl \
		--enable-cap-ng \
		--enable-linux-aio \
		--enable-usb-redir \
		--enable-libssh2 \
		--enable-vhost-net \
		--enable-snappy \
		--enable-tpm \
		--enable-libnfs \
		--enable-lzo \
		--enable-docs \
		--enable-curses \
		--enable-pie \
		--disable-linux-user \
		--target-list=x86_64-softmmu \
		"$@"
}

build() {
	mkdir -p "$builddir"/build \
		"$builddir"/build-user \
		"$builddir"/build-gtk

	cd "$builddir"/build-user
	_compile_common \
		--target-list="x86_64-linux-user" \
		--enable-linux-user \
		--disable-system \
		--static

	cd "$builddir"/build
	_compile_system \
		--enable-vnc \
		--enable-vnc-png \
		--enable-vnc-jpeg \
		--enable-spice \
		--enable-guest-agent \
		--disable-gtk


# tests fails on x86
# http://lists.gnu.org/archive/html/qemu-devel/2012-11/msg01429.html
# http://web.archiveorange.com/archive/v/21oVv8wOfpQGkyy8EK0N
#	make check

}

package() {
	cd "$builddir"/build-user
	make DESTDIR="$pkgdir" install

	cd "$builddir"/build
	make DESTDIR="$pkgdir" install
	paxmark -m "$pkgdir"/usr/bin/qemu-system-*

	install -Dm640 -g qemu "$srcdir"/bridge.conf \
		"$pkgdir"/etc/qemu/bridge.conf

	install -Dm644 "$srcdir"/80-kvm.rules \
		"$pkgdir"/lib/udev/rules.d/80-kvm.rules

	# qemu-bridge-helper needs suid to create tunX devices;
	# allow only users in the qemu group to run it.
	chmod 04710 "$pkgdir"/usr/lib/qemu/qemu-bridge-helper
	chgrp qemu "$pkgdir"/usr/lib/qemu/qemu-bridge-helper

	# Do not install HTML docs.
	rm "$pkgdir"/usr/share/doc/qemu/*.html
}

_subsys() {
	local name=${1:-"${subpkgname#$pkgname-}"}
	pkgdesc="Qemu ${name/-/ } emulator"
	options=""
	depends=""
	case "$name" in
		system*) depends="qemu";;
	esac

	mkdir -p "$subpkgdir"/usr/bin
	mv "$pkgdir"/usr/bin/qemu-$name "$subpkgdir"/usr/bin/
}

img() {
	pkgdesc="QEMU command line tool for manipulating disk images"
	depends=""
	options=""

	mkdir -p "$subpkgdir"/usr/bin
	mv "$pkgdir"/usr/bin/qemu-img \
		"$pkgdir"/usr/bin/qemu-io \
		"$pkgdir"/usr/bin/qemu-nbd \
		"$subpkgdir"/usr/bin/

}

guest() {
	pkgdesc="QEMU guest agent"
	depends=""
	options=""

	mkdir -p "$subpkgdir"/usr/bin
	mv "$pkgdir"/usr/bin/qemu-ga "$subpkgdir"/usr/bin/

	install -Dm755 "$srcdir"/qemu-guest-agent.initd \
		"$subpkgdir"/etc/init.d/qemu-guest-agent
	install -Dm644 "$srcdir"/qemu-guest-agent.confd \
		"$subpkgdir"/etc/conf.d/qemu-guest-agent
}

sha512sums="1a4a6ebf700ec6851c83cc2a71eaea8d95f14c685d094eaaa86c740eb9401e49a79074b72385f58681ca7646771a99bb6bbd9bebb39162f7220626d37ed0654f  qemu-2.10.1.tar.bz2
405008589cad1c8b609eca004d520bf944366e8525f85a19fc6e283c95b84b6c2429822ba064675823ab69f1406a57377266a65021623d1cd581e7db000134fd  0001-elfload-load-PIE-executables-to-right-address.patch
ec84b27648c01c6e58781295dcd0c2ff8e5a635f9836ef50c1da5d0ed125db1afc4cb5b01cb97606d6dd8f417acba93e1560d9a32ca29161a4bb730b302440ea  0006-linux-user-signal.c-define-__SIGRTMIN-MAX-for-non-GN.patch
224f5b44da749921e8a821359478c5238d8b6e24a9c0b4c5738c34e82f3062ec4639d495b8b5883d304af4a0d567e38aa6623aac1aa3a7164a5757c036528ac0  musl-F_SHLCK-and-F_EXLCK.patch
5da8114b9bd2e62f0f1f0f73f393fdbd738c5dea827ea60cedffd6f6edd0f5a97489c7148d37a8ec5a148d4e65d75cbefe9353714ee6b6f51a600200133fc914  fix-sigevent-and-sigval_t.patch
4b1e26ba4d53f9f762cbd5cea8ef6f8062d827ae3ae07bc36c5b0c0be4e94fc1856ad2477e8e791b074b8a25d51ed6d0ddd75e605e54600e5dd0799143793ce4  xattr_size_max.patch
b6ed02aaf95a9bb30a5f107d35371207967edca058f3ca11348b0b629ea7a9c4baa618db68a3df72199eea6d86d14ced74a5a229d17604cc3f0adedcfeae7a73  ncurses.patch
fd178f2913639a0c33199b3880cb17536961f2b3ff171c12b27f4be6bca032d6b88fd16302d09c692bb34883346babef5c44407a6804b20a39a465bb2bc85136  ignore-signals-33-and-64-to-allow-golang-emulation.patch
f0f99dc4f7fb475e3fab0262c0bc2c0dd8f17d77fe096c295fa1fc3e911ce07e1592f49c6ead7489246fecdd3a3f39f89ce05704af7f3fd384ce4f626f3c4601  fix-sockios-header.patch
d90c034cae3f9097466854ed1a9f32ab4b02089fcdf7320e8f4da13b2b1ff65067233f48809911485e4431d7ec1a22448b934121bc9522a2dc489009e87e2b1f  qemu-guest-agent.confd
316b40d97587fea717821852859d81039cfdcb276a658bb6e6fb554e321d5856a833ebb3778149c4732cea625bac320b1008d374c88a9aae35c0fb67977c01b7  qemu-guest-agent.initd
9b7a89b20fcf737832cb7b4d5dc7d8301dd88169cbe5339eda69fbb51c2e537d8cb9ec7cf37600899e734209e63410d50d0821bce97e401421db39c294d97be2  80-kvm.rules
749efa2e764006555b4fd3a8e2f6d1118ad2ea4d45acf99104a41a93cfe66dc9685f72027c17d8211e5716246c2a52322c962cf4b73b27541b69393cd57f53bb  bridge.conf
610f4e8e8fd8fa7353ca0e543bc041df563f2a8ac1a37e53acf60f79a93d535c4e5997dd12a01c4afe34355be2c5d371aa768001c34de4c65dcd6b6f5f368c3b  0007-fadt.patch"
