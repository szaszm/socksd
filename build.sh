#!/usr/bin/env bash

export CC="clang -fcolor-diagnostics -Qunused-arguments"
export CXX="clang++ -fcolor-diagnostics -Qunused-arguments"
export CCACHE_DIR="../../../cache"

function generate {
	echo Generating ninja project files...
	gyp -f ninja --depth .  main.gyp 
}

function genmsvs {
	echo Generating Visual Studio files...
	gyp -f msvs --depth . --generator-output out/msvs main.gyp
}

function build {
	export PATH="/usr/lib/ccache/bin:$PATH"
	export CCACHE_DIR="../../../cache"

	if [ ! -d "out" ]
	then
		generate
	fi
	pushd out/Debug &>/dev/null

	echo Building...
	ninja -v
	popd &>/dev/null
}

function run {
	pushd out/Debug &>/dev/null
	./socksd
	popd &>/dev/null
}

function clean {
	pushd out/Default &>/dev/null
	ninja -t clean
	popd &>/dev/null
}

function test {
	export PATH="/usr/lib/ccache/bin:$PATH"
	export CCACHE_DIR="../../../cache"

	pushd out/Default &>/dev/null
	ninja tests && \
	./tests
	popd &>/dev/null
}

if [[ $0 != "./build.sh" ]]
then
	echo You must call this script from the local directory
	exit 1;
fi

case $1 in
	"clean") clean ;;
	"rebuild") clean; build ;;
	"gen") generate ;;
	"genmsvs") genmsvs ;;
	"test") test ;;
	"run") run ;;
	"build"|*) build ;;
esac

echo Done.
