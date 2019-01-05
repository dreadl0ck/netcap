## Changelog

ecff680 added build.sh script to run docker container and extract compiled binary
5b0faee added notes on cross compilation for linux
4ebacd1 added v0.3.7 dist folder
e888edc added windows build tag to collector
af2438c bootstrapped docker container for compiling linux release
ad1dc0d deleted binary release files
383b098 implemented support for EAPOL and EAPOLKey
8999c33 refactored encoder package level init because the syscall for detemining block size is not available on windows
3bd6d26 use not windows build tag to allow compilation on macOS
