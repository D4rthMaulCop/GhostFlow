# Output binary name
BINARY_NAME=GhostToken
BUILD_DIR=_bin
TARGET_OS=linux
TARGET_ARCH=amd64

.PHONY: all clean build package

all: build package

build:
	@echo "[+] Compiling Go binary for $(TARGET_OS)/$(TARGET_ARCH)..."
	GOOS=$(TARGET_OS) GOARCH=$(TARGET_ARCH) go build -o $(BUILD_DIR)/$(BINARY_NAME) main.go

package: build
	@echo "[+] Creating deployment package in $(BUILD_DIR)/"
	@mkdir -p $(BUILD_DIR)/templates
	@cp -v templates/index.html $(BUILD_DIR)/templates/
	@cp -v templates/unauthorized.html $(BUILD_DIR)/templates/

clean:
	@echo "[*] Cleaning up..."
	@rm -rf $(BUILD_DIR)
