REPO_URL  := https://github.com/cpholguera/mas-app-ios
DIST_DIR  := $(CURDIR)/dist

ifdef TARGET_APP
BUILD_DIR   := $(CURDIR)/$(TARGET_APP)/build
CLONE_DIR   := $(BUILD_DIR)/mas-app-ios
DERIVED_DATA := $(BUILD_DIR)/DerivedData
IOS_APP_SRC := $(DERIVED_DATA)/Build/Products/Debug-iphonesimulator
APP_DST     := $(DIST_DIR)/$(TARGET_APP).target-app.app
endif

BUNDLE_ID := org.owasp.mastestapp.MASTestApp-iOS

ALL_APPS := $(shell find . -maxdepth 1 -mindepth 1 -type d \
	! -name dist ! -name '.*' \
	-exec basename {} \;)

.PHONY: build build-all install install-all clean clean-all

build: $(BUILD_DIR) $(DIST_DIR)
	@[ -n "$(TARGET_APP)" ] || { echo "ERROR: TARGET_APP is required. Usage: make build TARGET_APP=<name>"; exit 1; }

	@if [ ! -d "$(CLONE_DIR)/.git" ]; then \
		git clone $(REPO_URL) $(CLONE_DIR); \
	else \
		echo "Repo already cloned, skipping git clone."; \
	fi

	@[ -f "$(TARGET_APP)/MastgTest.swift" ] && \
		cp -f "$(TARGET_APP)/MastgTest.swift" \
			"$(CLONE_DIR)/MASTestApp/MastgTest.swift" && \
		echo "Copied MastgTest.swift" || true

	cp $(CLONE_DIR)/.github/Local.xcconfig.ci $(CLONE_DIR)/Local.xcconfig

	@perl -i -pe 's|^(PRODUCT_BUNDLE_IDENTIFIER\s*=\s*).*|$${1}$(subst -,_,$(TARGET_APP)).mastestapp|' \
		"$(CLONE_DIR)/Local.xcconfig" && \
		echo "Set PRODUCT_BUNDLE_IDENTIFIER to $(subst -,_,$(TARGET_APP)).mastestapp"

	cd $(CLONE_DIR) && \
		IOS_SCHEME=$$(xcodebuild -list -json | jq -r '.project.targets[0]') && \
		SIM_NAME=$$(xcrun simctl list devices available -j | \
			jq -r '[.devices | to_entries[] | select(.key | contains("iOS")) | .value[]] | map(select(.isAvailable == true)) | first | .name') && \
		echo "Using scheme: $$IOS_SCHEME" && \
		echo "Using simulator: $$SIM_NAME" && \
		xcodebuild build \
			-project "MASTestApp.xcodeproj" \
			-scheme "$$IOS_SCHEME" \
			-destination "platform=iOS Simulator,name=$$SIM_NAME" \
			-derivedDataPath "$(DERIVED_DATA)" \
			CODE_SIGN_IDENTITY="" \
			CODE_SIGNING_REQUIRED=NO \
			CODE_SIGNING_ALLOWED=NO

	mkdir -p $(DIST_DIR)
	cp -r $(IOS_APP_SRC)/*.app $(APP_DST)
	@echo "iOS app available at: $(APP_DST)"


build-all:
	@for app in $(ALL_APPS); do \
		echo "=== Building $$app ==="; \
		$(MAKE) build TARGET_APP=$$app; \
	done

install:
	@[ -n "$(TARGET_APP)" ] || { echo "ERROR: TARGET_APP is required. Usage: make install TARGET_APP=<name>"; exit 1; }
	xcrun simctl install booted "$(APP_DST)"
	xcrun simctl launch booted $(subst -,_,$(TARGET_APP)).mastestapp

install-all:
	@for app in $(ALL_APPS); do \
		echo "=== Installing $$app ==="; \
		$(MAKE) install TARGET_APP=$$app; \
	done

clean:
	@[ -n "$(TARGET_APP)" ] || { echo "ERROR: TARGET_APP is required. Usage: make clean TARGET_APP=<name>"; exit 1; }
	rm -rf $(BUILD_DIR)

clean-all:
	@for app in $(ALL_APPS); do \
		echo "=== Cleaning $$app ==="; \
		$(MAKE) clean TARGET_APP=$$app; \
	done
	rm -rf $(DIST_DIR)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(DIST_DIR):
	mkdir -p $(DIST_DIR)
